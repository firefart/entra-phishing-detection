# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go-based HTTP service that provides phishing protection for Microsoft Entra ID (formerly Azure AD) login pages. It exploits Microsoft's "company branding" feature: organizations can configure a custom image URL in Entra ID, and this service serves that image. The image returned depends on the `Referer` header — a safe image if the request comes from a legitimate Microsoft domain, or a warning image if not (indicating a phishing attempt).

## Commands

This project uses [Task](https://taskfile.dev) as the task runner (`Taskfile.yml`).

```bash
task build       # Format, vet, fix, and build the binary (CGO_ENABLED=0)
task test        # Run tests with race detector and coverage (CGO_ENABLED=1)
task lint        # Run golangci-lint (30m timeout) + go mod tidy
task run         # Build and run with -debug -config config.json
task dev         # Build and run with live reload via air
task configcheck # Validate the config file
task deps        # go mod tidy
task update      # Update all dependencies
```

Run a single test package:

```bash
go test -race ./internal/server/handlers/...
```

Run a specific test:

```bash
go test -race -run TestImageHandler ./internal/server/handlers/...
```

## Instructions

- When making changes, always make sure the changes are covered by test cases. If test cases are missing, add them.
- Run `task test` after every set of changes and fix all reported issues before considering the work done.
- Run `task lint` after every set of changes and fix all reported issues before considering the work done. The CI also runs golangci-lint on a schedule.
- When adding or updating code, make sure `CLAUDE.md` is up to date with the new or added features.

## Architecture

### Request Flow

1. Microsoft Entra ID fetches the configured image URL (the `/image` endpoint)
2. The `ImageHandler` inspects the `Referer` header
3. If the referer is in `AllowedOrigins` (e.g., `login.microsoftonline.com`), return the safe/OK image
4. Otherwise, return the phishing warning image — the user sees the warning on the Entra login page
5. Language selection uses `Accept-Language` header; images are keyed by primary language code (e.g., `"en"`, `"de"`)

### Package Structure

- **`main.go`** — Wires up config, logging, metrics, and starts three servers (main, metrics, optional pprof)
- **`internal/config/`** — Config loading via koanf (JSON file + env vars), validated with go-playground/validator
- **`internal/server/`** — HTTP server construction via `NewServer()` with functional options pattern
  - **`handlers/`** — `ImageHandler` (core logic), `HealthHandler`, `VersionHandler`
  - **`middleware/`** — `Recover`, `RealIP`, `RealHost`, `SecretKeyHeader`, `AccessLog`; each is independently testable
  - **`router/`** — Thin wrapper around `http.ServeMux` supporting middleware chains and route groups
  - **`httperror/`** — `HTTPError` type for structured HTTP error responses
  - **`embed.go`** — Embeds default SVG assets (`assets/` directory) at compile time
- **`internal/metrics/`** — Prometheus metrics (`ImageHits` counter with host/language/reason labels, `Errors` counter)
- **`internal/utils/`** — `Accept-Language` header parsing

### Key Design Decisions

- Handlers return `error` (not standard `http.HandlerFunc`); the router's error handler converts these to HTTP responses
- Health and version routes are protected by a secret key header (`SecretKeyHeaderName`/`SecretKeyHeaderValue`)
- The 404 handler returns HTTP 200 with an empty body (intentional — avoids leaking route info)
- Images are embedded at compile time; custom images can be provided via config file paths
- Multi-tenant: the `Host` header (after `RealHost` middleware) is used as a label in Prometheus metrics, enabling per-organization tracking

### Configuration

Configuration is a JSON file with optional env var overrides. See `config.sample.json` for the full structure. Key fields:

- `allowed_origins` — list of hostnames (supports `filepath.Match` glob patterns, e.g. `*.microsoftonline.com`) whose `Referer` is considered legitimate
- `treat_missing_referer_as_phishing` — whether to treat missing `Referer` as an attack
- `server.ip_header` / `server.host_headers` — reverse proxy header names for real IP/host
- Per-language image overrides via file paths in config; image language keys must be lowercase primary codes (no dashes), and `"en"` is always required

**Env var overrides** use the `ENTRA_` prefix. Key mapping: single `_` becomes `.` (nesting separator), double `__` becomes `_` (for keys containing underscores). Example: `ENTRA_SERVER__LISTEN` → `server.listen`.
