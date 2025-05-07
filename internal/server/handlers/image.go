package handlers

import (
	"log/slog"
	"net/http"
	"net/url"
	"slices"

	"github.com/firefart/entra-phishing-detection/internal/config"
	"github.com/firefart/entra-phishing-detection/internal/server/templates"
)

type ImageHandler struct {
	config config.Configuration
	logger *slog.Logger
}

func NewImageHandler(c config.Configuration, logger *slog.Logger) *ImageHandler {
	return &ImageHandler{
		config: c,
		logger: logger,
	}
}

func (h *ImageHandler) getRealIP(r *http.Request) string {
	if h.config.Server.IPHeader == "" {
		return r.RemoteAddr
	}

	realIP := r.Header.Get(h.config.Server.IPHeader)
	if realIP == "" {
		realIP = r.RemoteAddr
	}
	return realIP
}

func (h *ImageHandler) phishingAttempt(w http.ResponseWriter, r *http.Request, reason string) error {
	h.logger.With(
		slog.String("remote_ip", h.getRealIP(r)),
		slog.String("user_agent", r.Header.Get("User-Agent")),
		slog.String("referer", r.Header.Get("Referer")),
	).Warn("phishing attempt detected", slog.String("reason", reason))

	w.WriteHeader(http.StatusOK)
	return templates.ImageNOK().Render(r.Context(), w)
}

func (h *ImageHandler) safeURL(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusOK)
	return templates.ImageOK().Render(r.Context(), w)
}

func (h *ImageHandler) Handler(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Disposition", `inline; filename="image.svg"`)
	w.Header().Set("Content-Type", "image/svg+xml")
	// prevent caching of the response
	w.Header().Set("Cache-Control", "no-store")
	// https://http.dev/pragma
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	referer := r.Header.Get("Referer")
	if referer == "" {
		return h.phishingAttempt(w, r, "missing referer")
	}
	parsed, err := url.Parse(referer)
	if err != nil {
		return h.phishingAttempt(w, r, "invalid referer")
	}
	if slices.Contains(h.config.AllowedOrigins, parsed.Hostname()) {
		return h.safeURL(w, r)
	}
	return h.phishingAttempt(w, r, "referer not whitelisted")
}
