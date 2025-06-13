# syntax=docker/dockerfile:1

FROM golang:latest AS build-env
ENV CGO_ENABLED=0
WORKDIR /src
COPY go.* /src/
RUN go mod download
COPY . .
RUN go build -a -o app -ldflags="-s -w" -trimpath

FROM alpine:latest

RUN apk add --no-cache curl ca-certificates \
    && rm -rf /var/cache/*

RUN mkdir -p /app \
    && adduser -D user \
    && chown -R user:user /app

USER user
WORKDIR /app

COPY --from=build-env /src/app .

HEALTHCHECK --interval=5s --timeout=10s --start-period=5s --retries=3 CMD curl -f -sS http://localhost:8000/healthz || exit 1

ENTRYPOINT [ "./app" ]
