package handlers

import (
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/firefart/entra-phishing-detection/internal/config"
	"github.com/firefart/entra-phishing-detection/internal/metrics"
	"github.com/firefart/entra-phishing-detection/internal/server/middleware"
	"github.com/firefart/entra-phishing-detection/internal/server/templates"
)

type ImageHandler struct {
	config  config.Configuration
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewImageHandler(c config.Configuration, m *metrics.Metrics, logger *slog.Logger) *ImageHandler {
	return &ImageHandler{
		config:  c,
		logger:  logger,
		metrics: m,
	}
}

func (h *ImageHandler) phishingAttempt(w http.ResponseWriter, r *http.Request, reason string) error {
	ip, ok := r.Context().Value(middleware.ContextKeyIP).(string)
	if !ok {
		ip = r.RemoteAddr
	}
	header := make([]any, len(r.Header))
	i := 0
	for k, v := range r.Header {
		header[i] = slog.String(k, strings.Join(v, ", "))
		i++
	}

	h.logger.With(slog.String("reason", reason), slog.String("remote_ip", ip)).WithGroup("headers").Warn("phishing attempt detected", header...)
	h.metrics.ImageHits.WithLabelValues(reason).Inc()

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
