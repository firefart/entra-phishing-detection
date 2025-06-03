package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/firefart/entra-phishing-detection/internal/metrics"
	"github.com/firefart/entra-phishing-detection/internal/server/middleware"
	"github.com/firefart/entra-phishing-detection/internal/utils"
)

// ImageHandler handles requests for the phishing detection image endpoint.
// It analyzes the HTTP Referer header to determine if the request originates
// from a legitimate Microsoft login page.
type ImageHandler struct {
	ImageHandlerOptions
}

const (
	reasonMissingReferer        = "missing referer"
	reasonInvalidReferer        = "invalid referer"
	reasonRefererNotWhitelisted = "referer not whitelisted"
	reasonAllowedReferer        = "referer allowed"
)

type ImageHandlerOptions struct {
	// CAllowedOrigins holds the hostnames of the allowed referers
	AllowedOrigins []string
	// Metrics holds the metrics instance for tracking image hits.
	Metrics *metrics.Metrics
	// Logger is the logger instance for logging events.
	Logger *slog.Logger
	// ImagesOK contains the images to return for safe URLs.
	ImagesOK map[string][]byte
	// ImagesPhishing contains the images to return for phishing attempts.
	ImagesPhishing map[string][]byte
}

func NewImageHandler(opts ImageHandlerOptions) *ImageHandler {
	if opts.Logger == nil {
		panic("logger cannot be nil")
	}
	if opts.Metrics == nil {
		panic("metrics cannot be nil")
	}
	if len(opts.ImagesOK) == 0 {
		panic("ImagesOK cannot be nil or empty")
	}
	if len(opts.ImagesPhishing) == 0 {
		panic("ImagesPhishing cannot be nil or empty")
	}
	if i, ok := opts.ImagesOK["en"]; !ok || len(i) == 0 {
		panic("ImagesOK must contain an 'en' key with a valid image")
	}
	if i, ok := opts.ImagesPhishing["en"]; !ok || len(i) == 0 {
		panic("ImagesPhishing must contain an 'en' key with a valid image")
	}
	return &ImageHandler{
		ImageHandlerOptions: opts,
	}
}

func (h *ImageHandler) getImageOK(r *http.Request) (string, []byte) {
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept-Language
	languages := utils.GetLanguages(r.Header.Get("Accept-Language"))
	for _, lang := range languages {
		lang = strings.ToLower(strings.Split(lang, "-")[0]) // Normalize to primary language code
		// swtich between the defined languages
		if image, ok := h.ImagesOK[lang]; ok {
			return lang, image
		}
	}
	// Default to English if no specific language is found
	return "en", h.ImagesOK["en"]
}

func (h *ImageHandler) getImagePhishing(r *http.Request) (string, []byte) {
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept-Language
	languages := utils.GetLanguages(r.Header.Get("Accept-Language"))
	for _, lang := range languages {
		lang = strings.ToLower(strings.Split(lang, "-")[0]) // Normalize to primary language code
		// swtich between the defined languages
		if image, ok := h.ImagesPhishing[lang]; ok {
			return lang, image
		}
	}
	// Default to English if no specific language is found
	return "en", h.ImagesPhishing["en"]
}

func (h *ImageHandler) phishingAttempt(w http.ResponseWriter, r *http.Request, reason string) error {
	ip, ok := r.Context().Value(middleware.ContextKeyIP).(string)
	if !ok {
		ip = r.RemoteAddr
	}
	header := make([]any, len(r.Header))
	i := 0
	for k, v := range r.Header {
		header[i] = slog.String(http.CanonicalHeaderKey(k), strings.Join(v, ", "))
		i++
	}

	language, image := h.getImagePhishing(r)

	h.Logger.With(slog.String("reason", reason), slog.String("remote_ip", ip), slog.String("language", language), slog.String("host", r.Host)).WithGroup("headers").Warn("phishing attempt detected", header...)

	h.Metrics.ImageHits.WithLabelValues(r.Host, language, reason).Inc()

	w.WriteHeader(http.StatusOK)
	_, err := w.Write(image)
	if err != nil {
		return fmt.Errorf("failed to write phishing image response: %w", err)
	}
	return nil
}

func (h *ImageHandler) safeURL(w http.ResponseWriter, r *http.Request) error {
	language, image := h.getImageOK(r)

	h.Metrics.ImageHits.WithLabelValues(r.Host, language, reasonAllowedReferer).Inc()

	w.WriteHeader(http.StatusOK)
	_, err := w.Write(image)
	if err != nil {
		return fmt.Errorf("failed to write ok image response: %w", err)
	}
	return nil
}

// Handler processes image requests and returns different SVG content
// based on whether the request appears to be from a legitimate source.
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
		return h.phishingAttempt(w, r, reasonMissingReferer)
	}
	parsed, err := url.Parse(referer)
	if err != nil {
		return h.phishingAttempt(w, r, reasonInvalidReferer)
	}
	if slices.Contains(h.AllowedOrigins, parsed.Hostname()) {
		return h.safeURL(w, r)
	}
	return h.phishingAttempt(w, r, reasonRefererNotWhitelisted)
}
