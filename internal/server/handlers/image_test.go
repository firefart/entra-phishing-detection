package handlers_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/firefart/entra-phishing-detection/internal/config"
	"github.com/firefart/entra-phishing-detection/internal/metrics"
	"github.com/firefart/entra-phishing-detection/internal/server/handlers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestImage(t *testing.T) {
	configuration := config.Configuration{
		Server: config.Server{
			SecretKeyHeaderName:  "X-Secret-Key",
			SecretKeyHeaderValue: "SECRET",
		},
		AllowedOrigins: []string{"loginsite.internal"},
	}
	logger := slog.New(slog.DiscardHandler)
	m, err := metrics.NewMetrics(prometheus.NewRegistry())
	require.NoError(t, err)
	imageHandler := handlers.NewImageHandler(handlers.ImageHandlerOptions{
		AllowedOrigins: configuration.AllowedOrigins,
		Logger:         logger,
		Metrics:        m,
		ImageOK:        []byte("imageOK"),
		ImagePhishing:  []byte("imagePhishing"),
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	// test with no referer
	require.NoError(t, imageHandler.Handler(rec, req))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, `inline; filename="image.svg"`, rec.Header().Get("Content-Disposition"))
	require.Equal(t, "image/svg+xml", rec.Header().Get("Content-Type"))
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	require.Equal(t, "no-cache", rec.Header().Get("Pragma"))
	require.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
	require.Equal(t, "imagePhishing", rec.Body.String())

	// test with wrong referer
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Referer", "https://example.com")
	rec = httptest.NewRecorder()
	require.NoError(t, imageHandler.Handler(rec, req))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "imagePhishing", rec.Body.String())

	// test with invalid referer
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Referer", ")_*(()&&^%$#$%)")
	rec = httptest.NewRecorder()
	require.NoError(t, imageHandler.Handler(rec, req))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "imagePhishing", rec.Body.String())

	// test with correct referer
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Referer", "https://loginsite.internal/xxxx")
	rec = httptest.NewRecorder()
	require.NoError(t, imageHandler.Handler(rec, req))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "imageOK", rec.Body.String())
}

func TestNewImageHandlerPanics(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	m, err := metrics.NewMetrics(prometheus.NewRegistry())
	require.NoError(t, err)

	validOpts := handlers.ImageHandlerOptions{
		AllowedOrigins: []string{"example.com"},
		Logger:         logger,
		Metrics:        m,
		ImageOK:        []byte("ok"),
		ImagePhishing:  []byte("phishing"),
	}

	t.Run("nil logger panics", func(t *testing.T) {
		opts := validOpts
		opts.Logger = nil
		require.Panics(t, func() {
			handlers.NewImageHandler(opts)
		})
	})

	t.Run("nil metrics panics", func(t *testing.T) {
		opts := validOpts
		opts.Metrics = nil
		require.Panics(t, func() {
			handlers.NewImageHandler(opts)
		})
	})

	t.Run("empty ImageOK panics", func(t *testing.T) {
		opts := validOpts
		opts.ImageOK = []byte{}
		require.Panics(t, func() {
			handlers.NewImageHandler(opts)
		})
	})

	t.Run("nil ImageOK panics", func(t *testing.T) {
		opts := validOpts
		opts.ImageOK = nil
		require.Panics(t, func() {
			handlers.NewImageHandler(opts)
		})
	})

	t.Run("empty ImagePhishing panics", func(t *testing.T) {
		opts := validOpts
		opts.ImagePhishing = []byte{}
		require.Panics(t, func() {
			handlers.NewImageHandler(opts)
		})
	})

	t.Run("nil ImagePhishing panics", func(t *testing.T) {
		opts := validOpts
		opts.ImagePhishing = nil
		require.Panics(t, func() {
			handlers.NewImageHandler(opts)
		})
	})
}
