package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/firefart/entra-phishing-detection/internal/config"
	"github.com/firefart/entra-phishing-detection/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestWithLogger(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	s := &server{}

	opt := WithLogger(logger)
	opt(s)

	require.Equal(t, logger, s.logger)
}

func TestWithConfig(t *testing.T) {
	cfg := config.Configuration{
		AllowedOrigins: []string{"example.com"},
	}
	s := &server{}

	opt := WithConfig(cfg)
	opt(s)

	require.Equal(t, cfg, s.config)
}

func TestWithDebug(t *testing.T) {
	s := &server{}

	opt := WithDebug(true)
	opt(s)

	require.True(t, s.debug)

	opt = WithDebug(false)
	opt(s)

	require.False(t, s.debug)
}

func TestWithMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, err := metrics.NewMetrics(reg)
	require.NoError(t, err)

	s := &server{}

	opt := WithMetrics(m)
	opt(s)

	require.Equal(t, m, s.metrics)
}

func TestWithAccessLog(t *testing.T) {
	s := &server{}

	opt := WithAccessLog()
	opt(s)

	require.True(t, s.accessLog)
}

func TestNotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/notfound", nil)
	w := httptest.NewRecorder()

	err := notFound(w, req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, w.Code)
	require.Empty(t, w.Body.String())
}

func TestNewServer(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cfg := config.Configuration{
		AllowedOrigins: []string{"example.com"},
		Server: config.Server{
			SecretKeyHeaderName:  "X-Secret-Key",
			SecretKeyHeaderValue: "secret",
			IPHeader:             "X-Real-IP",
			PathImage:            "image",
			PathHealth:           "health",
			PathVersion:          "version",
		},
	}
	reg := prometheus.NewRegistry()
	m, err := metrics.NewMetrics(reg)
	require.NoError(t, err)

	handler := NewServer(
		WithLogger(logger),
		WithConfig(cfg),
		WithDebug(true),
		WithMetrics(m),
		WithAccessLog(),
	)

	require.NotNil(t, handler)

	// Test that the handler can handle requests
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestNewServerDefaultPaths(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cfg := config.Configuration{
		AllowedOrigins: []string{"example.com"},
		Server: config.Server{
			SecretKeyHeaderName:  "X-Secret-Key",
			SecretKeyHeaderValue: "secret",
			IPHeader:             "X-Real-IP",
			// Leave paths empty to test defaults
		},
	}
	reg := prometheus.NewRegistry()
	m, err := metrics.NewMetrics(reg)
	require.NoError(t, err)

	handler := NewServer(
		WithLogger(logger),
		WithConfig(cfg),
		WithMetrics(m),
	)

	require.NotNil(t, handler)

	// Test default health path
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Test default image path
	req = httptest.NewRequest(http.MethodGet, "/image", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestNewServerCustomPaths(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cfg := config.Configuration{
		AllowedOrigins: []string{"example.com"},
		Server: config.Server{
			SecretKeyHeaderName:  "X-Secret-Key",
			SecretKeyHeaderValue: "secret",
			IPHeader:             "X-Real-IP",
			PathImage:            "custom-image",
			PathHealth:           "custom-health",
			PathVersion:          "custom-version",
		},
	}
	reg := prometheus.NewRegistry()
	m, err := metrics.NewMetrics(reg)
	require.NoError(t, err)

	handler := NewServer(
		WithLogger(logger),
		WithConfig(cfg),
		WithMetrics(m),
	)

	require.NotNil(t, handler)

	// Test custom health path
	req := httptest.NewRequest(http.MethodGet, "/custom-health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Test custom image path
	req = httptest.NewRequest(http.MethodGet, "/custom-image", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Test custom version path (should require secret key)
	req = httptest.NewRequest(http.MethodGet, "/custom-version", nil)
	req.Header.Set("X-Secret-Key", "secret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestNewServerCatchAll(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cfg := config.Configuration{
		AllowedOrigins: []string{"example.com"},
		Server: config.Server{
			SecretKeyHeaderName:  "X-Secret-Key",
			SecretKeyHeaderValue: "secret",
			IPHeader:             "X-Real-IP",
		},
	}
	reg := prometheus.NewRegistry()
	m, err := metrics.NewMetrics(reg)
	require.NoError(t, err)

	handler := NewServer(
		WithLogger(logger),
		WithConfig(cfg),
		WithMetrics(m),
	)

	require.NotNil(t, handler)

	// Test catch-all route
	req := httptest.NewRequest(http.MethodGet, "/random-path", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Empty(t, w.Body.String())
}
