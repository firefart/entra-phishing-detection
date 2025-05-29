package middleware_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/firefart/entra-phishing-detection/internal/config"
	"github.com/firefart/entra-phishing-detection/internal/metrics"
	"github.com/firefart/entra-phishing-detection/internal/server"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestAccessLogMiddlewareIntegration(t *testing.T) {
	// Create a buffer to capture log output
	var logOutput bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logOutput, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create test configuration
	cfg := config.Configuration{
		Server: config.Server{
			SecretKeyHeaderName:  "X-Secret-Key",
			SecretKeyHeaderValue: "test-secret",
			IPHeader:             "X-Real-IP",
			PathImage:            "test-image",
			PathHealth:           "test-health",
			PathVersion:          "test-version",
		},
		AllowedOrigins: []string{"example.com"},
	}

	// Create metrics
	registry := prometheus.NewRegistry()
	m, err := metrics.NewMetrics(registry, metrics.WithAccessLog())
	require.NoError(t, err)

	// Create server with accesslog middleware
	handler := server.NewServer(
		server.WithLogger(logger),
		server.WithConfig(cfg),
		server.WithMetrics(m),
		server.WithDebug(false),
		server.WithAccessLog(),
	)

	t.Run("logs image endpoint request", func(t *testing.T) {
		// Clear previous log output
		logOutput.Reset()

		req := httptest.NewRequest(http.MethodGet, "/test-image", nil)
		req.Header.Set("X-Real-IP", "192.168.1.100")
		req.Header.Set("User-Agent", "Mozilla/5.0 Integration Test")
		req.Header.Set("Referer", "https://phishing-site.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Check that request was handled
		require.Equal(t, http.StatusOK, w.Code)

		// Parse log output
		logs := logOutput.String()
		require.NotEmpty(t, logs)

		// Split log entries (there might be multiple log lines)
		logLines := bytes.Split(logOutput.Bytes(), []byte("\n"))
		var requestLog map[string]interface{}

		// Find the request completed log entry
		for _, line := range logLines {
			if len(line) == 0 {
				continue
			}
			var logEntry map[string]interface{}
			err := json.Unmarshal(line, &logEntry)
			if err != nil {
				continue
			}
			if logEntry["msg"] == "request completed" {
				requestLog = logEntry
				break
			}
		}

		require.NotNil(t, requestLog, "Could not find 'request completed' log entry in: %s", logs)

		// Verify log fields
		require.Equal(t, "INFO", requestLog["level"])
		require.Equal(t, "request completed", requestLog["msg"])
		require.Equal(t, "GET", requestLog["method"])
		require.Equal(t, "/test-image", requestLog["path"])
		require.Equal(t, "192.168.1.100", requestLog["remote_ip"])
		require.Equal(t, float64(200), requestLog["status_code"]) // nolint:testifylint
		require.Contains(t, requestLog, "duration")

		// Check request headers
		require.Contains(t, requestLog, "request_headers")
		headers := requestLog["request_headers"].(map[string]interface{})
		require.Equal(t, "Mozilla/5.0 Integration Test", headers["user-agent"])
		require.Equal(t, "https://phishing-site.com", headers["referer"])
		require.Equal(t, "192.168.1.100", headers["x-real-ip"])
	})

	t.Run("logs health endpoint request", func(t *testing.T) {
		// Clear previous log output
		logOutput.Reset()

		req := httptest.NewRequest(http.MethodGet, "/test-health", nil)
		req.Header.Set("Accept", "application/json")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		// Parse log output to find request completed entry
		logLines := bytes.Split(logOutput.Bytes(), []byte("\n"))
		var requestLog map[string]interface{}

		for _, line := range logLines {
			if len(line) == 0 {
				continue
			}
			var logEntry map[string]interface{}
			err := json.Unmarshal(line, &logEntry)
			if err != nil {
				continue
			}
			if logEntry["msg"] == "request completed" {
				requestLog = logEntry
				break
			}
		}

		require.NotNil(t, requestLog)
		require.Equal(t, "GET", requestLog["method"])
		require.Equal(t, "/test-health", requestLog["path"])
		require.Equal(t, float64(200), requestLog["status_code"]) // nolint:testifylint

		// Check headers
		headers := requestLog["request_headers"].(map[string]interface{})
		require.Equal(t, "application/json", headers["accept"])
	})

	t.Run("logs version endpoint with auth", func(t *testing.T) {
		// Clear previous log output
		logOutput.Reset()

		req := httptest.NewRequest(http.MethodGet, "/test-version", nil)
		req.Header.Set("X-Secret-Key", "test-secret")
		req.Header.Set("Authorization", "Bearer token123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		// Parse log output
		logLines := bytes.Split(logOutput.Bytes(), []byte("\n"))
		var requestLog map[string]interface{}

		for _, line := range logLines {
			if len(line) == 0 {
				continue
			}
			var logEntry map[string]interface{}
			err := json.Unmarshal(line, &logEntry)
			if err != nil {
				continue
			}
			if logEntry["msg"] == "request completed" {
				requestLog = logEntry
				break
			}
		}

		require.NotNil(t, requestLog)
		require.Equal(t, "GET", requestLog["method"])
		require.Equal(t, "/test-version", requestLog["path"])
		require.Equal(t, float64(200), requestLog["status_code"]) // nolint:testifylint

		// Check that sensitive headers are logged (this is expected behavior)
		headers := requestLog["request_headers"].(map[string]interface{})
		require.Equal(t, "test-secret", headers["x-secret-key"])
		require.Equal(t, "Bearer token123", headers["authorization"])
	})
}
