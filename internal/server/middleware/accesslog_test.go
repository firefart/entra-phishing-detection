package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAccessLog(t *testing.T) {
	t.Run("logs successful request", func(t *testing.T) {
		var logOutput bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logOutput, nil))

		middleware := AccessLog(AccessLogConfig{Logger: logger})

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "success")
		})

		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/test?param=value", nil)
		req.Header.Set("User-Agent", "test-agent")
		req.Header.Set("X-Custom-Header", "custom-value")
		req.Header.Set("Referer", "https://example.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "success", w.Body.String())

		// Verify log output
		require.NotEmpty(t, logOutput.String())

		var logEntry map[string]interface{}
		err := json.Unmarshal(logOutput.Bytes(), &logEntry)
		require.NoError(t, err)

		require.Equal(t, "INFO", logEntry["level"])
		require.Equal(t, "request completed", logEntry["msg"])
		require.Equal(t, "GET", logEntry["method"])
		require.Equal(t, "/test", logEntry["path"])
		require.Equal(t, "param=value", logEntry["query"])
		require.Equal(t, float64(200), logEntry["status_code"]) // nolint:testifylint
		require.Contains(t, logEntry, "duration")
		require.Equal(t, float64(7), logEntry["response_body_length"]) // nolint:testifylint
		require.Equal(t, float64(0), logEntry["request_body_length"])  // nolint:testifylint
		// Check request headers group
		require.Contains(t, logEntry, "request_headers")
		headers := logEntry["request_headers"].(map[string]interface{})
		require.Equal(t, "test-agent", headers["user-agent"])
		require.Equal(t, "custom-value", headers["x-custom-header"])
		require.Equal(t, "https://example.com", headers["referer"])
	})

	t.Run("logs error status code", func(t *testing.T) {
		var logOutput bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logOutput, nil))

		middleware := AccessLog(AccessLogConfig{Logger: logger})

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "not found")
		})

		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodPost, "/nonexistent", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusNotFound, w.Code)

		var logEntry map[string]interface{}
		err := json.Unmarshal(logOutput.Bytes(), &logEntry)
		require.NoError(t, err)

		require.Equal(t, "POST", logEntry["method"])
		require.Equal(t, "/nonexistent", logEntry["path"])
		require.Equal(t, float64(404), logEntry["status_code"]) // nolint:testifylint
	})

	t.Run("captures IP from context", func(t *testing.T) {
		var logOutput bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logOutput, nil))

		middleware := AccessLog(AccessLogConfig{Logger: logger})

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		// Wrap with RealIP middleware first
		realIPMiddleware := RealIP(RealIPConfig{IPHeader: "X-Real-IP"})
		handler := realIPMiddleware(middleware(nextHandler))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Real-IP", "192.168.1.100")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		var logEntry map[string]interface{}
		err := json.Unmarshal(logOutput.Bytes(), &logEntry)
		require.NoError(t, err)

		require.Equal(t, "192.168.1.100", logEntry["remote_ip"])
	})

	t.Run("handles multiple header values", func(t *testing.T) {
		var logOutput bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logOutput, nil))

		middleware := AccessLog(AccessLogConfig{Logger: logger})

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Add("Accept", "text/html")
		req.Header.Add("Accept", "application/json")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		var logEntry map[string]interface{}
		err := json.Unmarshal(logOutput.Bytes(), &logEntry)
		require.NoError(t, err)

		headers := logEntry["request_headers"].(map[string]interface{})
		require.Equal(t, "text/html, application/json", headers["accept"])
	})

	t.Run("measures duration correctly", func(t *testing.T) {
		var logOutput bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logOutput, nil))

		middleware := AccessLog(AccessLogConfig{Logger: logger})

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(10 * time.Millisecond) // Small delay for testing
			w.WriteHeader(http.StatusOK)
		})

		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		start := time.Now()
		handler.ServeHTTP(w, req)
		actualDuration := time.Since(start)

		var logEntry map[string]interface{}
		err := json.Unmarshal(logOutput.Bytes(), &logEntry)
		require.NoError(t, err)

		loggedDuration := logEntry["duration"].(float64)
		require.Greater(t, loggedDuration, 5.0)                                    // Should be at least 5ms
		require.Less(t, loggedDuration, float64(actualDuration.Nanoseconds()+100)) // Allow some margin
	})

	t.Run("panics without logger", func(t *testing.T) {
		require.Panics(t, func() {
			AccessLog(AccessLogConfig{})
		})
	})

	t.Run("handles default status code", func(t *testing.T) {
		var logOutput bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logOutput, nil))

		middleware := AccessLog(AccessLogConfig{Logger: logger})

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// Don't explicitly set status code, should default to 200
			fmt.Fprint(w, "default status")
		})

		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var logEntry map[string]interface{}
		err := json.Unmarshal(logOutput.Bytes(), &logEntry)
		require.NoError(t, err)

		require.Equal(t, float64(200), logEntry["status_code"]) // nolint:testifylint
	})
}
