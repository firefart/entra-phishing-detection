package middleware

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecover(t *testing.T) {
	t.Run("normal operation without panic", func(t *testing.T) {
		var logOutput bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logOutput, nil))
		middleware := Recover(logger)
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		})
		handler := middleware(nextHandler)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "success", w.Body.String())
		require.Empty(t, logOutput.String())
	})

	t.Run("recovers from string panic", func(t *testing.T) {
		var logOutput bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logOutput, nil))
		middleware := Recover(logger)
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			panic("test panic")
		})
		handler := middleware(nextHandler)
		req := httptest.NewRequest(http.MethodPost, "/test?param=value", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusInternalServerError, w.Code)
		require.Equal(t, "Internal Server Error\n", w.Body.String())
		// Verify log output
		require.NotEmpty(t, logOutput.String())
		var logEntry map[string]any
		err := json.Unmarshal(logOutput.Bytes(), &logEntry)
		require.NoError(t, err)
		require.Equal(t, "ERROR", logEntry["level"])
		require.Equal(t, "panic recovered", logEntry["msg"])
		require.Equal(t, "POST", logEntry["method"])
		require.Equal(t, "/test?param=value", logEntry["url"])
		require.Equal(t, "test panic", logEntry["error"])
	})

	t.Run("recovers from error panic", func(t *testing.T) {
		var logOutput bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logOutput, nil))
		middleware := Recover(logger)
		nextHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			panic(http.ErrUseLastResponse)
		})
		handler := middleware(nextHandler)
		req := httptest.NewRequest(http.MethodPut, "/api/test", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusInternalServerError, w.Code)
		require.Equal(t, "Internal Server Error\n", w.Body.String())
		require.NotEmpty(t, logOutput.String())
	})

	t.Run("middleware chain continues after recovery", func(t *testing.T) {
		var logOutput bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logOutput, nil))
		middleware := Recover(logger)
		// Simulate a middleware chain where one handler panics
		panicHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			panic("middleware panic")
		})
		handler := middleware(panicHandler)
		req := httptest.NewRequest(http.MethodGet, "/chain", nil)
		w := httptest.NewRecorder()
		// This should not panic the test itself
		require.NotPanics(t, func() {
			handler.ServeHTTP(w, req)
		})
		require.Equal(t, http.StatusInternalServerError, w.Code)
		require.NotEmpty(t, logOutput.String())
	})
}
