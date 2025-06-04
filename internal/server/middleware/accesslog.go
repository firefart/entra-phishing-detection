package middleware

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/firefart/entra-phishing-detection/internal/metrics"
)

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode     int
	written        bool
	responseLength int64
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	if rw.written {
		return
	}
	rw.statusCode = statusCode
	rw.written = true
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriter) Write(data []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.ResponseWriter.Write(data)
	rw.responseLength += int64(n)
	return n, err
}

// AccessLogConfig holds configuration for the accesslog middleware
type AccessLogConfig struct {
	Logger  *slog.Logger
	Metrics *metrics.Metrics
}

// AccessLog creates a middleware that logs all HTTP requests with detailed information
func AccessLog(config AccessLogConfig) func(next http.Handler) http.Handler {
	if config.Logger == nil {
		panic("accesslog middleware requires a logger")
	}
	if config.Metrics == nil {
		panic("accesslog middleware requires metrics")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Wrap the response writer to capture status code
			wrapped := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK, // default status
				written:        false,
				responseLength: 0,
			}

			// Get IP from context (set by RealIP middleware)
			ip, ok := r.Context().Value(ContextKeyIP).(string)
			if !ok {
				ip = r.RemoteAddr
			}

			start := time.Now()
			// Call the next handler
			next.ServeHTTP(wrapped, r)
			// Calculate duration
			duration := time.Since(start)

			// Prepare header attributes for logging
			headerAttrs := make([]any, 0, len(r.Header))
			for name, values := range r.Header {
				headerAttrs = append(headerAttrs, slog.String(http.CanonicalHeaderKey(name), strings.Join(values, ", ")))
			}

			// Labels: "code", "method", "host", "url"
			labelValues := []string{
				strconv.Itoa(wrapped.statusCode),
				r.Method,
				r.Host,
				r.URL.Path,
			}
			config.Metrics.RequestCount.WithLabelValues(labelValues...).Inc()
			config.Metrics.RequestDuration.WithLabelValues(labelValues...).Observe(duration.Seconds())
			config.Metrics.RequestSize.WithLabelValues(labelValues...).Observe(float64(r.ContentLength))
			config.Metrics.ResponseSize.WithLabelValues(labelValues...).Observe(float64(wrapped.responseLength))

			// Log the request with all details
			config.Logger.With(
				// Request fields
				slog.String("method", r.Method),
				slog.String("proto", r.Proto),
				slog.String("host", r.Host),
				slog.String("path", r.URL.Path),
				slog.String("query", r.URL.RawQuery),
				slog.String("remote_addr", r.RemoteAddr),
				slog.String("remote_ip", ip),
				slog.Int64("request_body_length", r.ContentLength),
				slog.Int64("response_body_length", wrapped.responseLength),
				slog.Int("status_code", wrapped.statusCode),
				slog.Duration("duration", duration),
			).WithGroup("headers").Info("request completed", headerAttrs...)
		})
	}
}
