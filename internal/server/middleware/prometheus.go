package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/firefart/entra-phishing-detection/internal/metrics"
)

type statusCodeWrapper struct {
	http.ResponseWriter
	statusCode int
}

func newStatusCodeWrapper(w http.ResponseWriter) *statusCodeWrapper {
	return &statusCodeWrapper{w, http.StatusOK}
}

func (lrw *statusCodeWrapper) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func Prometheus(m *metrics.Metrics) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			lrw := newStatusCodeWrapper(w)
			start := time.Now()
			next.ServeHTTP(lrw, r)
			statusCode := strconv.Itoa(lrw.statusCode)
			method := r.Method
			host := r.Host
			path := r.URL.Path
			referer := r.Header.Get("Referer")
			// Labels: "code", "method", "host", "url", "referer"
			m.RequestCount.WithLabelValues(statusCode, method, host, path, referer).Inc()
			m.RequestDuration.WithLabelValues(statusCode, method, host, path, referer).Observe(time.Since(start).Seconds())
		})
	}
}
