package middleware

import (
	"context"
	"net/http"
	"strings"
)

const ContextKeyHost ContextKey = "host"

// HostConfig contains configuration for the host middleware
type HostConfig struct {
	// Headers is a list of headers to check for the host value, in order of preference
	Headers []string
}

// getHostFromHeaders attempts to extract the host from various proxy headers
func getHostFromHeaders(headers []string, r *http.Request) string {
	for _, header := range headers {
		if value := r.Header.Get(header); value != "" {
			// For X-Forwarded-Host, take the first value if comma-separated
			if strings.Contains(value, ",") {
				value = strings.TrimSpace(strings.Split(value, ",")[0])
			}
			return value
		}
	}
	return r.Host
}

// Host middleware sets the correct host header based on proxy headers
func Host(config HostConfig) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := getHostFromHeaders(config.Headers, r)
			// Set the Host header in the request
			r.Host = host
			// Also store in context for potential use by handlers
			ctx := context.WithValue(r.Context(), ContextKeyHost, host)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
