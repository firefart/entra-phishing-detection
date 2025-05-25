package middleware

import (
	"context"
	"net"
	"net/http"
)

type ContextKey string

const ContextKeyIP ContextKey = "ip"

// RealIPConfig contains configuration for the RealIP middleware
type RealIPConfig struct {
	IPHeader string
}

func getIPFromHostPort(hostPort string) string {
	if hostPort == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return host
}

func getRealIP(ipHeader string, r *http.Request) string {
	if ipHeader == "" {
		return getIPFromHostPort(r.RemoteAddr)
	}

	realIP := r.Header.Get(ipHeader)
	if realIP == "" {
		realIP = getIPFromHostPort(r.RemoteAddr)
	}
	return realIP
}

func RealIP(config RealIPConfig) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), ContextKeyIP, getRealIP(config.IPHeader, r))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
