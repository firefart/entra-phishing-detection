package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHostMiddleware(t *testing.T) {
	config := RealHostConfig{
		Headers: []string{"X-Forwarded-Host", "X-Original-Host"},
	}

	// Create a test handler that checks the host
	testHandler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Check if host is set correctly in request
		if r.Host != "proxy.example.com" {
			t.Errorf("Expected Host to be 'proxy.example.com', got '%s'", r.Host)
		}

		// Check if host is available in context
		if host := r.Context().Value(ContextKeyHost); host != "proxy.example.com" {
			t.Errorf("Expected context host to be 'proxy.example.com', got '%v'", host)
		}
	})

	// Wrap with middleware
	handler := RealHost(config)(testHandler)

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "original.example.com"
	req.Header.Set("X-Forwarded-Host", "proxy.example.com")

	// Execute request
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
}

func TestGetHostFromHeaders(t *testing.T) {
	tests := []struct {
		name           string
		headers        []string
		hostHeader     string
		requestHeaders map[string]string
		expectedHost   string
	}{
		{
			name:       "first header found",
			headers:    []string{"X-Forwarded-Host", "X-Original-Host"},
			hostHeader: "example.com",
			requestHeaders: map[string]string{
				"X-Forwarded-Host": "first.example.com",
				"X-Original-Host":  "second.example.com",
			},
			expectedHost: "first.example.com",
		},
		{
			name:       "second header found when first missing",
			headers:    []string{"X-Forwarded-Host", "X-Original-Host"},
			hostHeader: "example.com",
			requestHeaders: map[string]string{
				"X-Original-Host": "second.example.com",
			},
			expectedHost: "second.example.com",
		},
		{
			name:           "no headers found",
			headers:        []string{"X-Forwarded-Host", "X-Original-Host"},
			hostHeader:     "example.com",
			requestHeaders: map[string]string{},
			expectedHost:   "example.com",
		},
		{
			name:       "comma-separated values",
			headers:    []string{"X-Forwarded-Host"},
			hostHeader: "example.com",
			requestHeaders: map[string]string{
				"X-Forwarded-Host": "first.example.com, second.example.com, third.example.com",
			},
			expectedHost: "first.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Host = tt.hostHeader
			for key, value := range tt.requestHeaders {
				req.Header.Set(key, value)
			}

			host := getHostFromHeaders(tt.headers, req)
			if host != tt.expectedHost {
				t.Errorf("getHostFromHeaders() = %v, want %v", host, tt.expectedHost)
			}
		})
	}
}
