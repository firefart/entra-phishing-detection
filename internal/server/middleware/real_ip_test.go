package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRealIP(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(ContextKeyIP).(string) != "some-ip" {
			t.Error("IP not set correctly in context")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "next content")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "some-ip")
	rec := httptest.NewRecorder()
	RealIP(RealIPConfig{IPHeader: "X-Real-IP"})(next).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "next content", rec.Body.String())
}

func TestGetIPFromHostPort(t *testing.T) {
	tests := []struct {
		name     string
		hostPort string
		expected string
	}{
		{
			name:     "empty string",
			hostPort: "",
			expected: "",
		},
		{
			name:     "host with port",
			hostPort: "192.168.1.1:8080",
			expected: "192.168.1.1",
		},
		{
			name:     "host without port",
			hostPort: "192.168.1.1",
			expected: "192.168.1.1",
		},
		{
			name:     "ipv6 with port",
			hostPort: "[::1]:8080",
			expected: "::1",
		},
		{
			name:     "invalid format",
			hostPort: "invalid:host:port",
			expected: "invalid:host:port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getIPFromHostPort(tt.hostPort)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestGetRealIP(t *testing.T) {
	tests := []struct {
		name       string
		ipHeader   string
		headerVal  string
		remoteAddr string
		expected   string
	}{
		{
			name:       "with IP header set",
			ipHeader:   "X-Real-IP",
			headerVal:  "192.168.1.100",
			remoteAddr: "10.0.0.1:1234",
			expected:   "192.168.1.100",
		},
		{
			name:       "no IP header configured",
			ipHeader:   "",
			headerVal:  "",
			remoteAddr: "10.0.0.1:1234",
			expected:   "10.0.0.1",
		},
		{
			name:       "IP header configured but not present",
			ipHeader:   "X-Real-IP",
			headerVal:  "",
			remoteAddr: "10.0.0.1:1234",
			expected:   "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.headerVal != "" {
				req.Header.Set(tt.ipHeader, tt.headerVal)
			}

			result := getRealIP(tt.ipHeader, req)
			require.Equal(t, tt.expected, result)
		})
	}
}
