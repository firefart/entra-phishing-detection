package handlers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetHost(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)
	r.Header.Set("Host", "example.com")
	require.Equal(t, "example.com", getHost(r))

	r, err = http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)
	r.Header.Set("X-Forwarded-Host", "example2.com")
	require.Equal(t, "example2.com", getHost(r))

	r, err = http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)
	r.Host = "example3.com"
	require.Equal(t, "example3.com", getHost(r))

	r, err = http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)
	r.RemoteAddr = "example4.com"
	require.Equal(t, "example4.com", getHost(r))
}
