package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecretKeyHeader(t *testing.T) {
	mwConfig := SecretKeyHeaderConfig{
		SecretKeyHeaderName:  "X-Secret-Key",
		SecretKeyHeaderValue: "secret",
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "secret content")
	})

	// valid header
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(mwConfig.SecretKeyHeaderName, mwConfig.SecretKeyHeaderValue)
	rec := httptest.NewRecorder()
	SecretKeyHeader(mwConfig, next).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "secret content", rec.Body.String())

	// no header
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	SecretKeyHeader(mwConfig, next).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Empty(t, rec.Body.String())

	// wrong header value
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(mwConfig.SecretKeyHeaderName, "wrong value")
	rec = httptest.NewRecorder()
	SecretKeyHeader(mwConfig, next).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Empty(t, rec.Body.String())

	// debug should skip checks
	mwConfig = SecretKeyHeaderConfig{
		SecretKeyHeaderName:  "X-Secret-Key",
		SecretKeyHeaderValue: "secret",
		Debug:                true,
	}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(mwConfig.SecretKeyHeaderName, "wrong value")
	rec = httptest.NewRecorder()
	SecretKeyHeader(mwConfig, next).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "secret content", rec.Body.String())

	// panic if no header name set
	// debug should skip checks
	require.Panics(t, func() {
		SecretKeyHeader(SecretKeyHeaderConfig{
			SecretKeyHeaderValue: "secret",
		}, next).ServeHTTP(rec, req)
	})

	// panic if no header value set
	// debug should skip checks
	require.Panics(t, func() {
		SecretKeyHeader(SecretKeyHeaderConfig{
			SecretKeyHeaderName: "X-Secret-Key",
		}, next).ServeHTTP(rec, req)
	})
}
