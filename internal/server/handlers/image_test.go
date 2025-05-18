package handlers_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/firefart/entra-phishing-detection/internal/config"
	"github.com/firefart/entra-phishing-detection/internal/server/handlers"
	"github.com/stretchr/testify/require"
)

func TestImage(t *testing.T) {
	patternOK := `viewBox="0 0 1 1"`
	patternPhishing := `NUNG: GEBEN SIE HIER`
	configuration := config.Configuration{
		Server: config.Server{
			SecretKeyHeaderName:  "X-Secret-Key",
			SecretKeyHeaderValue: "SECRET",
		},
		AllowedOrigins: []string{"loginsite.internal"},
	}
	logger := slog.New(slog.DiscardHandler)
	imageHandler := handlers.NewImageHandler(configuration, logger)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	// test with no referer
	require.NoError(t, imageHandler.Handler(rec, req))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, `inline; filename="image.svg"`, rec.Header().Get("Content-Disposition"))
	require.Equal(t, "image/svg+xml", rec.Header().Get("Content-Type"))
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	require.Equal(t, "no-cache", rec.Header().Get("Pragma"))
	require.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
	require.Greater(t, len(rec.Body.String()), 10)
	require.Contains(t, rec.Body.String(), patternPhishing)

	// test with wrong referer
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Referer", "https://example.com")
	rec = httptest.NewRecorder()
	require.NoError(t, imageHandler.Handler(rec, req))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), patternPhishing)

	// test with invalid referer
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Referer", ")_*(()&&^%$#$%)")
	rec = httptest.NewRecorder()
	require.NoError(t, imageHandler.Handler(rec, req))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), patternPhishing)

	// test with correct referer
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Referer", "https://loginsite.internal/xxxx")
	rec = httptest.NewRecorder()
	require.NoError(t, imageHandler.Handler(rec, req))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), patternOK)
}
