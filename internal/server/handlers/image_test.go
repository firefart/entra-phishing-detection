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
	configuration := config.Configuration{
		Server: config.Server{
			SecretKeyHeaderName:  "X-Secret-Key",
			SecretKeyHeaderValue: "SECRET",
		},
	}
	logger := slog.New(slog.DiscardHandler)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	require.NoError(t, handlers.NewImageHandler(configuration, logger).Handler(rec, req))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Greater(t, len(rec.Body.String()), 10)
}
