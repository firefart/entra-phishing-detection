package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/firefart/entra-phishing-detection/internal/server/handlers"
	"github.com/stretchr/testify/require"
)

func TestVersion(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, handlers.NewVersionHandler().Handler(rec, req))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Greater(t, len(rec.Body.String()), 10)
}
