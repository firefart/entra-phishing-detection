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
	RealIP("X-Real-IP", next).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "next content", rec.Body.String())
}
