package httperror

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	err := New(http.StatusBadRequest, "test error message")
	require.NotNil(t, err)
	require.Equal(t, http.StatusBadRequest, err.StatusCode)
	require.Equal(t, "test error message", err.Error())
}

func TestHTTPError_Error(t *testing.T) {
	originalErr := errors.New("original error")
	httpErr := &HTTPError{
		Err:        originalErr,
		StatusCode: http.StatusInternalServerError,
	}

	require.Equal(t, "original error", httpErr.Error())
}

func TestBadRequest(t *testing.T) {
	err := BadRequest("bad request message")
	require.NotNil(t, err)
	require.Equal(t, http.StatusBadRequest, err.StatusCode)
	require.Equal(t, "bad request message", err.Error())
}

func TestInternalServerError(t *testing.T) {
	err := InternalServerError("internal server error message")
	require.NotNil(t, err)
	require.Equal(t, http.StatusInternalServerError, err.StatusCode)
	require.Equal(t, "internal server error message", err.Error())
}

func TestNotFound(t *testing.T) {
	err := NotFound("not found message")
	require.NotNil(t, err)
	require.Equal(t, http.StatusNotFound, err.StatusCode)
	require.Equal(t, "not found message", err.Error())
}
