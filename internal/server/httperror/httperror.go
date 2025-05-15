package httperror

import (
	"errors"
	"net/http"
)

type HTTPError struct {
	Err        error
	StatusCode int
}

func New(code int, message string) *HTTPError {
	return &HTTPError{
		Err:        errors.New(message),
		StatusCode: code,
	}
}

func (err HTTPError) Error() string {
	return err.Err.Error()
}

func BadRequest(message string) *HTTPError {
	return New(http.StatusBadRequest, message)
}

func InternalServerError(message string) *HTTPError {
	return New(http.StatusInternalServerError, message)
}

func NotFound(message string) *HTTPError {
	return New(http.StatusNotFound, message)
}
