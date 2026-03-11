package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
)

type VersionHandler struct{}

func NewVersionHandler() *VersionHandler {
	return &VersionHandler{}
}

func (h *VersionHandler) Handler(w http.ResponseWriter, _ *http.Request) error {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return errors.New("unable to determine version information")
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, buildInfo.String())
	return nil
}
