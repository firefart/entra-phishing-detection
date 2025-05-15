package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/firefart/entra-phishing-detection/internal/config"
	"github.com/firefart/entra-phishing-detection/internal/server/handlers"
	"github.com/firefart/entra-phishing-detection/internal/server/httperror"
	"github.com/firefart/entra-phishing-detection/internal/server/middleware"
	"github.com/firefart/entra-phishing-detection/internal/server/router"
)

type server struct {
	logger *slog.Logger
	config config.Configuration
	debug  bool
}

func notFound(w http.ResponseWriter, _ *http.Request) error {
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "")
	return nil
}

func NewServer(opts ...OptionsServerFunc) http.Handler {
	s := server{
		logger: slog.New(slog.DiscardHandler),
		debug:  false,
	}

	for _, o := range opts {
		o(&s)
	}

	secretKeyHeaderMW := middleware.SecretKeyHeaderConfig{
		SecretKeyHeaderName:  s.config.Server.SecretKeyHeaderName,
		SecretKeyHeaderValue: s.config.Server.SecretKeyHeaderValue,
		Logger:               s.logger,
		Debug:                s.debug,
	}

	r := router.New()

	r.SetErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
		s.logger.Error("error on request", slog.String("err", err.Error()))
		var httpErr *httperror.HTTPError
		if errors.As(err, &httpErr) {
			http.Error(w, "", httpErr.StatusCode)
		} else {
			http.Error(w, "", http.StatusInternalServerError)
		}
	})

	r.Use(middleware.RealIP(s.config.Server.IPHeader))

	// image generation route
	imageRoute := "image"
	if s.config.Server.PathImage != "" {
		imageRoute = s.config.Server.PathImage
	}
	s.logger.Info("image route", slog.String("route", imageRoute))
	r.HandleFunc(fmt.Sprintf("GET /%s", imageRoute), handlers.NewImageHandler(s.config, s.logger).Handler)
	// health check for monitoring
	healthRoute := "health"
	if s.config.Server.PathHealth != "" {
		healthRoute = s.config.Server.PathHealth
	}
	s.logger.Info("health route", slog.String("route", healthRoute))
	r.HandleFunc(fmt.Sprintf("GET /%s", healthRoute), handlers.NewHealthHandler().Handler)
	// version info
	versionRoute := "version"
	if s.config.Server.PathVersion != "" {
		versionRoute = s.config.Server.PathVersion
	}

	r.Group(func(r *router.Router) {
		r.Use(middleware.SecretKeyHeader(secretKeyHeaderMW))

		s.logger.Info("version route", slog.String("route", versionRoute))
		r.HandleFunc(fmt.Sprintf("GET /%s", versionRoute), handlers.NewVersionHandler().Handler)
	})

	// custom 404 for the rest
	r.HandleFunc("/", notFound)

	return r
}
