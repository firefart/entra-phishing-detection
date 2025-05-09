package server

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/firefart/entra-phishing-detection/internal/config"
	"github.com/firefart/entra-phishing-detection/internal/server/handlers"
	"github.com/firefart/entra-phishing-detection/internal/server/middleware"
)

type server struct {
	logger *slog.Logger
	config config.Configuration
	debug  bool
}

func (s *server) customHandler(f func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := f(w, r)
		if err != nil {
			s.logger.Error("error on request", slog.String("err", err.Error()))
			w.WriteHeader(http.StatusNoContent)
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "")
		}
	}
}

func notFound(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "")
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

	mux := http.NewServeMux()

	// image generation route
	imageRoute := "image"
	if s.config.Server.PathImage != "" {
		imageRoute = s.config.Server.PathImage
	}
	s.logger.Info("image route", slog.String("route", imageRoute))
	mux.HandleFunc(fmt.Sprintf("GET /%s", imageRoute), middleware.RealIP(s.config.Server.IPHeader, s.customHandler(handlers.NewImageHandler(s.config, s.logger).Handler)))
	// health check for monitoring
	healthRoute := "health"
	if s.config.Server.PathHealth != "" {
		healthRoute = s.config.Server.PathHealth
	}
	s.logger.Info("health route", slog.String("route", healthRoute))
	mux.HandleFunc(fmt.Sprintf("GET /%s", healthRoute), handlers.NewHealthHandler().Handler)
	// version info
	versionRoute := "version"
	if s.config.Server.PathVersion != "" {
		versionRoute = s.config.Server.PathVersion
	}
	s.logger.Info("version route", slog.String("route", versionRoute))
	mux.HandleFunc(fmt.Sprintf("GET /%s", versionRoute), middleware.RealIP(s.config.Server.IPHeader, middleware.SecretKeyHeader(secretKeyHeaderMW, s.customHandler(handlers.NewVersionHandler().Handler))))
	// custom 404 for the rest
	mux.HandleFunc("/", notFound)

	return mux
}
