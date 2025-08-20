package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/firefart/entra-phishing-detection/internal/config"
	"github.com/firefart/entra-phishing-detection/internal/metrics"
	"github.com/firefart/entra-phishing-detection/internal/server/handlers"
	"github.com/firefart/entra-phishing-detection/internal/server/httperror"
	"github.com/firefart/entra-phishing-detection/internal/server/middleware"
	"github.com/firefart/entra-phishing-detection/internal/server/router"
)

type server struct {
	logger         *slog.Logger
	config         config.Configuration
	debug          bool
	metrics        *metrics.Metrics
	accessLog      bool
	imagesOK       map[string][]byte
	imagesPhishing map[string][]byte
}

func notFound(w http.ResponseWriter, _ *http.Request) error {
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "")
	return nil
}

func NewServer(opts ...OptionsServerFunc) (http.Handler, error) {
	s := server{
		logger: slog.New(slog.DiscardHandler),
		debug:  false,
	}

	// baked in images, can be overriden by options
	s.imagesOK = make(map[string][]byte)
	s.imagesOK["en"] = imageOK
	s.imagesOK["de"] = imageOK
	s.imagesPhishing = make(map[string][]byte)
	s.imagesPhishing["en"] = imagePhishingEN
	s.imagesPhishing["de"] = imagePhishingDE

	for _, o := range opts {
		if err := o(&s); err != nil {
			return nil, err
		}
	}

	r := router.New()

	r.SetErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
		s.metrics.Errors.WithLabelValues(r.Host).Inc()
		s.logger.Error("error on request", slog.String("err", err.Error()))
		var httpErr *httperror.HTTPError
		if errors.As(err, &httpErr) {
			http.Error(w, "", httpErr.StatusCode)
		} else {
			http.Error(w, "", http.StatusInternalServerError)
		}
	})

	r.Use(middleware.Recover(s.logger))
	r.Use(middleware.RealIP(middleware.RealIPConfig{
		IPHeader: s.config.Server.IPHeader,
	}))
	r.Use(middleware.RealHost(middleware.RealHostConfig{
		Headers: s.config.Server.HostHeaders,
	}))

	imageRoute := "/image"
	if s.config.Server.PathImage != "" {
		imageRoute = fmt.Sprintf("/%s", s.config.Server.PathImage)
	}

	healthRoute := "/health"
	if s.config.Server.PathHealth != "" {
		healthRoute = fmt.Sprintf("/%s", s.config.Server.PathHealth)
	}

	versionRoute := "/version"
	if s.config.Server.PathVersion != "" {
		versionRoute = fmt.Sprintf("/%s", s.config.Server.PathVersion)
	}

	s.logger.Info("image route", slog.String("route", imageRoute))
	s.logger.Info("health route", slog.String("route", healthRoute))
	s.logger.Info("version route", slog.String("route", versionRoute))

	// version info and health checks secured by secret key header
	// note that those routes will not be logged by the access log middleware
	r.Group(func(r *router.Router) {
		r.Use(middleware.SecretKeyHeader(middleware.SecretKeyHeaderConfig{
			SecretKeyHeaderName:  s.config.Server.SecretKeyHeaderName,
			SecretKeyHeaderValue: s.config.Server.SecretKeyHeaderValue,
			Logger:               s.logger,
			Debug:                s.debug,
		}))

		// health check for monitoring
		r.HandleFunc(fmt.Sprintf("GET %s", healthRoute), handlers.NewHealthHandler().Handler)

		r.HandleFunc(fmt.Sprintf("GET %s", versionRoute), handlers.NewVersionHandler().Handler)
	})

	// custom group with addtional access log middleware
	// everything not in this group will not have access logs
	r.Group(func(r *router.Router) {
		if s.accessLog {
			r.Use(middleware.AccessLog(middleware.AccessLogConfig{
				Logger:  s.logger,
				Metrics: s.metrics,
			}))
		}
		r.HandleFunc(fmt.Sprintf("GET %s", imageRoute), handlers.NewImageHandler(handlers.ImageHandlerOptions{
			AllowedOrigins:                s.config.AllowedOrigins,
			Logger:                        s.logger,
			Metrics:                       s.metrics,
			ImagesOK:                      s.imagesOK,
			ImagesPhishing:                s.imagesPhishing,
			TreatMissingRefererAsPhishing: s.config.TreatMissingRefererAsPhishing,
		}).Handler)

		// custom 404 for the rest
		r.HandleFunc("/", notFound)
	})

	return r, nil
}
