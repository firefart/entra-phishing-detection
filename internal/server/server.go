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
	mux.HandleFunc("GET /30ce6ec8-1ca0-4dee-a4b0-b56fd4adf731", s.customHandler(handlers.NewImageHandler(s.config, s.logger).Handler))
	// health check for monitoring
	mux.HandleFunc("GET /10282d45-484d-4e18-8d55-40d38e82c39b/health", handlers.NewHealthHandler().Handler)
	// version info
	mux.HandleFunc("GET /d7cf1d1d-d4ba-49a0-8ff7-565c685c047a/version", middleware.SecretKeyHeader(secretKeyHeaderMW, s.customHandler(handlers.NewVersionHandler().Handler)))
	// custom 404 for the rest
	mux.HandleFunc("/", notFound)

	return mux
}
