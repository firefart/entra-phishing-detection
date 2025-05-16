package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
)

type SecretKeyHeaderConfig struct {
	// the secret key header name we should check
	SecretKeyHeaderName  string
	SecretKeyHeaderValue string

	Debug bool

	Logger *slog.Logger
}

func SecretKeyHeader(config SecretKeyHeaderConfig) func(next http.Handler) http.Handler {
	// Defaults
	if config.SecretKeyHeaderName == "" {
		panic("secret key header middleware requires a header name")
	}
	if config.SecretKeyHeaderValue == "" {
		panic("secret key header middleware requires a header value")
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.DiscardHandler)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if config.Debug {
				next.ServeHTTP(w, r)
				return
			}

			headerVal := r.Header.Get(config.SecretKeyHeaderName)
			// no header set
			if headerVal == "" {
				ip, ok := r.Context().Value(ContextKeyIP).(string)
				if !ok {
					ip = r.RemoteAddr
				}
				config.Logger.Error("url called without secret header", slog.String("url", r.URL.String()), slog.String("ip", ip))
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "")
				return
			}

			if headerVal == config.SecretKeyHeaderValue {
				next.ServeHTTP(w, r)
				return
			}

			ip, ok := r.Context().Value(ContextKeyIP).(string)
			if !ok {
				ip = r.RemoteAddr
			}
			config.Logger.Error("url called with wrong secret header", slog.String("header", headerVal), slog.String("ip", ip))
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "")
		})
	}
}
