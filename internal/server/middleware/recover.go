package middleware

import (
	"log/slog"
	"net/http"
	"runtime"
)

func collectStack() []byte {
	buf := make([]byte, 64<<10) // limit to 64kb
	buf = buf[:runtime.Stack(buf, false)]
	return buf
}

func Recover(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.Error("panic recovered", slog.String("method", r.Method), slog.String("url", r.URL.String()), slog.Any("error", err), slog.String("stack", string(collectStack())))
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
