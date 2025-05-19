package server

import (
	"log/slog"

	"github.com/firefart/entra-phishing-detection/internal/config"
	"github.com/firefart/entra-phishing-detection/internal/metrics"
)

type OptionsServerFunc func(c *server)

func WithLogger(logger *slog.Logger) OptionsServerFunc {
	return func(c *server) { c.logger = logger }
}

func WithConfig(config config.Configuration) OptionsServerFunc {
	return func(c *server) { c.config = config }
}

func WithDebug(d bool) OptionsServerFunc {
	return func(c *server) { c.debug = d }
}

func WithMetrics(m *metrics.Metrics) OptionsServerFunc {
	return func(c *server) { c.metrics = m }
}
