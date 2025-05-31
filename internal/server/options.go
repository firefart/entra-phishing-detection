package server

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/firefart/entra-phishing-detection/internal/config"
	"github.com/firefart/entra-phishing-detection/internal/metrics"
)

type OptionsServerFunc func(c *server) error

func WithLogger(logger *slog.Logger) OptionsServerFunc {
	return func(c *server) error { c.logger = logger; return nil }
}

func WithConfig(config config.Configuration) OptionsServerFunc {
	return func(c *server) error { c.config = config; return nil }
}

func WithDebug(d bool) OptionsServerFunc {
	return func(c *server) error { c.debug = d; return nil }
}

func WithMetrics(m *metrics.Metrics) OptionsServerFunc {
	return func(c *server) error { c.metrics = m; return nil }
}

func WithAccessLog() OptionsServerFunc {
	return func(c *server) error { c.accessLog = true; return nil }
}

func WithCustomImages(c config.Images) OptionsServerFunc {
	return func(s *server) error {
		// bail out if no custom images are provided
		if len(c.OK) == 0 && len(c.Phishing) == 0 {
			return nil
		}

		// override the default ok images with custom ones if provided
		if len(c.OK) > 0 {
			s.imagesOK = make(map[string][]byte, len(c.OK))
			for lang, filePath := range c.OK {
				content, err := os.ReadFile(filePath)
				if err != nil {
					return fmt.Errorf("failed to read OK image for language %s: %w", lang, err)
				}
				s.imagesOK[lang] = content
			}
		}

		// override the default phishing images with custom ones if provided
		if len(c.Phishing) > 0 {
			s.imagesPhishing = make(map[string][]byte, len(c.Phishing))
			for lang, filePath := range c.Phishing {
				content, err := os.ReadFile(filePath)
				if err != nil {
					return fmt.Errorf("failed to read Phishing image for language %s: %w", lang, err)
				}
				s.imagesPhishing[lang] = content
			}
		}

		return nil
	}
}
