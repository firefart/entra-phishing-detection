package metrics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

type OptionsMetricsFunc func(c *Metrics, reg prometheus.Registerer) error

func WithAccessLog() OptionsMetricsFunc {
	return func(m *Metrics, reg prometheus.Registerer) error {
		labels := []string{"code", "method", "host", "path"}
		m.RequestCount = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "entra_phishing_detection",
				Name:      "http_requests_total",
				Help:      "How many HTTP requests processed, partitioned by status code and HTTP method.",
			},
			labels,
		)
		m.RequestDuration = prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "entra_phishing_detection",
				Name:      "http_request_duration_seconds",
				Help:      "The HTTP request latencies in seconds.",
				Buckets:   prometheus.DefBuckets,
			},
			labels,
		)
		m.ResponseSize = prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "entra_phishing_detection",
				Name:      "http_response_size_bytes",
				Help:      "The HTTP response sizes in bytes.",
				Buckets:   prometheus.DefBuckets,
			},
			labels,
		)
		m.RequestSize = prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "entra_phishing_detection",
				Name:      "http_request_size_bytes",
				Help:      "The HTTP request sizes in bytes.",
				Buckets:   prometheus.DefBuckets,
			},
			labels,
		)
		if err := reg.Register(m.RequestCount); err != nil {
			return fmt.Errorf("failed to register request count metric: %w", err)
		}
		if err := reg.Register(m.RequestDuration); err != nil {
			return fmt.Errorf("failed to register request duration metric: %w", err)
		}
		if err := reg.Register(m.ResponseSize); err != nil {
			return fmt.Errorf("failed to register response size metric: %w", err)
		}
		if err := reg.Register(m.RequestSize); err != nil {
			return fmt.Errorf("failed to register request size metric: %w", err)
		}

		return nil
	}
}
