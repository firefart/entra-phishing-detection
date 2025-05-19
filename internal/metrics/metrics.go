package metrics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

type Metrics struct {
	RequestCount    *prometheus.CounterVec
	RequestDuration *prometheus.HistogramVec
}

func NewMetrics(reg prometheus.Registerer) (*Metrics, error) {
	labels := []string{"code", "method", "host", "url", "referer"}
	nameSpace := "entra_phishing_detection"
	m := &Metrics{
		RequestCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: nameSpace,
				Name:      "requests_total",
				Help:      "How many HTTP requests processed, partitioned by status code and HTTP method.",
			},
			labels,
		),
		RequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: nameSpace,
				Name:      "request_duration_seconds",
				Help:      "The HTTP request latencies in seconds.",
				Buckets:   prometheus.DefBuckets,
			},
			labels,
		),
	}
	// also add the default collectors
	if err := reg.Register(collectors.NewGoCollector()); err != nil {
		return nil, fmt.Errorf("failed to register go collector: %w", err)
	}
	if err := reg.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})); err != nil {
		return nil, fmt.Errorf("failed to register process collector: %w", err)
	}
	if err := reg.Register(m.RequestCount); err != nil {
		return nil, fmt.Errorf("failed to register request count metric: %w", err)
	}
	if err := reg.Register(m.RequestDuration); err != nil {
		return nil, fmt.Errorf("failed to register request duration metric: %w", err)
	}

	return m, nil
}
