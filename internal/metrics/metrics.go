package metrics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

type Metrics struct {
	ImageHits *prometheus.CounterVec
}

func NewMetrics(reg prometheus.Registerer) (*Metrics, error) {
	labels := []string{"status"}
	nameSpace := "entra_phishing_detection"
	m := &Metrics{
		ImageHits: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: nameSpace,
				Name:      "image_hits_total",
				Help:      "How many requests were made to the image handler. Includes the status of the response.",
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
	if err := reg.Register(m.ImageHits); err != nil {
		return nil, fmt.Errorf("failed to register request count metric: %w", err)
	}

	return m, nil
}
