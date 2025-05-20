package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestNewMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	testMetric := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_total",
		Help: "A test counter",
	})
	err := reg.Register(testMetric)

	require.NoError(t, err)
	m, err := NewMetrics(reg)
	require.NoError(t, err)
	require.NotNil(t, m)
	// we need to increment at least once so it will show up in the metrics
	testMetric.Add(69)
	m.ImageHits.WithLabelValues("host.com", "success").Add(69)
	gathered, err := reg.Gather()
	require.NoError(t, err)
	require.NotEmpty(t, gathered)
	foundCounter := false
	foundCustom := false
	for _, metric := range gathered {
		if metric.GetName() == "test_total" {
			foundCounter = true
			require.Len(t, metric.GetMetric(), 1)
			require.Equal(t, float64(69), metric.GetMetric()[0].GetCounter().GetValue()) // nolint:testifylint
		}
		if metric.GetName() == "entra_phishing_detection_image_hits_total" {
			foundCustom = true
			require.Len(t, metric.GetMetric(), 1)
			tmp := metric.GetMetric()[0]
			require.Equal(t, float64(69), tmp.GetCounter().GetValue()) // nolint:testifylint
			labels := tmp.GetLabel()
			require.Len(t, labels, 2)
			require.Equal(t, "host", labels[0].GetName())
			require.Equal(t, "host.com", labels[0].GetValue())
			require.Equal(t, "status", labels[1].GetName())
			require.Equal(t, "success", labels[1].GetValue())
		}
	}
	require.True(t, foundCounter, "Expected test_total to be found in gathered metrics")
	require.True(t, foundCustom, "Expected entra_phishing_detection_image_hits_total to be found in gathered metrics")
}
