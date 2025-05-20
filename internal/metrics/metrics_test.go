package metrics

import (
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestNewMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	testCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_counter",
		Help: "A test counter",
	})
	err := reg.Register(testCounter)

	require.NoError(t, err)
	m, err := NewMetrics(reg)
	require.NoError(t, err)
	require.NotNil(t, m)
	// we need to increment at least once so it will show up in the metrics
	testCounter.Add(69)
	m.ImageHits.WithLabelValues("success").Add(69)
	gathered, err := reg.Gather()
	require.NoError(t, err)
	require.NotEmpty(t, gathered)
	foundCounter := false
	foundCustom := false
	for _, metric := range gathered {
		fmt.Println(metric.GetName())
		if metric.GetName() == "test_counter" {
			foundCounter = true
			require.Len(t, metric.GetMetric(), 1)
			require.Equal(t, float64(69), metric.GetMetric()[0].GetCounter().GetValue())
		}
		if metric.GetName() == "entra_phishing_detection_image_hits_total" {
			foundCustom = true
			require.Len(t, metric.GetMetric(), 1)
			tmp := metric.GetMetric()[0]
			require.Equal(t, float64(69), tmp.GetCounter().GetValue())
			labels := tmp.GetLabel()
			require.Len(t, labels, 1)
			require.Equal(t, "success", labels[0].GetValue())
		}
	}
	require.True(t, foundCounter, "Expected test_counter to be found in gathered metrics")
	require.True(t, foundCustom, "Expected entra_phishing_detection_image_hits_total to be found in gathered metrics")
}
