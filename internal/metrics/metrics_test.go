package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
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

func TestNewMetricsErrors(t *testing.T) {
	// Test registration errors
	reg := prometheus.NewRegistry()

	// First registration should succeed
	m1, err := NewMetrics(reg)
	require.NoError(t, err)
	require.NotNil(t, m1)

	// Second registration should fail due to duplicate metric registration
	m2, err := NewMetrics(reg)
	require.Error(t, err)
	require.Nil(t, m2)
	require.Contains(t, err.Error(), "failed to register")
}

func TestMetricsImageHitsLabels(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, err := NewMetrics(reg)
	require.NoError(t, err)
	require.NotNil(t, m)

	// Test different label combinations
	testCases := []struct {
		host   string
		status string
		value  float64
	}{
		{"example.com", "success", 5.0},
		{"test.com", "phishing", 3.0},
		{"another.com", "success", 7.0},
		{"example.com", "phishing", 2.0}, // Same host, different status
	}

	for _, tc := range testCases {
		m.ImageHits.WithLabelValues(tc.host, tc.status).Add(tc.value)
	}

	// Gather metrics to verify all label combinations are recorded
	gathered, err := reg.Gather()
	require.NoError(t, err)

	var imageHitsMetric *dto.MetricFamily
	for _, metric := range gathered {
		if metric.GetName() == "entra_phishing_detection_image_hits_total" {
			imageHitsMetric = metric
			break
		}
	}

	require.NotNil(t, imageHitsMetric)
	require.Len(t, imageHitsMetric.GetMetric(), len(testCases))

	// Verify each metric has correct labels and values
	metricsByLabels := make(map[string]float64)
	for _, metric := range imageHitsMetric.GetMetric() {
		labels := metric.GetLabel()
		require.Len(t, labels, 2)

		var host, status string
		for _, label := range labels {
			if label.GetName() == "host" {
				host = label.GetValue()
			} else if label.GetName() == "status" {
				status = label.GetValue()
			}
		}

		key := host + ":" + status
		metricsByLabels[key] = metric.GetCounter().GetValue()
	}

	// Verify expected values
	require.Equal(t, 5.0, metricsByLabels["example.com:success"])  // nolint: testifylint
	require.Equal(t, 3.0, metricsByLabels["test.com:phishing"])    // nolint: testifylint
	require.Equal(t, 7.0, metricsByLabels["another.com:success"])  // nolint: testifylint
	require.Equal(t, 2.0, metricsByLabels["example.com:phishing"]) // nolint: testifylint
}

func TestMetricsDefaultCollectors(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, err := NewMetrics(reg)
	require.NoError(t, err)
	require.NotNil(t, m)

	// Gather metrics to verify default collectors are present
	gathered, err := reg.Gather()
	require.NoError(t, err)
	require.NotEmpty(t, gathered)

	// Check for Go collector metrics
	foundGoCollector := false
	foundProcessCollector := false

	for _, metric := range gathered {
		name := metric.GetName()
		if name == "go_info" || name == "go_goroutines" {
			foundGoCollector = true
		}
		if name == "process_cpu_seconds_total" || name == "process_start_time_seconds" {
			foundProcessCollector = true
		}
	}

	require.True(t, foundGoCollector, "Go collector metrics should be present")
	require.True(t, foundProcessCollector, "Process collector metrics should be present")
}
