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
	m.ImageHits.WithLabelValues("host.com", "en", "success").Add(69)
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
			require.Len(t, labels, 3)
			require.Equal(t, "host", labels[0].GetName())
			require.Equal(t, "host.com", labels[0].GetValue())
			require.Equal(t, "language", labels[1].GetName())
			require.Equal(t, "en", labels[1].GetValue())
			require.Equal(t, "status", labels[2].GetName())
			require.Equal(t, "success", labels[2].GetValue())
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
		lang   string
		status string
		value  float64
	}{
		{"example.com", "en", "success", 5.0},
		{"test.com", "en", "phishing", 3.0},
		{"another.com", "en", "success", 7.0},
		{"example.com", "en", "phishing", 2.0}, // Same host, different status
	}

	for _, tc := range testCases {
		m.ImageHits.WithLabelValues(tc.host, tc.lang, tc.status).Add(tc.value)
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
		require.Len(t, labels, 3)

		var host, lang, status string
		for _, label := range labels {
			switch label.GetName() {
			case "host":
				host = label.GetValue()
			case "status":
				status = label.GetValue()
			case "language":
				lang = label.GetValue()
			}
		}

		key := host + ":" + lang + ":" + status
		metricsByLabels[key] = metric.GetCounter().GetValue()
	}

	// Verify expected values
	require.Equal(t, 5.0, metricsByLabels["example.com:en:success"])  // nolint: testifylint
	require.Equal(t, 3.0, metricsByLabels["test.com:en:phishing"])    // nolint: testifylint
	require.Equal(t, 7.0, metricsByLabels["another.com:en:success"])  // nolint: testifylint
	require.Equal(t, 2.0, metricsByLabels["example.com:en:phishing"]) // nolint: testifylint
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

func TestNewMetricsWithOptions(t *testing.T) {
	t.Run("WithAccessLog option", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		m, err := NewMetrics(reg, WithAccessLog())
		require.NoError(t, err)
		require.NotNil(t, m)

		// Verify that additional metrics are created with WithAccessLog option
		require.NotNil(t, m.RequestCount, "RequestCount should be initialized with WithAccessLog option")
		require.NotNil(t, m.RequestDuration, "RequestDuration should be initialized with WithAccessLog option")
		require.NotNil(t, m.ResponseSize, "ResponseSize should be initialized with WithAccessLog option")
		require.NotNil(t, m.RequestSize, "RequestSize should be initialized with WithAccessLog option")

		// Test that we can use the additional metrics
		m.RequestCount.WithLabelValues("200", "GET", "example.com", "/test").Inc()
		m.RequestDuration.WithLabelValues("200", "GET", "example.com", "/test").Observe(0.5)
		m.RequestSize.WithLabelValues("200", "GET", "example.com", "/test").Observe(100.0)
		m.ResponseSize.WithLabelValues("200", "GET", "example.com", "/test").Observe(200.0)

		// Gather metrics to verify they are registered
		gathered, err := reg.Gather()
		require.NoError(t, err)
		require.NotEmpty(t, gathered)

		foundRequestCount := false
		foundRequestDuration := false
		foundResponseSize := false
		foundRequestSize := false

		for _, metric := range gathered {
			switch metric.GetName() {
			case "entra_phishing_detection_http_requests_total":
				foundRequestCount = true
				require.Len(t, metric.GetMetric(), 1)
				require.Equal(t, float64(1), metric.GetMetric()[0].GetCounter().GetValue()) // nolint:testifylint

				// Verify labels
				labels := metric.GetMetric()[0].GetLabel()
				require.Len(t, labels, 4)
				expectedLabels := map[string]string{
					"code":   "200",
					"method": "GET",
					"host":   "example.com",
					"path":   "/test",
				}
				for _, label := range labels {
					expectedValue, exists := expectedLabels[label.GetName()]
					require.True(t, exists, "Unexpected label: %s", label.GetName())
					require.Equal(t, expectedValue, label.GetValue())
				}
			case "entra_phishing_detection_http_request_duration_seconds":
				foundRequestDuration = true
				require.Len(t, metric.GetMetric(), 1)
				histogram := metric.GetMetric()[0].GetHistogram()
				require.NotNil(t, histogram)
				require.Equal(t, uint64(1), histogram.GetSampleCount())
				require.Equal(t, 0.5, histogram.GetSampleSum()) // nolint:testifylint

				// Verify labels
				labels := metric.GetMetric()[0].GetLabel()
				require.Len(t, labels, 4)
				expectedLabels := map[string]string{
					"code":   "200",
					"method": "GET",
					"host":   "example.com",
					"path":   "/test",
				}
				for _, label := range labels {
					expectedValue, exists := expectedLabels[label.GetName()]
					require.True(t, exists, "Unexpected label: %s", label.GetName())
					require.Equal(t, expectedValue, label.GetValue())
				}
			case "entra_phishing_detection_http_response_size_bytes":
				foundResponseSize = true
				require.Len(t, metric.GetMetric(), 1)
				histogram := metric.GetMetric()[0].GetHistogram()
				require.NotNil(t, histogram)
				require.Equal(t, uint64(1), histogram.GetSampleCount())
				require.Equal(t, 200.0, histogram.GetSampleSum()) // nolint:testifylint

				// Verify labels
				labels := metric.GetMetric()[0].GetLabel()
				require.Len(t, labels, 4)
				expectedLabels := map[string]string{
					"code":   "200",
					"method": "GET",
					"host":   "example.com",
					"path":   "/test",
				}
				for _, label := range labels {
					expectedValue, exists := expectedLabels[label.GetName()]
					require.True(t, exists, "Unexpected label: %s", label.GetName())
					require.Equal(t, expectedValue, label.GetValue())
				}
			case "entra_phishing_detection_http_request_size_bytes":
				foundRequestSize = true
				require.Len(t, metric.GetMetric(), 1)
				histogram := metric.GetMetric()[0].GetHistogram()
				require.NotNil(t, histogram)
				require.Equal(t, uint64(1), histogram.GetSampleCount())
				require.Equal(t, 100.0, histogram.GetSampleSum()) // nolint:testifylint

				// Verify labels
				labels := metric.GetMetric()[0].GetLabel()
				require.Len(t, labels, 4)
				expectedLabels := map[string]string{
					"code":   "200",
					"method": "GET",
					"host":   "example.com",
					"path":   "/test",
				}
				for _, label := range labels {
					expectedValue, exists := expectedLabels[label.GetName()]
					require.True(t, exists, "Unexpected label: %s", label.GetName())
					require.Equal(t, expectedValue, label.GetValue())
				}
			}
		}

		require.True(t, foundRequestCount, "Expected http_requests_total to be found in gathered metrics")
		require.True(t, foundRequestDuration, "Expected http_request_duration_seconds to be found in gathered metrics")
		require.True(t, foundResponseSize, "Expected http_response_size_bytes to be found in gathered metrics")
		require.True(t, foundRequestSize, "Expected http_request_size_bytes to be found in gathered metrics")
	})

	t.Run("Without options", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		m, err := NewMetrics(reg)
		require.NoError(t, err)
		require.NotNil(t, m)

		// Verify that optional metrics are NOT created without options
		require.Nil(t, m.RequestCount, "RequestCount should be nil without WithAccessLog option")
		require.Nil(t, m.RequestDuration, "RequestDuration should be nil without WithAccessLog option")
		require.Nil(t, m.ResponseSize, "ResponseSize should be nil without WithAccessLog option")
		require.Nil(t, m.RequestSize, "RequestSize should be nil without WithAccessLog option")

		// Gather metrics to verify only basic metrics are present
		gathered, err := reg.Gather()
		require.NoError(t, err)
		require.NotEmpty(t, gathered)

		foundRequestCount := false
		foundRequestDuration := false
		foundResponseSize := false
		foundRequestSize := false

		for _, metric := range gathered {
			switch metric.GetName() {
			case "entra_phishing_detection_http_requests_total":
				foundRequestCount = true
			case "entra_phishing_detection_http_request_duration_seconds":
				foundRequestDuration = true
			case "entra_phishing_detection_http_response_size_bytes":
				foundResponseSize = true
			case "entra_phishing_detection_http_request_size_bytes":
				foundRequestSize = true
			}
		}

		require.False(t, foundRequestCount, "http_requests_total should not be present without WithAccessLog option")
		require.False(t, foundRequestDuration, "http_request_duration_seconds should not be present without WithAccessLog option")
		require.False(t, foundResponseSize, "http_response_size_bytes should not be present without WithAccessLog option")
		require.False(t, foundRequestSize, "http_request_size_bytes should not be present without WithAccessLog option")
	})

	t.Run("Option registration error", func(t *testing.T) {
		reg := prometheus.NewRegistry()

		// First registration should succeed
		m1, err := NewMetrics(reg, WithAccessLog())
		require.NoError(t, err)
		require.NotNil(t, m1)

		// Second registration should fail due to duplicate metric registration in the option
		m2, err := NewMetrics(reg, WithAccessLog())
		require.Error(t, err)
		require.Nil(t, m2)
		require.Contains(t, err.Error(), "failed to register")
	})
}
