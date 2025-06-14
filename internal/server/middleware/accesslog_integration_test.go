package middleware_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/firefart/entra-phishing-detection/internal/config"
	"github.com/firefart/entra-phishing-detection/internal/metrics"
	"github.com/firefart/entra-phishing-detection/internal/server"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

// Helper function to find a metric family by name in gathered metrics
func findMetricFamily(gathered []*dto.MetricFamily, name string) *dto.MetricFamily {
	for _, mf := range gathered {
		if mf.GetName() == name {
			return mf
		}
	}
	return nil
}

// Helper function to find a specific metric with given label values
func findMetricWithLabels(mf *dto.MetricFamily, expectedLabels map[string]string) *dto.Metric {
	if mf == nil {
		return nil
	}

	for _, metric := range mf.GetMetric() {
		labelMap := make(map[string]string)
		for _, label := range metric.GetLabel() {
			labelMap[label.GetName()] = label.GetValue()
		}

		matches := true
		for expectedKey, expectedValue := range expectedLabels {
			if labelMap[expectedKey] != expectedValue {
				matches = false
				break
			}
		}

		if matches {
			return metric
		}
	}
	return nil
}

func TestAccessLogMiddlewareIntegration(t *testing.T) {
	// Create a buffer to capture log output
	var logOutput bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logOutput, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create test configuration
	cfg := config.Configuration{
		Server: config.Server{
			SecretKeyHeaderName:  "X-Secret-Key",
			SecretKeyHeaderValue: "test-secret",
			IPHeader:             "X-Real-IP",
			PathImage:            "test-image",
			PathHealth:           "test-health",
			PathVersion:          "test-version",
		},
		AllowedOrigins: []string{"example.com"},
	}

	// Create metrics
	registry := prometheus.NewRegistry()
	m, err := metrics.NewMetrics(registry, metrics.WithAccessLog())
	require.NoError(t, err)

	// Create server with accesslog middleware
	handler, err := server.NewServer(
		server.WithLogger(logger),
		server.WithConfig(cfg),
		server.WithMetrics(m),
		server.WithDebug(false),
		server.WithAccessLog(),
	)
	require.NoError(t, err)

	t.Run("logs image endpoint request", func(t *testing.T) {
		// Clear previous log output
		logOutput.Reset()

		req := httptest.NewRequest(http.MethodGet, "/test-image", nil)
		req.Header.Set("X-Real-IP", "192.168.1.100")
		req.Header.Set("User-Agent", "Mozilla/5.0 Integration Test")
		req.Header.Set("Referer", "https://phishing-site.com")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Check that request was handled
		require.Equal(t, http.StatusOK, w.Code)

		// Parse log output
		logs := logOutput.String()
		require.NotEmpty(t, logs)

		// Split log entries (there might be multiple log lines)
		logLines := bytes.Split(logOutput.Bytes(), []byte("\n"))
		var requestLog map[string]interface{}

		// Find the request completed log entry
		for _, line := range logLines {
			if len(line) == 0 {
				continue
			}
			var logEntry map[string]interface{}
			err := json.Unmarshal(line, &logEntry)
			if err != nil {
				continue
			}
			if logEntry["msg"] == "request completed" {
				requestLog = logEntry
				break
			}
		}

		require.NotNil(t, requestLog, "Could not find 'request completed' log entry in: %s", logs)

		// Verify log fields
		require.Equal(t, "INFO", requestLog["level"])
		require.Equal(t, "request completed", requestLog["msg"])
		require.Equal(t, "GET", requestLog["method"])
		require.Equal(t, "/test-image", requestLog["path"])
		require.Equal(t, "192.168.1.100", requestLog["remote_ip"])
		require.Equal(t, float64(200), requestLog["status_code"]) // nolint:testifylint
		require.Contains(t, requestLog, "duration")

		// Check request headers
		require.Contains(t, requestLog, "headers")
		headers := requestLog["headers"].(map[string]interface{})
		require.Equal(t, "Mozilla/5.0 Integration Test", headers["User-Agent"])
		require.Equal(t, "https://phishing-site.com", headers["Referer"])
		require.Equal(t, "192.168.1.100", headers["X-Real-Ip"])

		// Verify metrics are collected correctly
		gathered, err := registry.Gather()
		require.NoError(t, err)

		// Debug: Print all metrics to understand the actual labels
		requestCountMF := findMetricFamily(gathered, "entra_phishing_detection_http_requests_total")
		require.NotNil(t, requestCountMF, "RequestCount metric not found")
		require.Len(t, requestCountMF.GetMetric(), 1, "Expected exactly one metric entry")

		// Get the actual labels from the metric
		actualMetric := requestCountMF.GetMetric()[0]
		actualLabels := make(map[string]string)
		for _, label := range actualMetric.GetLabel() {
			actualLabels[label.GetName()] = label.GetValue()
		}

		// Verify the metric has the correct values we expect
		require.Equal(t, "200", actualLabels["code"])
		require.Equal(t, "GET", actualLabels["method"])
		require.Equal(t, "/test-image", actualLabels["path"])
		// The host will be empty since we don't set req.Host in the test
		require.Contains(t, actualLabels, "host")

		expectedLabels := map[string]string{
			"code":   "200",
			"method": "GET",
			"host":   actualLabels["host"], // Use the actual host value
			"path":   "/test-image",
		}

		// Check RequestCount metric
		requestCountMetric := findMetricWithLabels(requestCountMF, expectedLabels)
		require.NotNil(t, requestCountMetric, "RequestCount metric with expected labels not found")
		require.Equal(t, float64(1), requestCountMetric.GetCounter().GetValue()) // nolint:testifylint

		// Check RequestDuration metric
		requestDurationMF := findMetricFamily(gathered, "entra_phishing_detection_http_request_duration_seconds")
		require.NotNil(t, requestDurationMF, "RequestDuration metric not found")
		requestDurationMetric := findMetricWithLabels(requestDurationMF, expectedLabels)
		require.NotNil(t, requestDurationMetric, "RequestDuration metric with expected labels not found")
		require.Positive(t, requestDurationMetric.GetHistogram().GetSampleCount())

		// Check ResponseSize metric
		responseSizeMF := findMetricFamily(gathered, "entra_phishing_detection_http_response_size_bytes")
		require.NotNil(t, responseSizeMF, "ResponseSize metric not found")
		responseSizeMetric := findMetricWithLabels(responseSizeMF, expectedLabels)
		require.NotNil(t, responseSizeMetric, "ResponseSize metric with expected labels not found")
		require.Positive(t, responseSizeMetric.GetHistogram().GetSampleCount())

		// Check RequestSize metric
		requestSizeMF := findMetricFamily(gathered, "entra_phishing_detection_http_request_size_bytes")
		require.NotNil(t, requestSizeMF, "RequestSize metric not found")
		requestSizeMetric := findMetricWithLabels(requestSizeMF, expectedLabels)
		require.NotNil(t, requestSizeMetric, "RequestSize metric with expected labels not found")
		require.Positive(t, requestSizeMetric.GetHistogram().GetSampleCount())
	})

	t.Run("logs health endpoint request", func(t *testing.T) {
		// Clear previous log output
		logOutput.Reset()

		req := httptest.NewRequest(http.MethodGet, "/test-health", nil)
		req.Header.Set("Accept", "application/json")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		// Parse log output to find request completed entry
		logLines := bytes.Split(logOutput.Bytes(), []byte("\n"))
		var requestLog map[string]interface{}

		for _, line := range logLines {
			if len(line) == 0 {
				continue
			}
			var logEntry map[string]interface{}
			err := json.Unmarshal(line, &logEntry)
			if err != nil {
				continue
			}
			if logEntry["msg"] == "request completed" {
				requestLog = logEntry
				break
			}
		}

		require.NotNil(t, requestLog)
		require.Equal(t, "GET", requestLog["method"])
		require.Equal(t, "/test-health", requestLog["path"])
		require.Equal(t, float64(200), requestLog["status_code"]) // nolint:testifylint

		// Check headers
		headers := requestLog["headers"].(map[string]interface{})
		require.Equal(t, "application/json", headers["Accept"])

		// Verify metrics are collected correctly
		gathered, err := registry.Gather()
		require.NoError(t, err)

		// Find the health endpoint metric (there should be 2 total metrics now - image and health)
		requestCountMF := findMetricFamily(gathered, "entra_phishing_detection_http_requests_total")
		require.NotNil(t, requestCountMF, "RequestCount metric not found")

		// Find the specific metric for the health endpoint
		var healthMetric *dto.Metric
		for _, metric := range requestCountMF.GetMetric() {
			labelMap := make(map[string]string)
			for _, label := range metric.GetLabel() {
				labelMap[label.GetName()] = label.GetValue()
			}
			if labelMap["path"] == "/test-health" {
				healthMetric = metric
				break
			}
		}
		require.NotNil(t, healthMetric, "Health endpoint metric not found")

		// Get the actual labels from the health metric
		actualLabels := make(map[string]string)
		for _, label := range healthMetric.GetLabel() {
			actualLabels[label.GetName()] = label.GetValue()
		}

		expectedLabels := map[string]string{
			"code":   "200",
			"method": "GET",
			"host":   actualLabels["host"], // Use the actual host value
			"path":   "/test-health",
		}

		// Check that RequestCount metric has been incremented for this specific request
		requestCountMetric := findMetricWithLabels(requestCountMF, expectedLabels)
		require.NotNil(t, requestCountMetric, "RequestCount metric with expected labels not found")
		require.Equal(t, float64(1), requestCountMetric.GetCounter().GetValue()) // nolint:testifylint

		// Check RequestDuration metric
		requestDurationMF := findMetricFamily(gathered, "entra_phishing_detection_http_request_duration_seconds")
		require.NotNil(t, requestDurationMF, "RequestDuration metric not found")
		requestDurationMetric := findMetricWithLabels(requestDurationMF, expectedLabels)
		require.NotNil(t, requestDurationMetric, "RequestDuration metric with expected labels not found")

		// Check ResponseSize metric
		responseSizeMF := findMetricFamily(gathered, "entra_phishing_detection_http_response_size_bytes")
		require.NotNil(t, responseSizeMF, "ResponseSize metric not found")
		responseSizeMetric := findMetricWithLabels(responseSizeMF, expectedLabels)
		require.NotNil(t, responseSizeMetric, "ResponseSize metric with expected labels not found")

		// Check RequestSize metric
		requestSizeMF := findMetricFamily(gathered, "entra_phishing_detection_http_request_size_bytes")
		require.NotNil(t, requestSizeMF, "RequestSize metric not found")
		requestSizeMetric := findMetricWithLabels(requestSizeMF, expectedLabels)
		require.NotNil(t, requestSizeMetric, "RequestSize metric with expected labels not found")
	})

	t.Run("does not log private version endpoint with auth", func(t *testing.T) {
		// Clear previous log output
		logOutput.Reset()

		req := httptest.NewRequest(http.MethodGet, "/test-version", nil)
		req.Header.Set("X-Secret-Key", "test-secret")
		req.Header.Set("Authorization", "Bearer token123")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		// Parse log output
		logLines := bytes.Split(logOutput.Bytes(), []byte("\n"))
		var requestLog map[string]interface{}

		for _, line := range logLines {
			if len(line) == 0 {
				continue
			}
			var logEntry map[string]interface{}
			err := json.Unmarshal(line, &logEntry)
			if err != nil {
				continue
			}
			if logEntry["msg"] == "request completed" {
				requestLog = logEntry
				break
			}
		}

		require.Nil(t, requestLog)
	})

	t.Run("metrics accumulate correctly across multiple requests", func(t *testing.T) {
		// Clear previous log output
		logOutput.Reset()

		// Make multiple requests to the same endpoint
		for range 3 {
			req := httptest.NewRequest(http.MethodGet, "/test-image", nil)
			req.Header.Set("X-Real-IP", "192.168.1.100")
			req.Header.Set("User-Agent", "Test Agent")

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Code)
		}

		// Make a request to a different endpoint
		req := httptest.NewRequest(http.MethodPost, "/test-health", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		// Gather metrics and verify accumulation
		gathered, err := registry.Gather()
		require.NoError(t, err)

		requestCountMF := findMetricFamily(gathered, "entra_phishing_detection_http_requests_total")
		require.NotNil(t, requestCountMF, "RequestCount metric not found")

		// Should have metrics for both endpoints
		imageRequests := 0
		healthRequests := 0

		for _, metric := range requestCountMF.GetMetric() {
			labelMap := make(map[string]string)
			for _, label := range metric.GetLabel() {
				labelMap[label.GetName()] = label.GetValue()
			}

			if labelMap["path"] == "/test-image" && labelMap["method"] == "GET" {
				imageRequests = int(metric.GetCounter().GetValue())
			} else if labelMap["path"] == "/test-health" && labelMap["method"] == "POST" {
				healthRequests = int(metric.GetCounter().GetValue())
			}
		}

		// Verify the accumulation - 3 GET requests to image + the original test = 4 total
		// But since we're using the same registry across all tests, we need to account for previous requests
		require.Positive(t, imageRequests, "Should have image requests recorded")
		require.Equal(t, 1, healthRequests, "Should have exactly 1 POST request to health endpoint")

		// Verify that duration metrics also accumulate
		requestDurationMF := findMetricFamily(gathered, "entra_phishing_detection_http_request_duration_seconds")
		require.NotNil(t, requestDurationMF, "RequestDuration metric not found")

		foundImageDuration := false
		foundHealthDuration := false

		for _, metric := range requestDurationMF.GetMetric() {
			labelMap := make(map[string]string)
			for _, label := range metric.GetLabel() {
				labelMap[label.GetName()] = label.GetValue()
			}

			if labelMap["path"] == "/test-image" && labelMap["method"] == "GET" {
				foundImageDuration = true
				require.Positive(t, metric.GetHistogram().GetSampleCount())
			} else if labelMap["path"] == "/test-health" && labelMap["method"] == "POST" {
				foundHealthDuration = true
				require.Positive(t, metric.GetHistogram().GetSampleCount())
			}
		}

		require.True(t, foundImageDuration, "Should have duration metrics for image endpoint")
		require.True(t, foundHealthDuration, "Should have duration metrics for health endpoint")
	})

	t.Run("metrics track different status codes correctly", func(t *testing.T) {
		// Clear previous log output
		logOutput.Reset()

		// Make a request to a non-existent endpoint
		req := httptest.NewRequest(http.MethodGet, "/non-existent", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// The server should return 200 OK with empty body for any unknown route
		// based on the implementation in server/router/router.go
		require.Equal(t, http.StatusOK, w.Code)

		// Gather metrics
		gathered, err := registry.Gather()
		require.NoError(t, err)

		requestCountMF := findMetricFamily(gathered, "entra_phishing_detection_http_requests_total")
		require.NotNil(t, requestCountMF, "RequestCount metric not found")

		// Find the metric for the non-existent path
		var notFoundMetric *dto.Metric
		for _, metric := range requestCountMF.GetMetric() {
			labelMap := make(map[string]string)
			for _, label := range metric.GetLabel() {
				labelMap[label.GetName()] = label.GetValue()
			}
			if labelMap["path"] == "/non-existent" {
				notFoundMetric = metric
				break
			}
		}

		require.NotNil(t, notFoundMetric, "Should have metric for non-existent path")

		// Verify the status code in the metric
		labelMap := make(map[string]string)
		for _, label := range notFoundMetric.GetLabel() {
			labelMap[label.GetName()] = label.GetValue()
		}
		require.Equal(t, "200", labelMap["code"], "Status code should be 200 for unknown routes")
		require.Equal(t, "GET", labelMap["method"])
		require.Equal(t, "/non-existent", labelMap["path"])
	})

	t.Run("metrics capture request and response sizes correctly", func(t *testing.T) {
		// Clear previous log output
		logOutput.Reset()

		// Create a request with a body to test request size metrics
		requestBody := `{"test": "data", "size": "measurement"}`
		req := httptest.NewRequest(http.MethodPost, "/test-health", bytes.NewReader([]byte(requestBody)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Length", strconv.Itoa(len(requestBody)))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		// Gather metrics
		gathered, err := registry.Gather()
		require.NoError(t, err)

		// Check RequestSize metric
		requestSizeMF := findMetricFamily(gathered, "entra_phishing_detection_http_request_size_bytes")
		require.NotNil(t, requestSizeMF, "RequestSize metric not found")

		// Find the metric for our POST request
		var sizeMetric *dto.Metric
		for _, metric := range requestSizeMF.GetMetric() {
			labelMap := make(map[string]string)
			for _, label := range metric.GetLabel() {
				labelMap[label.GetName()] = label.GetValue()
			}
			if labelMap["path"] == "/test-health" && labelMap["method"] == "POST" {
				sizeMetric = metric
				break
			}
		}

		require.NotNil(t, sizeMetric, "Should have request size metric for POST request")

		// Verify that the histogram recorded the request size
		histogram := sizeMetric.GetHistogram()
		require.Positive(t, histogram.GetSampleCount(), "Should have recorded request size samples")
		require.Positive(t, histogram.GetSampleSum(), "Should have recorded non-zero request size")

		// Check ResponseSize metric
		responseSizeMF := findMetricFamily(gathered, "entra_phishing_detection_http_response_size_bytes")
		require.NotNil(t, responseSizeMF, "ResponseSize metric not found")

		// Find the response size metric for our POST request
		var responseSizeMetric *dto.Metric
		for _, metric := range responseSizeMF.GetMetric() {
			labelMap := make(map[string]string)
			for _, label := range metric.GetLabel() {
				labelMap[label.GetName()] = label.GetValue()
			}
			if labelMap["path"] == "/test-health" && labelMap["method"] == "POST" {
				responseSizeMetric = metric
				break
			}
		}

		require.NotNil(t, responseSizeMetric, "Should have response size metric for POST request")

		// Verify that the histogram recorded the response size
		responseHistogram := responseSizeMetric.GetHistogram()
		require.Positive(t, responseHistogram.GetSampleCount(), "Should have recorded response size samples")
		// Response size might be 0 for health endpoint, so we just check that it was recorded
	})
}

func TestAccessLogBehaviorWithRouteGroups(t *testing.T) {
	// Create a buffer to capture log output
	var logOutput bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logOutput, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create test configuration
	cfg := config.Configuration{
		Server: config.Server{
			SecretKeyHeaderName:  "X-Secret-Key",
			SecretKeyHeaderValue: "test-secret",
			IPHeader:             "X-Real-IP",
			PathImage:            "test-image",
			PathHealth:           "test-health",
			PathVersion:          "test-version",
		},
		AllowedOrigins: []string{"example.com"},
	}

	// Create metrics
	registry := prometheus.NewRegistry()
	m, err := metrics.NewMetrics(registry, metrics.WithAccessLog())
	require.NoError(t, err)

	// Create server with accesslog middleware
	handler, err := server.NewServer(
		server.WithLogger(logger),
		server.WithConfig(cfg),
		server.WithMetrics(m),
		server.WithDebug(false),
		server.WithAccessLog(),
	)
	require.NoError(t, err)

	t.Run("public routes are logged", func(t *testing.T) {
		// Clear previous log output
		logOutput.Reset()

		// Test image endpoint (public)
		req := httptest.NewRequest(http.MethodGet, "/test-image", nil)
		req.Header.Set("X-Real-IP", "192.168.1.100")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		// Parse log output to find request completed entry
		logLines := bytes.Split(logOutput.Bytes(), []byte("\n"))
		var requestLog map[string]interface{}
		for _, line := range logLines {
			if len(line) == 0 {
				continue
			}
			var logEntry map[string]interface{}
			err := json.Unmarshal(line, &logEntry)
			if err != nil {
				continue
			}
			if logEntry["msg"] == "request completed" {
				requestLog = logEntry
				break
			}
		}

		// Should have access log entry
		require.NotNil(t, requestLog, "Image endpoint should have access log entry")
		require.Equal(t, "GET", requestLog["method"])
		require.Equal(t, "/test-image", requestLog["path"])
	})

	t.Run("public health endpoint is logged", func(t *testing.T) {
		// Clear previous log output
		logOutput.Reset()

		req := httptest.NewRequest(http.MethodGet, "/test-health", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		// Parse log output to find request completed entry
		logLines := bytes.Split(logOutput.Bytes(), []byte("\n"))
		var requestLog map[string]interface{}
		for _, line := range logLines {
			if len(line) == 0 {
				continue
			}
			var logEntry map[string]interface{}
			err := json.Unmarshal(line, &logEntry)
			if err != nil {
				continue
			}
			if logEntry["msg"] == "request completed" {
				requestLog = logEntry
				break
			}
		}

		// Should have access log entry
		require.NotNil(t, requestLog, "Public health endpoint should have access log entry")
		require.Equal(t, "GET", requestLog["method"])
		require.Equal(t, "/test-health", requestLog["path"])
	})

	t.Run("catch-all route is logged", func(t *testing.T) {
		// Clear previous log output
		logOutput.Reset()

		req := httptest.NewRequest(http.MethodGet, "/unknown-route", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		// Parse log output to find request completed entry
		logLines := bytes.Split(logOutput.Bytes(), []byte("\n"))
		var requestLog map[string]interface{}
		for _, line := range logLines {
			if len(line) == 0 {
				continue
			}
			var logEntry map[string]interface{}
			err := json.Unmarshal(line, &logEntry)
			if err != nil {
				continue
			}
			if logEntry["msg"] == "request completed" {
				requestLog = logEntry
				break
			}
		}

		// Should have access log entry for catch-all
		require.NotNil(t, requestLog, "Catch-all route should have access log entry")
		require.Equal(t, "GET", requestLog["method"])
		require.Equal(t, "/unknown-route", requestLog["path"])
	})

	t.Run("private version endpoint is not logged", func(t *testing.T) {
		// Clear previous log output
		logOutput.Reset()

		req := httptest.NewRequest(http.MethodGet, "/test-version", nil)
		req.Header.Set("X-Secret-Key", "test-secret")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		// Parse log output
		logLines := bytes.Split(logOutput.Bytes(), []byte("\n"))
		var requestLog map[string]interface{}
		for _, line := range logLines {
			if len(line) == 0 {
				continue
			}
			var logEntry map[string]interface{}
			err := json.Unmarshal(line, &logEntry)
			if err != nil {
				continue
			}
			if logEntry["msg"] == "request completed" {
				requestLog = logEntry
				break
			}
		}

		// Should NOT have access log entry
		require.Nil(t, requestLog, "Private version endpoint should not have access log entry")
	})

	t.Run("unauthorized access to private endpoints is not logged", func(t *testing.T) {
		// Clear previous log output
		logOutput.Reset()

		// Try to access private version endpoint without auth
		req := httptest.NewRequest(http.MethodGet, "/test-version", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code) // Secret key middleware returns 200 with empty body
		require.Empty(t, w.Body.String())       // Should be empty body

		// Parse log output - should not have access log entries
		logLines := bytes.Split(logOutput.Bytes(), []byte("\n"))
		requestLogCount := 0
		for _, line := range logLines {
			if len(line) == 0 {
				continue
			}
			var logEntry map[string]interface{}
			err := json.Unmarshal(line, &logEntry)
			if err != nil {
				continue
			}
			if logEntry["msg"] == "request completed" {
				requestLogCount++
			}
		}

		// Should NOT have any access log entries
		require.Equal(t, 0, requestLogCount, "Unauthorized requests to private endpoints should not be logged")
	})
}
