package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConfigCheck(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.json")

	// Valid config
	validConfig := `{
		"server": {
			"graceful_timeout": "5s",
			"secret_key_header_name": "X-Secret-Key",
			"secret_key_header_value": "secret",
			"ip_header": "X-Real-IP"
		},
		"allowed_origins": ["example.com"],
		"timeout": "10s"
	}`

	err := os.WriteFile(configFile, []byte(validConfig), 0644)
	require.NoError(t, err)

	// Test valid config
	err = configCheck(configFile)
	require.NoError(t, err)

	// Test invalid config file
	err = configCheck("non-existent-file.json")
	require.Error(t, err)

	// Test invalid JSON
	invalidConfig := `{invalid json`
	err = os.WriteFile(configFile, []byte(invalidConfig), 0644)
	require.NoError(t, err)

	err = configCheck(configFile)
	require.Error(t, err)
}

func TestRunErrorCases(t *testing.T) {
	// Test with no config file
	cli := cliOptions{}
	err := run(t.Context(), nil, cli)
	require.Error(t, err)
	require.Contains(t, err.Error(), "please provide a config file")

	// Test with invalid config file
	cli.configFilename = "non-existent-file.json"
	err = run(t.Context(), nil, cli)
	require.Error(t, err)
}

func TestRunWithValidConfig(t *testing.T) {
	// This test is more complex since run() starts servers
	// We'll test the initial validation only
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.json")

	validConfig := `{
		"server": {
			"graceful_timeout": "100ms",
			"secret_key_header_name": "X-Secret-Key",
			"secret_key_header_value": "secret",
			"ip_header": "X-Real-IP"
		},
		"allowed_origins": ["example.com"],
		"timeout": "1s"
	}`

	err := os.WriteFile(configFile, []byte(validConfig), 0644)
	require.NoError(t, err)

	cli := cliOptions{
		configFilename: configFile,
		listen:         "127.0.0.1:0", // Use random port
		listenMetrics:  "127.0.0.1:0", // Use random port
	}

	// Use a context with timeout to avoid hanging
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	// Create a test logger
	logger := newLogger(false, false, nil)

	// This should start and then shutdown gracefully due to context timeout
	err = run(ctx, logger, cli)
	// We don't expect an error since the context cancellation is expected
	require.NoError(t, err)
}
