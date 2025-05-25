package main

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewLogger(t *testing.T) {
	t.Run("default logger with stdout", func(t *testing.T) {
		logger := newLogger(false, false, nil)
		require.NotNil(t, logger)
		require.IsType(t, &slog.Logger{}, logger)
	})

	t.Run("debug mode logger", func(t *testing.T) {
		logger := newLogger(true, false, nil)
		require.NotNil(t, logger)
		require.IsType(t, &slog.Logger{}, logger)
	})

	t.Run("json output logger", func(t *testing.T) {
		logger := newLogger(false, true, nil)
		require.NotNil(t, logger)
		require.IsType(t, &slog.Logger{}, logger)
	})

	t.Run("logger with log file", func(t *testing.T) {
		var buf bytes.Buffer
		logger := newLogger(false, false, &buf)
		require.NotNil(t, logger)
		require.IsType(t, &slog.Logger{}, logger)
	})

	t.Run("debug mode with json output", func(t *testing.T) {
		logger := newLogger(true, true, nil)
		require.NotNil(t, logger)
		require.IsType(t, &slog.Logger{}, logger)
	})

	t.Run("debug mode with log file", func(t *testing.T) {
		var buf bytes.Buffer
		logger := newLogger(true, false, &buf)
		require.NotNil(t, logger)
		require.IsType(t, &slog.Logger{}, logger)
	})

	t.Run("logger with multiwriter", func(t *testing.T) {
		var buf bytes.Buffer
		logger := newLogger(false, true, &buf)
		require.NotNil(t, logger)

		// Test that logging works
		logger.Info("test message")
		// The buffer should contain the log message when using multiwriter
		require.NotEmpty(t, buf.String())
	})

	t.Run("debug logger with source information", func(t *testing.T) {
		var buf bytes.Buffer
		logger := newLogger(true, true, &buf)
		require.NotNil(t, logger)

		// Test that logging works with source information
		logger.Debug("debug message")
		logOutput := buf.String()
		require.NotEmpty(t, logOutput)
		// In debug mode with JSON, source information should be included
		require.Contains(t, logOutput, "source")
	})
}

func TestNewLoggerReplaceFunc(t *testing.T) {
	// Test the source file path replacement functionality
	var buf bytes.Buffer
	logger := newLogger(true, true, &buf)
	require.NotNil(t, logger)

	// Log a message that will trigger source information
	logger.Debug("test message with source")

	logOutput := buf.String()
	require.NotEmpty(t, logOutput)

	// The source file path should be relative, not absolute
	wd, err := os.Getwd()
	require.NoError(t, err)
	require.NotContains(t, logOutput, wd)
}

func TestNewLoggerNonTerminal(t *testing.T) {
	// This test simulates non-terminal output by using a buffer
	// The logger should use text handler when not in a terminal
	var buf bytes.Buffer

	// Temporarily redirect stdout to simulate non-terminal
	originalStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w                                 // nolint: reassign
	defer func() { os.Stdout = originalStdout }() // nolint: reassign

	logger := newLogger(false, false, &buf)
	require.NotNil(t, logger)

	// Close the pipe
	w.Close()
	r.Close()
}

func TestNewLoggerHandlerSelection(t *testing.T) {
	tests := []struct {
		name       string
		debugMode  bool
		jsonOutput bool
		logFile    io.Writer
	}{
		{
			name:       "json handler",
			debugMode:  false,
			jsonOutput: true,
			logFile:    nil,
		},
		{
			name:       "debug json handler",
			debugMode:  true,
			jsonOutput: true,
			logFile:    nil,
		},
		{
			name:       "text handler with file",
			debugMode:  false,
			jsonOutput: false,
			logFile:    &bytes.Buffer{},
		},
		{
			name:       "debug text handler with file",
			debugMode:  true,
			jsonOutput: false,
			logFile:    &bytes.Buffer{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := newLogger(tt.debugMode, tt.jsonOutput, tt.logFile)
			require.NotNil(t, logger)

			// Test that the logger can actually log
			if tt.logFile != nil {
				if buf, ok := tt.logFile.(*bytes.Buffer); ok {
					logger.Info("test message")
					require.NotEmpty(t, buf.String())
				}
			}
		})
	}
}
