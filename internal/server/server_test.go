package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/firefart/entra-phishing-detection/internal/config"
	"github.com/firefart/entra-phishing-detection/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestWithLogger(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	s := &server{}

	opt := WithLogger(logger)
	opt(s)

	require.Equal(t, logger, s.logger)
}

func TestWithConfig(t *testing.T) {
	cfg := config.Configuration{
		AllowedOrigins: []string{"example.com"},
	}
	s := &server{}

	opt := WithConfig(cfg)
	opt(s)

	require.Equal(t, cfg, s.config)
}

func TestWithDebug(t *testing.T) {
	s := &server{}

	opt := WithDebug(true)
	opt(s)

	require.True(t, s.debug)

	opt = WithDebug(false)
	opt(s)

	require.False(t, s.debug)
}

func TestWithMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, err := metrics.NewMetrics(reg)
	require.NoError(t, err)

	s := &server{}

	opt := WithMetrics(m)
	opt(s)

	require.Equal(t, m, s.metrics)
}

func TestWithAccessLog(t *testing.T) {
	s := &server{}

	opt := WithAccessLog()
	opt(s)

	require.True(t, s.accessLog)
}

func TestNotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/notfound", nil)
	w := httptest.NewRecorder()

	err := notFound(w, req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, w.Code)
	require.Empty(t, w.Body.String())
}

func TestNewServer(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cfg := config.Configuration{
		AllowedOrigins: []string{"example.com"},
		Server: config.Server{
			SecretKeyHeaderName:  "X-Secret-Key",
			SecretKeyHeaderValue: "secret",
			IPHeader:             "X-Real-IP",
			PathImage:            "image",
			PathHealth:           "health",
			PathVersion:          "version",
		},
	}
	reg := prometheus.NewRegistry()
	m, err := metrics.NewMetrics(reg)
	require.NoError(t, err)

	handler, err := NewServer(
		WithLogger(logger),
		WithConfig(cfg),
		WithDebug(true),
		WithMetrics(m),
		WithAccessLog(),
	)

	require.NoError(t, err)
	require.NotNil(t, handler)

	// Test that the handler can handle requests
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestNewServerDefaultPaths(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cfg := config.Configuration{
		AllowedOrigins: []string{"example.com"},
		Server: config.Server{
			SecretKeyHeaderName:  "X-Secret-Key",
			SecretKeyHeaderValue: "secret",
			IPHeader:             "X-Real-IP",
			// Leave paths empty to test defaults
		},
	}
	reg := prometheus.NewRegistry()
	m, err := metrics.NewMetrics(reg)
	require.NoError(t, err)

	handler, err := NewServer(
		WithLogger(logger),
		WithConfig(cfg),
		WithMetrics(m),
	)

	require.NoError(t, err)
	require.NotNil(t, handler)

	// Test default health path
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Test default image path
	req = httptest.NewRequest(http.MethodGet, "/image", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestNewServerCustomPaths(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cfg := config.Configuration{
		AllowedOrigins: []string{"example.com"},
		Server: config.Server{
			SecretKeyHeaderName:  "X-Secret-Key",
			SecretKeyHeaderValue: "secret",
			IPHeader:             "X-Real-IP",
			PathImage:            "custom-image",
			PathHealth:           "custom-health",
			PathVersion:          "custom-version",
		},
	}
	reg := prometheus.NewRegistry()
	m, err := metrics.NewMetrics(reg)
	require.NoError(t, err)

	handler, err := NewServer(
		WithLogger(logger),
		WithConfig(cfg),
		WithMetrics(m),
	)

	require.NoError(t, err)
	require.NotNil(t, handler)

	// Test custom health path
	req := httptest.NewRequest(http.MethodGet, "/custom-health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Test custom image path
	req = httptest.NewRequest(http.MethodGet, "/custom-image", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Test custom version path (should require secret key)
	req = httptest.NewRequest(http.MethodGet, "/custom-version", nil)
	req.Header.Set("X-Secret-Key", "secret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestNewServerCatchAll(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cfg := config.Configuration{
		AllowedOrigins: []string{"example.com"},
		Server: config.Server{
			SecretKeyHeaderName:  "X-Secret-Key",
			SecretKeyHeaderValue: "secret",
			IPHeader:             "X-Real-IP",
		},
	}
	reg := prometheus.NewRegistry()
	m, err := metrics.NewMetrics(reg)
	require.NoError(t, err)

	handler, err := NewServer(
		WithLogger(logger),
		WithConfig(cfg),
		WithMetrics(m),
	)

	require.NoError(t, err)
	require.NotNil(t, handler)

	// Test catch-all route
	req := httptest.NewRequest(http.MethodGet, "/random-path", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Empty(t, w.Body.String())
}

func TestWithCustomImages(t *testing.T) {
	t.Run("empty config does nothing", func(t *testing.T) {
		s := &server{
			imagesOK:       map[string][]byte{"en": []byte("default_ok")},
			imagesPhishing: map[string][]byte{"en": []byte("default_phishing")},
		}

		cfg := config.Images{}
		opt := WithCustomImages(cfg)
		err := opt(s)

		require.NoError(t, err)
		require.Equal(t, []byte("default_ok"), s.imagesOK["en"])
		require.Equal(t, []byte("default_phishing"), s.imagesPhishing["en"])
	})

	t.Run("custom OK images override defaults", func(t *testing.T) {
		// Create temporary test files
		tmpDir := t.TempDir()
		okFile := filepath.Join(tmpDir, "ok_en.svg")
		err := os.WriteFile(okFile, []byte("custom_ok_content"), 0o644)
		require.NoError(t, err)

		s := &server{
			imagesOK:       map[string][]byte{"en": []byte("default_ok")},
			imagesPhishing: map[string][]byte{"en": []byte("default_phishing")},
		}

		cfg := config.Images{
			OK: map[string]string{"en": okFile},
		}
		opt := WithCustomImages(cfg)
		err = opt(s)

		require.NoError(t, err)
		require.Equal(t, []byte("custom_ok_content"), s.imagesOK["en"])
		require.Equal(t, []byte("default_phishing"), s.imagesPhishing["en"])
	})

	t.Run("custom phishing images override defaults", func(t *testing.T) {
		// Create temporary test files
		tmpDir := t.TempDir()
		phishingFile := filepath.Join(tmpDir, "phishing_de.svg")
		err := os.WriteFile(phishingFile, []byte("custom_phishing_content"), 0o644)
		require.NoError(t, err)

		s := &server{
			imagesOK:       map[string][]byte{"en": []byte("default_ok")},
			imagesPhishing: map[string][]byte{"de": []byte("default_phishing")},
		}

		cfg := config.Images{
			Phishing: map[string]string{"de": phishingFile},
		}
		opt := WithCustomImages(cfg)
		err = opt(s)

		require.NoError(t, err)
		require.Equal(t, []byte("default_ok"), s.imagesOK["en"])
		require.Equal(t, []byte("custom_phishing_content"), s.imagesPhishing["de"])
	})

	t.Run("both custom OK and phishing images", func(t *testing.T) {
		// Create temporary test files
		tmpDir := t.TempDir()
		okFile := filepath.Join(tmpDir, "ok_en.svg")
		phishingFile := filepath.Join(tmpDir, "phishing_en.svg")
		err := os.WriteFile(okFile, []byte("custom_ok_en"), 0o644)
		require.NoError(t, err)
		err = os.WriteFile(phishingFile, []byte("custom_phishing_en"), 0o644)
		require.NoError(t, err)

		s := &server{
			imagesOK:       map[string][]byte{"en": []byte("default_ok")},
			imagesPhishing: map[string][]byte{"en": []byte("default_phishing")},
		}

		cfg := config.Images{
			OK:       map[string]string{"en": okFile},
			Phishing: map[string]string{"en": phishingFile},
		}
		opt := WithCustomImages(cfg)
		err = opt(s)

		require.NoError(t, err)
		require.Equal(t, []byte("custom_ok_en"), s.imagesOK["en"])
		require.Equal(t, []byte("custom_phishing_en"), s.imagesPhishing["en"])
	})

	t.Run("multiple languages", func(t *testing.T) {
		// Create temporary test files
		tmpDir := t.TempDir()
		okFileEn := filepath.Join(tmpDir, "ok_en.svg")
		okFileDe := filepath.Join(tmpDir, "ok_de.svg")
		phishingFileEn := filepath.Join(tmpDir, "phishing_en.svg")
		phishingFileDe := filepath.Join(tmpDir, "phishing_de.svg")

		err := os.WriteFile(okFileEn, []byte("custom_ok_en"), 0o644)
		require.NoError(t, err)
		err = os.WriteFile(okFileDe, []byte("custom_ok_de"), 0o644)
		require.NoError(t, err)
		err = os.WriteFile(phishingFileEn, []byte("custom_phishing_en"), 0o644)
		require.NoError(t, err)
		err = os.WriteFile(phishingFileDe, []byte("custom_phishing_de"), 0o644)
		require.NoError(t, err)

		s := &server{}

		cfg := config.Images{
			OK: map[string]string{
				"en": okFileEn,
				"de": okFileDe,
			},
			Phishing: map[string]string{
				"en": phishingFileEn,
				"de": phishingFileDe,
			},
		}
		opt := WithCustomImages(cfg)
		err = opt(s)

		require.NoError(t, err)
		require.Equal(t, []byte("custom_ok_en"), s.imagesOK["en"])
		require.Equal(t, []byte("custom_ok_de"), s.imagesOK["de"])
		require.Equal(t, []byte("custom_phishing_en"), s.imagesPhishing["en"])
		require.Equal(t, []byte("custom_phishing_de"), s.imagesPhishing["de"])
	})

	t.Run("error reading OK image file", func(t *testing.T) {
		s := &server{}

		cfg := config.Images{
			OK: map[string]string{"en": "/nonexistent/file.svg"},
		}
		opt := WithCustomImages(cfg)
		err := opt(s)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read OK image for language en")
	})

	t.Run("error reading phishing image file", func(t *testing.T) {
		s := &server{}

		cfg := config.Images{
			Phishing: map[string]string{"de": "/nonexistent/file.svg"},
		}
		opt := WithCustomImages(cfg)
		err := opt(s)

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read Phishing image for language de")
	})
}

func TestNewServerWithCustomImages(t *testing.T) {
	t.Run("server with custom images", func(t *testing.T) {
		// Create temporary test files
		tmpDir := t.TempDir()
		okFile := filepath.Join(tmpDir, "ok_custom.svg")
		phishingFile := filepath.Join(tmpDir, "phishing_custom.svg")

		err := os.WriteFile(okFile, []byte("<svg>custom ok</svg>"), 0o644)
		require.NoError(t, err)
		err = os.WriteFile(phishingFile, []byte("<svg>custom phishing</svg>"), 0o644)
		require.NoError(t, err)

		logger := slog.New(slog.DiscardHandler)
		cfg := config.Configuration{
			AllowedOrigins: []string{"example.com"},
			Server: config.Server{
				SecretKeyHeaderName:  "X-Secret-Key",
				SecretKeyHeaderValue: "secret",
				IPHeader:             "X-Real-IP",
				PathImage:            "image",
				PathHealth:           "health",
				PathVersion:          "version",
			},
			Images: config.Images{
				OK:       map[string]string{"en": okFile},
				Phishing: map[string]string{"en": phishingFile},
			},
		}
		reg := prometheus.NewRegistry()
		m, err := metrics.NewMetrics(reg)
		require.NoError(t, err)

		handler, err := NewServer(
			WithLogger(logger),
			WithConfig(cfg),
			WithCustomImages(cfg.Images),
			WithMetrics(m),
		)

		require.NoError(t, err)
		require.NotNil(t, handler)

		// Test that the server uses custom images - we can test this by making a request
		// to the image endpoint and checking if it returns a response (the exact content
		// would depend on the image handler implementation)
		req := httptest.NewRequest(http.MethodGet, "/image", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("server with default images when no custom images provided", func(t *testing.T) {
		logger := slog.New(slog.DiscardHandler)
		cfg := config.Configuration{
			AllowedOrigins: []string{"example.com"},
			Server: config.Server{
				SecretKeyHeaderName:  "X-Secret-Key",
				SecretKeyHeaderValue: "secret",
				IPHeader:             "X-Real-IP",
				PathImage:            "image",
				PathHealth:           "health",
				PathVersion:          "version",
			},
			Images: config.Images{}, // Empty images config
		}
		reg := prometheus.NewRegistry()
		m, err := metrics.NewMetrics(reg)
		require.NoError(t, err)

		handler, err := NewServer(
			WithLogger(logger),
			WithConfig(cfg),
			WithCustomImages(cfg.Images), // This should not override defaults since config is empty
			WithMetrics(m),
		)

		require.NoError(t, err)
		require.NotNil(t, handler)

		// Test that the server still works with default images
		req := httptest.NewRequest(http.MethodGet, "/image", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	})
}

func TestDefaultImagesSetCorrectly(t *testing.T) {
	// Create a server to access its internal state
	s := server{}

	// Apply default initialization (similar to NewServer)
	s.imagesOK = make(map[string][]byte)
	s.imagesOK["en"] = imageOK
	s.imagesOK["de"] = imageOK
	s.imagesPhishing = make(map[string][]byte)
	s.imagesPhishing["en"] = imagePhishingEN
	s.imagesPhishing["de"] = imagePhishingDE

	// Verify default images are set
	require.NotNil(t, s.imagesOK["en"])
	require.NotNil(t, s.imagesOK["de"])
	require.NotNil(t, s.imagesPhishing["en"])
	require.NotNil(t, s.imagesPhishing["de"])

	// Verify that the default English and German OK images are the same (both use imageOK)
	require.Equal(t, s.imagesOK["en"], s.imagesOK["de"])

	// Verify that English and German phishing images are not the same
	require.NotEqual(t, s.imagesPhishing["en"], s.imagesPhishing["de"])

	// Verify they contain actual embedded content (not empty)
	require.NotEmpty(t, s.imagesOK["en"])
	require.NotEmpty(t, s.imagesPhishing["en"])
	require.NotEmpty(t, s.imagesPhishing["de"])
}

func TestCustomImagesCompletelyOverrideDefaults(t *testing.T) {
	// Create temporary test files with specific content
	tmpDir := t.TempDir()
	okFileEn := filepath.Join(tmpDir, "ok_en.svg")
	okFileDe := filepath.Join(tmpDir, "ok_de.svg")
	phishingFileEn := filepath.Join(tmpDir, "phishing_en.svg")
	phishingFileDe := filepath.Join(tmpDir, "phishing_de.svg")

	customOkEnContent := []byte("<svg>custom_ok_en_content</svg>")
	customOkDeContent := []byte("<svg>custom_ok_de_content</svg>")
	customPhishingEnContent := []byte("<svg>custom_phishing_en_content</svg>")
	customPhishingDeContent := []byte("<svg>custom_phishing_de_content</svg>")

	err := os.WriteFile(okFileEn, customOkEnContent, 0o644)
	require.NoError(t, err)
	err = os.WriteFile(okFileDe, customOkDeContent, 0o644)
	require.NoError(t, err)
	err = os.WriteFile(phishingFileEn, customPhishingEnContent, 0o644)
	require.NoError(t, err)
	err = os.WriteFile(phishingFileDe, customPhishingDeContent, 0o644)
	require.NoError(t, err)

	s := &server{}

	// Set default images first (simulating NewServer behavior)
	s.imagesOK = make(map[string][]byte)
	s.imagesOK["en"] = imageOK
	s.imagesOK["de"] = imageOK
	s.imagesPhishing = make(map[string][]byte)
	s.imagesPhishing["en"] = imagePhishingEN
	s.imagesPhishing["de"] = imagePhishingDE

	// Store original default content for comparison
	originalOkEn := make([]byte, len(s.imagesOK["en"]))
	copy(originalOkEn, s.imagesOK["en"])
	originalPhishingEn := make([]byte, len(s.imagesPhishing["en"]))
	copy(originalPhishingEn, s.imagesPhishing["en"])

	// Apply custom images
	cfg := config.Images{
		OK: map[string]string{
			"en": okFileEn,
			"de": okFileDe,
		},
		Phishing: map[string]string{
			"en": phishingFileEn,
			"de": phishingFileDe,
		},
	}
	opt := WithCustomImages(cfg)
	err = opt(s)
	require.NoError(t, err)

	// Verify custom content completely replaced defaults
	require.Equal(t, customOkEnContent, s.imagesOK["en"])
	require.Equal(t, customOkDeContent, s.imagesOK["de"])
	require.Equal(t, customPhishingEnContent, s.imagesPhishing["en"])
	require.Equal(t, customPhishingDeContent, s.imagesPhishing["de"])

	// Verify that custom content is different from original defaults
	require.NotEqual(t, originalOkEn, s.imagesOK["en"])
	require.NotEqual(t, originalPhishingEn, s.imagesPhishing["en"])

	// Verify the maps have been completely replaced (not just individual entries)
	require.Len(t, s.imagesOK, 2)
	require.Len(t, s.imagesPhishing, 2)
}

func TestServer_TreatMissingRefererAsPhishing_Integration(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	reg := prometheus.NewRegistry()
	m, err := metrics.NewMetrics(reg)
	require.NoError(t, err)

	// Create temporary files for testing
	tempDir := t.TempDir()
	okImagePath := filepath.Join(tempDir, "ok.svg")
	phishingImagePath := filepath.Join(tempDir, "phishing.svg")

	okContent := "test_ok_image"
	phishingContent := "test_phishing_image"

	err = os.WriteFile(okImagePath, []byte(okContent), 0o644)
	require.NoError(t, err)
	err = os.WriteFile(phishingImagePath, []byte(phishingContent), 0o644)
	require.NoError(t, err)

	testCases := []struct {
		name                          string
		treatMissingRefererAsPhishing bool
		referer                       string
		expectedImageContent          string
		expectedStatus                int
	}{
		{
			name:                          "Missing referer treated as phishing",
			treatMissingRefererAsPhishing: true,
			referer:                       "",
			expectedImageContent:          phishingContent,
			expectedStatus:                http.StatusOK,
		},
		{
			name:                          "Missing referer treated as safe",
			treatMissingRefererAsPhishing: false,
			referer:                       "",
			expectedImageContent:          okContent,
			expectedStatus:                http.StatusOK,
		},
		{
			name:                          "Valid referer always returns OK regardless of setting (true)",
			treatMissingRefererAsPhishing: true,
			referer:                       "https://example.com/login",
			expectedImageContent:          okContent,
			expectedStatus:                http.StatusOK,
		},
		{
			name:                          "Valid referer always returns OK regardless of setting (false)",
			treatMissingRefererAsPhishing: false,
			referer:                       "https://example.com/auth",
			expectedImageContent:          okContent,
			expectedStatus:                http.StatusOK,
		},
		{
			name:                          "Invalid referer always returns phishing regardless of setting (true)",
			treatMissingRefererAsPhishing: true,
			referer:                       "https://malicious.com",
			expectedImageContent:          phishingContent,
			expectedStatus:                http.StatusOK,
		},
		{
			name:                          "Invalid referer always returns phishing regardless of setting (false)",
			treatMissingRefererAsPhishing: false,
			referer:                       "https://evil.example",
			expectedImageContent:          phishingContent,
			expectedStatus:                http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Configuration{
				AllowedOrigins:                []string{"example.com"},
				TreatMissingRefererAsPhishing: tc.treatMissingRefererAsPhishing,
				Server: config.Server{
					SecretKeyHeaderName:  "X-Secret-Key",
					SecretKeyHeaderValue: "secret",
					PathImage:            "image",
				},
			}

			// Use custom images with file paths
			customImages := config.Images{
				OK:       map[string]string{"en": okImagePath},
				Phishing: map[string]string{"en": phishingImagePath},
			}

			handler, err := NewServer(
				WithLogger(logger),
				WithConfig(cfg),
				WithMetrics(m),
				WithCustomImages(customImages),
			)
			require.NoError(t, err)
			require.NotNil(t, handler)

			// Make request to image endpoint
			req := httptest.NewRequest(http.MethodGet, "/image", nil)
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			require.Equal(t, tc.expectedStatus, rec.Code)
			require.Equal(t, tc.expectedImageContent, rec.Body.String())

			// Verify standard headers are set
			require.Equal(t, `inline; filename="image.svg"`, rec.Header().Get("Content-Disposition"))
			require.Equal(t, "image/svg+xml", rec.Header().Get("Content-Type"))
			require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			require.Equal(t, "no-cache", rec.Header().Get("Pragma"))
			require.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
		})
	}
}

func TestServer_TreatMissingRefererAsPhishing_DefaultBehavior(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	reg := prometheus.NewRegistry()
	m, err := metrics.NewMetrics(reg)
	require.NoError(t, err)

	// Test with default configuration (should treat missing referer as phishing by default)
	cfg := config.Configuration{
		AllowedOrigins:                []string{"example.com"},
		TreatMissingRefererAsPhishing: true, // This is the default
		Server: config.Server{
			SecretKeyHeaderName:  "X-Secret-Key",
			SecretKeyHeaderValue: "secret",
		},
	}

	// Use built-in default images (no custom images)
	handler, err := NewServer(
		WithLogger(logger),
		WithConfig(cfg),
		WithMetrics(m),
	)
	require.NoError(t, err)

	// Test request with no referer (should be treated as phishing by default)
	req := httptest.NewRequest(http.MethodGet, "/image", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	// The default images should contain some content (we don't check exact content since it's built-in)
	require.NotEmpty(t, rec.Body.String())

	// Test that a valid referer returns a different response
	req2 := httptest.NewRequest(http.MethodGet, "/image", nil)
	req2.Header.Set("Referer", "https://example.com/login")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	require.Equal(t, http.StatusOK, rec2.Code)
	require.NotEmpty(t, rec2.Body.String())

	// The responses should be different (phishing vs OK)
	require.NotEqual(t, rec.Body.String(), rec2.Body.String(),
		"Missing referer should return different content than valid referer")
}
