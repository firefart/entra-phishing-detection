package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseConfig(t *testing.T) {
	config := `{
  "server": {
    "graceful_timeout": "5s",
    "secret_key_header_name": "X-Secret-Key-Header",
    "secret_key_header_value": "SECRET",
		"ip_header": "IP-Header",
    "path_image": "image_path",
    "path_health": "health_path",
    "path_version": "version_path"
  },
  "timeout": "5s"
}`

	f, err := os.CreateTemp(t.TempDir(), "config")
	require.NoError(t, err)
	tmpFilename := f.Name()
	_, err = f.WriteString(config)
	require.NoError(t, err)

	c, err := GetConfig(tmpFilename)
	require.NoError(t, err)

	require.Equal(t, 5*time.Second, c.Server.GracefulTimeout)
	require.Equal(t, "X-Secret-Key-Header", c.Server.SecretKeyHeaderName)
	require.Equal(t, "SECRET", c.Server.SecretKeyHeaderValue)

	require.Equal(t, "IP-Header", c.Server.IPHeader)
	require.Equal(t, "image_path", c.Server.PathImage)
	require.Equal(t, "health_path", c.Server.PathHealth)
	require.Equal(t, "version_path", c.Server.PathVersion)

	require.Equal(t, 5*time.Second, c.Timeout)
}

func TestGetConfigDefaults(t *testing.T) {
	// Create minimal config that should use defaults
	config := `{
		"server": {
			"secret_key_header_name": "X-Secret-Key",
			"secret_key_header_value": "SECRET"
		}
	}`

	f, err := os.CreateTemp(t.TempDir(), "config")
	require.NoError(t, err)
	tmpFilename := f.Name()
	_, err = f.WriteString(config)
	require.NoError(t, err)

	c, err := GetConfig(tmpFilename)
	require.NoError(t, err)

	// Should use default values
	require.Equal(t, 10*time.Second, c.Server.GracefulTimeout)
	require.Equal(t, []string{"login.microsoftonline.com"}, c.AllowedOrigins)
	require.Equal(t, 5*time.Second, c.Timeout)
}

func TestGetConfigValidationErrors(t *testing.T) {
	tests := []struct {
		name   string
		config string
		err    string
	}{
		{
			name: "missing secret key header value",
			config: `{
				"server": {
					"secret_key_header_name": "X-Secret-Key",
					"secret_key_header_value": ""
				}
			}`,
			err: "'SecretKeyHeaderValue' failed on the 'required' tag",
		},
		{
			name: "empty secret key header name",
			config: `{
				"server": {
					"secret_key_header_name": "",
					"secret_key_header_value": "SECRET"
				}
			}`,
			err: "'SecretKeyHeaderName' failed on the 'required' tag",
		},
		{
			name: "invalid allowed origins",
			config: `{
				"server": {
					"secret_key_header_name": "X-Secret-Key",
					"secret_key_header_value": "SECRET"
				},
				"allowed_origins": ["invalid-domain"]
			}`,
			err: "AllowedOrigins[0]' failed on the 'fqdn' tag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "config")
			require.NoError(t, err)
			tmpFilename := f.Name()
			_, err = f.WriteString(tt.config)
			require.NoError(t, err)

			_, err = GetConfig(tmpFilename)
			require.Error(t, err)
			require.ErrorContains(t, err, tt.err)
		})
	}
}

func TestGetConfigFileErrors(t *testing.T) {
	// Test non-existent file
	_, err := GetConfig("non-existent-file.json")
	require.Error(t, err)

	// Test invalid JSON
	f, err := os.CreateTemp(t.TempDir(), "config")
	require.NoError(t, err)
	tmpFilename := f.Name()

	_, err = f.WriteString("{invalid json")
	require.NoError(t, err)

	_, err = GetConfig(tmpFilename)
	require.Error(t, err)
}

func TestGetConfigPathCleaning(t *testing.T) {
	config := `{
		"server": {
			"secret_key_header_name": "X-Secret-Key",
			"secret_key_header_value": "SECRET",
			"path_image": "/image",
			"path_health": "//health",
			"path_version": "///version"
		}
	}`

	f, err := os.CreateTemp(t.TempDir(), "config")
	require.NoError(t, err)
	tmpFilename := f.Name()
	_, err = f.WriteString(config)
	require.NoError(t, err)

	c, err := GetConfig(tmpFilename)
	require.NoError(t, err)

	// Paths should have leading slashes removed
	require.Equal(t, "image", c.Server.PathImage)
	require.Equal(t, "health", c.Server.PathHealth)
	require.Equal(t, "version", c.Server.PathVersion)
}

func TestGetConfigWithHostHeaders(t *testing.T) {
	config := `{
		"server": {
			"secret_key_header_name": "X-Secret-Key",
			"secret_key_header_value": "SECRET",
			"host_headers": ["X-Forwarded-Host", "X-Original-Host"]
		},
		"allowed_origins": ["example.com"]
	}`

	f, err := os.CreateTemp(t.TempDir(), "config")
	require.NoError(t, err)
	tmpFilename := f.Name()
	_, err = f.WriteString(config)
	require.NoError(t, err)

	c, err := GetConfig(tmpFilename)
	require.NoError(t, err)
	require.Equal(t, []string{"X-Forwarded-Host", "X-Original-Host"}, c.Server.HostHeaders)
}

func TestConfigWithEnvVars(t *testing.T) {
	t.Setenv("ENTRA_SERVER_SECRET__KEY__HEADER__NAME", "X-XXXX")
	t.Setenv("ENTRA_SERVER_SECRET__KEY__HEADER__VALUE", "SECRET")
	c, err := GetConfig("")
	require.NoError(t, err)
	require.Equal(t, "X-XXXX", c.Server.SecretKeyHeaderName)
	require.Equal(t, "SECRET", c.Server.SecretKeyHeaderValue)
}

func TestGetConfigImageHandling(t *testing.T) {
	tests := []struct {
		name        string
		config      string
		expectedErr string
		validate    func(t *testing.T, c Configuration)
	}{
		{
			name: "valid images with case conversion",
			config: `{
				"server": {
					"secret_key_header_name": "X-Secret-Key",
					"secret_key_header_value": "SECRET"
				},
				"images": {
					"ok": {
						"EN": "ok_en.svg",
						"DE": "ok_de.svg"
					},
					"phishing": {
						"EN": "phishing_en.svg",
						"DE": "phishing_de.svg"
					}
				}
			}`,
			validate: func(t *testing.T, c Configuration) {
				require.Equal(t, "ok_en.svg", c.Images.OK["en"])
				require.Equal(t, "ok_de.svg", c.Images.OK["de"])
				require.Equal(t, "phishing_en.svg", c.Images.Phishing["en"])
				require.Equal(t, "phishing_de.svg", c.Images.Phishing["de"])
				// Original uppercase keys should be removed
				_, exists := c.Images.OK["EN"]
				require.False(t, exists)
				_, exists = c.Images.OK["DE"]
				require.False(t, exists)
			},
		},
		{
			name: "image name with dash should fail",
			config: `{
				"server": {
					"secret_key_header_name": "X-Secret-Key",
					"secret_key_header_value": "SECRET"
				},
				"images": {
					"ok": {
						"en-US": "ok_en_us.svg",
						"en": "ok_en.svg"
					},
					"phishing": {
						"en": "phishing_en.svg"
					}
				}
			}`,
			expectedErr: "ok image name \"en-US\" contains a dash, please only use the primary language",
		},
		{
			name: "phishing image name with dash should fail",
			config: `{
				"server": {
					"secret_key_header_name": "X-Secret-Key",
					"secret_key_header_value": "SECRET"
				},
				"images": {
					"ok": {
						"en": "ok_en.svg"
					},
					"phishing": {
						"en-GB": "phishing_en_gb.svg",
						"en": "phishing_en.svg"
					}
				}
			}`,
			expectedErr: "phishing image name \"en-GB\" contains a dash, please only use the primary language",
		},
		{
			name: "missing required 'en' ok image",
			config: `{
				"server": {
					"secret_key_header_name": "X-Secret-Key",
					"secret_key_header_value": "SECRET"
				},
				"images": {
					"ok": {
						"de": "ok_de.svg"
					},
					"phishing": {
						"en": "phishing_en.svg"
					}
				}
			}`,
			expectedErr: "ok image 'en' is required, please add it to the images map",
		},
		{
			name: "missing required 'en' phishing image",
			config: `{
				"server": {
					"secret_key_header_name": "X-Secret-Key",
					"secret_key_header_value": "SECRET"
				},
				"images": {
					"ok": {
						"en": "ok_en.svg"
					},
					"phishing": {
						"de": "phishing_de.svg"
					}
				}
			}`,
			expectedErr: "phishing image 'en' is required, please add it to the images map",
		},
		{
			name: "empty images config should not fail",
			config: `{
				"server": {
					"secret_key_header_name": "X-Secret-Key",
					"secret_key_header_value": "SECRET"
				},
				"images": {
					"ok": {},
					"phishing": {}
				}
			}`,
			validate: func(t *testing.T, c Configuration) {
				require.Empty(t, c.Images.OK)
				require.Empty(t, c.Images.Phishing)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "config")
			require.NoError(t, err)
			tmpFilename := f.Name()
			_, err = f.WriteString(tt.config)
			require.NoError(t, err)

			c, err := GetConfig(tmpFilename)

			if tt.expectedErr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, c)
				}
			}
		})
	}
}

func TestEnvironmentVariableTransformation(t *testing.T) {
	tests := []struct {
		name     string
		envVar   string
		envValue string
		expected string
		getField func(c Configuration) string
	}{
		{
			name:     "double underscore to single underscore",
			envVar:   "ENTRA_SERVER_SECRET__KEY__HEADER__NAME",
			envValue: "X-Custom-Header",
			expected: "X-Custom-Header",
			getField: func(c Configuration) string { return c.Server.SecretKeyHeaderName },
		},
		{
			name:     "single underscore to dot",
			envVar:   "ENTRA_SERVER_GRACEFUL__TIMEOUT",
			envValue: "15s",
			expected: "15s",
			getField: func(c Configuration) string { return c.Server.GracefulTimeout.String() },
		},
		{
			name:     "mixed underscores",
			envVar:   "ENTRA_SERVER_SECRET__KEY__HEADER__VALUE",
			envValue: "secret-value-123",
			expected: "secret-value-123",
			getField: func(c Configuration) string { return c.Server.SecretKeyHeaderValue },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear any existing environment variables
			os.Clearenv()

			// Set the test environment variable and required fields
			t.Setenv(tt.envVar, tt.envValue)
			// Set required fields that aren't being tested
			t.Setenv("ENTRA_SERVER_SECRET__KEY__HEADER__NAME", "X-Secret-Key")
			t.Setenv("ENTRA_SERVER_SECRET__KEY__HEADER__VALUE", "SECRET")

			// Override with the specific test value if it's one of the required fields
			t.Setenv(tt.envVar, tt.envValue)

			// Get config without a file (only env vars and defaults)
			c, err := GetConfig("")
			require.NoError(t, err)

			// Validate the field was set correctly
			actual := tt.getField(c)
			require.Equal(t, tt.expected, actual)
		})
	}
}

func TestGetConfigNoFile(t *testing.T) {
	// Set required environment variables for validation
	t.Setenv("ENTRA_SERVER_SECRET__KEY__HEADER__VALUE", "SECRET")

	// Test that GetConfig works with empty filename (only defaults + env vars)
	c, err := GetConfig("")
	require.NoError(t, err)

	// Should have default values
	require.Equal(t, "127.0.0.1:8000", c.Server.Listen)
	require.Empty(t, c.Server.ListenMetrics)
	require.Empty(t, c.Server.ListenPprof)
	require.Equal(t, 10*time.Second, c.Server.GracefulTimeout)
	require.Equal(t, "X-Secret-Key-Header", c.Server.SecretKeyHeaderName)
	require.Equal(t, "SECRET", c.Server.SecretKeyHeaderValue)
	require.Equal(t, []string{"login.microsoftonline.com"}, c.AllowedOrigins)
	require.Equal(t, 5*time.Second, c.Timeout)
}

func TestGetConfigLoggingValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      string
		expectedErr string
	}{
		{
			name: "invalid max_size should fail validation",
			config: `{
				"server": {
					"secret_key_header_name": "X-Secret-Key",
					"secret_key_header_value": "SECRET"
				},
				"logging": {
					"rotate": {
						"enabled": true,
						"max_size": -1
					}
				}
			}`,
			expectedErr: "'MaxSize' failed on the 'gte' tag",
		},
		{
			name: "invalid max_backups should fail validation",
			config: `{
				"server": {
					"secret_key_header_name": "X-Secret-Key",
					"secret_key_header_value": "SECRET"
				},
				"logging": {
					"rotate": {
						"enabled": true,
						"max_backups": -1
					}
				}
			}`,
			expectedErr: "'MaxBackups' failed on the 'gte' tag",
		},
		{
			name: "invalid max_age should fail validation",
			config: `{
				"server": {
					"secret_key_header_name": "X-Secret-Key",
					"secret_key_header_value": "SECRET"
				},
				"logging": {
					"rotate": {
						"enabled": true,
						"max_age": -1
					}
				}
			}`,
			expectedErr: "'MaxAge' failed on the 'gte' tag",
		},
		{
			name: "valid logging config should pass",
			config: `{
				"server": {
					"secret_key_header_name": "X-Secret-Key",
					"secret_key_header_value": "SECRET"
				},
				"logging": {
					"access_log": true,
					"json": true,
					"log_file": "/var/log/app.log",
					"rotate": {
						"enabled": true,
						"max_size": 100,
						"max_backups": 5,
						"max_age": 30,
						"compress": true
					}
				}
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "config")
			require.NoError(t, err)
			tmpFilename := f.Name()
			_, err = f.WriteString(tt.config)
			require.NoError(t, err)

			_, err = GetConfig(tmpFilename)
			if tt.expectedErr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
