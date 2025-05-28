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
