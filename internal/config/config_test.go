package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseConfig(t *testing.T) {
	public, err := os.CreateTemp(t.TempDir(), "test")
	require.NoError(t, err)
	defer func(public *os.File) {
		err := public.Close()
		require.NoError(t, err)
	}(public)
	defer func(name string) {
		err := os.Remove(name)
		require.NoError(t, err)
	}(public.Name())
	private, err := os.CreateTemp(t.TempDir(), "test")
	require.NoError(t, err)
	defer func(private *os.File) {
		err := private.Close()
		require.NoError(t, err)
	}(private)
	defer func(name string) {
		err := os.Remove(name)
		require.NoError(t, err)
	}(private.Name())

	config := `{
  "server": {
    "graceful_timeout": "5s",
    "secret_key_header_name": "X-Secret-Key-Header",
    "secret_key_header_value": "SECRET",
		"ip_header": "IP-Header",
    "path_image": "iamge_path",
    "path_health": "health_path",
    "path_version": "version_path"
  },
  "timeout": "5s"
}`

	f, err := os.CreateTemp(t.TempDir(), "config")
	require.NoError(t, err)
	tmpFilename := f.Name()
	defer func(f *os.File) {
		err := f.Close()
		require.NoError(t, err)
	}(f)
	defer func(name string) {
		err := os.Remove(name)
		require.NoError(t, err)
	}(tmpFilename)
	_, err = f.WriteString(config)
	require.NoError(t, err)

	c, err := GetConfig(tmpFilename)
	require.NoError(t, err)

	require.Equal(t, 5*time.Second, c.Server.GracefulTimeout)
	require.Equal(t, "X-Secret-Key-Header", c.Server.SecretKeyHeaderName)
	require.Equal(t, "SECRET", c.Server.SecretKeyHeaderValue)

	require.Equal(t, "IP-Header", c.Server.IPHeader)
	require.Equal(t, "iamge_path", c.Server.PathImage)
	require.Equal(t, "health_path", c.Server.PathHealth)
	require.Equal(t, "version_path", c.Server.PathVersion)

	require.Equal(t, 5*time.Second, c.Timeout)
}
