package pivzavr

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeConfig writes a configuration file in a temporary config directory and
// returns the base directory so it can be exported as XDG_CONFIG_HOME.
func writeConfig(t *testing.T, contents string) string {
	t.Helper()

	base := t.TempDir()
	dir := filepath.Join(base, configDirName)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, configFileName), []byte(contents), 0o600))
	return base
}

func TestParseConfigLine(t *testing.T) {
	testCases := []struct {
		name      string
		line      string
		wantKey   string
		wantValue string
	}{
		{"blank", "   ", "", ""},
		{"comment", "# pinentry /usr/bin/pinentry-qt", "", ""},
		{"space separated", "pinentry /usr/bin/pinentry-qt", "pinentry", "/usr/bin/pinentry-qt"},
		{"equals separated", "pkcs11-module=/usr/lib/libykcs11.so", "pkcs11-module", "/usr/lib/libykcs11.so"},
		{"equals with spaces", "pkcs11-module = /usr/lib/libykcs11.so", "pkcs11-module", "/usr/lib/libykcs11.so"},
		{"tabs and outer spaces", "\tpinentry\t/usr/bin/pinentry-curses \t", "pinentry", "/usr/bin/pinentry-curses"},
		{"key only", "pinentry", "pinentry", ""},
		{"value with spaces", "pinentry /opt/my pinentry", "pinentry", "/opt/my pinentry"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			key, value := parseConfigLine(testCase.line)
			assert.Equal(t, testCase.wantKey, key)
			assert.Equal(t, testCase.wantValue, value)
		})
	}
}

func TestReadConfig(t *testing.T) {
	base := writeConfig(t, "# pivzavr configuration\n\npinentry /usr/bin/pinentry-qt\npkcs11-module=/usr/lib/libykcs11.so\nserial 12345678\nunknown value\n")
	t.Setenv(configDirEnv, base)

	cfg, err := readConfig()
	require.NoError(t, err)
	assert.Equal(t, "/usr/bin/pinentry-qt", cfg.pinentry)
	assert.Equal(t, "/usr/lib/libykcs11.so", cfg.pkcs11Module)
	assert.Equal(t, "12345678", cfg.serial)
}

func TestReadConfigMissingFile(t *testing.T) {
	t.Setenv(configDirEnv, t.TempDir())

	cfg, err := readConfig()
	require.NoError(t, err)
	assert.Empty(t, cfg.pinentry)
	assert.Empty(t, cfg.pkcs11Module)
	assert.Empty(t, cfg.serial)
}

func TestConfigPath(t *testing.T) {
	t.Setenv(configDirEnv, "/tmp/xdg")

	path, err := configPath()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("/tmp/xdg", configDirName, configFileName), path)
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	assert.Equal(t, home, expandHome("~"))
	assert.Equal(t, filepath.Join(home, "bin", "pinentry"), expandHome("~/bin/pinentry"))
	assert.Equal(t, "/usr/bin/pinentry", expandHome("/usr/bin/pinentry"))
	assert.Equal(t, "relative", expandHome("relative"))
}

func TestResolvePinentryPath(t *testing.T) {
	t.Run("environment overrides config", func(t *testing.T) {
		base := writeConfig(t, "pinentry /config/pinentry\n")
		t.Setenv(configDirEnv, base)
		t.Setenv(pinentryEnv, "/env/pinentry")

		path, err := resolvePinentryPath()
		require.NoError(t, err)
		assert.Equal(t, "/env/pinentry", path)
	})

	t.Run("config overrides default", func(t *testing.T) {
		base := writeConfig(t, "pinentry /config/pinentry\n")
		t.Setenv(configDirEnv, base)
		t.Setenv(pinentryEnv, "")

		path, err := resolvePinentryPath()
		require.NoError(t, err)
		assert.Equal(t, "/config/pinentry", path)
	})

	t.Run("default is used without config", func(t *testing.T) {
		t.Setenv(configDirEnv, t.TempDir())
		t.Setenv(pinentryEnv, "")

		path, err := resolvePinentryPath()
		wantPath, wantErr := findPinentryPath()
		if wantErr != nil {
			assert.Error(t, err)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, wantPath, path)
	})
}

func TestResolvePKCS11Module(t *testing.T) {
	t.Run("environment overrides config", func(t *testing.T) {
		base := writeConfig(t, "pkcs11-module /config/libykcs11.so\n")
		t.Setenv(configDirEnv, base)
		t.Setenv(pkcs11ModuleEnv, "/env/libykcs11.so")

		path, err := resolvePKCS11Module()
		require.NoError(t, err)
		assert.Equal(t, "/env/libykcs11.so", path)
	})

	t.Run("config overrides default", func(t *testing.T) {
		base := writeConfig(t, "pkcs11-module /config/libykcs11.so\n")
		t.Setenv(configDirEnv, base)
		t.Setenv(pkcs11ModuleEnv, "")

		path, err := resolvePKCS11Module()
		require.NoError(t, err)
		assert.Equal(t, "/config/libykcs11.so", path)
	})
}

func TestSerial(t *testing.T) {
	t.Run("environment overrides config", func(t *testing.T) {
		base := writeConfig(t, "serial CONFIG123\n")
		t.Setenv(configDirEnv, base)
		t.Setenv(serialEnv, "ENV456")

		serial, err := Serial()
		require.NoError(t, err)
		assert.Equal(t, "ENV456", serial)
	})

	t.Run("config overrides default", func(t *testing.T) {
		base := writeConfig(t, "serial CONFIG123\n")
		t.Setenv(configDirEnv, base)
		t.Setenv(serialEnv, "")

		serial, err := Serial()
		require.NoError(t, err)
		assert.Equal(t, "CONFIG123", serial)
	})

	t.Run("default is empty without config", func(t *testing.T) {
		t.Setenv(configDirEnv, t.TempDir())
		t.Setenv(serialEnv, "")

		serial, err := Serial()
		require.NoError(t, err)
		assert.Empty(t, serial)
	})
}

func TestFirstExistingProgram(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "pinentry-qt")
	require.NoError(t, os.WriteFile(existing, []byte("#!/bin/sh\n"), 0o600))

	path, ok := firstExistingProgram([]string{filepath.Join(dir, "missing"), existing})
	require.True(t, ok)
	assert.Equal(t, existing, path)

	// Directories are not programs.
	_, ok = firstExistingProgram([]string{dir})
	assert.False(t, ok)

	// A bare name is resolved through PATH; "sh" is widely available.
	if sh, err := exec.LookPath("sh"); err == nil {
		path, ok = firstExistingProgram([]string{"sh"})
		require.True(t, ok)
		assert.Equal(t, sh, path)
	}
}

func TestCandidatePinentryPaths(t *testing.T) {
	linux := candidatePinentryPaths("linux")
	require.NotEmpty(t, linux)
	assert.Equal(t, filepath.Join("/usr/bin", "pinentry-qt"), linux[0])
	assert.Equal(t, filepath.Join("/usr/bin", "pinentry-gtk"), linux[1])
	assert.Equal(t, filepath.Join("/usr/bin", "pinentry-curses"), linux[3])

	darwin := candidatePinentryPaths("darwin")
	require.NotEmpty(t, darwin)
	assert.Equal(t, filepath.Join("/opt/homebrew/bin", "pinentry-qt"), darwin[0])

	windows := candidatePinentryPaths("windows")
	require.NotEmpty(t, windows)
	assert.Contains(t, windows, filepath.Join(`C:\Program Files\GnuPG\bin`, "pinentry-qt"))
}
