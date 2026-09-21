package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsVendorModule checks the classification of the PKCS#11 modules of the
// vendors whose cards pivzavr supports.
func TestIsVendorModule(t *testing.T) {
	rutoken := []string{
		"librtpkcs11ecp.so",
		"librtPKCS11ECP.so",
		"/usr/lib64/librtPKCS11ECP.so",
		"/usr/lib/x86_64-linux-gnu/librtpkcs11ecp.so",
	}
	for _, path := range rutoken {
		assert.True(t, IsRtPKCS11Module(path), path)
		assert.False(t, IsJcPKCS11Module(path), path)
		assert.False(t, IsYkcs11Module(path), path)
	}

	jacarta := []string{
		"libjcPKCS11.so",
		"libjcPKCS11-2.so",
		"/usr/lib/libjcPKCS11.so",
	}
	for _, path := range jacarta {
		assert.True(t, IsJcPKCS11Module(path), path)
		assert.False(t, IsRtPKCS11Module(path), path)
		assert.False(t, IsYkcs11Module(path), path)
	}

	assert.False(t, IsRtPKCS11Module("/usr/lib/opensc-pkcs11.so"))
	assert.False(t, IsJcPKCS11Module("/usr/lib/opensc-pkcs11.so"))
}

// TestCandidateModulePathsIncludeVendors checks that the vendor modules are
// among the conventional locations, in front of OpenSC, so that a Rutoken or a
// JaCarta is reached through the module of its vendor.
func TestCandidateModulePathsIncludeVendors(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "freebsd"} {
		paths := candidateModulePaths(goos, "amd64")

		vendor, opensc := -1, -1
		for i, path := range paths {
			if IsRtPKCS11Module(path) || IsJcPKCS11Module(path) {
				if vendor < 0 {
					vendor = i
				}
			}
			if isOpenscModule(path) && opensc < 0 {
				opensc = i
			}
		}
		assert.NotEqual(t, -1, vendor, "%s: no vendor module is listed", goos)
		assert.NotEqual(t, -1, opensc, "%s: OpenSC is not listed", goos)
		assert.Less(t, vendor, opensc, "%s: the vendor module must be listed before OpenSC", goos)
	}
}

// isOpenscModule reports whether path refers to the OpenSC PKCS#11 module.
func isOpenscModule(path string) bool {
	return filepath.Base(path) == "opensc-pkcs11.so" || filepath.Base(path) == "opensc-pkcs11.dylib"
}

// TestModuleList checks how a PKCS#11 module setting is split into the paths it
// names.
func TestModuleList(t *testing.T) {
	assert.Empty(t, moduleList(""))
	assert.Empty(t, moduleList("  "))
	assert.Equal(t, []string{"/usr/lib/libykcs11.so"}, moduleList("/usr/lib/libykcs11.so"))

	joined := "/usr/lib/libykcs11.so" + string(os.PathListSeparator) + "/usr/lib/librtpkcs11ecp.so"
	assert.Equal(t, []string{"/usr/lib/libykcs11.so", "/usr/lib/librtpkcs11ecp.so"}, moduleList(joined))
}

// TestPKCS11ModulePaths checks the order of the sources of the module list: the
// environment variable, then the configuration file, then the modules that are
// installed.
func TestPKCS11ModulePaths(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(ConfigDirEnv, dir)
	t.Setenv(PKCS11ModuleEnv, "")

	// Without a configuration the installed modules are reported. A system
	// without an installed PKCS#11 module, such as a macOS CI runner, reports
	// none and an error instead.
	paths, err := PKCS11ModulePaths()
	if err != nil {
		assert.ErrorContains(t, err, "PKCS#11 module not found")
	} else {
		assert.NotEmpty(t, paths)
	}

	// A configuration file names the modules to use.
	configDir := filepath.Join(dir, configDirName)
	assert.NoError(t, os.MkdirAll(configDir, 0o700))
	configFile := filepath.Join(configDir, configFileName)
	assert.NoError(t, os.WriteFile(configFile, []byte("pkcs11-module /usr/lib/libykcs11.so\n"), 0o600))

	paths, err = PKCS11ModulePaths()
	assert.NoError(t, err)
	assert.Equal(t, []string{"/usr/lib/libykcs11.so"}, paths)

	// Several modules may be named in one setting.
	assert.NoError(t, os.WriteFile(configFile,
		[]byte("pkcs11-module "+"/usr/lib/libykcs11.so"+string(os.PathListSeparator)+"/usr/lib/librtpkcs11ecp.so"+"\n"), 0o600))
	paths, err = PKCS11ModulePaths()
	assert.NoError(t, err)
	assert.Equal(t, []string{"/usr/lib/libykcs11.so", "/usr/lib/librtpkcs11ecp.so"}, paths)

	// The environment variable takes precedence over the configuration file.
	t.Setenv(PKCS11ModuleEnv, "/usr/lib/libjcPKCS11.so")
	paths, err = PKCS11ModulePaths()
	assert.NoError(t, err)
	assert.Equal(t, []string{"/usr/lib/libjcPKCS11.so"}, paths)
}
