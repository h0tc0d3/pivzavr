package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCandidateModulePaths(t *testing.T) {
	linuxAMD64 := candidateModulePaths("linux", "amd64")
	require.NotEmpty(t, linuxAMD64)
	assert.Equal(t, "/usr/lib/x86_64-linux-gnu/libykcs11.so", linuxAMD64[0])
	assert.Contains(t, linuxAMD64, "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so")
	assert.Contains(t, linuxAMD64, "/usr/lib64/libykcs11.so")
	assert.Contains(t, linuxAMD64, "/usr/local/lib/opensc-pkcs11.so")

	linuxUnknownArch := candidateModulePaths("linux", "riscv64")
	require.NotEmpty(t, linuxUnknownArch)
	assert.Equal(t, "/usr/lib64/libykcs11.so", linuxUnknownArch[0])

	darwin := candidateModulePaths("darwin", "arm64")
	require.NotEmpty(t, darwin)
	assert.Equal(t, "/opt/homebrew/lib/libykcs11.dylib", darwin[0])

	freebsd := candidateModulePaths("freebsd", "amd64")
	require.NotEmpty(t, freebsd)
	assert.Equal(t, "/usr/local/lib/libykcs11.so", freebsd[0])

	windows := candidateModulePaths("windows", "amd64")
	require.NotEmpty(t, windows)
	assert.Equal(t, "libykcs11.so", windows[0])
}

func TestIsYkcs11Module(t *testing.T) {
	assert.True(t, IsYkcs11Module("/usr/lib/x86_64-linux-gnu/libykcs11.so"))
	assert.True(t, IsYkcs11Module("/usr/lib64/libykcs11.so"))
	assert.True(t, IsYkcs11Module("/opt/homebrew/lib/libykcs11.dylib"))
	assert.True(t, IsYkcs11Module("libykcs11.so"))
	assert.False(t, IsYkcs11Module("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"))
	assert.False(t, IsYkcs11Module("/usr/lib/opensc-pkcs11.so"))
}

func TestFirstExistingModule(t *testing.T) {
	dir := t.TempDir()
	yk := filepath.Join(dir, "libykcs11.so")
	opensc := filepath.Join(dir, "opensc-pkcs11.so")
	require.NoError(t, os.WriteFile(yk, []byte("ykcs11"), 0o600))
	require.NoError(t, os.WriteFile(opensc, []byte("opensc"), 0o600))

	path, ok := firstExistingModule([]string{yk, opensc}, false)
	require.True(t, ok)
	assert.Equal(t, opensc, path)

	path, ok = firstExistingModule([]string{yk, opensc}, true)
	require.True(t, ok)
	assert.Equal(t, yk, path)

	path, ok = firstExistingModule([]string{filepath.Join(dir, "missing.so"), opensc}, false)
	require.True(t, ok)
	assert.Equal(t, opensc, path)

	_, ok = firstExistingModule(nil, true)
	assert.False(t, ok)
}

func TestSysfsVendorPresent(t *testing.T) {
	relDir := filepath.Join("bus", "usb", "devices")

	root := t.TempDir()
	device := filepath.Join(root, relDir, "1-1")
	require.NoError(t, os.MkdirAll(device, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(device, "idVendor"), []byte("1050\n"), 0o600))

	assert.True(t, sysfsVendorPresent(root, relDir, "1050"))
	assert.False(t, sysfsVendorPresent(root, relDir, "1234"))
	assert.False(t, sysfsVendorPresent(filepath.Join(root, "missing"), relDir, "1050"))

	// sysfs exposes each USB device under /sys/bus/usb/devices as a symlink
	// that resolves inside /sys, so the vendor scan must follow those links.
	symlinkRoot := t.TempDir()
	devicesDir := filepath.Join(symlinkRoot, relDir)
	targetDir := filepath.Join(symlinkRoot, "devices", "usb1", "1-1")
	require.NoError(t, os.MkdirAll(devicesDir, 0o700))
	require.NoError(t, os.MkdirAll(targetDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(targetDir, "idVendor"), []byte("1050\n"), 0o600))
	require.NoError(t, os.Symlink(
		filepath.Join("..", "..", "..", "devices", "usb1", "1-1"),
		filepath.Join(devicesDir, "1-1"),
	))

	assert.True(t, sysfsVendorPresent(symlinkRoot, relDir, "1050"))
}
