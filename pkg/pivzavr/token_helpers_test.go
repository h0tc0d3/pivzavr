package pivzavr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
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
	assert.True(t, isYkcs11Module("/usr/lib/x86_64-linux-gnu/libykcs11.so"))
	assert.True(t, isYkcs11Module("/usr/lib64/libykcs11.so"))
	assert.True(t, isYkcs11Module("/opt/homebrew/lib/libykcs11.dylib"))
	assert.True(t, isYkcs11Module("libykcs11.so"))
	assert.False(t, isYkcs11Module("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"))
	assert.False(t, isYkcs11Module("/usr/lib/opensc-pkcs11.so"))
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

func TestEncodeECDSASignature(t *testing.T) {
	sig, err := encodeECDSASignature([]byte{0x01, 0x02})
	require.NoError(t, err)

	var parsed struct {
		R, S *big.Int
	}
	_, err = asn1.Unmarshal(sig, &parsed)
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(1), parsed.R)
	assert.Equal(t, big.NewInt(2), parsed.S)

	_, err = encodeECDSASignature([]byte{0x01, 0x02, 0x03})
	assert.Error(t, err)

	_, err = encodeECDSASignature(nil)
	assert.Error(t, err)
}

func TestPkcs1DigestInfo(t *testing.T) {
	digest := []byte("digest")

	testCases := []struct {
		name string
		hash crypto.Hash
		oid  asn1.ObjectIdentifier
	}{
		{"sha1", crypto.SHA1, asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}},
		{"sha224", crypto.SHA224, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}},
		{"sha256", crypto.SHA256, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}},
		{"sha384", crypto.SHA384, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}},
		{"sha512", crypto.SHA512, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			der, err := pkcs1DigestInfo(tc.hash, digest)
			require.NoError(t, err)

			var info struct {
				Algorithm pkix.AlgorithmIdentifier
				Digest    []byte
			}
			_, err = asn1.Unmarshal(der, &info)
			require.NoError(t, err)
			assert.Equal(t, tc.oid, info.Algorithm.Algorithm)
			assert.Equal(t, digest, info.Digest)
		})
	}

	_, err := pkcs1DigestInfo(crypto.MD5, digest)
	assert.Error(t, err)
}

func TestPkcs11SignerPublic(t *testing.T) {
	pub := &ecdsa.PublicKey{}
	signer := &pkcs11Signer{pub: pub}

	assert.Same(t, pub, signer.Public())
}
