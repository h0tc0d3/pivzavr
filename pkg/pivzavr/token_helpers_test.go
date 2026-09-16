package pivzavr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
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
