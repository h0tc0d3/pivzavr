package pivzavr

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestEncodeECDSASignatureDerPassthrough(t *testing.T) {
	// Some PKCS#11 modules (e.g. the YubiKey module) return the ECDSA
	// signature already DER encoded. Such a signature must not be encoded a
	// second time, otherwise its integers are wrapped in another SEQUENCE and
	// the signature no longer verifies.
	der, err := asn1.Marshal(struct{ R, S *big.Int }{
		R: new(big.Int).SetBytes([]byte{
			0x00, 0xc6, 0x79, 0xf8, 0xdc, 0x0f, 0x85, 0x32, 0x04, 0x47, 0xd3, 0x1a,
			0x80, 0x3f, 0x63, 0x2d, 0xb1, 0xa2, 0x89, 0x48, 0x5c, 0xd8, 0xb3, 0x83,
			0xb2, 0xb3, 0x88, 0xeb, 0xc0, 0xfc, 0x7e, 0xeb, 0x09, 0x08, 0xd3, 0x86,
			0xe3, 0xf3, 0xe3, 0x30, 0xdd, 0x4b, 0x1b, 0x3c, 0x33, 0xed, 0x8f, 0x39,
			0x45,
		}),
		S: new(big.Int).SetBytes([]byte{
			0x00, 0xb2, 0xcd, 0xdd, 0xd4, 0x77, 0x73, 0x91, 0xb6, 0xc7, 0x0a, 0x5f,
			0x32, 0xb7, 0x51, 0xb7, 0x1c, 0x8f, 0x86, 0x75, 0xa4, 0xb6, 0x63, 0xdb,
			0x20, 0x26, 0x5a, 0x0a, 0xbb, 0x99, 0xe6, 0xa9, 0x19, 0xa9, 0x5a, 0xd5,
			0xfb, 0x49, 0xec, 0x5d, 0x79, 0x1b, 0x3a, 0xae, 0x5b, 0xe8, 0x3a, 0xb3,
			0x69,
		}),
	})
	require.NoError(t, err)

	encoded, err := encodeECDSASignature(der)
	require.NoError(t, err)
	assert.Equal(t, der, encoded)

	// A DER signature that carries trailing data is not a valid signature and
	// must still be rejected rather than passed through.
	_, err = encodeECDSASignature(append(append([]byte{}, der...), 0x00, 0x00, 0x00))
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

func TestPkcs1v15Pad(t *testing.T) {
	info := []byte("digest-info")

	padded, err := pkcs1v15Pad(info, 128)
	require.NoError(t, err)
	require.Len(t, padded, 128)
	assert.Equal(t, []byte{0x00, 0x01}, padded[:2])
	assert.Equal(t, bytes.Repeat([]byte{0xFF}, 128-len(info)-3), padded[2:128-len(info)-1])
	assert.Equal(t, byte(0x00), padded[128-len(info)-1])
	assert.Equal(t, info, padded[128-len(info):])

	// A DigestInfo that leaves only the 0x00, 0x01 prefix and the separator
	// before it is still padded.
	exact, err := pkcs1v15Pad(bytes.Repeat([]byte{0x01}, 117), 128)
	require.NoError(t, err)
	assert.Equal(t, bytes.Repeat([]byte{0xFF}, 8), exact[2:10])

	// A DigestInfo that does not leave room for the padding block is refused.
	_, err = pkcs1v15Pad(bytes.Repeat([]byte{0x01}, 118), 128)
	assert.ErrorContains(t, err, "does not fit into a 128 byte RSA signature")
}

func TestNormalizeCHUID(t *testing.T) {
	// The YubiKey PKCS#11 module returns the CHUID as the card stores it,
	// without the TLV that a PIV data object is returned in.
	raw := mustHex(t, "3019D4E739DA739CED39CE739D836858210842108421C84210C3EB3410807EF3230BD740369D93A63377564EC3350832303330303130313E00FE00")
	assert.Equal(t, raw, normalizeCHUID(raw))

	// OpenSC returns the same value wrapped in the 53 data object TLV, which
	// has to be removed for the two modules to agree on one identifier.
	wrapped := append([]byte{0x53, byte(len(raw))}, raw...)
	assert.Equal(t, raw, normalizeCHUID(wrapped))

	// A value that is not wrapped is handed back unchanged.
	plain := []byte("not a data object")
	assert.Equal(t, plain, normalizeCHUID(plain))
}

func TestTokenKey(t *testing.T) {
	// The module of a card's vendor and OpenSC see the same card but report
	// different serial numbers and CHUID wrapping. Both have to yield one
	// key, so that the card is not reported twice when both modules are
	// loaded.
	raw := mustHex(t, "3019D4E739DA739CED39CE739D836858210842108421C84210C3EB3410807EF3230BD740369D93A63377564EC3350832303330303130313E00FE00")
	wrapped := append([]byte{0x53, byte(len(raw))}, raw...)

	yubikey := tokenKey(raw, true, "32898787")
	opensc := tokenKey(wrapped, true, "9d93a63377564ec3")
	assert.Equal(t, yubikey, opensc)

	// A card whose CHUID is not exposed through PKCS#11 is identified by its
	// serial number, and a card that exposes neither yields no key.
	assert.Equal(t, "serial:32898787", tokenKey(nil, false, "32898787"))
	assert.Equal(t, "", tokenKey(nil, false, ""))
}
