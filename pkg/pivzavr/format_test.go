package pivzavr

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// nilParamsCurve is an elliptic.Curve whose Params method returns nil, used to
// verify that CertKeyType handles curves without parameters gracefully.
type nilParamsCurve struct{}

func (nilParamsCurve) Params() *elliptic.CurveParams { return nil }
func (nilParamsCurve) IsOnCurve(x, y *big.Int) bool  { return false }
func (nilParamsCurve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	return nil, nil
}
func (nilParamsCurve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	return nil, nil
}
func (nilParamsCurve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	return nil, nil
}
func (nilParamsCurve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return nil, nil
}

func TestFormatCertificate(t *testing.T) {
	tok, err := testToken()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := generateKeyAndCertificate(tok, SlotSignature); err != nil {
		t.Fatal(err)
	}

	opts := &CertificateOpts{Slot: SlotSignature}
	output, err := Certificate(tok, opts)
	if err != nil {
		t.Fatal(err)
	}

	formatted := FormatCertificate(output)
	assert.Contains(t, formatted, "Slot:          9c (Digital Signature)")
	assert.Contains(t, formatted, "Fingerprint:   "+output.Fingerprint)
	assert.Contains(t, formatted, "Serial Number: "+fmt.Sprintf("%x", output.Certificate.SerialNumber))
	assert.Contains(t, formatted, "Key Type:      ECDSA NIST P-384")
	assert.Contains(t, formatted, "Not Before:    ")
	assert.Contains(t, formatted, "Not After:     ")
	assert.Contains(t, formatted, "Subject DN:    CN=pivzavr test")
	assert.Contains(t, formatted, "Issuer DN:     CN=pivzavr test")
	assert.True(t, strings.HasSuffix(formatted, output.CertificatePem+"\n"))
}

func TestFormatName(t *testing.T) {
	name := pkix.Name{
		CommonName: "pivzavr test",
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: "pivzavr@example.com"},
			{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "example"},
			{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}, Value: []byte("5.7.0")},
		},
	}

	formatted := formatName(name)
	assert.Contains(t, formatted, "CN=pivzavr test")
	assert.Contains(t, formatted, "emailAddress=pivzavr@example.com")
	assert.Contains(t, formatted, "DC=example")
	assert.Contains(t, formatted, "1.3.6.1.4.1.41482.3.3=5.7.0")
	assert.NotContains(t, formatted, "1.2.840.113549.1.9.1")
	assert.NotContains(t, formatted, "0.9.2342.19200300.100.1.25")
}

func TestFormatSlot(t *testing.T) {
	tok, err := testToken()
	if err != nil {
		t.Fatal(err)
	}

	cert, err := generateKeyAndCertificate(tok, SlotRetiredKeyManagement2)
	if err != nil {
		t.Fatal(err)
	}

	formatted := FormatSlot(SlotRetiredKeyManagement2, cert)
	assert.Contains(t, formatted, "Slot: 83 (Retired Key Management 2)")
	assert.Contains(t, formatted, "Fingerprint: "+CertHexFingerprint(cert))
	assert.Contains(t, formatted, "Key Type: "+CertKeyType(cert))
	assert.Contains(t, formatted, "Subject DN: CN=pivzavr test")
	assert.Contains(t, formatted, "Issuer DN: CN=pivzavr test")
	assert.Contains(t, formatted, "Not Before: "+formatTime(cert.NotBefore))
	assert.Contains(t, formatted, "Not After: "+formatTime(cert.NotAfter))
}

func TestFormatDeviceInfo(t *testing.T) {
	tok, err := testToken()
	if err != nil {
		t.Fatal(err)
	}

	first, err := generateKeyAndCertificate(tok, SlotAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	second, err := generateKeyAndCertificate(tok, SlotSignature)
	if err != nil {
		t.Fatal(err)
	}

	tok.chuid = "CHUIDVALUE"
	tok.ccc = "CCCVALUE"
	tok.pinRetries = 3
	tok.pukRetries = 2

	info, err := tok.Info()
	if err != nil {
		t.Fatal(err)
	}

	formatted := FormatDeviceInfo(info)
	assert.Contains(t, formatted, "Name:        pivzavr test")
	assert.Contains(t, formatted, "Firmware:    1.0")
	assert.Contains(t, formatted, "Serial:      00000000")
	assert.Contains(t, formatted, "CHUID:       CHUIDVALUE")
	assert.Contains(t, formatted, "CCC:         CCCVALUE")
	assert.Contains(t, formatted, "PIN Retries: 3")
	assert.Contains(t, formatted, "PUK Retries: 2")
	assert.NotContains(t, formatted, "Active Slots:")
	assert.Contains(t, formatted, "\n\n"+FormatSlot(SlotAuthentication, first))
	assert.Contains(t, formatted, FormatSlot(SlotSignature, second))
}

func TestFormatDeviceInfoNoSlots(t *testing.T) {
	info := &DeviceInfo{
		Name:       "pivzavr test",
		PinRetries: RetriesUnknown,
		PukRetries: RetriesUnknown,
	}

	formatted := FormatDeviceInfo(info)
	assert.Contains(t, formatted, "Name:        pivzavr test")
	assert.Contains(t, formatted, "CHUID:       (unavailable)")
	assert.Contains(t, formatted, "CCC:         (unavailable)")
	assert.Contains(t, formatted, "PIN Retries: (unavailable)")
	assert.Contains(t, formatted, "PUK Retries: (unavailable)")
	assert.NotContains(t, formatted, "Active Slots:")
	assert.True(t, strings.HasSuffix(formatted, "PUK Retries: (unavailable)\n"))
}

func TestCertKeyType(t *testing.T) {
	testCases := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{
			name: "RSA 2048",
			cert: &x509.Certificate{PublicKey: &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047)}},
			want: "RSA 2048",
		},
		{
			name: "ECDSA P-224",
			cert: &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: elliptic.P224()}},
			want: "ECDSA NIST P-224",
		},
		{
			name: "ECDSA P-256",
			cert: &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: elliptic.P256()}},
			want: "ECDSA NIST P-256",
		},
		{
			name: "ECDSA P-384",
			cert: &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: elliptic.P384()}},
			want: "ECDSA NIST P-384",
		},
		{
			name: "ECDSA P-521",
			cert: &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: elliptic.P521()}},
			want: "ECDSA NIST P-521",
		},
		{
			name: "ECDSA SECG secp256r1",
			cert: &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: &elliptic.CurveParams{Name: "secp256r1"}}},
			want: "ECDSA SECG secp256r1",
		},
		{
			name: "ECDSA SECG secp256k1",
			cert: &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: &elliptic.CurveParams{Name: "secp256k1"}}},
			want: "ECDSA SECG secp256k1",
		},
		{
			name: "ECDSA SECG sect283k1",
			cert: &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: &elliptic.CurveParams{Name: "sect283k1"}}},
			want: "ECDSA SECG sect283k1",
		},
		{
			name: "ECDSA Brainpool brainpoolP256r1",
			cert: &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: &elliptic.CurveParams{Name: "brainpoolP256r1"}}},
			want: "ECDSA Brainpool brainpoolP256r1",
		},
		{
			name: "ECDSA Brainpool brainpoolP384r1",
			cert: &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: &elliptic.CurveParams{Name: "brainpoolP384r1"}}},
			want: "ECDSA Brainpool brainpoolP384r1",
		},
		{
			name: "ECDSA Brainpool brainpoolP512r1",
			cert: &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: &elliptic.CurveParams{Name: "brainpoolP512r1"}}},
			want: "ECDSA Brainpool brainpoolP512r1",
		},
		{
			name: "ECDSA unknown curve name",
			cert: &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: &elliptic.CurveParams{Name: "prime256v1"}}},
			want: "ECDSA prime256v1",
		},
		{
			name: "ECDSA with nil curve params",
			cert: &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: nilParamsCurve{}}},
			want: "ECDSA",
		},
		{
			name: "ECDSA without curve",
			cert: &x509.Certificate{PublicKey: &ecdsa.PublicKey{}},
			want: "ECDSA",
		},
		{
			name: "Ed25519",
			cert: &x509.Certificate{PublicKey: ed25519.PublicKey{1, 2, 3}},
			want: "Ed25519",
		},
		{
			name: "RSA fallback",
			cert: &x509.Certificate{PublicKeyAlgorithm: x509.RSA},
			want: "RSA",
		},
		{
			name: "ECDSA fallback",
			cert: &x509.Certificate{PublicKeyAlgorithm: x509.ECDSA},
			want: "ECDSA",
		},
		{
			name: "DSA fallback",
			cert: &x509.Certificate{PublicKeyAlgorithm: x509.DSA},
			want: "DSA",
		},
		{
			name: "Ed25519 fallback",
			cert: &x509.Certificate{PublicKeyAlgorithm: x509.Ed25519},
			want: "Ed25519",
		},
		{
			name: "unknown",
			cert: &x509.Certificate{},
			want: "Unknown",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, CertKeyType(tc.cert))
		})
	}
}

func TestEscapeNameValue(t *testing.T) {
	testCases := []struct {
		name  string
		value string
		want  string
	}{
		{name: "empty", value: "", want: ""},
		{name: "plain", value: "simple", want: "simple"},
		{name: "comma", value: "a,b", want: `a\,b`},
		{name: "plus", value: "a+b", want: `a\+b`},
		{name: "quote", value: `a"b`, want: `a\"b`},
		{name: "backslash", value: `a\b`, want: `a\\b`},
		{name: "angle brackets", value: "a<b>c", want: `a\<b\>c`},
		{name: "semicolon", value: "a;b", want: `a\;b`},
		{name: "leading space", value: " a", want: `\ a`},
		{name: "trailing space", value: "a ", want: `a\ `},
		{name: "internal space", value: "a b", want: "a b"},
		{name: "leading hash", value: "#a", want: `\#a`},
		{name: "internal hash", value: "a#b", want: "a#b"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, escapeNameValue(tc.value))
		})
	}
}

func TestAttributeValue(t *testing.T) {
	testCases := []struct {
		name  string
		value any
		want  string
	}{
		{name: "string", value: "hello", want: "hello"},
		{name: "utf8 bytes", value: []byte("hello"), want: "hello"},
		{name: "non-utf8 bytes", value: []byte{0xff, 0xfe}, want: "#fffe"},
		{name: "non-string fallback", value: 123, want: "123"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, attributeValue(tc.value))
		})
	}
}
