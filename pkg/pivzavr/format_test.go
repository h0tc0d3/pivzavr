package pivzavr

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
	assert.Contains(t, formatted, "Serial Number: "+output.Certificate.SerialNumber.String())
	assert.Contains(t, formatted, "Key Type:      ECDSA P-384")
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
	assert.Contains(t, formatted, "Subject: CN=pivzavr test")
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
			name: "ECDSA P-256",
			cert: &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: elliptic.P256()}},
			want: "ECDSA P-256",
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
