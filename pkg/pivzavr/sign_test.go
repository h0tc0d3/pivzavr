package pivzavr

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	tok, err := testToken()
	if err != nil {
		t.Fatal(err)
	}

	cert, err := generateKeyAndCertificate(tok, SlotCardAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := CertHexFingerprint(cert)

	testCases := []struct {
		description  string
		armor        bool
		detach       bool
		clearsign    bool
		userID       string
		timestampURL string
		slot         Slot
		expectError  bool
		skipCI       bool
	}{
		{
			description: "no certificate found",
			slot:        SlotSignature,
			expectError: true,
		},
		{
			description: "bad fingerprint",
			slot:        SlotCardAuthentication,
			expectError: true,
		},
		{
			description: "default options",
			userID:      fingerprint,
			slot:        SlotCardAuthentication,
		},
		{
			description: "with armor",
			armor:       true,
			userID:      fingerprint,
			slot:        SlotCardAuthentication,
		},
		{
			description: "detached signature",
			detach:      true,
			userID:      fingerprint,
			slot:        SlotCardAuthentication,
		},
		{
			description: "clear text signature",
			clearsign:   true,
			userID:      fingerprint,
			slot:        SlotCardAuthentication,
		},
		{
			description:  "with timestamp server",
			userID:       fingerprint,
			timestampURL: "http://timestamp.digicert.com",
			slot:         SlotCardAuthentication,
			skipCI:       true,
		},
		{
			description:  "bad timestamp server",
			userID:       fingerprint,
			timestampURL: "http://127.0.0.1",
			slot:         SlotCardAuthentication,
			expectError:  true,
		},
	}
	for _, test := range testCases {
		t.Run(test.description, func(t *testing.T) {
			if test.skipCI {
				skipCI(t)
			}

			signOpts := &SignOpts{
				StatusFd:           0,
				Detach:             test.detach,
				Armor:              test.armor,
				Clearsign:          test.clearsign,
				UserID:             test.userID,
				TimestampAuthority: test.timestampURL,
				Message:            &bytes.Buffer{},
				Slot:               test.slot,
			}
			sig, err := Sign(tok, signOpts)
			if test.expectError {
				assert.Error(t, err)
				assert.Nil(t, sig)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, sig)
				if test.armor || test.clearsign {
					block, _ := pem.Decode(sig)
					require.NotNil(t, block)
					assert.Equal(t, pkcs7PemHeader, block.Type)
				}
			}
		})
	}
}

// TestIsSignaturePemHeader checks the PEM labels that VerifySignature accepts.
func TestIsSignaturePemHeader(t *testing.T) {
	// The armor of pivzavr is a PKCS#7 block; the label OpenSSL's cms command
	// writes and the label pivzavr used before the change are accepted as well.
	assert.True(t, isSignaturePemHeader(pkcs7PemHeader))
	assert.True(t, isSignaturePemHeader(cmsPemHeader))
	assert.True(t, isSignaturePemHeader(signedMessagePemHeader))

	assert.False(t, isSignaturePemHeader("CERTIFICATE"))
	assert.False(t, isSignaturePemHeader(""))
}

// TestSignatureType checks that the SIG_CREATED type names the kind of signature
// an invocation makes, so that a clear text signature is reported as one.
func TestSignatureType(t *testing.T) {
	testCases := []struct {
		description string
		opts        *SignOpts
		expected    string
	}{
		{description: "attached signature", opts: &SignOpts{}, expected: "S"},
		{description: "detached signature", opts: &SignOpts{Detach: true}, expected: "D"},
		{description: "clear text signature", opts: &SignOpts{Clearsign: true}, expected: "C"},
		{description: "clear text signature wins over detach", opts: &SignOpts{Detach: true, Clearsign: true}, expected: "C"},
	}
	for _, test := range testCases {
		t.Run(test.description, func(t *testing.T) {
			assert.Equal(t, test.expected, signatureType(test.opts))
		})
	}
}

// TestClearTextSignatureRoundTrip checks that the message of a clear text
// signature is recovered byte for byte, whatever the message ends with, so that
// a signature that was made over the message verifies against the file.
func TestClearTextSignatureRoundTrip(t *testing.T) {
	armored := []byte("-----BEGIN PKCS7-----\nsig\n-----END PKCS7-----\n")

	testCases := []struct {
		description string
		message     string
	}{
		{description: "message without trailing newline", message: "hello"},
		{description: "message with trailing newline", message: "hello\n"},
		{description: "empty message", message: ""},
		{description: "multi line message", message: "one\ntwo\ntwo and a half\n"},
		{description: "message with blank lines", message: "one\n\n\ntwo\n"},
	}

	for _, test := range testCases {
		t.Run(test.description, func(t *testing.T) {
			signed := clearTextSignature([]byte(test.message), armored)

			// The message is written verbatim, followed by a blank line and
			// the armored signature.
			assert.True(t, bytes.HasPrefix(signed, []byte(test.message+clearTextSignatureSeparator)))
			assert.True(t, bytes.HasSuffix(signed, armored))

			message, ok := splitClearTextSignature(signed)
			require.True(t, ok)
			assert.Equal(t, test.message, string(message))
		})
	}
}

// TestSplitClearTextSignature checks that a signature without a message in
// front of it is not taken for a clear text signature.
func TestSplitClearTextSignature(t *testing.T) {
	_, ok := splitClearTextSignature([]byte("-----BEGIN PKCS7-----\nsig\n-----END PKCS7-----\n"))
	assert.False(t, ok)

	_, ok = splitClearTextSignature([]byte("plain message"))
	assert.False(t, ok)

	// A signature whose message is attached holds the block right behind the
	// message, without a blank line, so it is not a clear text signature
	// either.
	_, ok = splitClearTextSignature([]byte("message\n-----BEGIN PKCS7-----\nsig\n-----END PKCS7-----\n"))
	assert.False(t, ok)
}

func TestNormalizeEmail(t *testing.T) {
	testCases := []struct {
		description string
		userID      string
		expected    string
		expectError bool
	}{
		{
			description: "bare email address",
			userID:      "user@example.com",
			expected:    "user@example.com",
		},
		{
			description: "name and email in angle brackets",
			userID:      "Full Name <user@example.com>",
			expected:    "user@example.com",
		},
		{
			description: "hex fingerprint",
			userID:      "0xDEADBEEF",
			expectError: true,
		},
		{
			description: "missing closing angle bracket",
			userID:      "Full Name <user@example.com",
			expectError: true,
		},
		{
			description: "empty angle brackets",
			userID:      "<>",
			expectError: true,
		},
	}
	for _, test := range testCases {
		t.Run(test.description, func(t *testing.T) {
			email, err := normalizeEmail(test.userID)
			if test.expectError {
				assert.Error(t, err)
				assert.Empty(t, email)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, email)
			}
		})
	}
}

func TestCertificateContainsUserID(t *testing.T) {
	tok, err := testToken()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := generateKeyAndCertificate(tok, SlotCardAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := CertHexFingerprint(cert)

	assert.NoError(t, certificateContainsUserID(cert, fingerprint))
	assert.NoError(t, certificateContainsUserID(cert, "0x"+fingerprint))
	assert.Error(t, certificateContainsUserID(cert, strings.Repeat("0", 40)))

	emailCert := &x509.Certificate{EmailAddresses: []string{"user@example.com"}}
	assert.NoError(t, certificateContainsUserID(emailCert, "user@example.com"))
	assert.NoError(t, certificateContainsUserID(emailCert, "Full Name <user@example.com>"))
	assert.Error(t, certificateContainsUserID(emailCert, "other@example.com"))

	dnEmailCert := &x509.Certificate{
		Subject: pkix.Name{Names: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: "dn@example.com"},
		}},
	}
	assert.NoError(t, certificateContainsUserID(dnEmailCert, "dn@example.com"))
	assert.Error(t, certificateContainsUserID(dnEmailCert, "other@example.com"))

	// An address in the Issuer DN belongs to the issuer and, unlike an address
	// in the Subject DN, must not select the certificate.
	issuerEmailCert := &x509.Certificate{
		Issuer: pkix.Name{Names: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: "issuer@example.com"},
		}},
	}
	assert.Error(t, certificateContainsUserID(issuerEmailCert, "issuer@example.com"))
}

func TestCertificateContainsEmail(t *testing.T) {
	emailOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	mailOID := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 3}

	cert := &x509.Certificate{EmailAddresses: []string{"User@Example.com"}}

	assert.True(t, certificateContainsEmail(cert, "user@example.com"))
	assert.True(t, certificateContainsEmail(cert, "USER@EXAMPLE.COM"))
	assert.False(t, certificateContainsEmail(cert, "other@example.com"))
	assert.False(t, certificateContainsEmail(&x509.Certificate{}, "user@example.com"))

	subjectEmail := &x509.Certificate{
		Subject: pkix.Name{Names: []pkix.AttributeTypeAndValue{
			{Type: emailOID, Value: "subject@example.com"},
		}},
	}
	assert.True(t, certificateContainsEmail(subjectEmail, "SUBJECT@example.com"))
	assert.False(t, certificateContainsEmail(subjectEmail, "other@example.com"))

	issuerEmail := &x509.Certificate{
		Issuer: pkix.Name{Names: []pkix.AttributeTypeAndValue{
			{Type: emailOID, Value: "issuer@example.com"},
		}},
	}
	// The issuer is a different party, so an address that only the issuer
	// carries does not identify the subject.
	assert.False(t, certificateContainsEmail(issuerEmail, "issuer@example.com"))
	assert.False(t, certificateContainsEmail(issuerEmail, "other@example.com"))

	extraNamesEmail := &x509.Certificate{
		Subject: pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: emailOID, Value: []byte("extra@example.com")},
		}},
	}
	assert.True(t, certificateContainsEmail(extraNamesEmail, "extra@example.com"))

	mailEmail := &x509.Certificate{
		Subject: pkix.Name{Names: []pkix.AttributeTypeAndValue{
			{Type: mailOID, Value: "mail@example.com"},
		}},
	}
	assert.True(t, certificateContainsEmail(mailEmail, "mail@example.com"))
}

// selfSignedCAWithEmail returns a self-signed CA certificate whose Subject DN
// carries email, together with the key that signed it.
func selfSignedCAWithEmail(t *testing.T, email string) (*x509.Certificate, crypto.Signer) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "pivzavr test CA",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: email},
			},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// TestCertificateContainsEmail_issuerIgnored verifies with real, parsed
// certificates that the Subject DN is searched while the Issuer DN is ignored.
// The leaf below is issued by a CA that carries an email address in its Subject
// DN, so the same address also appears in the leaf's Issuer DN.
func TestCertificateContainsEmail_issuerIgnored(t *testing.T) {
	ca, caKey := selfSignedCAWithEmail(t, "ca@example.com")

	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "pivzavr test leaf",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: "leaf@example.com"},
			},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, leafKey.Public(), caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	// The CA email is carried by the leaf's Issuer DN ...
	require.True(t, nameContainsEmail(leaf.Issuer, "ca@example.com"))
	// ... but the issuer is not the subject, so -u must not select the leaf.
	assert.False(t, certificateContainsEmail(leaf, "ca@example.com"))
	assert.Error(t, certificateContainsUserID(leaf, "ca@example.com"))

	// The leaf's own Subject DN is searched.
	assert.True(t, certificateContainsEmail(leaf, "leaf@example.com"))
	assert.NoError(t, certificateContainsUserID(leaf, "leaf@example.com"))
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("boom")
}

func TestSign_readMessageError(t *testing.T) {
	tok, err := testToken()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := generateKeyAndCertificate(tok, SlotCardAuthentication)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Sign(tok, &SignOpts{
		StatusFd: 0,
		UserID:   CertHexFingerprint(cert),
		Message:  errReader{},
		Slot:     SlotCardAuthentication,
	})
	assert.Error(t, err)
}

func TestSign_signerError(t *testing.T) {
	tok, err := testToken()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := generateKeyAndCertificate(tok, SlotCardAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	tok.slots[SlotCardAuthentication] = &slotContent{cert: cert}

	_, err = Sign(tok, &SignOpts{
		StatusFd: 0,
		UserID:   CertHexFingerprint(cert),
		Message:  &bytes.Buffer{},
		Slot:     SlotCardAuthentication,
	})
	assert.Error(t, err)
}

// skipCI skips a test if we can determine the environment we're running in is a NixOS sandbox
// it's used to skip tests that use networking for example
func skipCI(t *testing.T) {
	if os.Getenv("NIX_ENFORCE_PURITY") != "" {
		t.Skip("Skipping test in CI environment")
	}
}
