package pivzavr

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
		userId       string
		timestampUrl string
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
			userId:      fingerprint,
			slot:        SlotCardAuthentication,
		},
		{
			description: "with armor",
			armor:       true,
			userId:      fingerprint,
			slot:        SlotCardAuthentication,
		},
		{
			description: "detached signature",
			detach:      true,
			userId:      fingerprint,
			slot:        SlotCardAuthentication,
		},
		{
			description:  "with timestamp server",
			userId:       fingerprint,
			timestampUrl: "http://timestamp.digicert.com",
			slot:         SlotCardAuthentication,
			skipCI:       true,
		},
		{
			description:  "bad timestamp server",
			userId:       fingerprint,
			timestampUrl: "http://127.0.0.1",
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
				UserId:             test.userId,
				TimestampAuthority: test.timestampUrl,
				Message:            &bytes.Buffer{},
				Slot:               test.slot,
				Prompt:             nil,
			}
			sig, err := Sign(tok, signOpts)
			if test.expectError {
				assert.Error(t, err)
				assert.Nil(t, sig)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, sig)
				if test.armor {
					block, _ := pem.Decode(sig)
					assert.Equal(t, "SIGNED MESSAGE", block.Type)
				}
			}
		})
	}
}

func TestNormalizeEmail(t *testing.T) {
	testCases := []struct {
		description string
		userId      string
		expected    string
		expectError bool
	}{
		{
			description: "bare email address",
			userId:      "user@example.com",
			expected:    "user@example.com",
		},
		{
			description: "name and email in angle brackets",
			userId:      "Full Name <user@example.com>",
			expected:    "user@example.com",
		},
		{
			description: "hex fingerprint",
			userId:      "0xDEADBEEF",
			expectError: true,
		},
		{
			description: "missing closing angle bracket",
			userId:      "Full Name <user@example.com",
			expectError: true,
		},
		{
			description: "empty angle brackets",
			userId:      "<>",
			expectError: true,
		},
	}
	for _, test := range testCases {
		t.Run(test.description, func(t *testing.T) {
			email, err := normalizeEmail(test.userId)
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

func TestCertificateContainsUserId(t *testing.T) {
	tok, err := testToken()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := generateKeyAndCertificate(tok, SlotCardAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := CertHexFingerprint(cert)

	assert.NoError(t, certificateContainsUserId(cert, fingerprint))
	assert.NoError(t, certificateContainsUserId(cert, "0x"+fingerprint))
	assert.Error(t, certificateContainsUserId(cert, strings.Repeat("0", 40)))

	emailCert := &x509.Certificate{EmailAddresses: []string{"user@example.com"}}
	assert.NoError(t, certificateContainsUserId(emailCert, "user@example.com"))
	assert.NoError(t, certificateContainsUserId(emailCert, "Full Name <user@example.com>"))
	assert.Error(t, certificateContainsUserId(emailCert, "other@example.com"))

	dnEmailCert := &x509.Certificate{
		Subject: pkix.Name{Names: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: "dn@example.com"},
		}},
	}
	assert.NoError(t, certificateContainsUserId(dnEmailCert, "dn@example.com"))
	assert.Error(t, certificateContainsUserId(dnEmailCert, "other@example.com"))
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
	assert.True(t, certificateContainsEmail(issuerEmail, "issuer@example.com"))
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
		UserId:   CertHexFingerprint(cert),
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
		UserId:   CertHexFingerprint(cert),
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
