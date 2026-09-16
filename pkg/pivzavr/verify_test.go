package pivzavr

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifySignature(t *testing.T) {
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
		name    string
		detach  bool
		armor   bool
		message io.Reader
	}{
		{
			name:    "detached, not armored",
			detach:  true,
			armor:   false,
			message: &bytes.Buffer{},
		},
		{
			name:    "attached, not armored",
			detach:  false,
			armor:   false,
			message: &bytes.Buffer{},
		},
		{
			name:    "detached and armored",
			detach:  true,
			armor:   true,
			message: &bytes.Buffer{},
		},
		{
			name:    "attached and armored",
			detach:  false,
			armor:   true,
			message: &bytes.Buffer{},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			sig, err := Sign(tok, &SignOpts{
				StatusFd:           0,
				Detach:             test.detach,
				Armor:              test.armor,
				UserId:             fingerprint,
				TimestampAuthority: "",
				Message:            test.message,
				Slot:               SlotCardAuthentication,
			})
			if err != nil {
				t.Fatal(err)
			}

			var message io.Reader
			if test.detach {
				message = test.message
			} else {
				message = nil
			}
			err = VerifySignature(tok, &VerifyOpts{
				Signature: bytes.NewReader(sig),
				Message:   message,
				Slot:      SlotCardAuthentication,
			})
			assert.NoError(t, err)
		})
	}

	t.Run("attached with message parameter", func(t *testing.T) {
		sig, err := Sign(tok, &SignOpts{
			StatusFd:           0,
			Detach:             false,
			Armor:              false,
			UserId:             fingerprint,
			TimestampAuthority: "",
			Message:            &bytes.Buffer{},
			Slot:               SlotCardAuthentication,
		})
		if err != nil {
			t.Fatal(err)
		}
		err = VerifySignature(tok, &VerifyOpts{
			Signature: bytes.NewReader(sig),
			Message:   &bytes.Buffer{},
			Slot:      SlotCardAuthentication,
		})
		assert.NoError(t, err)
	})

	t.Run("attached with untrusted signer", func(t *testing.T) {
		tok, err := testToken()
		if err != nil {
			t.Fatal(err)
		}
		cert, err := generateKeyAndCertificate(tok, SlotCardAuthentication)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint := CertHexFingerprint(cert)

		sig, err := Sign(tok, &SignOpts{
			StatusFd:           0,
			Detach:             false,
			Armor:              false,
			UserId:             fingerprint,
			TimestampAuthority: "",
			Message:            &bytes.Buffer{},
			Slot:               SlotCardAuthentication,
		})
		if err != nil {
			t.Fatal(err)
		}

		// Replace the certificate with a different one so the signer is no
		// longer trusted when the attached signature is verified.
		if _, err := generateKeyAndCertificate(tok, SlotCardAuthentication); err != nil {
			t.Fatal(err)
		}

		err = VerifySignature(tok, &VerifyOpts{
			Signature: bytes.NewReader(sig),
			Slot:      SlotCardAuthentication,
		})
		assert.Error(t, err)
	})

	t.Run("unexpected PEM header", func(t *testing.T) {
		sig, err := Sign(tok, &SignOpts{
			StatusFd:           0,
			Detach:             false,
			Armor:              true,
			UserId:             fingerprint,
			TimestampAuthority: "",
			Message:            &bytes.Buffer{},
			Slot:               SlotCardAuthentication,
		})
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(sig)
		sig = pem.EncodeToMemory(&pem.Block{
			Type:  "UNEXPECTED",
			Bytes: block.Bytes,
		})
		err = VerifySignature(tok, &VerifyOpts{
			Signature: bytes.NewReader(sig),
			Message:   &bytes.Buffer{},
			Slot:      SlotCardAuthentication,
		})
		assert.Error(t, err)
	})

	t.Run("bad detach signature", func(t *testing.T) {
		sig, err := Sign(tok, &SignOpts{
			StatusFd:           0,
			Detach:             true,
			Armor:              false,
			UserId:             fingerprint,
			TimestampAuthority: "",
			Message:            &bytes.Buffer{},
			Slot:               SlotCardAuthentication,
		})
		if err != nil {
			t.Fatal(err)
		}
		err = VerifySignature(tok, &VerifyOpts{
			Signature: bytes.NewReader(sig),
			Message:   bytes.NewReader([]byte("not the same signed message")),
			Slot:      SlotCardAuthentication,
		})
		assert.Error(t, err)
	})

	t.Run("detached without message", func(t *testing.T) {
		sig, err := Sign(tok, &SignOpts{
			StatusFd:           0,
			Detach:             true,
			Armor:              false,
			UserId:             fingerprint,
			TimestampAuthority: "",
			Message:            &bytes.Buffer{},
			Slot:               SlotCardAuthentication,
		})
		if err != nil {
			t.Fatal(err)
		}
		err = VerifySignature(tok, &VerifyOpts{
			Signature: bytes.NewReader(sig),
			Slot:      SlotCardAuthentication,
		})
		assert.Error(t, err)
	})

	t.Run("detached with message read error", func(t *testing.T) {
		sig, err := Sign(tok, &SignOpts{
			StatusFd:           0,
			Detach:             true,
			Armor:              false,
			UserId:             fingerprint,
			TimestampAuthority: "",
			Message:            &bytes.Buffer{},
			Slot:               SlotCardAuthentication,
		})
		if err != nil {
			t.Fatal(err)
		}
		err = VerifySignature(tok, &VerifyOpts{
			Signature: bytes.NewReader(sig),
			Message:   errReader{},
			Slot:      SlotCardAuthentication,
		})
		assert.Error(t, err)
	})

	t.Run("signature read error", func(t *testing.T) {
		err := VerifySignature(tok, &VerifyOpts{
			Signature: errReader{},
			Slot:      SlotCardAuthentication,
		})
		assert.Error(t, err)
	})
}

func TestVerifyOpts_emptyToken(t *testing.T) {
	tok, err := testToken()
	if err != nil {
		t.Fatal(err)
	}

	opts := verifyOpts(tok, SlotSignature)
	assert.NotNil(t, opts.Roots)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, opts.KeyUsages)
}
