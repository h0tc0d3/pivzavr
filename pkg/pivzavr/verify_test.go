package pivzavr

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"testing"
	"time"

	"github.com/h0tc0d3/pivzavr/pkg/testcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifySignature(t *testing.T) {
	tok, err := testToken()
	if err != nil {
		t.Fatal(err)
	}

	// A CA bundle is installed so that the test does not download the real
	// one and never reaches the network.
	root, _ := testcert.Identity(t)
	useCABundle(t, root)

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
				UserID:             fingerprint,
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

	t.Run("accepted PEM headers", func(t *testing.T) {
		sig, err := Sign(tok, &SignOpts{
			StatusFd: 0,
			Armor:    true,
			UserID:   fingerprint,
			Message:  &bytes.Buffer{},
			Slot:     SlotCardAuthentication,
		})
		require.NoError(t, err)
		block, _ := pem.Decode(sig)
		require.NotNil(t, block)

		// A signature is accepted whatever label the block carries, so a
		// signature that was armored by another CMS tool and a signature
		// written before the armor was made a PKCS#7 block still verify.
		for _, header := range []string{pkcs7PemHeader, cmsPemHeader, signedMessagePemHeader} {
			rearmored := pem.EncodeToMemory(&pem.Block{Type: header, Bytes: block.Bytes})
			require.NoError(t, VerifySignature(tok, &VerifyOpts{
				Signature: bytes.NewReader(rearmored),
				Message:   &bytes.Buffer{},
				Slot:      SlotCardAuthentication,
			}))
		}
	})

	t.Run("clear text round trip", func(t *testing.T) {
		message := []byte("hello, clear text\n")
		sig, err := Sign(tok, &SignOpts{
			StatusFd:  0,
			Clearsign: true,
			UserID:    fingerprint,
			Message:   bytes.NewReader(message),
			Slot:      SlotCardAuthentication,
		})
		require.NoError(t, err)

		// The message is written verbatim, in front of the armored signature
		// and separated from it by a blank line.
		assert.True(t, bytes.HasPrefix(sig, append(append([]byte{}, message...), '\n', '\n')))
		assert.Contains(t, string(sig), "-----BEGIN "+pkcs7PemHeader+"-----\n")

		// The message of a clear text signature is read from the file itself.
		require.NoError(t, VerifySignature(tok, &VerifyOpts{
			Signature: bytes.NewReader(sig),
			Slot:      SlotCardAuthentication,
		}))
	})

	t.Run("attached with message parameter", func(t *testing.T) {
		sig, err := Sign(tok, &SignOpts{
			StatusFd:           0,
			Detach:             false,
			Armor:              false,
			UserID:             fingerprint,
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
			UserID:             fingerprint,
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
			UserID:             fingerprint,
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
			UserID:             fingerprint,
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
			UserID:             fingerprint,
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
			UserID:             fingerprint,
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

func TestVerifyOpts(t *testing.T) {
	root, _ := testcert.Identity(t)
	useCABundle(t, root)

	anchors := loadTrustAnchors()
	opts := verifyOpts(anchors.roots)
	assert.NotNil(t, opts.Roots)

	// Every extended key usage is accepted by crypto/x509, which cannot tell
	// an absent extension from an unconstrained one; the constraint is checked
	// by validateSigningCertificate instead.
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, opts.KeyUsages)

	// The certificate of the bundle is trusted, while the certificate store
	// of the system is not used.
	assert.NoError(t, testcert.Trust(root, opts.Roots))

	// A bundle without public keys yields no other trust anchor.
	assert.Empty(t, anchors.keys)
}

func TestLoadTrustAnchorsWithPublicKeys(t *testing.T) {
	root, _ := testcert.Identity(t)
	key := keyPair(t)
	useTrustStore(t, []*x509.Certificate{root}, []crypto.PublicKey{key})

	anchors := loadTrustAnchors()
	assert.NoError(t, testcert.Trust(root, anchors.roots))
	require.Len(t, anchors.keys, 1)
	assert.True(t, samePublicKeyValue(key, anchors.keys[0]))
}

func TestVerifyOptsIgnoresCardCertificate(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)

	root, _ := testcert.Identity(t)
	useCABundle(t, root)

	cardCert, err := generateKeyAndCertificate(tok, SlotSignature)
	require.NoError(t, err)

	// A certificate that the CA bundle does not hold is not trusted, not even
	// when it is stored on the smart card that verifies the signature.
	assert.Error(t, testcert.Trust(cardCert, loadTrustAnchors().roots))
}

// samePublicKeyValue reports whether two public keys have the same DER encoding.
func samePublicKeyValue(a, b crypto.PublicKey) bool {
	first, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	second, err := x509.MarshalPKIXPublicKey(b)
	return err == nil && bytes.Equal(first, second)
}

// issueCertificate creates a certificate from tmpl for the key of slot and
// stores it in the slot. A nil ca makes the certificate self-signed; otherwise
// it is issued by ca with caKey. It returns the certificate.
func issueCertificate(t *testing.T, tok *fakeToken, slot Slot, ca *x509.Certificate, caKey crypto.Signer, tmpl *x509.Certificate) *x509.Certificate {
	t.Helper()

	key, err := tok.Signer(slot)
	require.NoError(t, err)

	if tmpl.SerialNumber == nil {
		serial, err := randomSerial()
		require.NoError(t, err)
		tmpl.SerialNumber = serial
	}
	if tmpl.Subject.CommonName == "" {
		tmpl.Subject = pkix.Name{CommonName: "pivzavr test"}
	}
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(time.Hour)
	}

	parent, parentKey := ca, caKey
	if parent == nil {
		parent, parentKey = tmpl, key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	tok.slots[slot].cert = cert
	return cert
}

// signingTemplate returns a certificate template for a leaf certificate that
// may make digital signatures.
func signingTemplate() *x509.Certificate {
	return &x509.Certificate{
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

func TestVerifySignatureIssuedByCA(t *testing.T) {
	ca, caKey := testIssuer(t)
	useCABundle(t, ca)

	tok, err := testToken()
	require.NoError(t, err)
	_, err = generateKeyAndCertificate(tok, SlotCardAuthentication)
	require.NoError(t, err)
	cert := issueCertificate(t, tok, SlotCardAuthentication, ca, caKey, signingTemplate())

	sig, err := Sign(tok, &SignOpts{
		StatusFd: 0,
		UserID:   CertHexFingerprint(cert),
		Message:  &bytes.Buffer{},
		Slot:     SlotCardAuthentication,
	})
	require.NoError(t, err)

	require.NoError(t, VerifySignature(tok, &VerifyOpts{
		Signature: bytes.NewReader(sig),
		Slot:      SlotCardAuthentication,
	}))
}

func TestVerifySignatureRejectsUntrustedCA(t *testing.T) {
	ca, caKey := testIssuer(t)
	trusted, _ := testIssuer(t)
	useCABundle(t, trusted)

	tok, err := testToken()
	require.NoError(t, err)
	_, err = generateKeyAndCertificate(tok, SlotCardAuthentication)
	require.NoError(t, err)
	cert := issueCertificate(t, tok, SlotCardAuthentication, ca, caKey, signingTemplate())

	sig, err := Sign(tok, &SignOpts{
		StatusFd: 0,
		UserID:   CertHexFingerprint(cert),
		Message:  &bytes.Buffer{},
		Slot:     SlotCardAuthentication,
	})
	require.NoError(t, err)

	// The certificate chains up to a CA that the bundle does not hold, and it
	// is not self-signed, so the signature is rejected.
	err = VerifySignature(tok, &VerifyOpts{
		Signature: bytes.NewReader(sig),
		Slot:      SlotCardAuthentication,
	})
	assert.Error(t, err)
}

func TestVerifySignatureRejectsCertificateWithoutSigningUsage(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)
	_, err = generateKeyAndCertificate(tok, SlotCardAuthentication)
	require.NoError(t, err)

	// The certificate of the card is trusted because it is its own root, but
	// its Key Usage does not permit digital signatures.
	cert := issueCertificate(t, tok, SlotCardAuthentication, nil, nil, &x509.Certificate{
		KeyUsage: x509.KeyUsageKeyEncipherment,
	})
	useCABundle(t, cert)

	sig, err := Sign(tok, &SignOpts{
		StatusFd: 0,
		UserID:   CertHexFingerprint(cert),
		Message:  &bytes.Buffer{},
		Slot:     SlotCardAuthentication,
	})
	require.NoError(t, err)

	err = VerifySignature(tok, &VerifyOpts{
		Signature: bytes.NewReader(sig),
		Slot:      SlotCardAuthentication,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not permit digital signatures")
}

// signWithReplacedCard signs a message with the current certificate of the card
// and then replaces that certificate, so that the signature was made with a
// certificate that the card no longer holds. It returns the signature and the
// certificate that made it.
func signWithReplacedCard(t *testing.T, tok *fakeToken) ([]byte, *x509.Certificate) {
	t.Helper()

	cert, err := generateKeyAndCertificate(tok, SlotCardAuthentication)
	require.NoError(t, err)

	sig, err := Sign(tok, &SignOpts{
		StatusFd: 0,
		UserID:   CertHexFingerprint(cert),
		Message:  &bytes.Buffer{},
		Slot:     SlotCardAuthentication,
	})
	require.NoError(t, err)

	// The card is re-keyed, so its current certificate is no longer the one
	// that made the signature.
	_, err = generateKeyAndCertificate(tok, SlotCardAuthentication)
	require.NoError(t, err)
	return sig, cert
}

func TestVerifySignatureWithConfiguredPublicKey(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)
	sig, cert := signWithReplacedCard(t, tok)

	// Neither the CA bundle nor the self-signed certificate of the card can
	// vouch for the signature, but its public key is configured.
	ca, _ := testIssuer(t)
	useTrustStore(t, []*x509.Certificate{ca}, []crypto.PublicKey{cert.PublicKey})

	output := captureStdout(t, func() {
		require.NoError(t, VerifySignature(tok, &VerifyOpts{
			Signature: bytes.NewReader(sig),
			Slot:      SlotCardAuthentication,
		}))
	})

	assert.Contains(t, output, "Good signature. Subject DN:")
	assert.Contains(t, output, "signer and trust anchor")
	assert.Contains(t, output, "trusted (configured public key)")
}

func TestVerifySignatureRejectsUnrelatedPublicKey(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)
	sig, _ := signWithReplacedCard(t, tok)

	// A configured public key that does not belong to the certificate of the
	// signature cannot vouch for it.
	ca, _ := testIssuer(t)
	useTrustStore(t, []*x509.Certificate{ca}, []crypto.PublicKey{keyPair(t)})

	err = VerifySignature(tok, &VerifyOpts{
		Signature: bytes.NewReader(sig),
		Slot:      SlotCardAuthentication,
	})
	assert.Error(t, err)
}

func TestVerifySignatureWithConfiguredPublicKeyForIssuedCertificate(t *testing.T) {
	// A certificate that was issued by a CA whose certificate is not part of
	// the trust store is accepted when its public key is configured.
	ca, caKey := testIssuer(t)
	other, _ := testIssuer(t)

	tok, err := testToken()
	require.NoError(t, err)
	_, err = generateKeyAndCertificate(tok, SlotCardAuthentication)
	require.NoError(t, err)
	cert := issueCertificate(t, tok, SlotCardAuthentication, ca, caKey, signingTemplate())

	sig, err := Sign(tok, &SignOpts{
		StatusFd: 0,
		UserID:   CertHexFingerprint(cert),
		Message:  &bytes.Buffer{},
		Slot:     SlotCardAuthentication,
	})
	require.NoError(t, err)

	useTrustStore(t, []*x509.Certificate{other}, []crypto.PublicKey{cert.PublicKey})

	output := captureStdout(t, func() {
		require.NoError(t, VerifySignature(tok, &VerifyOpts{
			Signature: bytes.NewReader(sig),
			Slot:      SlotCardAuthentication,
		}))
	})
	assert.Contains(t, output, "trusted (configured public key)")
}

func TestTrustedKeySigner(t *testing.T) {
	// A signature without a single signer certificate cannot be trusted by a
	// key that was configured.
	assert.False(t, matchesPublicKey(&x509.Certificate{}, nil))

	cert, _ := testcert.Identity(t)
	assert.True(t, matchesPublicKey(cert, []crypto.PublicKey{cert.PublicKey}))
	assert.False(t, matchesPublicKey(cert, []crypto.PublicKey{keyPair(t)}))
}
