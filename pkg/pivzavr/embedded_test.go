package pivzavr

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"io"
	"os"
	"testing"

	"github.com/h0tc0d3/pivzavr/pkg/embed"
	"github.com/h0tc0d3/pivzavr/pkg/testcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStdout runs f with the standard output replaced by a pipe and returns
// what f wrote to it.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()

	reader, writer, err := os.Pipe()
	require.NoError(t, err)

	original := os.Stdout
	os.Stdout = writer
	defer func() {
		os.Stdout = original
	}()

	f()
	require.NoError(t, writer.Close())

	out, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	return string(out)
}

func TestSignAndVerifyEmbedded(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)
	root, _ := testcert.Identity(t)
	useCABundle(t, root)

	cert, err := generateKeyAndCertificate(tok, SlotCardAuthentication)
	require.NoError(t, err)

	source := []byte(`<?xml version="1.0" encoding="UTF-8"?><note><to>You</to></note>`)

	var signed bytes.Buffer
	require.NoError(t, SignEmbedded(tok, &EmbeddedSignOpts{
		StatusFd: 0,
		UserID:   CertHexFingerprint(cert),
		Format:   embed.XML,
		Message:  bytes.NewReader(source),
		Output:   &signed,
		Slot:     SlotCardAuthentication,
	}))
	require.NotEqual(t, source, signed.Bytes())

	require.NoError(t, VerifyEmbedded(tok, &EmbeddedVerifyOpts{
		Format:  embed.XML,
		Message: bytes.NewReader(signed.Bytes()),
		Slot:    SlotCardAuthentication,
	}))

	// A document that was changed after it was signed is rejected.
	tampered := bytes.Replace(signed.Bytes(), []byte("<to>You</to>"), []byte("<to>Me</to>"), 1)
	require.Error(t, VerifyEmbedded(tok, &EmbeddedVerifyOpts{
		Format:  embed.XML,
		Message: bytes.NewReader(tampered),
		Slot:    SlotCardAuthentication,
	}))
}

// signEmbeddedXML signs an XML document with the current card and returns the
// signed document and the certificate that made the signature.
func signEmbeddedXML(t *testing.T, tok *fakeToken) ([]byte, *x509.Certificate) {
	t.Helper()

	cert, err := generateKeyAndCertificate(tok, SlotCardAuthentication)
	require.NoError(t, err)

	var signed bytes.Buffer
	require.NoError(t, SignEmbedded(tok, &EmbeddedSignOpts{
		StatusFd: 0,
		UserID:   CertHexFingerprint(cert),
		Format:   embed.XML,
		Message:  bytes.NewReader([]byte(`<?xml version="1.0" encoding="UTF-8"?><note><to>You</to></note>`)),
		Output:   &signed,
		Slot:     SlotCardAuthentication,
	}))
	return signed.Bytes(), cert
}

func TestVerifyEmbeddedWithConfiguredPublicKey(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)
	signed, cert := signEmbeddedXML(t, tok)

	// The card is re-keyed and no CA of the bundle certifies the certificate
	// of the signature, so only its configured public key can vouch for it.
	_, err = generateKeyAndCertificate(tok, SlotCardAuthentication)
	require.NoError(t, err)
	ca, _ := testIssuer(t)
	useTrustStore(t, []*x509.Certificate{ca}, []crypto.PublicKey{cert.PublicKey})

	require.NoError(t, VerifyEmbedded(tok, &EmbeddedVerifyOpts{
		Format:  embed.XML,
		Message: bytes.NewReader(signed),
		Slot:    SlotCardAuthentication,
	}))
}

func TestVerifyEmbeddedRejectsUnrelatedPublicKey(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)
	signed, _ := signEmbeddedXML(t, tok)

	_, err = generateKeyAndCertificate(tok, SlotCardAuthentication)
	require.NoError(t, err)
	ca, _ := testIssuer(t)
	useTrustStore(t, []*x509.Certificate{ca}, []crypto.PublicKey{keyPair(t)})

	err = VerifyEmbedded(tok, &EmbeddedVerifyOpts{
		Format:  embed.XML,
		Message: bytes.NewReader(signed),
		Slot:    SlotCardAuthentication,
	})
	assert.Error(t, err)
}

func TestSignEmbeddedRejectsWrongUser(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)
	_, err = generateKeyAndCertificate(tok, SlotCardAuthentication)
	require.NoError(t, err)

	err = SignEmbedded(tok, &EmbeddedSignOpts{
		StatusFd: 0,
		UserID:   "somebody@example.com",
		Format:   embed.XML,
		Message:  bytes.NewReader([]byte("<note></note>")),
		Output:   &bytes.Buffer{},
		Slot:     SlotCardAuthentication,
	})
	assert.ErrorContains(t, err, "No suitable certificate found")
}

func TestSignEmbeddedRejectsUnsupportedFormat(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)

	err = SignEmbedded(tok, &EmbeddedSignOpts{
		StatusFd: 0,
		UserID:   "irrelevant",
		Format:   embed.Unknown,
		Message:  bytes.NewReader([]byte("text")),
		Output:   &bytes.Buffer{},
		Slot:     SlotCardAuthentication,
	})
	assert.ErrorContains(t, err, "cannot be embedded")
}

func TestVerifySignatureReportsChainOfTrust(t *testing.T) {
	ca, caKey := testIssuer(t)
	useCABundle(t, ca)

	tok, err := testToken()
	require.NoError(t, err)
	_, err = generateKeyAndCertificate(tok, SlotCardAuthentication)
	require.NoError(t, err)
	cert := issueCertificate(t, tok, SlotCardAuthentication, ca, caKey, signingTemplate())

	signature, err := Sign(tok, &SignOpts{
		StatusFd: 0,
		UserID:   CertHexFingerprint(cert),
		Message:  &bytes.Buffer{},
		Slot:     SlotCardAuthentication,
	})
	require.NoError(t, err)

	output := captureStdout(t, func() {
		require.NoError(t, VerifySignature(tok, &VerifyOpts{
			Signature: bytes.NewReader(signature),
			Slot:      SlotCardAuthentication,
		}))
	})

	assert.Contains(t, output, "Signature made using certificate ID 0x")
	assert.Contains(t, output, "Good signature. Subject DN:")
	assert.Contains(t, output, "Not Before: "+formatTime(cert.NotBefore))
	assert.Contains(t, output, "Not After: "+formatTime(cert.NotAfter))
	assert.Contains(t, output, "Signing date: ")
	assert.Contains(t, output, "Signature algorithm: ")
	assert.Contains(t, output, "Chain of Trust:")
	assert.Contains(t, output, "[signer]")
	assert.Contains(t, output, "[root]")
	assert.Contains(t, output, "trusted (CA bundle)")
}

func TestVerifySignatureReportsSelfSignedChainOfTrust(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)
	root, _ := testcert.Identity(t)
	useCABundle(t, root)

	cert, err := generateKeyAndCertificate(tok, SlotCardAuthentication)
	require.NoError(t, err)

	signature, err := Sign(tok, &SignOpts{
		StatusFd: 0,
		UserID:   CertHexFingerprint(cert),
		Message:  &bytes.Buffer{},
		Slot:     SlotCardAuthentication,
	})
	require.NoError(t, err)

	output := captureStdout(t, func() {
		require.NoError(t, VerifySignature(tok, &VerifyOpts{
			Signature: bytes.NewReader(signature),
			Slot:      SlotCardAuthentication,
		}))
	})

	assert.Contains(t, output, "Chain of Trust:")
	assert.Contains(t, output, "Not Before: "+formatTime(cert.NotBefore))
	assert.Contains(t, output, "Not After: "+formatTime(cert.NotAfter))
	assert.Contains(t, output, "trusted (self-signed card certificate)")
}
