// Package testcert provides self-signed certificates and matching signers for
// the tests of the pivzavr packages.
package testcert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// signer is a crypto.Signer that reports the public key it was created with,
// which may differ from the key of the certificate it is used with. That lets a
// test detect that a signature was made with the key it expected.
type signer struct {
	crypto.Signer
	pub crypto.PublicKey
}

// Public returns the public key the signer was created with.
func (s signer) Public() crypto.PublicKey { return s.pub }

// Identity returns a self-signed certificate and a signer for its key. The
// certificate is valid for an hour around the current time.
func Identity(t testing.TB) (*x509.Certificate, crypto.Signer) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return Certificate(t, key)
}

// Certificate returns a self-signed certificate for key and a signer that
// reports key's public key.
func Certificate(t testing.TB, key crypto.Signer) (*x509.Certificate, crypto.Signer) {
	t.Helper()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial number: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		SubjectKeyId: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	return cert, signer{Signer: key, pub: key.Public()}
}

// PEM returns the PEM encoding of certs, in the form a CA bundle holds them.
func PEM(certs ...*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}
	return buf.Bytes()
}

// Trust verifies cert against pool, accepting any extended key usage, and
// returns the verification error.
func Trust(cert *x509.Certificate, pool *x509.CertPool) error {
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}
