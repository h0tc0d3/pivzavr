package pivzavr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/h0tc0d3/pivzavr/pkg/config"
	"github.com/stretchr/testify/require"
)

// useCABundle stores a trust store holding certs in a temporary config
// directory and points XDG_CONFIG_HOME at it, so that a test never reaches the
// network.
func useCABundle(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()

	return useTrustStore(t, certs, nil)
}

// useTrustStore stores a trust store holding certs and keys in a temporary
// config directory and points XDG_CONFIG_HOME at it, so that a test never
// reaches the network.
func useTrustStore(t *testing.T, certs []*x509.Certificate, keys []crypto.PublicKey) string {
	t.Helper()

	base := t.TempDir()
	t.Setenv(config.ConfigDirEnv, base)

	path, err := config.TrustPath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))

	data, err := config.MarshalTrust(certs, keys)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return base
}

// useConfig writes a pivzavr configuration file in a temporary config directory
// and points XDG_CONFIG_HOME at it, so that a test never reads the real
// configuration of the user.
func useConfig(t *testing.T, contents string) {
	t.Helper()

	base := t.TempDir()
	t.Setenv(config.ConfigDirEnv, base)

	// TrustPath locates the configuration directory without repeating its
	// layout here.
	trustPath, err := config.TrustPath()
	require.NoError(t, err)
	dir := filepath.Dir(trustPath)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config"), []byte(contents), 0o600))
}

// newCertificate creates a certificate from tmpl for a fresh key. A nil parent
// makes the certificate self-signed; otherwise it is signed by parent with
// parentKey. It returns the certificate and the key it was created for.
func newCertificate(t *testing.T, parent *x509.Certificate, parentKey crypto.Signer, tmpl *x509.Certificate) (*x509.Certificate, crypto.Signer) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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

	signer, signerKey := parent, parentKey
	if signer == nil {
		signer, signerKey = tmpl, key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, key.Public(), signerKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// testIssuer returns a CA certificate and its key for the tests that need a
// certificate that issues others.
func testIssuer(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()

	return newCertificate(t, nil, nil, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "pivzavr test issuer"},
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	})
}

// keyPair returns the public key of a fresh key, for the tests that configure a
// public key as a trust anchor.
func keyPair(t *testing.T) crypto.PublicKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key.Public()
}
