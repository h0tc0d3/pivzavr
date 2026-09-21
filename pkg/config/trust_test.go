package config

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/h0tc0d3/pivzavr/pkg/testcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// certificateHandler serves the given certificates as a PEM bundle.
func certificateHandler(certs ...*x509.Certificate) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		for _, cert := range certs {
			_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		}
	}
}

// publicKeyHandler serves the given public keys as a PEM bundle.
func publicKeyHandler(keys ...crypto.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		for _, key := range keys {
			der, err := x509.MarshalPKIXPublicKey(key)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		}
	}
}

// setCASources points the CA downloader at the given URLs for the duration of
// the test.
func setCASources(t *testing.T, mozilla string, smart ...string) {
	t.Helper()

	mozillaURL, smartURLs := mozillaCAURL, smartCardCAURLs
	t.Cleanup(func() {
		mozillaCAURL, smartCardCAURLs = mozillaURL, smartURLs
	})
	mozillaCAURL = mozilla
	smartCardCAURLs = smart
}

// useTrustStore stores a trust store holding certs and keys in a temporary
// config directory and points XDG_CONFIG_HOME at it, so that a test never
// reaches the network.
func useTrustStore(t *testing.T, certs []*x509.Certificate, keys []crypto.PublicKey) string {
	t.Helper()

	base := t.TempDir()
	dir := filepath.Join(base, configDirName)
	require.NoError(t, os.MkdirAll(dir, 0o700))

	data, err := MarshalTrust(certs, keys)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, trustFileName), data, 0o600))

	t.Setenv(ConfigDirEnv, base)
	return base
}

// useCABundle stores a trust store that holds certs and no public keys.
func useCABundle(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()
	return useTrustStore(t, certs, nil)
}

// readTrustStore decodes the trust store at path.
func readTrustStore(t *testing.T, path string) ([]*x509.Certificate, []crypto.PublicKey) {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	certs, keys, err := decodeTrust(data)
	require.NoError(t, err)
	return certs, keys
}

// readCAPool returns a pool holding the CA certificates of the trust store at
// path.
func readCAPool(t *testing.T, path string) *x509.CertPool {
	t.Helper()

	certs, _ := readTrustStore(t, path)
	return newCertPool(certs)
}

// countCertificates returns the number of certificates in the trust store at
// path.
func countCertificates(t *testing.T, path string) int {
	t.Helper()

	certs, _ := readTrustStore(t, path)
	return len(certs)
}

// countPublicKeys returns the number of public keys in the trust store at path.
func countPublicKeys(t *testing.T, path string) int {
	t.Helper()

	_, keys := readTrustStore(t, path)
	return len(keys)
}

// keyPair returns a public key of a fresh key.
func keyPair(t *testing.T) crypto.PublicKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key.Public()
}

// trustedKey reports whether key is one of keys.
func trustedKey(t *testing.T, key crypto.PublicKey, keys []crypto.PublicKey) bool {
	t.Helper()

	want, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)
	for _, candidate := range keys {
		got, err := x509.MarshalPKIXPublicKey(candidate)
		require.NoError(t, err)
		if bytes.Equal(want, got) {
			return true
		}
	}
	return false
}

// sha256Sum returns the checksum that a trust store payload is verified with, so
// that a test can build a store that passes the checksum with a payload of its
// own.
func sha256Sum(payload []byte) []byte {
	sum := sha256.Sum256(payload)
	return sum[:]
}

// trustStore builds a trust store with the header of a valid store and the given
// payload, so that the decoder can be exercised on a payload that a store would
// not otherwise hold.
func trustStore(payload []byte) []byte {
	store := append([]byte(trustMagic), 0, 0, 0, byte(trustVersion))
	store = append(store, make([]byte, trustChecksumSize)...)
	copy(store[len(trustMagic)+4:trustHeaderSize], sha256Sum(payload))
	return append(store, payload...)
}

func TestMarshalTrustRoundTrip(t *testing.T) {
	first, _ := testcert.Identity(t)
	second, _ := testcert.Identity(t)
	key := keyPair(t)

	data, err := MarshalTrust([]*x509.Certificate{first, second}, []crypto.PublicKey{key})
	require.NoError(t, err)

	// The store is not a PEM bundle: it is a binary file that starts with its
	// magic and holds the certificates and keys as DER.
	assert.True(t, bytes.HasPrefix(data, []byte(trustMagic)))
	assert.NotContains(t, string(data), "-----BEGIN")

	certs, keys, err := decodeTrust(data)
	require.NoError(t, err)
	require.Len(t, certs, 2)
	assert.Equal(t, first.Raw, certs[0].Raw)
	assert.Equal(t, second.Raw, certs[1].Raw)
	require.Len(t, keys, 1)
	assert.True(t, trustedKey(t, key, keys))
}

func TestMarshalTrustEmpty(t *testing.T) {
	data, err := MarshalTrust(nil, nil)
	require.NoError(t, err)

	certs, keys, err := decodeTrust(data)
	require.NoError(t, err)
	assert.Empty(t, certs)
	assert.Empty(t, keys)
}

func TestDecodeTrustRejectsEditedStore(t *testing.T) {
	cert, _ := testcert.Identity(t)
	data, err := MarshalTrust([]*x509.Certificate{cert}, nil)
	require.NoError(t, err)

	// A byte that is flipped anywhere in the payload no longer matches the
	// checksum, so the store is rejected rather than partly trusted.
	edited := append([]byte(nil), data...)
	edited[len(edited)-1] ^= 0xff
	_, _, err = decodeTrust(edited)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checksum")

	// A store whose format version was changed is rejected as well.
	edited = append([]byte(nil), data...)
	edited[len(trustMagic)]++
	_, _, err = decodeTrust(edited)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Unsupported trust store version")
}

func TestDecodeTrustRejectsMalformedStore(t *testing.T) {
	cert, _ := testcert.Identity(t)

	testCases := []struct {
		name  string
		data  []byte
		error string
	}{
		{"empty", nil, "too short"},
		{"short file", []byte("short"), "too short"},
		{"text bundle", testcert.PEM(cert), "not a pivzavr trust store"},
		{"wrong magic", append([]byte("NOTTRUST"), make([]byte, trustHeaderSize-len("NOTTRUST"))...), "not a pivzavr trust store"},
		{
			"unsupported version",
			func() []byte {
				versioned, err := MarshalTrust(nil, nil)
				require.NoError(t, err)
				versioned[len(trustMagic)] = byte(trustVersion + 1)
				return versioned
			}(),
			"Unsupported trust store version",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, _, err := decodeTrust(testCase.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), testCase.error)
		})
	}
}

func TestDecodeTrustRejectsTruncatedRecords(t *testing.T) {
	cert, _ := testcert.Identity(t)
	data, err := MarshalTrust([]*x509.Certificate{cert}, nil)
	require.NoError(t, err)

	// The payload is cut short while the checksum is recomputed, so the store
	// passes the checksum and fails on the truncated certificate instead.
	payload := data[trustHeaderSize:]
	store := trustStore(payload[:len(payload)-1])

	_, _, err = decodeTrust(store)
	assert.Error(t, err)
}

func TestDecodeTrustRejectsHugeEntryCount(t *testing.T) {
	// A count that no payload could hold is rejected before anything is
	// allocated for it.
	payload := []byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0}

	_, _, err := decodeTrust(trustStore(payload))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "entry count is out of range")
}

func TestDecodeTrustRejectsTrailingData(t *testing.T) {
	cert, _ := testcert.Identity(t)
	data, err := MarshalTrust([]*x509.Certificate{cert}, nil)
	require.NoError(t, err)

	payload := append(append([]byte(nil), data[trustHeaderSize:]...), 0x00)

	_, _, err = decodeTrust(trustStore(payload))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trailing data")
}

func TestUpdateTrust(t *testing.T) {
	root, _ := testcert.Identity(t)
	smartCard, _ := testcert.Identity(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/mozilla.pem", certificateHandler(root))
	mux.HandleFunc("/smart.pem", certificateHandler(smartCard))
	server := httptest.NewServer(mux)
	defer server.Close()

	setCASources(t, server.URL+"/mozilla.pem", server.URL+"/smart.pem")
	base := t.TempDir()
	t.Setenv(ConfigDirEnv, base)

	path, err := UpdateTrust()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(base, configDirName, trustFileName), path)

	// The store is private to the user.
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	pool := readCAPool(t, path)
	assert.Equal(t, 2, countCertificates(t, path))
	assert.NoError(t, testcert.Trust(root, pool))
	assert.NoError(t, testcert.Trust(smartCard, pool))

	// A store without configured public keys holds none.
	assert.Equal(t, 0, countPublicKeys(t, path))
}

func TestUpdateTrustSkipsUnavailableSmartCardSource(t *testing.T) {
	cert, _ := testcert.Identity(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/mozilla.pem", certificateHandler(cert))
	mux.HandleFunc("/smart.pem", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	setCASources(t, server.URL+"/mozilla.pem", server.URL+"/smart.pem")
	t.Setenv(ConfigDirEnv, t.TempDir())

	path, err := UpdateTrust()
	require.NoError(t, err)

	// The update succeeds without the CA certificates of the smart card.
	pool := readCAPool(t, path)
	assert.Equal(t, 1, countCertificates(t, path))
	assert.NoError(t, testcert.Trust(cert, pool))
}

func TestUpdateTrustReplacesStore(t *testing.T) {
	cert, _ := testcert.Identity(t)
	previous, _ := testcert.Identity(t)
	base := useCABundle(t, previous)

	server := httptest.NewServer(certificateHandler(cert))
	defer server.Close()
	setCASources(t, server.URL)

	path, err := UpdateTrust()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(base, configDirName, trustFileName), path)

	pool := readCAPool(t, path)
	assert.Equal(t, 1, countCertificates(t, path))
	assert.NoError(t, testcert.Trust(cert, pool))
	assert.Error(t, testcert.Trust(previous, pool))
}

func TestUpdateTrustDeduplicates(t *testing.T) {
	cert, _ := testcert.Identity(t)

	server := httptest.NewServer(certificateHandler(cert))
	defer server.Close()

	// The same certificate is offered by the Mozilla source and by a smart
	// card source.
	setCASources(t, server.URL, server.URL)
	t.Setenv(ConfigDirEnv, t.TempDir())

	path, err := UpdateTrust()
	require.NoError(t, err)

	// The certificate is stored once even though both sources offer it.
	assert.Equal(t, 1, countCertificates(t, path))
}

func TestUpdateTrustRetriesDownload(t *testing.T) {
	cert, _ := testcert.Identity(t)

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}))
	defer server.Close()
	setCASources(t, server.URL)
	t.Setenv(ConfigDirEnv, t.TempDir())

	path, err := UpdateTrust()
	require.NoError(t, err)

	// The download that failed once is tried again.
	assert.Equal(t, int32(2), requests.Load())
	assert.Equal(t, 1, countCertificates(t, path))
}

func TestUpdateTrustDownloadError(t *testing.T) {
	server := httptest.NewServer(certificateHandler())
	defer server.Close()
	setCASources(t, server.URL)

	base := t.TempDir()
	t.Setenv(ConfigDirEnv, base)

	_, err := UpdateTrust()
	require.Error(t, err)

	// A failed download does not leave a store behind.
	assert.NoFileExists(t, filepath.Join(base, configDirName, trustFileName))
}

func TestUpdateTrustKeepsStoreOnError(t *testing.T) {
	cert, _ := testcert.Identity(t)
	base := useCABundle(t, cert)
	path := filepath.Join(base, configDirName, trustFileName)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusInternalServerError)
	}))
	defer server.Close()
	setCASources(t, server.URL)

	_, err := UpdateTrust()
	require.Error(t, err)

	// The store that was stored before is kept.
	assert.FileExists(t, path)
	assert.Equal(t, 1, countCertificates(t, path))
	assert.NoError(t, testcert.Trust(cert, readCAPool(t, path)))
}

func TestTrustPath(t *testing.T) {
	t.Setenv(ConfigDirEnv, "/tmp/xdg")

	path, err := TrustPath()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("/tmp/xdg", configDirName, trustFileName), path)
}

func TestRootCAsCreatesTrustStore(t *testing.T) {
	cert, _ := testcert.Identity(t)

	server := httptest.NewServer(certificateHandler(cert))
	defer server.Close()
	setCASources(t, server.URL)

	base := t.TempDir()
	t.Setenv(ConfigDirEnv, base)

	pool, err := RootCAs()
	require.NoError(t, err)

	path, err := TrustPath()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(base, configDirName, trustFileName), path)
	assert.Equal(t, 1, countCertificates(t, path))
	assert.NoError(t, testcert.Trust(cert, pool))

	// The store is stored, so a later verification does not download it
	// again.
	assert.FileExists(t, path)
}

func TestRootCAsUsesStoredTrustStore(t *testing.T) {
	cert, _ := testcert.Identity(t)
	base := useCABundle(t, cert)
	path := filepath.Join(base, configDirName, trustFileName)

	// A source that fails proves that the stored store is used instead of a
	// download.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusInternalServerError)
	}))
	defer server.Close()
	setCASources(t, server.URL)

	pool, err := RootCAs()
	require.NoError(t, err)
	assert.Equal(t, 1, countCertificates(t, path))
	assert.NoError(t, testcert.Trust(cert, pool))
}

func TestRootCAsEmptyTrustStore(t *testing.T) {
	useTrustStore(t, nil, nil)

	_, err := RootCAs()
	assert.ErrorContains(t, err, "No CA certificates")
}

func TestRootCAsRejectsEditedTrustStore(t *testing.T) {
	cert, _ := testcert.Identity(t)
	base := useCABundle(t, cert)

	path := filepath.Join(base, configDirName, trustFileName)
	require.NoError(t, os.WriteFile(path, []byte("edited by hand\n"), 0o600))

	// An edited store is not silently replaced by a download: the file is
	// reported as invalid, so that a trust anchor that was removed on purpose
	// does not come back behind the back of the user.
	_, err := RootCAs()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid trust store")
}

func TestTrustAnchors(t *testing.T) {
	cert, _ := testcert.Identity(t)
	key := keyPair(t)
	useTrustStore(t, []*x509.Certificate{cert}, []crypto.PublicKey{key})

	pool, keys, err := TrustAnchors()
	require.NoError(t, err)
	assert.NoError(t, testcert.Trust(cert, pool))
	require.Len(t, keys, 1)
	assert.True(t, trustedKey(t, key, keys))
}

func TestTrustAnchorsWithoutStore(t *testing.T) {
	// A store that does not exist is created by an update, which fails because
	// every source is unavailable.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusInternalServerError)
	}))
	defer server.Close()
	setCASources(t, server.URL)
	t.Setenv(ConfigDirEnv, t.TempDir())

	_, _, err := TrustAnchors()
	assert.Error(t, err)
}

func TestCaSources(t *testing.T) {
	setCASources(t, "https://mozilla.example/ca.pem", "https://smart.example/ca.pem")
	t.Setenv(ConfigDirEnv, t.TempDir())

	sources, err := caSources()
	require.NoError(t, err)
	assert.Equal(t, []trustSource{
		{location: "https://mozilla.example/ca.pem", isURL: true, required: true},
		{location: "https://smart.example/ca.pem", isURL: true},
	}, sources)
}

func TestCaSourcesIncludesConfiguredCertificates(t *testing.T) {
	setCASources(t, "https://mozilla.example/ca.pem", "https://smart.example/ca.pem")
	base := writeConfig(t,
		"# CA certificates of the company, added to the store\n"+
			"ca-certificate https://intranet.example/ca.pem\n"+
			"ca-certificate ~/certs/company.pem\n"+
			"ca-certificate file:///etc/pki/tls/certs/local.pem\n"+
			"ca-certificate /var/lib/pivzavr/other.pem\n")
	t.Setenv(ConfigDirEnv, base)

	home, err := os.UserHomeDir()
	require.NoError(t, err)

	sources, err := caSources()
	require.NoError(t, err)
	assert.Equal(t, []trustSource{
		{location: "https://mozilla.example/ca.pem", isURL: true, required: true},
		{location: "https://smart.example/ca.pem", isURL: true},
		{location: "https://intranet.example/ca.pem", isURL: true, required: true},
		{location: filepath.Join(home, "certs", "company.pem"), required: true},
		{location: "/etc/pki/tls/certs/local.pem", required: true},
		{location: "/var/lib/pivzavr/other.pem", required: true},
	}, sources)
}

func TestPublicKeySources(t *testing.T) {
	t.Setenv(ConfigDirEnv, t.TempDir())

	sources, err := publicKeySources()
	require.NoError(t, err)
	assert.Empty(t, sources)
}

func TestPublicKeySourcesIncludesConfiguredKeys(t *testing.T) {
	base := writeConfig(t,
		"# public keys of the signing card\n"+
			"public-key https://intranet.example/signer.pem\n"+
			"public-key ~/keys/signer.pem\n"+
			"public-key file:///etc/pivzavr/signer.pem\n"+
			"public-key /var/lib/pivzavr/signer.der\n")
	t.Setenv(ConfigDirEnv, base)

	home, err := os.UserHomeDir()
	require.NoError(t, err)

	sources, err := publicKeySources()
	require.NoError(t, err)
	assert.Equal(t, []trustSource{
		{location: "https://intranet.example/signer.pem", isURL: true, required: true},
		{location: filepath.Join(home, "keys", "signer.pem"), required: true},
		{location: "/etc/pivzavr/signer.pem", required: true},
		{location: "/var/lib/pivzavr/signer.der", required: true},
	}, sources)
}

func TestUpdateTrustAddsConfiguredFile(t *testing.T) {
	mozilla, _ := testcert.Identity(t)
	company, _ := testcert.Identity(t)

	server := httptest.NewServer(certificateHandler(mozilla))
	defer server.Close()
	setCASources(t, server.URL)

	certFile := filepath.Join(t.TempDir(), "company.pem")
	require.NoError(t, os.WriteFile(certFile, testcert.PEM(company), 0o600))
	base := writeConfig(t, "ca-certificate "+certFile+"\n")
	t.Setenv(ConfigDirEnv, base)

	path, err := UpdateTrust()
	require.NoError(t, err)

	// The configured certificate is part of the store.
	pool := readCAPool(t, path)
	assert.Equal(t, 2, countCertificates(t, path))
	assert.NoError(t, testcert.Trust(mozilla, pool))
	assert.NoError(t, testcert.Trust(company, pool))
}

func TestUpdateTrustAddsConfiguredDERFile(t *testing.T) {
	mozilla, _ := testcert.Identity(t)
	company, _ := testcert.Identity(t)

	server := httptest.NewServer(certificateHandler(mozilla))
	defer server.Close()
	setCASources(t, server.URL)

	certFile := filepath.Join(t.TempDir(), "company.der")
	require.NoError(t, os.WriteFile(certFile, company.Raw, 0o600))
	t.Setenv(ConfigDirEnv, writeConfig(t, "ca-certificate "+certFile+"\n"))

	path, err := UpdateTrust()
	require.NoError(t, err)

	pool := readCAPool(t, path)
	assert.Equal(t, 2, countCertificates(t, path))
	assert.NoError(t, testcert.Trust(company, pool))
}

func TestUpdateTrustFailsOnMissingConfiguredFile(t *testing.T) {
	mozilla, _ := testcert.Identity(t)

	server := httptest.NewServer(certificateHandler(mozilla))
	defer server.Close()
	setCASources(t, server.URL)

	base := writeConfig(t, "ca-certificate "+filepath.Join(t.TempDir(), "missing.pem")+"\n")
	t.Setenv(ConfigDirEnv, base)

	// A configured source is required, so an update that cannot read it fails
	// instead of storing a store without it.
	_, err := UpdateTrust()
	require.Error(t, err)
	assert.NoFileExists(t, filepath.Join(base, configDirName, trustFileName))
}

func TestUpdateTrustFailsOnUnavailableConfiguredURL(t *testing.T) {
	mozilla, _ := testcert.Identity(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/mozilla.pem", certificateHandler(mozilla))
	mux.HandleFunc("/company.pem", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	setCASources(t, server.URL+"/mozilla.pem")
	base := writeConfig(t, "ca-certificate "+server.URL+"/company.pem\n")
	t.Setenv(ConfigDirEnv, base)

	_, err := UpdateTrust()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/company.pem")
	assert.NoFileExists(t, filepath.Join(base, configDirName, trustFileName))
}

func TestUpdateTrustAddsConfiguredPublicKey(t *testing.T) {
	mozilla, _ := testcert.Identity(t)
	key := keyPair(t)

	server := httptest.NewServer(certificateHandler(mozilla))
	defer server.Close()
	setCASources(t, server.URL)

	der, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)
	keyFile := filepath.Join(t.TempDir(), "signer.pem")
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600))
	t.Setenv(ConfigDirEnv, writeConfig(t, "public-key "+keyFile+"\n"))

	path, err := UpdateTrust()
	require.NoError(t, err)
	assert.Equal(t, 1, countCertificates(t, path))
	require.Equal(t, 1, countPublicKeys(t, path))

	_, keys := readTrustStore(t, path)
	assert.True(t, trustedKey(t, key, keys))
}

func TestUpdateTrustReadsCertificateAsPublicKey(t *testing.T) {
	mozilla, _ := testcert.Identity(t)
	company, _ := testcert.Identity(t)

	server := httptest.NewServer(certificateHandler(mozilla))
	defer server.Close()
	setCASources(t, server.URL)

	// A certificate is accepted as a public key source, and contributes the
	// public key of the certificate rather than the certificate itself.
	certFile := filepath.Join(t.TempDir(), "signer.pem")
	require.NoError(t, os.WriteFile(certFile, testcert.PEM(company), 0o600))
	t.Setenv(ConfigDirEnv, writeConfig(t, "public-key "+certFile+"\n"))

	path, err := UpdateTrust()
	require.NoError(t, err)
	assert.Equal(t, 1, countCertificates(t, path))
	require.Equal(t, 1, countPublicKeys(t, path))

	_, keys := readTrustStore(t, path)
	assert.True(t, trustedKey(t, company.PublicKey, keys))
}

func TestUpdateTrustAddsPublicKeyFromURL(t *testing.T) {
	mozilla, _ := testcert.Identity(t)
	key := keyPair(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/mozilla.pem", certificateHandler(mozilla))
	mux.HandleFunc("/signer.pem", publicKeyHandler(key))
	server := httptest.NewServer(mux)
	defer server.Close()
	setCASources(t, server.URL+"/mozilla.pem")

	t.Setenv(ConfigDirEnv, writeConfig(t, "public-key "+server.URL+"/signer.pem\n"))

	path, err := UpdateTrust()
	require.NoError(t, err)
	require.Equal(t, 1, countPublicKeys(t, path))

	_, keys := readTrustStore(t, path)
	assert.True(t, trustedKey(t, key, keys))
}

func TestUpdateTrustDeduplicatesPublicKeys(t *testing.T) {
	mozilla, _ := testcert.Identity(t)
	key := keyPair(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/mozilla.pem", certificateHandler(mozilla))
	mux.HandleFunc("/signer.pem", publicKeyHandler(key))
	server := httptest.NewServer(mux)
	defer server.Close()
	setCASources(t, server.URL+"/mozilla.pem")

	// The same key is offered by two sources.
	t.Setenv(ConfigDirEnv, writeConfig(t,
		"public-key "+server.URL+"/signer.pem\n"+
			"public-key "+server.URL+"/signer.pem\n"))

	path, err := UpdateTrust()
	require.NoError(t, err)
	assert.Equal(t, 1, countPublicKeys(t, path))
}

func TestUpdateTrustFailsOnMissingConfiguredPublicKey(t *testing.T) {
	mozilla, _ := testcert.Identity(t)

	server := httptest.NewServer(certificateHandler(mozilla))
	defer server.Close()
	setCASources(t, server.URL)

	base := writeConfig(t, "public-key "+filepath.Join(t.TempDir(), "missing.pem")+"\n")
	t.Setenv(ConfigDirEnv, base)

	// A configured public key is required, so an update that cannot read it
	// fails instead of storing a store without it.
	_, err := UpdateTrust()
	require.Error(t, err)
	assert.NoFileExists(t, filepath.Join(base, configDirName, trustFileName))
}

func TestReadCAFile(t *testing.T) {
	cert, _ := testcert.Identity(t)

	t.Run("pem file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ca.pem")
		require.NoError(t, os.WriteFile(path, testcert.PEM(cert), 0o600))

		certs, err := readCAFile(path)
		require.NoError(t, err)
		require.Len(t, certs, 1)
		assert.Equal(t, cert.Raw, certs[0].Raw)
	})

	t.Run("der file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ca.der")
		require.NoError(t, os.WriteFile(path, cert.Raw, 0o600))

		certs, err := readCAFile(path)
		require.NoError(t, err)
		require.Len(t, certs, 1)
		assert.Equal(t, cert.Raw, certs[0].Raw)
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := readCAFile(filepath.Join(t.TempDir(), "missing.pem"))
		assert.Error(t, err)
	})
}

func TestReadPublicKeyFile(t *testing.T) {
	key := keyPair(t)
	der, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)

	t.Run("pem file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key.pem")
		require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600))

		keys, err := readPublicKeyFile(path)
		require.NoError(t, err)
		require.Len(t, keys, 1)
		assert.True(t, trustedKey(t, key, keys))
	})

	t.Run("der file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key.der")
		require.NoError(t, os.WriteFile(path, der, 0o600))

		keys, err := readPublicKeyFile(path)
		require.NoError(t, err)
		require.Len(t, keys, 1)
		assert.True(t, trustedKey(t, key, keys))
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := readPublicKeyFile(filepath.Join(t.TempDir(), "missing.pem"))
		assert.Error(t, err)
	})
}

func TestParseCertificates(t *testing.T) {
	cert, _ := testcert.Identity(t)

	t.Run("pem bundle with comments", func(t *testing.T) {
		var data bytes.Buffer
		data.WriteString("# Yubico PIV CA certificates\n")
		data.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		data.WriteString("\n# a trailing comment\n")

		certs, err := parseCertificates(data.Bytes())
		require.NoError(t, err)
		require.Len(t, certs, 1)
		assert.Equal(t, cert.Raw, certs[0].Raw)
	})

	t.Run("der certificate", func(t *testing.T) {
		certs, err := parseCertificates(cert.Raw)
		require.NoError(t, err)
		require.Len(t, certs, 1)
		assert.Equal(t, cert.Raw, certs[0].Raw)
	})

	t.Run("no certificates", func(t *testing.T) {
		_, err := parseCertificates([]byte("not a certificate"))
		assert.Error(t, err)
	})

	t.Run("broken certificate", func(t *testing.T) {
		block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("broken")})
		_, err := parseCertificates(block)
		assert.Error(t, err)
	})
}

func TestParsePublicKeys(t *testing.T) {
	key := keyPair(t)
	der, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)
	cert, _ := testcert.Identity(t)

	t.Run("pem public key", func(t *testing.T) {
		keys, err := parsePublicKeys(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		require.NoError(t, err)
		require.Len(t, keys, 1)
		assert.True(t, trustedKey(t, key, keys))
	})

	t.Run("pem rsa public key", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		block := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey),
		})

		keys, err := parsePublicKeys(block)
		require.NoError(t, err)
		require.Len(t, keys, 1)
		assert.True(t, trustedKey(t, &rsaKey.PublicKey, keys))
	})

	t.Run("pem certificate", func(t *testing.T) {
		keys, err := parsePublicKeys(testcert.PEM(cert))
		require.NoError(t, err)
		require.Len(t, keys, 1)
		assert.True(t, trustedKey(t, cert.PublicKey, keys))
	})

	t.Run("der public key", func(t *testing.T) {
		keys, err := parsePublicKeys(der)
		require.NoError(t, err)
		require.Len(t, keys, 1)
		assert.True(t, trustedKey(t, key, keys))
	})

	t.Run("bundle with comments", func(t *testing.T) {
		var data bytes.Buffer
		data.WriteString("# signer keys\n")
		data.Write(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		data.WriteString("\n# a trailing comment\n")

		keys, err := parsePublicKeys(data.Bytes())
		require.NoError(t, err)
		require.Len(t, keys, 1)
	})

	t.Run("several keys", func(t *testing.T) {
		other := keyPair(t)
		otherDER, err := x509.MarshalPKIXPublicKey(other)
		require.NoError(t, err)

		var data bytes.Buffer
		data.Write(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		data.Write(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherDER}))

		keys, err := parsePublicKeys(data.Bytes())
		require.NoError(t, err)
		require.Len(t, keys, 2)
	})

	t.Run("no keys", func(t *testing.T) {
		_, err := parsePublicKeys([]byte("not a key"))
		assert.Error(t, err)
	})

	t.Run("broken key", func(t *testing.T) {
		block := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("broken")})
		_, err := parsePublicKeys(block)
		assert.Error(t, err)
	})
}
