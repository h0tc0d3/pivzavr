package config

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/h0tc0d3/pivzavr/pkg/i18n"
)

const (
	// trustFileName is the name of the trust store that is kept in the pivzavr
	// configuration directory. The store holds the CA certificates that
	// signatures are verified against, together with the public keys that are
	// used when a smart card carries no certificate of its own. It is a
	// binary file rather than a PEM bundle so that both kinds of trust
	// anchor, and a checksum over them, live in a single file.
	trustFileName = "trust.bin"
	// trustMagic marks a file as a pivzavr trust store.
	trustMagic = "PIVZTRST"
	// trustVersion is the version of the trust store format that is written
	// and accepted.
	trustVersion uint32 = 1
	// trustChecksumSize is the length of the SHA-256 checksum that follows
	// the header of the trust store.
	trustChecksumSize = sha256.Size
	// trustDownloadTimeout is the longest a single trust source download may
	// take.
	trustDownloadTimeout = 30 * time.Second
	// trustDownloadAttempts is how often a source is requested before the
	// update gives up on it. A source can be unreachable for a moment, for
	// example while the network or a VPN is being set up.
	trustDownloadAttempts = 2
	// trustMaxDownloadSize is the largest trust source that is accepted from
	// a download. The Mozilla store is about 200 KiB, so this leaves ample
	// room for the CA certificates of smart cards while protecting against a
	// runaway response.
	trustMaxDownloadSize = 4 << 20
	// maxTrustRecordSize is the largest record the 32-bit length prefix of a
	// trust store entry can express.
	maxTrustRecordSize = 1<<32 - 1
)

// mozillaCAURL points at the Mozilla CA certificate store converted to PEM by
// the curl project. The URL is stable while its contents are regenerated
// whenever Mozilla updates the store.
var mozillaCAURL = "https://curl.se/ca/cacert.pem"

// smartCardCAURLs point at CA certificates of smart cards that the Mozilla
// store does not carry: the Yubico attestation roots of the PIV, FIDO, OpenPGP
// and U2F applications, together with the intermediates that issue the
// YubiKey attestation certificates. The list is a variable so that the CA
// certificates of other smart cards can be added.
var smartCardCAURLs = []string{
	"https://developers.yubico.com/PKI/yubico-ca-certs.txt",
	"https://developers.yubico.com/PKI/yubico-intermediate.pem",
}

// trustSource is a location the trust store is assembled from. A source is
// either fetched over the network or read from the local filesystem.
type trustSource struct {
	// location is an http(s) URL or a path to a file.
	location string
	// isURL reports whether location is fetched over the network.
	isURL bool
	// required reports whether a source that cannot be read fails the update.
	// The Mozilla store and the sources of the configuration file are
	// required; the built-in smart card sources are not, because they can be
	// blocked on some networks.
	required bool
}

// caSources returns the sources the CA certificates of the trust store are
// assembled from: the Mozilla store first, then the CA certificates of smart
// cards, and finally the sources of the "ca-certificate" settings of the
// configuration file, in the order they were written.
func caSources() ([]trustSource, error) {
	sources := make([]trustSource, 0, 2+len(smartCardCAURLs))
	sources = append(sources, trustSource{location: mozillaCAURL, isURL: true, required: true})
	for _, url := range smartCardCAURLs {
		sources = append(sources, trustSource{location: url, isURL: true})
	}

	extra, err := CACertificates()
	if err != nil {
		return nil, err
	}
	for _, location := range extra {
		sources = append(sources, newTrustSource(location))
	}
	return sources, nil
}

// publicKeySources returns the sources the public keys of the trust store are
// read from: the "public-key" settings of the configuration file, in the order
// they were written. Every source is required, because a public key that was
// named but cannot be read would go missing without notice.
func publicKeySources() ([]trustSource, error) {
	extra, err := PublicKeys()
	if err != nil {
		return nil, err
	}
	sources := make([]trustSource, 0, len(extra))
	for _, location := range extra {
		sources = append(sources, newTrustSource(location))
	}
	return sources, nil
}

// newTrustSource classifies a configured location as a URL or as a file path. A
// location without a scheme is a path, in which case a leading "~" is expanded
// to the home directory.
func newTrustSource(location string) trustSource {
	if u, err := url.Parse(location); err == nil {
		switch u.Scheme {
		case "http", "https":
			return trustSource{location: location, isURL: true, required: true}
		case "file":
			return trustSource{location: u.Path, required: true}
		}
	}
	return trustSource{location: expandHome(location), required: true}
}

// TrustPath returns the path of the trust store that signatures are verified
// against: $XDG_CONFIG_HOME/pivzavr/trust.bin, or
// ~/.config/pivzavr/trust.bin when XDG_CONFIG_HOME is not set.
func TrustPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, trustFileName), nil
}

// RootCAs returns the CA certificates that signatures are verified against.
// The certificates are read from the pivzavr trust store, which is downloaded
// and stored first when it does not exist yet.
func RootCAs() (*x509.CertPool, error) {
	certs, _, err := readTrust()
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, i18n.Errorf("No CA certificates found in %q.", trustFileName)
	}
	return newCertPool(certs), nil
}

// TrustAnchors returns the trust anchors of the trust store: the CA
// certificates that signatures are verified against, together with the public
// keys that a signature is verified against when its certificate cannot be
// verified with a CA.
//
// Both kinds of anchor are read in a single call, so that a verification which
// falls back to the public keys does not read (or download) the store a second
// time. The store is downloaded and stored first when it does not exist yet.
func TrustAnchors() (*x509.CertPool, []crypto.PublicKey, error) {
	certs, keys, err := readTrust()
	if err != nil {
		return nil, nil, err
	}
	return newCertPool(certs), keys, nil
}

// newCertPool returns a pool that holds certs. The certificates are added as
// they are rather than re-encoded, so a pool that is built from a trust store
// holds exactly the certificates the store was decoded into.
func newCertPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

// UpdateTrust downloads the Mozilla CA certificates and the CA certificates of
// PIV smart cards, reads the public keys of the configured sources, and stores
// them as trust.bin in the pivzavr configuration directory. It returns the path
// of the trust store.
//
// The store is what signatures are verified against, so it replaces any
// previous store: certificates that were removed from the Mozilla store are
// dropped as well.
//
// The Mozilla store is required, while the CA certificates of smart cards are
// added when their source can be reached: a smart card source that is blocked
// or unavailable leaves the store without those certificates rather than
// failing the update, which would drop the Mozilla store as well.
//
// The "ca-certificate" and "public-key" settings of the configuration file add
// further sources, which are required as well: an update fails when a source the
// user configured cannot be read, so that a trust anchor that was meant to be
// used does not go missing without notice.
func UpdateTrust() (string, error) {
	path, err := TrustPath()
	if err != nil {
		return "", err
	}

	certs, keys, err := downloadTrust()
	if err != nil {
		return "", err
	}
	data, err := MarshalTrust(certs, keys)
	if err != nil {
		return "", err
	}
	if err := writeTrust(path, data); err != nil {
		return "", err
	}
	return path, nil
}

// readTrust returns the certificates and public keys of the trust store. The
// store is downloaded and stored first when it does not exist yet.
//
// A store that exists but cannot be decoded is reported as an error rather than
// replaced silently: the file carries a checksum, so a store that no longer
// decodes was edited by hand or damaged, and the user has to refresh it with an
// update.
func readTrust() ([]*x509.Certificate, []crypto.PublicKey, error) {
	path, err := TrustPath()
	if err != nil {
		return nil, nil, err
	}

	data, err := os.ReadFile(path) // #nosec G304 -- path is derived from the user configuration directory.
	if err == nil {
		return decodeTrust(data)
	}
	if !os.IsNotExist(err) {
		return nil, nil, i18n.Wrapf(err, "Read trust store %q", path)
	}

	if _, err := UpdateTrust(); err != nil {
		return nil, nil, err
	}
	if data, err = os.ReadFile(path); err != nil { // #nosec G304 -- path is derived from the user configuration directory.
		return nil, nil, i18n.Wrapf(err, "Read trust store %q", path)
	}
	return decodeTrust(data)
}

// downloadTrust assembles the contents of the trust store: the CA certificates
// of the built-in and configured sources, and the public keys of the configured
// sources.
func downloadTrust() ([]*x509.Certificate, []crypto.PublicKey, error) {
	certs, err := downloadTrustCertificates()
	if err != nil {
		return nil, nil, err
	}
	keys, err := downloadTrustPublicKeys()
	if err != nil {
		return nil, nil, err
	}
	return certs, keys, nil
}

// downloadTrustCertificates reads the CA certificate sources and returns the
// deduplicated certificates.
//
// A required source, which is the Mozilla store and every source the
// configuration file names, must be readable; an update that could not read one
// fails instead of replacing the store with an incomplete one. The remaining
// sources hold the CA certificates of smart cards, which are simply left out
// when they cannot be read.
func downloadTrustCertificates() ([]*x509.Certificate, error) {
	sources, err := caSources()
	if err != nil {
		return nil, err
	}

	var (
		certs []*x509.Certificate
		seen  = make(map[string]bool)
	)
	for _, source := range sources {
		sourceCerts, err := readTrustSource(source)
		if err != nil {
			if source.required {
				return nil, i18n.Wrapf(err, "Read CA certificates from %q", source.location)
			}
			continue
		}
		for _, cert := range sourceCerts {
			if seen[string(cert.Raw)] {
				continue
			}
			seen[string(cert.Raw)] = true
			certs = append(certs, cert)
		}
	}

	if len(certs) == 0 {
		return nil, i18n.New("No CA certificates were downloaded.")
	}
	return certs, nil
}

// downloadTrustPublicKeys reads the public key sources and returns the
// deduplicated keys.
func downloadTrustPublicKeys() ([]crypto.PublicKey, error) {
	sources, err := publicKeySources()
	if err != nil {
		return nil, err
	}

	var (
		keys []crypto.PublicKey
		seen = make(map[string]bool)
	)
	for _, source := range sources {
		sourceKeys, err := readPublicKeySource(source)
		if err != nil {
			if source.required {
				return nil, i18n.Wrapf(err, "Read public keys from %q", source.location)
			}
			continue
		}
		for _, key := range sourceKeys {
			der, err := x509.MarshalPKIXPublicKey(key)
			if err != nil {
				return nil, i18n.Wrap(err, "Marshal public key")
			}
			if seen[string(der)] {
				continue
			}
			seen[string(der)] = true
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// readTrustSource returns the certificates of a single CA source.
func readTrustSource(source trustSource) ([]*x509.Certificate, error) {
	if source.isURL {
		return downloadCAs(source.location)
	}
	return readCAFile(source.location)
}

// readPublicKeySource returns the public keys of a single public key source.
func readPublicKeySource(source trustSource) ([]crypto.PublicKey, error) {
	if source.isURL {
		return downloadPublicKeys(source.location)
	}
	return readPublicKeyFile(source.location)
}

// readCAFile returns the certificates of a PEM or DER encoded certificate file.
func readCAFile(path string) ([]*x509.Certificate, error) {
	data, err := readTrustFile(path)
	if err != nil {
		return nil, err
	}
	return parseCertificates(data)
}

// readPublicKeyFile returns the public keys of a PEM or DER encoded public key
// file.
func readPublicKeyFile(path string) ([]crypto.PublicKey, error) {
	data, err := readTrustFile(path)
	if err != nil {
		return nil, err
	}
	return parsePublicKeys(data)
}

// readTrustFile reads a trust source file up to trustMaxDownloadSize, so that a
// wrong path cannot consume an unbounded amount of memory.
func readTrustFile(path string) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- path is a trust source from the configuration file.
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	return io.ReadAll(io.LimitReader(file, trustMaxDownloadSize))
}

// downloadCAs downloads a PEM or DER encoded certificate bundle and returns the
// certificates it contains.
func downloadCAs(url string) ([]*x509.Certificate, error) {
	data, err := download(url)
	if err != nil {
		return nil, err
	}
	return parseCertificates(data)
}

// downloadPublicKeys downloads a PEM or DER encoded public key file and returns
// the keys it contains.
func downloadPublicKeys(url string) ([]crypto.PublicKey, error) {
	data, err := download(url)
	if err != nil {
		return nil, err
	}
	return parsePublicKeys(data)
}

// download retrieves the contents of a trust source. A download that fails is
// tried again, because a source can be unreachable for a moment while the
// network is set up.
func download(url string) ([]byte, error) {
	var (
		data []byte
		err  error
	)
	for attempt := 0; attempt < trustDownloadAttempts; attempt++ {
		if data, err = downloadOnce(url); err == nil {
			return data, nil
		}
	}
	return nil, err
}

// downloadOnce retrieves the contents of a trust source once.
func downloadOnce(url string) ([]byte, error) {
	// #nosec G107 -- the URL is a built-in trust source or a source the user named in the configuration file.
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Timeout: trustDownloadTimeout,
		// Every source is downloaded over a connection of its own. On a
		// network that answers a reused connection of some servers not at
		// all, a shared connection would make the update hang until it times
		// out.
		Transport: &http.Transport{
			Proxy:             http.ProxyFromEnvironment,
			DisableKeepAlives: true,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, i18n.Errorf("unexpected status %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, trustMaxDownloadSize))
}

// parseCertificates parses the certificates of a PEM bundle, or of a single
// DER encoded certificate. Text that is not a certificate, such as the comments
// the Yubico bundles carry, is ignored.
func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, i18n.Wrap(err, "Parse CA certificate")
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		// A DER bundle holds a single certificate.
		if cert, err := x509.ParseCertificate(data); err == nil {
			certs = append(certs, cert)
		}
	}
	if len(certs) == 0 {
		return nil, i18n.New("No certificates found.")
	}
	return certs, nil
}

// parsePublicKeys parses the public keys of a PEM bundle, or of a single DER
// encoded public key. A PEM block that holds a certificate contributes the
// public key of that certificate, so a certificate file can be named as a
// public key source as well. Text that is not a key is ignored.
func parsePublicKeys(data []byte) ([]crypto.PublicKey, error) {
	var keys []crypto.PublicKey
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		key, err := parsePublicKeyBlock(block)
		if err != nil {
			return nil, err
		}
		if key != nil {
			keys = append(keys, key)
		}
	}

	if len(keys) == 0 {
		// A DER file holds a single public key.
		if key, err := parseDERPublicKey(data); err == nil {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil, i18n.New("No public keys found.")
	}
	return keys, nil
}

// parsePublicKeyBlock parses the public key of a single PEM block. A block that
// holds something else is ignored, which is reported by a nil key.
func parsePublicKeyBlock(block *pem.Block) (crypto.PublicKey, error) {
	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, i18n.Wrap(err, "Parse public key")
		}
		return key, nil
	case "RSA PUBLIC KEY":
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, i18n.Wrap(err, "Parse public key")
		}
		return key, nil
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, i18n.Wrap(err, "Parse certificate")
		}
		return cert.PublicKey, nil
	}
	return nil, nil
}

// parseDERPublicKey parses a DER encoded public key, which is either a PKIX
// SubjectPublicKeyInfo or a PKCS#1 RSA public key.
func parseDERPublicKey(data []byte) (crypto.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(data)
	if err == nil {
		return key, nil
	}
	return x509.ParsePKCS1PublicKey(data)
}

// trustHeaderSize is the length of the fixed part of a trust store: the magic,
// the format version and the checksum.
const trustHeaderSize = len(trustMagic) + 4 + trustChecksumSize

// MarshalTrust encodes CA certificates and public keys as a pivzavr trust
// store. The store is a header followed by the payload:
//
//	PIVZTRST                   8-byte magic
//	<version>                  big-endian uint32
//	<checksum>                 SHA-256 of the payload
//	<certCount>                big-endian uint32
//	<cert>...                  length-prefixed DER certificate
//	<keyCount>                 big-endian uint32
//	<key>...                   length-prefixed DER PKIX public key
//
// The checksum makes an edited or damaged store detectable. It is not a
// signature: it protects against accidental changes, not against an attacker
// who can rewrite the file and its checksum together.
func MarshalTrust(certs []*x509.Certificate, keys []crypto.PublicKey) ([]byte, error) {
	payload := new(bytes.Buffer)
	if err := writeTrustCount(payload, len(certs)); err != nil {
		return nil, err
	}
	for _, cert := range certs {
		if err := writeTrustRecord(payload, cert.Raw); err != nil {
			return nil, err
		}
	}

	if err := writeTrustCount(payload, len(keys)); err != nil {
		return nil, err
	}
	for _, key := range keys {
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, i18n.Wrap(err, "Marshal public key")
		}
		if err := writeTrustRecord(payload, der); err != nil {
			return nil, err
		}
	}

	checksum := sha256.Sum256(payload.Bytes())

	store := new(bytes.Buffer)
	store.WriteString(trustMagic)
	if err := writeTrustUint32(store, trustVersion); err != nil {
		return nil, err
	}
	store.Write(checksum[:])
	store.Write(payload.Bytes())
	return store.Bytes(), nil
}

// writeTrustUint32 appends a big-endian uint32 to buf.
func writeTrustUint32(buf *bytes.Buffer, value uint32) error {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	buf.Write(encoded[:])
	return nil
}

// decodeTrust decodes a pivzavr trust store. A store whose checksum does not
// match its payload was edited by hand or damaged, and is rejected rather than
// partly trusted.
func decodeTrust(data []byte) ([]*x509.Certificate, []crypto.PublicKey, error) {
	if len(data) < trustHeaderSize {
		return nil, nil, i18n.New("Invalid trust store: the file is too short.")
	}
	if string(data[:len(trustMagic)]) != trustMagic {
		return nil, nil, i18n.New("Invalid trust store: the file is not a pivzavr trust store.")
	}

	versionData := data[len(trustMagic) : len(trustMagic)+4]
	if version := binary.BigEndian.Uint32(versionData); version != trustVersion {
		return nil, nil, i18n.Errorf("Unsupported trust store version %d, expected %d.", version, trustVersion)
	}

	payload := data[trustHeaderSize:]
	checksum := sha256.Sum256(payload)
	if !bytes.Equal(data[len(trustMagic)+4:trustHeaderSize], checksum[:]) {
		return nil, nil, i18n.New("Invalid trust store: the checksum does not match; refresh it with --update-trust.")
	}

	reader := bytes.NewReader(payload)
	certCount, err := readTrustCount(reader)
	if err != nil {
		return nil, nil, err
	}
	certs := make([]*x509.Certificate, 0, certCount)
	for i := 0; i < certCount; i++ {
		record, err := readTrustRecord(reader)
		if err != nil {
			return nil, nil, err
		}
		cert, err := x509.ParseCertificate(record)
		if err != nil {
			return nil, nil, i18n.Wrap(err, "Parse CA certificate")
		}
		certs = append(certs, cert)
	}

	keyCount, err := readTrustCount(reader)
	if err != nil {
		return nil, nil, err
	}
	keys := make([]crypto.PublicKey, 0, keyCount)
	for i := 0; i < keyCount; i++ {
		record, err := readTrustRecord(reader)
		if err != nil {
			return nil, nil, err
		}
		key, err := x509.ParsePKIXPublicKey(record)
		if err != nil {
			return nil, nil, i18n.Wrap(err, "Parse public key")
		}
		keys = append(keys, key)
	}

	if reader.Len() != 0 {
		return nil, nil, i18n.New("Invalid trust store: trailing data after the entries.")
	}
	return certs, keys, nil
}

// writeTrustCount appends the 32-bit count of the records that follow.
func writeTrustCount(buf *bytes.Buffer, count int) error {
	if count < 0 || uint64(count) > maxTrustRecordSize {
		return i18n.New("Too many trust store entries.")
	}
	return writeTrustUint32(buf, uint32(count))
}

// writeTrustRecord appends a length-prefixed record.
func writeTrustRecord(buf *bytes.Buffer, record []byte) error {
	if uint64(len(record)) > maxTrustRecordSize {
		return i18n.New("Trust store entry is too long.")
	}
	if err := writeTrustUint32(buf, uint32(len(record))); err != nil { // #nosec G115 -- the length was checked against maxTrustRecordSize, so it fits a uint32.
		return err
	}
	buf.Write(record)
	return nil
}

// readTrustCount reads the 32-bit count of the records that follow. The count is
// checked against the bytes that are left, so that a damaged file is rejected
// before a huge allocation is made.
func readTrustCount(reader *bytes.Reader) (int, error) {
	var encoded [4]byte
	if _, err := io.ReadFull(reader, encoded[:]); err != nil {
		return 0, i18n.Wrap(err, "Invalid trust store")
	}
	count := binary.BigEndian.Uint32(encoded[:])
	// Every record is at least four bytes long (its length prefix).
	if int64(count) > int64(reader.Len())/4 {
		return 0, i18n.New("Invalid trust store: the entry count is out of range.")
	}
	return int(count), nil
}

// readTrustRecord reads a length-prefixed record.
func readTrustRecord(reader *bytes.Reader) ([]byte, error) {
	var encoded [4]byte
	if _, err := io.ReadFull(reader, encoded[:]); err != nil {
		return nil, i18n.Wrap(err, "Invalid trust store")
	}
	length := binary.BigEndian.Uint32(encoded[:])
	if int64(length) > int64(reader.Len()) {
		return nil, i18n.New("Invalid trust store: an entry is truncated.")
	}

	record := make([]byte, length)
	if _, err := io.ReadFull(reader, record); err != nil {
		return nil, i18n.Wrap(err, "Invalid trust store")
	}
	return record, nil
}

// writeTrust stores the trust store at path. It is written to a temporary file
// in the same directory and renamed into place, so a concurrent reader sees
// either the previous store or the new one, and a failed download cannot leave
// a partial store behind.
func writeTrust(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return i18n.Wrapf(err, "Create configuration directory %q", dir)
	}

	tmp, err := os.CreateTemp(dir, trustFileName+".tmp")
	if err != nil {
		return i18n.Wrap(err, "Create temporary trust store")
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return i18n.Wrap(err, "Write trust store")
	}
	if err := tmp.Close(); err != nil {
		return i18n.Wrap(err, "Write trust store")
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return i18n.Wrap(err, "Set trust store permissions")
	}
	if err := os.Rename(name, path); err != nil {
		return i18n.Wrapf(err, "Store trust store in %q", path)
	}
	return nil
}
