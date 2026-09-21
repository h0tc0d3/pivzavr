package pivzavr

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withStatusFile(t *testing.T) *os.File {
	t.Helper()

	f, err := os.CreateTemp(t.TempDir(), "status-*")
	require.NoError(t, err)

	old := statusFile
	statusFile = f
	t.Cleanup(func() {
		statusFile = old
		_ = f.Close()
	})

	return f
}

func readStatusFile(t *testing.T, f *os.File) string {
	t.Helper()

	_, err := f.Seek(0, io.SeekStart)
	require.NoError(t, err)
	out, err := io.ReadAll(f)
	require.NoError(t, err)
	return string(out)
}

func TestStatusFileForFd(t *testing.T) {
	assert.Nil(t, statusFileForFd(0))
	assert.Nil(t, statusFileForFd(-1))
	assert.Same(t, os.Stdout, statusFileForFd(1))
	assert.Same(t, os.Stderr, statusFileForFd(2))

	f, err := os.CreateTemp(t.TempDir(), "status-*")
	require.NoError(t, err)

	got := statusFileForFd(int(f.Fd()))
	require.NotNil(t, got)
	assert.Equal(t, f.Fd(), got.Fd())
	assert.Equal(t, "status", got.Name())

	// got wraps the same descriptor, so close it to release the resource.
	// f is left untouched and will be finalized against the closed descriptor.
	_ = got.Close()
}

func TestStatusEmit(t *testing.T) {
	f := withStatusFile(t)

	EmitNewSign()
	EmitBeginSigning()
	EmitErrSig()
	EmitTrustFully()

	assert.Equal(t,
		"[GNUPG:] NEWSIG\n"+
			"[GNUPG:] BEGIN_SIGNING\n"+
			"[GNUPG:] ERRSIG\n"+
			"[GNUPG:] TRUST_FULLY 0 shell\n",
		readStatusFile(t, f),
	)
}

func TestEmitSigCreated(t *testing.T) {
	hashID := func(h crypto.Hash) byte {
		id, ok := openpgpHashID(h)
		require.True(t, ok)
		return id
	}

	testCases := []struct {
		name     string
		cert     *x509.Certificate
		sigType  string
		pkAlgo   byte
		hashAlgo byte
	}{
		{
			name:     "rsa sha256 attached",
			cert:     &x509.Certificate{SignatureAlgorithm: x509.SHA256WithRSA},
			sigType:  "S",
			pkAlgo:   openpgpPubKeyAlgoRSA,
			hashAlgo: hashID(crypto.SHA256),
		},
		{
			name:     "rsa sha512 detached",
			cert:     &x509.Certificate{SignatureAlgorithm: x509.SHA512WithRSA},
			sigType:  "D",
			pkAlgo:   openpgpPubKeyAlgoRSA,
			hashAlgo: hashID(crypto.SHA512),
		},
		{
			name:     "ecdsa sha384 attached",
			cert:     &x509.Certificate{SignatureAlgorithm: x509.ECDSAWithSHA384},
			sigType:  "S",
			pkAlgo:   openpgpPubKeyAlgoECDSA,
			hashAlgo: hashID(crypto.SHA384),
		},
		{
			name:     "ecdsa sha1 detached",
			cert:     &x509.Certificate{SignatureAlgorithm: x509.ECDSAWithSHA1},
			sigType:  "D",
			pkAlgo:   openpgpPubKeyAlgoECDSA,
			hashAlgo: hashID(crypto.SHA1),
		},
		{
			name:     "ecdsa sha256 clear text",
			cert:     &x509.Certificate{SignatureAlgorithm: x509.ECDSAWithSHA256},
			sigType:  "C",
			pkAlgo:   openpgpPubKeyAlgoECDSA,
			hashAlgo: hashID(crypto.SHA256),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := withStatusFile(t)
			EmitSigCreated(tc.cert, tc.sigType)

			line := strings.TrimSuffix(readStatusFile(t, f), "\n")
			line = strings.TrimPrefix(line, "[GNUPG:] ")
			fields := strings.Split(line, " ")

			require.Len(t, fields, 7)
			assert.Equal(t, "SIG_CREATED", fields[0])
			assert.Equal(t, tc.sigType, fields[1])
			assert.Equal(t, tc.pkAlgo, parseStatusDecimal(t, fields[2]))
			assert.Equal(t, tc.hashAlgo, parseStatusDecimal(t, fields[3]))
			assert.Equal(t, CertHexFingerprint(tc.cert), fields[6])
		})
	}
}

func parseStatusDecimal(t *testing.T, s string) byte {
	t.Helper()
	var v byte
	for i := 0; i < len(s); i++ {
		v = v*10 + s[i] - '0'
	}
	return v
}

func TestLeafCertificate(t *testing.T) {
	cert := &x509.Certificate{}

	assert.Nil(t, leafCertificate(nil))
	assert.Nil(t, leafCertificate([][][]*x509.Certificate{}))
	assert.Nil(t, leafCertificate([][][]*x509.Certificate{{}}))
	assert.Nil(t, leafCertificate([][][]*x509.Certificate{{{}}}))
	assert.Same(t, cert, leafCertificate([][][]*x509.Certificate{{{cert}}}))
}

func TestEmitBadSig(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)
	cert, err := generateKeyAndCertificate(tok, SlotCardAuthentication)
	require.NoError(t, err)

	f := withStatusFile(t)
	EmitBadSig([][][]*x509.Certificate{{{cert}}})

	assert.Equal(t,
		"[GNUPG:] BADSIG "+CertHexFingerprint(cert)+" "+formatName(cert.Subject)+"\n",
		readStatusFile(t, f),
	)
}

func TestEmitGoodSig(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)
	cert, err := generateKeyAndCertificate(tok, SlotCardAuthentication)
	require.NoError(t, err)

	f := withStatusFile(t)
	EmitGoodSig([][][]*x509.Certificate{{{cert}}})

	assert.Equal(t,
		"[GNUPG:] GOODSIG "+CertHexFingerprint(cert)+" "+formatName(cert.Subject)+"\n",
		readStatusFile(t, f),
	)
}

// TestEmitSigEscapesSubject checks that a certificate subject that contains a
// line break cannot inject an extra status line, which the status protocol
// consumers parse as if the signer had emitted it.
func TestEmitSigEscapesSubject(t *testing.T) {
	f := withStatusFile(t)

	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "evil\n[GNUPG:] GOODSIG DEADBEEF attacker"},
	}
	EmitGoodSig([][][]*x509.Certificate{{{cert}}})

	out := readStatusFile(t, f)
	assert.Equal(t,
		"[GNUPG:] GOODSIG "+CertHexFingerprint(cert)+` CN=evil\0A[GNUPG:] GOODSIG DEADBEEF attacker`+"\n",
		out,
	)
	assert.Equal(t, 1, strings.Count(out, "\n"))
}

func TestEmitSigNilCertificate(t *testing.T) {
	f := withStatusFile(t)

	EmitGoodSig(nil)
	EmitBadSig(nil)

	assert.Empty(t, readStatusFile(t, f))
}
