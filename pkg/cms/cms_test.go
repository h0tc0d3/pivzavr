package cms

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/h0tc0d3/pivzavr/pkg/testcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// verifyOptions returns verify options that trust cert as a root.
func verifyOptions(cert *x509.Certificate) x509.VerifyOptions {
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return x509.VerifyOptions{Roots: roots}
}

func TestSignersReportMetadata(t *testing.T) {
	cert, signer := testcert.Identity(t)
	before := time.Now().Add(-time.Second)

	sd, err := NewSignedData([]byte("hello metadata"))
	require.NoError(t, err)
	require.NoError(t, sd.Sign([]*x509.Certificate{cert}, signer))

	details, err := sd.Signers()
	require.NoError(t, err)
	require.Len(t, details, 1)

	// The signing time is taken from the signing-time signed attribute, which
	// every signature carries.
	assert.False(t, details[0].SigningTime.IsZero())
	assert.WithinDuration(t, before, details[0].SigningTime, time.Minute)
	assert.WithinDuration(t, time.Now(), details[0].SigningTime, time.Minute)
	assert.NotEqual(t, x509.UnknownSignatureAlgorithm, details[0].SignatureAlgorithm)
	assert.False(t, details[0].DigestAlgorithm.Algorithm.Equal(asn1.ObjectIdentifier{}))
}

func TestSignersOfSignatureWithoutSigningTime(t *testing.T) {
	cert, signer := testcert.Identity(t)

	sd, err := NewSignedData([]byte("hello metadata"))
	require.NoError(t, err)
	require.NoError(t, sd.Sign([]*x509.Certificate{cert}, signer))

	// A signature that does not carry the attribute reports the zero time
	// rather than an error, so that a report of a signature never fails on
	// metadata alone.
	sd.sd.SignerInfos[0].SignedAttrs = nil
	details, err := sd.Signers()
	require.NoError(t, err)
	require.Len(t, details, 1)
	assert.True(t, details[0].SigningTime.IsZero())
}

func TestSignVerifyAttached(t *testing.T) {
	cert, signer := testcert.Identity(t)
	message := []byte("hello attached world")

	sd, err := NewSignedData(message)
	require.NoError(t, err)
	require.NoError(t, sd.Sign([]*x509.Certificate{cert}, signer))

	assert.False(t, sd.IsDetached())

	data, err := sd.GetData()
	require.NoError(t, err)
	assert.Equal(t, message, data)

	certs, err := sd.GetCertificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, cert.Raw, certs[0].Raw)

	der, err := sd.ToDER()
	require.NoError(t, err)

	parsed, err := ParseSignedData(der)
	require.NoError(t, err)
	chains, err := parsed.Verify(verifyOptions(cert))
	require.NoError(t, err)
	require.Len(t, chains, 1)
	assert.Equal(t, cert.Raw, chains[0][0][0].Raw)

	// A detached verification must be rejected for an attached signature.
	_, err = parsed.VerifyDetached(message, verifyOptions(cert))
	assert.Error(t, err)
}

func TestSignVerifyDetached(t *testing.T) {
	cert, signer := testcert.Identity(t)
	message := []byte("hello detached world")

	sd, err := NewSignedData(message)
	require.NoError(t, err)
	require.NoError(t, sd.Sign([]*x509.Certificate{cert}, signer))
	sd.Detached()

	assert.True(t, sd.IsDetached())

	data, err := sd.GetData()
	require.NoError(t, err)
	assert.Nil(t, data)

	der, err := sd.ToDER()
	require.NoError(t, err)

	parsed, err := ParseSignedData(der)
	require.NoError(t, err)
	require.True(t, parsed.IsDetached())

	chains, err := parsed.VerifyDetached(message, verifyOptions(cert))
	require.NoError(t, err)
	require.Len(t, chains, 1)

	// Wrong message.
	_, err = parsed.VerifyDetached([]byte("different"), verifyOptions(cert))
	assert.Error(t, err)

	// Attached verification must be rejected for a detached signature.
	_, err = parsed.Verify(verifyOptions(cert))
	assert.Error(t, err)
}

func TestSignVerifyRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert, signer := testcert.Certificate(t, key)
	message := []byte("rsa message")

	sd, err := NewSignedData(message)
	require.NoError(t, err)
	require.NoError(t, sd.Sign([]*x509.Certificate{cert}, signer))

	der, err := sd.ToDER()
	require.NoError(t, err)

	parsed, err := ParseSignedData(der)
	require.NoError(t, err)
	_, err = parsed.Verify(verifyOptions(cert))
	require.NoError(t, err)
}
func TestSetCertificates(t *testing.T) {
	cert, _ := testcert.Identity(t)
	sd, err := NewSignedData([]byte("data"))
	require.NoError(t, err)

	require.NoError(t, sd.SetCertificates([]*x509.Certificate{cert}))
	certs, err := sd.GetCertificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)

	// Setting the same certificate again must not duplicate it.
	require.NoError(t, sd.SetCertificates([]*x509.Certificate{cert}))
	certs, err = sd.GetCertificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)

	require.NoError(t, sd.SetCertificates(nil))
	certs, err = sd.GetCertificates()
	require.NoError(t, err)
	assert.Empty(t, certs)
}

func TestSignNoMatchingCertificate(t *testing.T) {
	_, signer := testcert.Identity(t)
	otherCert, _ := testcert.Identity(t)

	sd, err := NewSignedData([]byte("data"))
	require.NoError(t, err)

	err = sd.Sign([]*x509.Certificate{otherCert}, signer)
	assert.ErrorIs(t, err, errNoCertificate)
}

func TestSignAfterDetach(t *testing.T) {
	cert, signer := testcert.Identity(t)

	sd, err := NewSignedData([]byte("data"))
	require.NoError(t, err)
	sd.Detached()

	err = sd.Sign([]*x509.Certificate{cert}, signer)
	assert.Error(t, err)
}

func TestGetDataWrongType(t *testing.T) {
	eci, err := newEncapsulatedContentInfo(oidContentTypeTSTInfo, []byte{0x30, 0x00})
	require.NoError(t, err)

	sd := &SignedData{sd: newSignedData(eci)}
	_, err = sd.GetData()
	assert.ErrorIs(t, err, errWrongType)
}

func TestParseSignedDataErrors(t *testing.T) {
	_, err := ParseSignedData(nil)
	assert.Error(t, err)

	_, err = ParseSignedData([]byte{0x01, 0x02, 0x03})
	assert.Error(t, err)

	// A ContentInfo whose contentType is id-data is not signedData.
	inner := []byte{0x30, 0x00}
	ci := contentInfo{
		ContentType: oidContentTypeData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			Bytes:      inner,
			IsCompound: true,
		},
	}
	der, err := asn1.Marshal(ci)
	require.NoError(t, err)

	_, err = ParseSignedData(der)
	assert.ErrorIs(t, err, errWrongType)
}

func TestFindCertificate(t *testing.T) {
	cert, _ := testcert.Identity(t)

	// Version 1: issuerAndSerialNumber.
	sid, err := newIssuerAndSerialNumber(cert)
	require.NoError(t, err)
	v1 := signerInfo{Version: 1, SID: sid}
	found, err := v1.findCertificate([]*x509.Certificate{cert})
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, found.Raw)

	// Version 3: subjectKeyIdentifier.
	v3 := signerInfo{
		Version: 3,
		SID:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: cert.SubjectKeyId},
	}
	found, err = v3.findCertificate([]*x509.Certificate{cert})
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, found.Raw)

	// Unknown version.
	v9 := signerInfo{Version: 9}
	_, err = v9.findCertificate([]*x509.Certificate{cert})
	assert.ErrorIs(t, err, errUnsupported)

	// No matching certificate.
	otherCert, _ := testcert.Identity(t)
	_, err = v1.findCertificate([]*x509.Certificate{otherCert})
	assert.ErrorIs(t, err, errNoCertificate)
}

func TestVerifyTamperedContent(t *testing.T) {
	cert, signer := testcert.Identity(t)

	sd, err := NewSignedData([]byte("original message"))
	require.NoError(t, err)
	require.NoError(t, sd.Sign([]*x509.Certificate{cert}, signer))

	der, err := sd.ToDER()
	require.NoError(t, err)
	parsed, err := ParseSignedData(der)
	require.NoError(t, err)

	// Replace the content; the MessageDigest attribute no longer matches.
	tampered, err := newDataEncapsulatedContentInfo([]byte("tampered message"))
	require.NoError(t, err)
	parsed.sd.EncapContentInfo = tampered

	_, err = parsed.Verify(verifyOptions(cert))
	assert.Error(t, err)
}

func TestVerifyTamperedSignature(t *testing.T) {
	cert, signer := testcert.Identity(t)

	sd, err := NewSignedData([]byte("message"))
	require.NoError(t, err)
	require.NoError(t, sd.Sign([]*x509.Certificate{cert}, signer))

	der, err := sd.ToDER()
	require.NoError(t, err)
	parsed, err := ParseSignedData(der)
	require.NoError(t, err)

	parsed.sd.SignerInfos[0].Signature[0] ^= 0xff

	_, err = parsed.Verify(verifyOptions(cert))
	assert.Error(t, err)
}

func mustBER(t *testing.T, ber []byte) []byte {
	t.Helper()
	der, err := berToDER(ber)
	require.NoError(t, err)
	return der
}

func TestBERToDER(t *testing.T) {
	// Definite short form is passed through unchanged.
	assert.Equal(t, []byte{0x02, 0x01, 0x2a}, mustBER(t, []byte{0x02, 0x01, 0x2a}))

	// Indefinite length SEQUENCE becomes a definite length SEQUENCE.
	assert.Equal(t,
		[]byte{0x30, 0x03, 0x02, 0x01, 0x01},
		mustBER(t, []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00}))

	// Long form length is preserved.
	content := bytes.Repeat([]byte{0xff}, 200)
	berLong := append([]byte{0x04, 0x81, 0xc8}, content...)
	assert.Equal(t, berLong, mustBER(t, berLong))

	// High tag number.
	assert.Equal(t, []byte{0x3f, 0x1f, 0x00}, mustBER(t, []byte{0x3f, 0x1f, 0x00}))

	// Errors.
	_, err := berToDER(nil)
	assert.Error(t, err)
	_, err = berToDER([]byte{0x30})
	assert.Error(t, err)
	_, err = berToDER([]byte{0x30, 0x81})
	assert.Error(t, err)
	_, err = berToDER([]byte{0x30, 0x82, 0x00, 0x01})
	assert.Error(t, err)
	_, err = berToDER([]byte{0x30, 0x05, 0x02, 0x01})
	assert.Error(t, err)
	_, err = berToDER([]byte{0x04, 0x80, 0x00, 0x00})
	assert.Error(t, err)
}

func TestBERToDERMaxDepth(t *testing.T) {
	// Nesting up to the limit is accepted.
	depth := maxBERDepth
	nested := bytes.Repeat([]byte{0x30, 0x80}, depth)
	nested = append(nested, bytes.Repeat([]byte{0x00, 0x00}, depth)...)
	_, err := berToDER(nested)
	assert.NoError(t, err)

	// Deeper nesting is rejected instead of exhausting the stack.
	depth = maxBERDepth + 2
	tooDeep := bytes.Repeat([]byte{0x30, 0x80}, depth)
	tooDeep = append(tooDeep, bytes.Repeat([]byte{0x00, 0x00}, depth)...)
	_, err = berToDER(tooDeep)
	assert.Error(t, err)
}

func TestTimestampRequestDo(t *testing.T) {
	imprint, err := newMessageImprint(crypto.SHA256, bytes.NewReader([]byte("data")))
	require.NoError(t, err)
	req := timeStampReq{Version: 1, MessageImprint: imprint, CertReq: true, Nonce: big.NewInt(1)}

	// SEQUENCE { PKIStatusInfo { status granted(0) } }, a TimeStampResp that
	// carries no token.
	okBody := []byte{0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00}

	testCases := []struct {
		name        string
		contentType string
		status      int
		body        []byte
		wantErr     bool
	}{
		{name: "granted", contentType: contentTypeTSReply, status: http.StatusOK, body: okBody},
		{name: "unexpected status", contentType: contentTypeTSReply, status: http.StatusInternalServerError, body: okBody, wantErr: true},
		{name: "unexpected content type", contentType: "application/octet-stream", status: http.StatusOK, body: okBody, wantErr: true},
		{name: "response too large", contentType: contentTypeTSReply, status: http.StatusOK, body: make([]byte, timestampMaxResponseSize+1), wantErr: true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				_, _ = w.Write(tc.body)
			}))
			defer server.Close()

			resp, err := req.do(server.URL)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, 0, resp.Status.Status)
		})
	}
}

func TestSignedMessageFor(t *testing.T) {
	dataECI, err := newDataEncapsulatedContentInfo([]byte("content"))
	require.NoError(t, err)
	content := []byte("content")

	// Signed attributes are optional for id-data content.
	msg, err := signedMessageFor(signerInfo{}, content, dataECI)
	require.NoError(t, err)
	assert.Equal(t, content, msg)

	// They are required for any other content type.
	tstECI, err := newEncapsulatedContentInfo(oidContentTypeTSTInfo, []byte{0x30, 0x00})
	require.NoError(t, err)
	_, err = signedMessageFor(signerInfo{}, content, tstECI)
	assert.Error(t, err)

	// A mismatched ContentType attribute is rejected.
	contentType, err := newAttribute(oidAttrContentType, oidContentTypeTSTInfo)
	require.NoError(t, err)
	si := signerInfo{
		DigestAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidDigestSHA256},
		SignedAttrs:     attributes{contentType},
	}
	_, err = signedMessageFor(si, content, dataECI)
	assert.Error(t, err)
}

func TestMessageImprint(t *testing.T) {
	mi, err := newMessageImprint(crypto.SHA256, bytes.NewReader([]byte("abc")))
	require.NoError(t, err)

	hash, err := mi.hash()
	require.NoError(t, err)
	assert.Equal(t, crypto.SHA256, hash)

	other, err := newMessageImprint(crypto.SHA256, bytes.NewReader([]byte("abc")))
	require.NoError(t, err)
	assert.True(t, mi.equal(other))

	diff, err := newMessageImprint(crypto.SHA256, bytes.NewReader([]byte("abd")))
	require.NoError(t, err)
	assert.False(t, mi.equal(diff))

	// An unregistered hash is unsupported.
	_, err = newMessageImprint(crypto.MD4, bytes.NewReader(nil))
	assert.Error(t, err)
}

func TestAccuracyDuration(t *testing.T) {
	a := accuracy{Seconds: 1, Millis: 2, Micros: 3}
	assert.Equal(t, time.Second+2*time.Millisecond+3*time.Microsecond, a.duration())
}

func TestTSTInfoTimeBounds(t *testing.T) {
	now := time.Now()
	info := tstInfo{GenTime: now, Accuracy: accuracy{Seconds: 1}}

	assert.True(t, info.after(now.Add(-2*time.Second)))
	assert.False(t, info.after(now))
	assert.True(t, info.before(now.Add(2*time.Second)))
	assert.False(t, info.before(now))
}

func TestParseTSTInfo(t *testing.T) {
	imprint, err := newMessageImprint(crypto.SHA256, bytes.NewReader([]byte("sig")))
	require.NoError(t, err)

	info := tstInfo{
		Version:        1,
		Policy:         oidContentTypeTSTInfo,
		MessageImprint: imprint,
		SerialNumber:   big.NewInt(7),
		GenTime:        time.Now().UTC().Truncate(time.Second),
	}

	der, err := asn1.Marshal(info)
	require.NoError(t, err)
	eci, err := newEncapsulatedContentInfo(oidContentTypeTSTInfo, der)
	require.NoError(t, err)

	got, err := parseTSTInfo(eci)
	require.NoError(t, err)
	assert.Equal(t, 1, got.Version)
	assert.True(t, info.GenTime.Equal(got.GenTime))
	assert.True(t, imprint.equal(got.MessageImprint))

	// Wrong content type.
	dataECI, err := newDataEncapsulatedContentInfo(der)
	require.NoError(t, err)
	_, err = parseTSTInfo(dataECI)
	assert.ErrorIs(t, err, errWrongType)
}

func TestPKIStatusInfo(t *testing.T) {
	assert.NoError(t, pkiStatusInfo{Status: 0}.statusError())
	assert.Error(t, pkiStatusInfo{Status: 2}.statusError())

	si := pkiStatusInfo{
		Status:   2,
		FailInfo: asn1.BitString{Bytes: []byte{0x80}, BitLength: 1},
	}
	assert.Contains(t, si.Error(), "status 2")
	assert.Contains(t, si.Error(), "FailInfo")

	der, err := asn1.Marshal("denied")
	require.NoError(t, err)
	var rv asn1.RawValue
	_, err = asn1.Unmarshal(der, &rv)
	require.NoError(t, err)
	assert.Equal(t, []string{"denied"}, decodeStatusStrings([]asn1.RawValue{rv}))
}

func TestGenerateNonce(t *testing.T) {
	nonce := generateNonce()
	require.NotNil(t, nonce)
	assert.NotZero(t, nonce.Sign())
}

func TestParseContentInfoTrailingData(t *testing.T) {
	// Build a ContentInfo whose inner content has trailing data.
	inner := []byte{0x30, 0x00, 0xff}
	ci := contentInfo{
		ContentType: oidContentTypeSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			Bytes:      inner,
			IsCompound: true,
		},
	}
	der, err := asn1.Marshal(ci)
	require.NoError(t, err)

	_, err = ParseSignedData(der)
	assert.Error(t, err)
}
