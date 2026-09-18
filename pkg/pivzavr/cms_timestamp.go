package pivzavr

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const (
	contentTypeTSQuery = "application/timestamp-query"
	contentTypeTSReply = "application/timestamp-reply"
	timestampNonceSize = 16
)

// AddTimestamps adds an RFC 3161 timestamp, obtained from the timestamping
// service at url, to every signature in the SignedData. A timestamp proves that
// the signature existed at the time it was created, which lets verifiers keep
// trusting a message signed with a key that has since been revoked.
func (sd *SignedData) AddTimestamps(url string) error {
	attrs := make([]attribute, len(sd.sd.SignerInfos))

	// Fetch every timestamp before modifying the SignedData so that a failure
	// cannot leave it partially timestamped.
	for i := range attrs {
		attr, err := fetchTimestamp(url, sd.sd.SignerInfos[i])
		if err != nil {
			return err
		}
		attrs[i] = attr
	}

	for i := range attrs {
		sd.sd.SignerInfos[i].UnsignedAttrs = append(sd.sd.SignerInfos[i].UnsignedAttrs, attrs[i])
	}

	return nil
}

// fetchTimestamp requests a timestamp token over the signature of si and wraps
// it in the timestamp token attribute.
func fetchTimestamp(url string, si signerInfo) (attribute, error) {
	req, err := timestampRequestFor(si)
	if err != nil {
		return attribute{}, err
	}

	resp, err := req.do(url)
	if err != nil {
		return attribute{}, err
	}

	info, err := resp.info()
	if err != nil {
		return attribute{}, err
	}
	if !req.matches(info) {
		return attribute{}, errors.New("cms: invalid timestamp message imprint")
	}

	return newAttribute(oidAttrTimeStampToken, resp.TimeStampToken)
}

// timestampRequestFor builds the timestamp request for si's signature.
func timestampRequestFor(si signerInfo) (timeStampReq, error) {
	hash, err := si.hash()
	if err != nil {
		return timeStampReq{}, err
	}

	imprint, err := newMessageImprint(hash, bytes.NewReader(si.Signature))
	if err != nil {
		return timeStampReq{}, err
	}

	return timeStampReq{
		Version:        1,
		CertReq:        true,
		Nonce:          generateNonce(),
		MessageImprint: imprint,
	}, nil
}

// generateNonce generates a random timestamp request nonce.
func generateNonce() *big.Int {
	buf := make([]byte, timestampNonceSize)
	if _, err := rand.Read(buf); err != nil {
		return nil
	}
	return new(big.Int).SetBytes(buf)
}

// getTimestamp verifies and returns the timestamp info embedded in si.
func getTimestamp(si signerInfo, opts x509.VerifyOptions) (tstInfo, error) {
	var nilInfo tstInfo

	rawValue, err := si.UnsignedAttrs.onlyValue(oidAttrTimeStampToken)
	if err != nil {
		return nilInfo, err
	}

	tst, err := ParseSignedData(rawValue.FullBytes)
	if err != nil {
		return nilInfo, err
	}

	info, err := parseTSTInfo(tst.sd.EncapContentInfo)
	if err != nil {
		return nilInfo, err
	}
	if info.Version != 1 {
		return nilInfo, errUnsupported
	}

	// Verify the timestamp signature and its certificate chain.
	if _, err = tst.Verify(opts); err != nil {
		return nilInfo, err
	}

	// Verify the timestamp token matches the signature.
	hash, err := info.MessageImprint.hash()
	if err != nil {
		return nilInfo, err
	}
	imprint, err := newMessageImprint(hash, bytes.NewReader(si.Signature))
	if err != nil {
		return nilInfo, err
	}
	if !imprint.equal(info.MessageImprint) {
		return nilInfo, errors.New("cms: invalid timestamp message imprint")
	}

	return info, nil
}

// hasTimestamp reports whether si carries a timestamp token attribute.
func hasTimestamp(si signerInfo) (bool, error) {
	vals, err := si.UnsignedAttrs.values(oidAttrTimeStampToken)
	if err != nil {
		return false, err
	}
	return len(vals) > 0, nil
}

//	messageImprint ::= SEQUENCE {
//	  hashAlgorithm AlgorithmIdentifier,
//	  hashedMessage OCTET STRING }
type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// newMessageImprint digests all bytes read from r using hash.
func newMessageImprint(hash crypto.Hash, r io.Reader) (messageImprint, error) {
	var mi messageImprint

	oid, ok := hashToDigest[hash]
	if !ok || !hash.Available() {
		return mi, errUnsupported
	}

	h := hash.New()
	if _, err := io.Copy(h, r); err != nil {
		return mi, err
	}

	return messageImprint{
		HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oid},
		HashedMessage: h.Sum(nil),
	}, nil
}

// hash returns the crypto.Hash associated with the imprint's digest algorithm.
func (mi messageImprint) hash() (crypto.Hash, error) {
	hash := digestToHash[mi.HashAlgorithm.Algorithm.String()]
	if hash == 0 || !hash.Available() {
		return 0, errUnsupported
	}
	return hash, nil
}

// equal reports whether two message imprints are identical.
func (mi messageImprint) equal(other messageImprint) bool {
	if !mi.HashAlgorithm.Algorithm.Equal(other.HashAlgorithm.Algorithm) {
		return false
	}
	if len(mi.HashAlgorithm.Parameters.Bytes) > 0 || len(other.HashAlgorithm.Parameters.Bytes) > 0 {
		if !bytes.Equal(mi.HashAlgorithm.Parameters.FullBytes, other.HashAlgorithm.Parameters.FullBytes) {
			return false
		}
	}
	return bytes.Equal(mi.HashedMessage, other.HashedMessage)
}

//	timeStampReq ::= SEQUENCE {
//	  version INTEGER { v1(1) },
//	  messageImprint MessageImprint,
//	  reqPolicy TSAPolicyId OPTIONAL,
//	  nonce INTEGER OPTIONAL,
//	  certReq BOOLEAN DEFAULT FALSE,
//	  extensions [0] IMPLICIT Extensions OPTIONAL }
type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []pkix.Extension      `asn1:"tag:1,optional"`
}

// matches reports whether a response echoes this request's message imprint and
// nonce.
func (req timeStampReq) matches(info tstInfo) bool {
	if !req.MessageImprint.equal(info.MessageImprint) {
		return false
	}
	if req.Nonce == nil || info.Nonce == nil {
		return req.Nonce == nil && info.Nonce == nil
	}
	return req.Nonce.Cmp(info.Nonce) == 0
}

// do sends the timestamp request to url and parses the response.
func (req timeStampReq) do(url string) (timeStampResp, error) {
	var nilResp timeStampResp

	der, err := asn1.Marshal(req)
	if err != nil {
		return nilResp, err
	}

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(der))
	if err != nil {
		return nilResp, err
	}
	httpReq.Header.Set("Content-Type", contentTypeTSQuery)

	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nilResp, err
	}
	defer func() { _ = httpResp.Body.Close() }()

	if ct := httpResp.Header.Get("Content-Type"); ct != contentTypeTSReply {
		return nilResp, fmt.Errorf("cms: unexpected timestamp response content type %q", ct)
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nilResp, err
	}

	return parseTimeStampResp(body)
}

//	timeStampResp ::= SEQUENCE {
//	  status PKIStatusInfo,
//	  timeStampToken TimeStampToken OPTIONAL }
//
// TimeStampToken ::= ContentInfo
type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken contentInfo `asn1:"optional"`
}

// parseTimeStampResp parses a BER encoded TimeStampResp.
func parseTimeStampResp(ber []byte) (timeStampResp, error) {
	var resp timeStampResp

	der, err := berToDER(ber)
	if err != nil {
		return resp, err
	}

	rest, err := asn1.Unmarshal(der, &resp)
	if err != nil {
		return resp, err
	}
	if len(rest) > 0 {
		return resp, errTrailingData
	}

	return resp, nil
}

// info returns the TSTInfo carried by the response without verifying the
// timestamp token.
func (r timeStampResp) info() (tstInfo, error) {
	var nilInfo tstInfo

	if err := r.Status.statusError(); err != nil {
		return nilInfo, err
	}

	sd, err := r.TimeStampToken.signedDataContent()
	if err != nil {
		return nilInfo, err
	}

	return parseTSTInfo(sd.EncapContentInfo)
}

//	accuracy ::= SEQUENCE {
//	  seconds INTEGER OPTIONAL,
//	  millis [0] INTEGER (1..999) OPTIONAL,
//	  micros [1] INTEGER (1..999) OPTIONAL }
type accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"tag:0,optional"`
	Micros  int `asn1:"tag:1,optional"`
}

// duration returns the accuracy as a time.Duration.
func (a accuracy) duration() time.Duration {
	return time.Duration(a.Seconds)*time.Second +
		time.Duration(a.Millis)*time.Millisecond +
		time.Duration(a.Micros)*time.Microsecond
}

//	tstInfo ::= SEQUENCE {
//	  version INTEGER { v1(1) },
//	  policy TSAPolicyId,
//	  messageImprint MessageImprint,
//	  serialNumber INTEGER,
//	  genTime GeneralizedTime,
//	  accuracy Accuracy OPTIONAL,
//	  ordering BOOLEAN DEFAULT FALSE,
//	  nonce INTEGER OPTIONAL,
//	  tsa [0] GeneralName OPTIONAL,
//	  extensions [1] IMPLICIT Extensions OPTIONAL }
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time        `asn1:"generalized"`
	Accuracy       accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"tag:0,optional"`
	Extensions     []pkix.Extension `asn1:"tag:1,optional"`
}

// before reports whether the latest time the token could have been generated is
// before t, taking the reported accuracy into account.
func (i tstInfo) before(t time.Time) bool {
	return i.GenTime.Add(i.Accuracy.duration()).Before(t)
}

// after reports whether the earliest time the token could have been generated
// is after t, taking the reported accuracy into account.
func (i tstInfo) after(t time.Time) bool {
	return i.GenTime.Add(-i.Accuracy.duration()).After(t)
}

// parseTSTInfo parses the TSTInfo encapsulated in a CMS content info.
func parseTSTInfo(eci encapsulatedContentInfo) (tstInfo, error) {
	var info tstInfo

	if !eci.EContentType.Equal(oidContentTypeTSTInfo) {
		return info, errWrongType
	}

	content, err := eci.contentValue()
	if err != nil {
		return info, err
	}
	if content == nil {
		return info, ASN1Error{Message: "missing timestamp content"}
	}

	rest, err := asn1.Unmarshal(content, &info)
	if err != nil {
		return info, err
	}
	if len(rest) > 0 {
		return info, errTrailingData
	}

	return info, nil
}

//	pkiStatusInfo ::= SEQUENCE {
//	  status PKIStatus,
//	  statusString PKIFreeText OPTIONAL,
//	  failInfo PKIFailureInfo OPTIONAL }
type pkiStatusInfo struct {
	Status       int
	StatusString []asn1.RawValue `asn1:"optional"`
	FailInfo     asn1.BitString  `asn1:"optional"`
}

// statusError returns the status as an error unless the request was granted.
func (si pkiStatusInfo) statusError() error {
	if si.Status == 0 {
		return nil
	}
	return si
}

// Error implements the error interface.
func (si pkiStatusInfo) Error() string {
	failInfo := ""
	if si.FailInfo.BitLength > 0 {
		bits := make([]byte, si.FailInfo.BitLength)
		for i := range bits {
			if si.FailInfo.At(i) == 1 {
				bits[i] = '1'
			} else {
				bits[i] = '0'
			}
		}
		failInfo = fmt.Sprintf(" FailInfo(0b%s)", string(bits))
	}

	status := ""
	if strs := decodeStatusStrings(si.StatusString); len(strs) > 0 {
		status = fmt.Sprintf(" StatusString(%s)", strings.Join(strs, ","))
	}

	return fmt.Sprintf("cms: bad timestamp response status %d%s%s", si.Status, status, failInfo)
}

// decodeStatusStrings decodes the UTF8String elements of a PKIFreeText.
func decodeStatusStrings(elements []asn1.RawValue) []string {
	var out []string
	for _, elt := range elements {
		var s string
		if rest, err := asn1.Unmarshal(elt.FullBytes, &s); err == nil && len(rest) == 0 {
			out = append(out, s)
		}
	}
	return out
}
