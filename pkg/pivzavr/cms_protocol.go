// This file implements the subset of the Cryptographic Message Syntax
// (RFC 5652) and of the RFC 3161 timestamping protocol that pivzavr needs to
// create and verify S/MIME signatures.
//
// The implementation is intentionally small: it supports the SignedData
// content type of type id-data, issuerAndSerialNumber and subjectKeyIdentifier
// signer identifiers, the mandatory signed attributes, and the SHA-2 family of
// digest algorithms. It does not implement encryption, countersignatures or
// revocation checking.
package pivzavr

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"sort"
	"time"
)

// ASN1Error describes a failure while parsing or encoding an ASN.1 structure.
type ASN1Error struct {
	Message string
}

// Error implements the error interface.
func (e ASN1Error) Error() string {
	return "cms: " + e.Message
}

var (
	// errWrongType is returned when a value is not of the type a helper method
	// assumes it to be.
	errWrongType = errors.New("cms: unexpected choice or any type")

	// errNoCertificate is returned when the certificate that made a signature
	// cannot be found among the embedded certificates.
	errNoCertificate = errors.New("cms: signer certificate not found")

	// errUnsupported is returned for unsupported types, versions and
	// algorithms.
	errUnsupported = ASN1Error{Message: "unsupported type or version"}

	// errTrailingData is returned when extra data follows an ASN.1 structure.
	errTrailingData = ASN1Error{Message: "unexpected trailing data"}
)

//	contentInfo ::= SEQUENCE {
//	  contentType ContentType,
//	  content [0] EXPLICIT ANY DEFINED BY contentType }
//
// ContentType ::= OBJECT IDENTIFIER
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// parseContentInfo parses a top-level ContentInfo from BER encoded data.
func parseContentInfo(ber []byte) (contentInfo, error) {
	var ci contentInfo

	der, err := berToDER(ber)
	if err != nil {
		return ci, err
	}

	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		return ci, err
	}
	if len(rest) > 0 {
		return ci, errTrailingData
	}

	return ci, nil
}

// signedDataContent gets the content assuming contentType is signedData.
func (ci contentInfo) signedDataContent() (*signedData, error) {
	if !ci.ContentType.Equal(oidContentTypeSignedData) {
		return nil, errWrongType
	}

	sd := new(signedData)
	rest, err := asn1.Unmarshal(ci.Content.Bytes, sd)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errTrailingData
	}

	return sd, nil
}

//	encapsulatedContentInfo ::= SEQUENCE {
//	  eContentType ContentType,
//	  eContent [0] EXPLICIT OCTET STRING OPTIONAL }
type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// newDataEncapsulatedContentInfo creates an EncapsulatedContentInfo of type
// id-data.
func newDataEncapsulatedContentInfo(data []byte) (encapsulatedContentInfo, error) {
	return newEncapsulatedContentInfo(oidContentTypeData, data)
}

// newEncapsulatedContentInfo creates an EncapsulatedContentInfo.
func newEncapsulatedContentInfo(contentType asn1.ObjectIdentifier, content []byte) (encapsulatedContentInfo, error) {
	octets, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagOctetString,
		Bytes:      content,
		IsCompound: false,
	})
	if err != nil {
		return encapsulatedContentInfo{}, err
	}

	return encapsulatedContentInfo{
		EContentType: contentType,
		EContent: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			Bytes:      octets,
			IsCompound: true,
		},
	}, nil
}

// contentValue gets the OCTET STRING eContent value without tag or length. This
// is the data the message digest is calculated over. A nil byte slice is
// returned when the OPTIONAL eContent field is absent.
func (eci encapsulatedContentInfo) contentValue() ([]byte, error) {
	if eci.EContent.Bytes == nil {
		return nil, nil
	}

	// eContent is an [0] EXPLICIT OCTET STRING. The EXPLICIT tag wraps the
	// OCTET STRING, so EContent.Bytes holds the encoded OCTET STRING.
	var octets asn1.RawValue
	rest, err := asn1.Unmarshal(eci.EContent.Bytes, &octets)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errTrailingData
	}
	if octets.Class != asn1.ClassUniversal || octets.Tag != asn1.TagOctetString {
		return nil, ASN1Error{Message: "bad eContent tag or class"}
	}

	// A BER encoded OCTET STRING may be constructed from several primitive
	// chunks instead of using the definite length form. Concatenate them.
	if !octets.IsCompound {
		return octets.Bytes, nil
	}

	var value []byte
	rest = octets.Bytes
	for len(rest) > 0 {
		var chunk asn1.RawValue
		if rest, err = asn1.Unmarshal(rest, &chunk); err != nil {
			return nil, err
		}
		if chunk.Class != asn1.ClassUniversal || chunk.Tag != asn1.TagOctetString || chunk.IsCompound {
			return nil, ASN1Error{Message: "bad eContent chunk class or tag"}
		}
		value = append(value, chunk.Bytes...)
	}

	return value, nil
}

// isTypeData reports whether the eContentType is id-data.
func (eci encapsulatedContentInfo) isTypeData() bool {
	return eci.EContentType.Equal(oidContentTypeData)
}

//	attribute ::= SEQUENCE {
//	  attrType OBJECT IDENTIFIER,
//	  attrValues SET OF AttributeValue }
//
// AttributeValue ::= ANY
type attribute struct {
	Type asn1.ObjectIdentifier

	// RawValue holds the DER encoded SET OF AttributeValue. encoding/asn1
	// cannot marshal a slice of ANY, so the SET is encoded manually.
	RawValue asn1.RawValue
}

// newAttribute creates a single-value attribute.
func newAttribute(oid asn1.ObjectIdentifier, value any) (attribute, error) {
	der, err := asn1.Marshal(value)
	if err != nil {
		return attribute{}, err
	}

	var rv asn1.RawValue
	if _, err = asn1.Unmarshal(der, &rv); err != nil {
		return attribute{}, err
	}

	raw, err := encodeAnySet(rv)
	if err != nil {
		return attribute{}, err
	}

	return attribute{Type: oid, RawValue: raw}, nil
}

// value decodes the attribute value as a SET OF ANY.
func (a attribute) value() ([]asn1.RawValue, error) {
	return decodeAnySet(a.RawValue)
}

// attributes is the common Go type for SignedAttributes and UnsignedAttributes.
type attributes []attribute

// marshaledForSigning encodes the attributes for message digest calculation.
// RFC 5652 requires a separate encoding in which the IMPLICIT [0] tag is
// replaced by an EXPLICIT SET OF tag.
func (attrs attributes) marshaledForSigning() ([]byte, error) {
	der, err := asn1.Marshal(struct {
		Attributes attributes `asn1:"set"`
	}{attrs})
	if err != nil {
		return nil, err
	}

	var raw asn1.RawValue
	if _, err = asn1.Unmarshal(der, &raw); err != nil {
		return nil, err
	}

	// raw is the outer SEQUENCE; its content is the EXPLICIT SET OF encoding.
	return raw.Bytes, nil
}

// marshaledForVerification encodes the attributes for signature verification.
// Unlike signing, the received ordering is preserved and only the SEQUENCE tag
// is rewritten to a SET tag.
func (attrs attributes) marshaledForVerification() ([]byte, error) {
	der, err := asn1.Marshal(struct {
		Attributes attributes `asn1:"sequence"`
	}{attrs})
	if err != nil {
		return nil, err
	}

	var raw asn1.RawValue
	if _, err = asn1.Unmarshal(der, &raw); err != nil {
		return nil, err
	}
	if len(raw.Bytes) == 0 {
		return nil, ASN1Error{Message: "empty signed attributes"}
	}

	// Change the SEQUENCE tag (0x30) of the inner encoding to a SET tag (0x31).
	raw.Bytes[0] = 0x31
	return raw.Bytes, nil
}

// values returns the decoded value sets of every attribute with the given OID.
// A nil result means the OPTIONAL attribute set is absent; an empty result
// means the attribute is not present.
func (attrs attributes) values(oid asn1.ObjectIdentifier) ([][]asn1.RawValue, error) {
	if attrs == nil {
		return nil, nil
	}

	var vals [][]asn1.RawValue
	for _, attr := range attrs {
		if !attr.Type.Equal(oid) {
			continue
		}
		val, err := attr.value()
		if err != nil {
			return nil, err
		}
		vals = append(vals, val)
	}

	return vals, nil
}

// onlyValue returns the single value of the single attribute with the given
// OID.
func (attrs attributes) onlyValue(oid asn1.ObjectIdentifier) (asn1.RawValue, error) {
	vals, err := attrs.values(oid)
	if err != nil {
		return asn1.RawValue{}, err
	}
	if len(vals) != 1 {
		return asn1.RawValue{}, ASN1Error{Message: "unexpected attribute count"}
	}
	if len(vals[0]) != 1 {
		return asn1.RawValue{}, ASN1Error{Message: "unexpected attribute value count"}
	}
	return vals[0][0], nil
}

// sortAttributes sorts attributes by their full DER encoding as required by the
// Distinguished Encoding Rules (X.690 section 11.6).
func sortAttributes(attrs ...attribute) attributes {
	sort.Slice(attrs, func(i, j int) bool {
		return bytes.Compare(attrs[i].RawValue.FullBytes, attrs[j].RawValue.FullBytes) < 0
	})
	return attrs
}

// encodeAnySet encodes a SET OF ANY, which encoding/asn1 cannot handle directly.
func encodeAnySet(elements ...asn1.RawValue) (asn1.RawValue, error) {
	rv := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
	}

	for _, elt := range elements {
		der, err := asn1.Marshal(elt)
		if err != nil {
			return asn1.RawValue{}, err
		}
		rv.Bytes = append(rv.Bytes, der...)
	}

	full, err := asn1.Marshal(rv)
	if err != nil {
		return asn1.RawValue{}, err
	}
	rv.FullBytes = full

	return rv, nil
}

// decodeAnySet decodes a SET OF ANY, which encoding/asn1 cannot handle directly.
func decodeAnySet(rv asn1.RawValue) ([]asn1.RawValue, error) {
	if rv.Class != asn1.ClassUniversal || rv.Tag != asn1.TagSet {
		return nil, ASN1Error{Message: "expected a SET"}
	}

	var elements []asn1.RawValue
	rest := rv.Bytes
	for len(rest) > 0 {
		var elt asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &elt); err != nil {
			return nil, err
		}
		elements = append(elements, elt)
	}

	return elements, nil
}

//	issuerAndSerialNumber ::= SEQUENCE {
//	  issuer Name,
//	  serialNumber CertificateSerialNumber }
type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// newIssuerAndSerialNumber builds an issuerAndSerialNumber signer identifier
// for the given certificate.
func newIssuerAndSerialNumber(cert *x509.Certificate) (asn1.RawValue, error) {
	isn := issuerAndSerialNumber{SerialNumber: new(big.Int).Set(cert.SerialNumber)}

	if _, err := asn1.Unmarshal(cert.RawIssuer, &isn.Issuer); err != nil {
		return asn1.RawValue{}, err
	}

	der, err := asn1.Marshal(isn)
	if err != nil {
		return asn1.RawValue{}, err
	}

	var rv asn1.RawValue
	if _, err = asn1.Unmarshal(der, &rv); err != nil {
		return asn1.RawValue{}, err
	}

	return rv, nil
}

//	signerInfo ::= SEQUENCE {
//	  version CMSVersion,
//	  sid SignerIdentifier,
//	  digestAlgorithm DigestAlgorithmIdentifier,
//	  signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//	  signatureAlgorithm SignatureAlgorithmIdentifier,
//	  signature SignatureValue,
//	  unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        attributes `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      attributes `asn1:"set,optional,tag:1"`
}

// findCertificate locates this signer's certificate among certs.
func (si signerInfo) findCertificate(certs []*x509.Certificate) (*x509.Certificate, error) {
	switch si.Version {
	case 1: // SID is issuerAndSerialNumber
		isn, err := si.issuerAndSerialNumberSID()
		if err != nil {
			return nil, err
		}
		for _, cert := range certs {
			if bytes.Equal(cert.RawIssuer, isn.Issuer.FullBytes) && isn.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return cert, nil
			}
		}
	case 3: // SID is subjectKeyIdentifier
		ski, err := si.subjectKeyIdentifierSID()
		if err != nil {
			return nil, err
		}
		for _, cert := range certs {
			for _, ext := range cert.Extensions {
				if oidExtensionSubjectKeyIdentifier.Equal(ext.Id) && subjectKeyIdentifierMatches(ski, ext.Value) {
					return cert, nil
				}
			}
		}
	default:
		return nil, errUnsupported
	}

	return nil, errNoCertificate
}

// subjectKeyIdentifierMatches reports whether the signer identifier bytes match
// the value of a SubjectKeyIdentifier extension. The extension value is the DER
// encoding of an OCTET STRING, while the signer identifier holds the raw key
// identifier.
func subjectKeyIdentifierMatches(ski, extValue []byte) bool {
	if bytes.Equal(ski, extValue) {
		return true
	}
	var octets asn1.RawValue
	if rest, err := asn1.Unmarshal(extValue, &octets); err == nil && len(rest) == 0 &&
		octets.Class == asn1.ClassUniversal && octets.Tag == asn1.TagOctetString {
		return bytes.Equal(ski, octets.Bytes)
	}
	return false
}

// issuerAndSerialNumberSID gets the SID, assuming it is an issuerAndSerialNumber.
func (si signerInfo) issuerAndSerialNumberSID() (issuerAndSerialNumber, error) {
	var isn issuerAndSerialNumber

	if si.SID.Class != asn1.ClassUniversal || si.SID.Tag != asn1.TagSequence {
		return isn, errWrongType
	}

	rest, err := asn1.Unmarshal(si.SID.FullBytes, &isn)
	if err != nil {
		return isn, err
	}
	if len(rest) > 0 {
		return isn, errTrailingData
	}

	return isn, nil
}

// subjectKeyIdentifierSID gets the SID, assuming it is a subjectKeyIdentifier.
func (si signerInfo) subjectKeyIdentifierSID() ([]byte, error) {
	if si.SID.Class != asn1.ClassContextSpecific || si.SID.Tag != 0 {
		return nil, errWrongType
	}
	return si.SID.Bytes, nil
}

// hash returns the crypto.Hash associated with this signer's digest algorithm.
func (si signerInfo) hash() (crypto.Hash, error) {
	hash := digestToHash[si.DigestAlgorithm.Algorithm.String()]
	if hash == 0 || !hash.Available() {
		return 0, errUnsupported
	}
	return hash, nil
}

// x509SignatureAlgorithm returns the x509.SignatureAlgorithm used to verify
// this signer's signature.
func (si signerInfo) x509SignatureAlgorithm() x509.SignatureAlgorithm {
	sigOID := si.SignatureAlgorithm.Algorithm.String()
	digestOID := si.DigestAlgorithm.Algorithm.String()

	if sa := sigAlgToX509[sigOID]; sa != x509.UnknownSignatureAlgorithm {
		return sa
	}
	return pubKeyAndDigestToX509[sigOID][digestOID]
}

// contentTypeAttribute returns the signed ContentType attribute.
func (si signerInfo) contentTypeAttribute() (asn1.ObjectIdentifier, error) {
	rv, err := si.SignedAttrs.onlyValue(oidAttrContentType)
	if err != nil {
		return nil, err
	}

	var contentType asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(rv.FullBytes, &contentType)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errTrailingData
	}

	return contentType, nil
}

// messageDigestAttribute returns the signed MessageDigest attribute.
func (si signerInfo) messageDigestAttribute() ([]byte, error) {
	rv, err := si.SignedAttrs.onlyValue(oidAttrMessageDigest)
	if err != nil {
		return nil, err
	}
	if rv.Class != asn1.ClassUniversal || rv.Tag != asn1.TagOctetString {
		return nil, ASN1Error{Message: "bad message digest tag or class"}
	}
	return rv.Bytes, nil
}

//	signedData ::= SEQUENCE {
//	  version CMSVersion,
//	  digestAlgorithms DigestAlgorithmIdentifiers,
//	  encapContentInfo EncapsulatedContentInfo,
//	  certificates [0] IMPLICIT CertificateSet OPTIONAL,
//	  crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//	  signerInfos SignerInfos }
type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certificates     []asn1.RawValue `asn1:"optional,set,tag:0"`
	CRLs             []asn1.RawValue `asn1:"optional,set,tag:1"`
	SignerInfos      []signerInfo    `asn1:"set"`
}

// newSignedData creates a new SignedData wrapping eci.
func newSignedData(eci encapsulatedContentInfo) *signedData {
	// Version 1 is used for id-data content, version 3 otherwise.
	version := 1
	if !eci.isTypeData() {
		version = 3
	}

	return &signedData{
		Version:          version,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{},
		EncapContentInfo: eci,
		SignerInfos:      []signerInfo{},
	}
}

// addSignerInfo signs the encapsulated content with signer and appends the
// resulting SignerInfo. The certificate associated with signer is stored in the
// SignedData as well.
func (sd *signedData) addSignerInfo(chain []*x509.Certificate, signer crypto.Signer) error {
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return err
	}

	var (
		cert    *x509.Certificate
		certPub []byte
	)

	for _, c := range chain {
		if err = sd.addCertificate(c); err != nil {
			return err
		}

		if certPub, err = x509.MarshalPKIXPublicKey(c.PublicKey); err != nil {
			return err
		}

		if bytes.Equal(pub, certPub) {
			cert = c
		}
	}
	if cert == nil {
		return errNoCertificate
	}

	content, err := sd.EncapContentInfo.contentValue()
	if err != nil {
		return err
	}
	if content == nil {
		return errors.New("cms: content already detached")
	}

	sid, err := newIssuerAndSerialNumber(cert)
	if err != nil {
		return err
	}

	digestAlgorithm := digestAlgorithmForPublicKey(pub)

	signatureOID, ok := x509PubKeyAndDigestToSig[cert.PublicKeyAlgorithm][digestAlgorithm.Algorithm.String()]
	if !ok {
		return errors.New("cms: unsupported certificate public key algorithm")
	}

	si := signerInfo{
		Version:            1,
		SID:                sid,
		DigestAlgorithm:    digestAlgorithm,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: signatureOID},
	}

	hash, err := si.hash()
	if err != nil {
		return err
	}

	// Digest the encapsulated content.
	md := hash.New()
	if _, err = md.Write(content); err != nil {
		return err
	}

	// Build the signed attributes.
	signingTime, err := newAttribute(oidAttrSigningTime, time.Now().UTC())
	if err != nil {
		return err
	}
	messageDigest, err := newAttribute(oidAttrMessageDigest, md.Sum(nil))
	if err != nil {
		return err
	}
	contentType, err := newAttribute(oidAttrContentType, sd.EncapContentInfo.EContentType)
	if err != nil {
		return err
	}

	si.SignedAttrs = sortAttributes(signingTime, messageDigest, contentType)

	// The signature is over the DER encoding of the signed attributes.
	signed, err := si.SignedAttrs.marshaledForSigning()
	if err != nil {
		return err
	}
	signedDigest := hash.New()
	if _, err = signedDigest.Write(signed); err != nil {
		return err
	}
	if si.Signature, err = signer.Sign(rand.Reader, signedDigest.Sum(nil), hash); err != nil {
		return err
	}

	sd.addDigestAlgorithm(si.DigestAlgorithm)
	sd.SignerInfos = append(sd.SignerInfos, si)

	return nil
}

// digestAlgorithmForPublicKey selects the digest algorithm to use with the
// given public key.
func digestAlgorithmForPublicKey(pub crypto.PublicKey) pkix.AlgorithmIdentifier {
	if ecPub, ok := pub.(*ecdsa.PublicKey); ok {
		switch ecPub.Curve {
		case elliptic.P384():
			return pkix.AlgorithmIdentifier{Algorithm: oidDigestSHA384}
		case elliptic.P521():
			return pkix.AlgorithmIdentifier{Algorithm: oidDigestSHA512}
		}
	}

	return pkix.AlgorithmIdentifier{Algorithm: oidDigestSHA256}
}

// clearCertificates removes all certificates.
func (sd *signedData) clearCertificates() {
	sd.Certificates = []asn1.RawValue{}
}

// addCertificate adds an X.509 certificate.
func (sd *signedData) addCertificate(cert *x509.Certificate) error {
	for _, existing := range sd.Certificates {
		if bytes.Equal(existing.FullBytes, cert.Raw) {
			return nil
		}
	}

	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(cert.Raw, &rv); err != nil {
		return err
	}

	sd.Certificates = append(sd.Certificates, rv)

	return nil
}

// addDigestAlgorithm records a digest algorithm if it is not present yet.
func (sd *signedData) addDigestAlgorithm(algo pkix.AlgorithmIdentifier) {
	for _, existing := range sd.DigestAlgorithms {
		if existing.Algorithm.Equal(algo.Algorithm) {
			return
		}
	}
	sd.DigestAlgorithms = append(sd.DigestAlgorithms, algo)
}

// x509Certificates returns the embedded certificates, assuming they are X.509
// encoded.
func (sd *signedData) x509Certificates() ([]*x509.Certificate, error) {
	if sd.Certificates == nil {
		return nil, nil
	}
	if len(sd.Certificates) == 0 {
		return []*x509.Certificate{}, nil
	}

	certs := make([]*x509.Certificate, 0, len(sd.Certificates))
	for _, raw := range sd.Certificates {
		if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence {
			return nil, errUnsupported
		}

		cert, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

// contentInfoDER returns the SignedData wrapped in a ContentInfo and DER
// encoded.
func (sd *signedData) contentInfoDER() ([]byte, error) {
	der, err := asn1.Marshal(*sd)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(contentInfo{
		ContentType: oidContentTypeSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			Bytes:      der,
			IsCompound: true,
		},
	})
}

// berToDER transcodes the first BER encoded value in ber into DER.
//
// BER permits indefinite lengths, constructed encodings of primitive types and
// non-minimal length encodings, none of which encoding/asn1 accepts. This
// function rewrites the encoding using definite, minimal lengths while
// preserving the identifier and content octets.
func berToDER(ber []byte) ([]byte, error) {
	if len(ber) == 0 {
		return nil, ASN1Error{Message: "input is empty"}
	}

	der, _, err := transcodeElement(ber)
	if err != nil {
		return nil, err
	}

	return der, nil
}

// transcodeElement transcodes one BER element and returns the DER encoding plus
// the unread remainder of ber.
func transcodeElement(ber []byte) (der, rest []byte, err error) {
	tag, rest, err := readTag(ber)
	if err != nil {
		return nil, nil, err
	}

	length, indefinite, rest, err := readLength(rest)
	if err != nil {
		return nil, nil, err
	}

	constructed := tag[0]&0x20 != 0

	if !constructed {
		if indefinite {
			return nil, nil, ASN1Error{Message: "primitive value with indefinite length"}
		}
		if length > len(rest) {
			return nil, nil, ASN1Error{Message: "value longer than available data"}
		}
		content := rest[:length]
		rest = rest[length:]

		out := make([]byte, 0, len(tag)+len(content)+2)
		out = append(out, tag...)
		out = append(out, encodeLength(len(content))...)
		out = append(out, content...)
		return out, rest, nil
	}

	var content []byte
	if indefinite {
		for {
			if len(rest) >= 2 && rest[0] == 0x00 && rest[1] == 0x00 {
				rest = rest[2:]
				break
			}
			var child []byte
			if child, rest, err = transcodeElement(rest); err != nil {
				return nil, nil, err
			}
			content = append(content, child...)
		}
	} else {
		if length > len(rest) {
			return nil, nil, ASN1Error{Message: "value longer than available data"}
		}
		body := rest[:length]
		rest = rest[length:]
		for len(body) > 0 {
			var child []byte
			if child, body, err = transcodeElement(body); err != nil {
				return nil, nil, err
			}
			content = append(content, child...)
		}
	}

	out := make([]byte, 0, len(tag)+len(content)+2)
	out = append(out, tag...)
	out = append(out, encodeLength(len(content))...)
	out = append(out, content...)
	return out, rest, nil
}

// readTag reads an ASN.1 identifier, supporting the high-tag-number form.
func readTag(ber []byte) (tag, rest []byte, err error) {
	if len(ber) == 0 {
		return nil, nil, ASN1Error{Message: "truncated identifier"}
	}

	i := 1
	if ber[0]&0x1f == 0x1f {
		for {
			if i >= len(ber) {
				return nil, nil, ASN1Error{Message: "truncated identifier"}
			}
			last := ber[i]&0x80 == 0
			i++
			if last {
				break
			}
		}
	}

	return ber[:i], ber[i:], nil
}

// readLength reads an ASN.1 length, supporting both the definite and the
// indefinite form.
func readLength(ber []byte) (length int, indefinite bool, rest []byte, err error) {
	if len(ber) == 0 {
		return 0, false, nil, ASN1Error{Message: "truncated length"}
	}

	first := ber[0]
	rest = ber[1:]

	switch {
	case first == 0x80:
		return 0, true, rest, nil
	case first < 0x80:
		return int(first), false, rest, nil
	}

	n := int(first & 0x7f)
	if n == 0 || n > 4 {
		return 0, false, nil, ASN1Error{Message: "invalid length encoding"}
	}
	if len(rest) < n {
		return 0, false, nil, ASN1Error{Message: "truncated length"}
	}
	if rest[0] == 0x00 {
		return 0, false, nil, ASN1Error{Message: "non-minimal length encoding"}
	}

	for i := 0; i < n; i++ {
		length = length<<8 | int(rest[i])
	}

	return length, false, rest[n:], nil
}

// encodeLength encodes a definite DER length.
func encodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)} // #nosec G115 -- length is below 128 here.
	}

	var buf []byte
	for n := length; n > 0; n >>= 8 {
		buf = append([]byte{byte(n)}, buf...) // #nosec G115 -- only the low byte is kept.
	}

	out := make([]byte, 0, len(buf)+1)
	out = append(out, byte(0x80|len(buf))) // #nosec G115 -- at most 4 length bytes for an int.
	out = append(out, buf...)

	return out
}
