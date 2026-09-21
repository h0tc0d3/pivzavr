package embed

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// The namespaces and algorithm identifiers of an XML Signature.
const (
	// dsigNS is the XML Signature namespace.
	dsigNS = "http://www.w3.org/2000/09/xmldsig#"
	// xadesNS is the XAdES namespace that carries the signing time.
	xadesNS = "http://uri.etsi.org/01903/v1.3.2#"
	// excC14N is exclusive canonicalization, the canonicalization the
	// signatures are made with.
	excC14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
	// envelopedTransform removes the signature element from the signed
	// document.
	envelopedTransform = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

	digestSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	digestSHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	digestSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"

	signatureRSASHA256    = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	signatureRSASHA384    = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	signatureRSASHA512    = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	signatureECDSASHA256  = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	signatureECDSASHA384  = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	signatureECDSASHA512  = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
	signatureEd25519      = "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519"
	signedPropertiesType  = "http://uri.etsi.org/01903#SignedProperties"
	signatureVersionValue = "1.0"
)

// The identifiers of the elements an embedded XML Signature is built of.
const (
	signatureID        = "pivzavr-signature"
	manifestID         = "pivzavr-manifest"
	manifestRefID      = "pivzavr-reference-manifest"
	contentRefID       = "pivzavr-reference-content"
	propertiesRefID    = "pivzavr-reference-properties"
	propertiesID       = "pivzavr-signed-properties"
	qualifyingPropsID  = "pivzavr-qualifying-properties"
	manifestObjectID   = "pivzavr-manifest-object"
	propertiesObjectID = "pivzavr-properties-object"
)

// xmlAlgorithm is the algorithm suite of an XML signature: the digest, the
// signature method and the crypto.Hash both are computed with.
type xmlAlgorithm struct {
	Hash               crypto.Hash
	SignatureMethod    string
	DigestMethod       string
	SignatureAlgorithm x509.SignatureAlgorithm
}

// algorithmFor returns the XML signature algorithm that matches the key of a
// certificate.
func algorithmFor(cert *x509.Certificate) (xmlAlgorithm, error) {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() >= 3072 {
			return xmlAlgorithm{crypto.SHA384, signatureRSASHA384, digestSHA384, x509.SHA384WithRSA}, nil
		}
		return xmlAlgorithm{crypto.SHA256, signatureRSASHA256, digestSHA256, x509.SHA256WithRSA}, nil
	case *ecdsa.PublicKey:
		if key.Curve != nil {
			switch key.Curve.Params().BitSize {
			case 384:
				return xmlAlgorithm{crypto.SHA384, signatureECDSASHA384, digestSHA384, x509.ECDSAWithSHA384}, nil
			case 521:
				return xmlAlgorithm{crypto.SHA512, signatureECDSASHA512, digestSHA512, x509.ECDSAWithSHA512}, nil
			}
		}
		return xmlAlgorithm{crypto.SHA256, signatureECDSASHA256, digestSHA256, x509.ECDSAWithSHA256}, nil
	case ed25519.PublicKey:
		return xmlAlgorithm{crypto.SHA512, signatureEd25519, digestSHA512, x509.PureEd25519}, nil
	}
	return xmlAlgorithm{}, errors.Errorf("unsupported key type %T for an XML signature", cert.PublicKey)
}

// algorithmFromSignatureMethod returns the algorithm suite of a signature
// method identifier.
func algorithmFromSignatureMethod(uri string) (xmlAlgorithm, error) {
	switch uri {
	case signatureRSASHA256:
		return xmlAlgorithm{crypto.SHA256, signatureRSASHA256, digestSHA256, x509.SHA256WithRSA}, nil
	case signatureRSASHA384:
		return xmlAlgorithm{crypto.SHA384, signatureRSASHA384, digestSHA384, x509.SHA384WithRSA}, nil
	case signatureRSASHA512:
		return xmlAlgorithm{crypto.SHA512, signatureRSASHA512, digestSHA512, x509.SHA512WithRSA}, nil
	case signatureECDSASHA256:
		return xmlAlgorithm{crypto.SHA256, signatureECDSASHA256, digestSHA256, x509.ECDSAWithSHA256}, nil
	case signatureECDSASHA384:
		return xmlAlgorithm{crypto.SHA384, signatureECDSASHA384, digestSHA384, x509.ECDSAWithSHA384}, nil
	case signatureECDSASHA512:
		return xmlAlgorithm{crypto.SHA512, signatureECDSASHA512, digestSHA512, x509.ECDSAWithSHA512}, nil
	case signatureEd25519:
		return xmlAlgorithm{crypto.SHA512, signatureEd25519, digestSHA512, x509.PureEd25519}, nil
	}
	return xmlAlgorithm{}, errors.Errorf("unsupported signature method %q", uri)
}

// hashForDigestMethod returns the hash of a digest method identifier.
func hashForDigestMethod(uri string) (crypto.Hash, error) {
	switch uri {
	case digestSHA256:
		return crypto.SHA256, nil
	case digestSHA384:
		return crypto.SHA384, nil
	case digestSHA512:
		return crypto.SHA512, nil
	}
	return 0, errors.Errorf("unsupported digest method %q", uri)
}

// xmlReference describes a Reference of the SignedInfo that covers content.
type xmlReference struct {
	// ID is the value of the Id attribute of the Reference.
	ID string
	// URI is the value of the URI attribute of the Reference.
	URI string
	// Type is the value of the Type attribute of the Reference. It is empty
	// when the Reference has no type.
	Type string
	// Transforms are the algorithm identifiers of the transforms that are
	// applied to the content before it is hashed.
	Transforms []string
}

// xmlPart is a part of a container that a manifest digests.
type xmlPart struct {
	// Name is the name of the part, which is the URI of its reference.
	Name string
	// Digest is the digest over the bytes of the part.
	Digest []byte
}

// newXMLSignature returns a ds:Signature element with empty digest and
// signature values, ready to be filled in by finalizeXMLSignature. parts holds
// the digests of the parts a manifest covers; it is empty for a signature that
// covers a single document.
func newXMLSignature(algorithm xmlAlgorithm, cert *x509.Certificate, signingTime time.Time, reference xmlReference, parts []xmlPart) (*element, error) {
	if signingTime.IsZero() {
		signingTime = time.Now()
	}

	var builder strings.Builder
	builder.WriteString(`<ds:Signature xmlns:ds="` + dsigNS + `" xmlns:xades="` + xadesNS + `" Id="` + signatureID + `">`)
	builder.WriteString(`<ds:SignedInfo>`)
	builder.WriteString(`<ds:CanonicalizationMethod Algorithm="` + excC14N + `"/>`)
	builder.WriteString(`<ds:SignatureMethod Algorithm="` + algorithm.SignatureMethod + `"/>`)
	builder.WriteString(referenceXML(reference, algorithm.DigestMethod))
	builder.WriteString(referenceXML(xmlReference{
		ID:         propertiesRefID,
		URI:        "#" + propertiesID,
		Type:       signedPropertiesType,
		Transforms: []string{excC14N},
	}, algorithm.DigestMethod))
	builder.WriteString(`</ds:SignedInfo>`)
	builder.WriteString(`<ds:SignatureValue></ds:SignatureValue>`)
	builder.WriteString(`<ds:KeyInfo Id="pivzavr-keyinfo"><ds:X509Data><ds:X509Certificate>`)
	builder.WriteString(base64.StdEncoding.EncodeToString(cert.Raw))
	builder.WriteString(`</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`)
	if len(parts) > 0 {
		builder.WriteString(manifestXML(parts, algorithm.DigestMethod))
	}
	builder.WriteString(`<ds:Object Id="` + propertiesObjectID + `">`)
	builder.WriteString(`<xades:QualifyingProperties Id="` + qualifyingPropsID + `" Target="#` + signatureID + `">`)
	builder.WriteString(`<xades:SignedProperties Id="` + propertiesID + `">`)
	builder.WriteString(`<xades:SignedSignatureProperties>`)
	builder.WriteString(`<xades:SigningTime>` + signingTime.UTC().Format(time.RFC3339) + `</xades:SigningTime>`)
	builder.WriteString(`</xades:SignedSignatureProperties>`)
	builder.WriteString(`</xades:SignedProperties>`)
	builder.WriteString(`</xades:QualifyingProperties>`)
	builder.WriteString(`</ds:Object>`)
	builder.WriteString(`</ds:Signature>`)

	roots, err := parseXML([]byte(builder.String()))
	if err != nil {
		return nil, err
	}
	return rootElement(roots)
}

// referenceXML returns the XML of a Reference element with an empty digest
// value.
func referenceXML(reference xmlReference, digestMethod string) string {
	var builder strings.Builder
	builder.WriteString(`<ds:Reference`)
	if reference.ID != "" {
		builder.WriteString(` Id="` + reference.ID + `"`)
	}
	builder.WriteString(` URI="` + escapeAttribute(reference.URI) + `"`)
	if reference.Type != "" {
		builder.WriteString(` Type="` + reference.Type + `"`)
	}
	builder.WriteString(`>`)
	if len(reference.Transforms) > 0 {
		builder.WriteString(`<ds:Transforms>`)
		for _, transform := range reference.Transforms {
			builder.WriteString(`<ds:Transform Algorithm="` + transform + `"/>`)
		}
		builder.WriteString(`</ds:Transforms>`)
	}
	builder.WriteString(`<ds:DigestMethod Algorithm="` + digestMethod + `"/>`)
	builder.WriteString(`<ds:DigestValue></ds:DigestValue>`)
	builder.WriteString(`</ds:Reference>`)
	return builder.String()
}

// manifestXML returns the XML of the Object element that carries a Manifest with
// one Reference per part, each with the digest of its part.
func manifestXML(parts []xmlPart, digestMethod string) string {
	var builder strings.Builder
	builder.WriteString(`<ds:Object Id="` + manifestObjectID + `"><ds:Manifest Id="` + manifestID + `">`)
	for _, part := range parts {
		builder.WriteString(`<ds:Reference URI="` + escapeAttribute(part.Name) + `">`)
		builder.WriteString(`<ds:DigestMethod Algorithm="` + digestMethod + `"/>`)
		builder.WriteString(`<ds:DigestValue>` + base64.StdEncoding.EncodeToString(part.Digest) + `</ds:DigestValue>`)
		builder.WriteString(`</ds:Reference>`)
	}
	builder.WriteString(`</ds:Manifest></ds:Object>`)
	return builder.String()
}

// scopeAt returns the namespace bindings that are visible at target, which must
// be an element of the document whose root is root.
func scopeAt(root, target *element) map[string]string {
	scope := scopeOf(root, map[string]string{"xml": xmlNS})
	if root == target {
		return scope
	}
	var result map[string]string
	var walk func(e *element, scope map[string]string)
	walk = func(e *element, scope map[string]string) {
		if result != nil {
			return
		}
		for _, child := range childElements(e) {
			childScope := scopeOf(child, scope)
			if child == target {
				result = childScope
				return
			}
			walk(child, childScope)
		}
	}
	walk(root, scope)
	if result == nil {
		return scope
	}
	return result
}

// hashBytes returns the digest of data with the hash of an algorithm.
func hashBytes(hash crypto.Hash, data []byte) []byte {
	hasher := hash.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}

// finalizeXMLSignature fills in the digest of the content reference, the digest
// of the signed properties and the signature value, and signs the canonical
// form of the SignedInfo with the key of the smart card. contentDigest is the
// digest over the canonical form of the content.
func finalizeXMLSignature(signature, root *element, algorithm xmlAlgorithm, contentDigest []byte, signer *Signer) error {
	signedInfo := firstChild(signature, "SignedInfo")
	if signedInfo == nil {
		return errors.New("the signature has no SignedInfo element")
	}

	references := referencesOf(signedInfo, 2)
	if len(references) < 2 {
		return errors.New("the signature has no reference to its properties")
	}
	contentDigestValue := firstChild(references[0], "DigestValue")
	if contentDigestValue == nil {
		return errors.New("the content reference has no DigestValue element")
	}
	setText(contentDigestValue, base64.StdEncoding.EncodeToString(contentDigest))

	properties := elementByID(signature, propertiesID)
	if properties == nil {
		return errors.New("the signature has no signed properties")
	}
	propertiesDigest := hashBytes(algorithm.Hash, canonicalizeElement(properties, scopeAt(root, properties)))
	setText(firstChild(references[1], "DigestValue"), base64.StdEncoding.EncodeToString(propertiesDigest))

	signed := canonicalizeElement(signedInfo, scopeAt(root, signedInfo))
	digest := hashBytes(algorithm.Hash, signed)
	value, err := signer.Signer.Sign(rand.Reader, digest, algorithm.Hash)
	if err != nil {
		return errors.Wrap(err, "Sign XML")
	}
	setText(firstChild(signature, "SignatureValue"), base64.StdEncoding.EncodeToString(value))
	return nil
}

// referencesOf returns up to limit Reference children of signedInfo, in
// document order.
func referencesOf(signedInfo *element, limit int) []*element {
	var references []*element
	for _, child := range childElements(signedInfo) {
		if child.Name.Local != "Reference" {
			continue
		}
		references = append(references, child)
		if len(references) == limit {
			break
		}
	}
	return references
}

// signatureElement returns the first ds:Signature element of a document, or nil
// when the document holds none.
func signatureElement(root *element) *element {
	for _, e := range descendants(root) {
		if e.Name.Local == "Signature" && firstChild(e, "SignedInfo") != nil {
			return e
		}
	}
	return nil
}

// attrValue returns the value of the attribute with the given local name, or an
// empty string when the element has no such attribute.
func attrValue(e *element, local string) string {
	if e == nil {
		return ""
	}
	for _, a := range e.Attrs {
		if a.Name.Local == local {
			return a.Value
		}
	}
	return ""
}

// signXML embeds an enveloped XML signature in an XML document.
func signXML(data []byte, signer *Signer) ([]byte, error) {
	roots, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	root, err := rootElement(roots)
	if err != nil {
		return nil, err
	}
	if signatureElement(root) != nil {
		return nil, errors.New("the XML document already carries an XML signature")
	}

	algorithm, err := algorithmFor(signer.Certificate)
	if err != nil {
		return nil, err
	}

	signature, err := newXMLSignature(algorithm, signer.Certificate, signer.SigningTime, xmlReference{
		ID:         contentRefID,
		URI:        "",
		Transforms: []string{envelopedTransform, excC14N},
	}, nil)
	if err != nil {
		return nil, err
	}

	// The enveloped transform removes the signature from the document before it
	// is hashed, so the digest is computed over a copy of the document that
	// does not have the signature.
	contentDigest := hashBytes(algorithm.Hash, canonicalize(cloneDocument(roots)))

	appendChild(root, signature)
	if err := finalizeXMLSignature(signature, root, algorithm, contentDigest, signer); err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if err := serialize(buf, roots); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// verifyXML verifies the enveloped XML signature of a document.
func verifyXML(data []byte) (*Signature, error) {
	return verifyXMLSignatureDocument(data, nil)
}

// verifyXMLSignatureDocument verifies the ds:Signature element of a document
// and the manifest it may carry. parts holds the bytes of the parts a manifest
// digests, keyed by part name; it is nil for a signature that covers a single
// document.
func verifyXMLSignatureDocument(data []byte, parts map[string][]byte) (*Signature, error) {
	roots, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	root, err := rootElement(roots)
	if err != nil {
		return nil, err
	}
	signature := signatureElement(root)
	if signature == nil {
		return nil, errors.New("the document carries no XML signature")
	}
	return verifyXMLSignature(roots, root, signature, parts)
}

// verifyXMLSignature verifies an XML Signature against the document that holds
// it.
func verifyXMLSignature(roots []any, root, signature *element, parts map[string][]byte) (*Signature, error) {
	signedInfo := firstChild(signature, "SignedInfo")
	if signedInfo == nil {
		return nil, errors.New("the signature has no SignedInfo element")
	}
	if method := attrValue(firstChild(signedInfo, "CanonicalizationMethod"), "Algorithm"); method != excC14N {
		return nil, errors.Errorf("unsupported canonicalization method %q", method)
	}
	algorithm, err := algorithmFromSignatureMethod(attrValue(firstChild(signedInfo, "SignatureMethod"), "Algorithm"))
	if err != nil {
		return nil, err
	}

	signatureValue, err := base64.StdEncoding.DecodeString(text(firstChild(signature, "SignatureValue")))
	if err != nil {
		return nil, errors.Wrap(err, "Decode signature value")
	}
	certificates, err := certificatesFromSignature(signature)
	if err != nil {
		return nil, err
	}

	references := referencesOf(signedInfo, 0)
	if len(references) == 0 {
		return nil, errors.New("the signature covers no content")
	}
	for _, reference := range references {
		if err := checkXMLReference(reference, roots, root, parts); err != nil {
			return nil, err
		}
	}

	// A manifest holds one reference per part of the container it covers.
	if manifest := elementByID(root, manifestID); manifest != nil {
		if parts == nil {
			return nil, errors.New("the signature covers the parts of a container, but none were provided")
		}
		for _, reference := range referencesOf(manifest, 0) {
			if err := checkXMLReference(reference, roots, root, parts); err != nil {
				return nil, err
			}
		}
	}

	signed := canonicalizeElement(signedInfo, scopeAt(root, signedInfo))
	digest := hashBytes(algorithm.Hash, signed)
	certificate, err := checkXMLSignatureValue(certificates, algorithm, digest, signatureValue)
	if err != nil {
		return nil, err
	}

	return &Signature{
		Format:             XML,
		Certificate:        certificate,
		Certificates:       certificates,
		SigningTime:        signingTimeOf(signature),
		SignatureAlgorithm: algorithm.SignatureAlgorithm,
	}, nil
}

// checkXMLReference verifies that the content a Reference covers matches the
// digest it carries.
func checkXMLReference(reference *element, roots []any, root *element, parts map[string][]byte) error {
	hash, err := hashForDigestMethod(attrValue(firstChild(reference, "DigestMethod"), "Algorithm"))
	if err != nil {
		return err
	}
	digestValue, err := base64.StdEncoding.DecodeString(text(firstChild(reference, "DigestValue")))
	if err != nil {
		return errors.Wrap(err, "Decode reference digest")
	}

	uri := attrValue(reference, "URI")
	var actual []byte
	switch {
	case uri == "":
		// The reference covers the whole document; the enveloped transform
		// removes the signature from it.
		unsignedRoots := cloneDocument(roots)
		unsignedRoot, err := rootElement(unsignedRoots)
		if err != nil {
			return err
		}
		unsigned := signatureElement(unsignedRoot)
		if unsigned == nil {
			return errors.New("the enveloped signature is no longer part of the document")
		}
		removeChild(unsignedRoot, unsigned)
		actual = hashBytes(hash, canonicalize(unsignedRoots))
	case strings.HasPrefix(uri, "#"):
		target := elementByID(root, strings.TrimPrefix(uri, "#"))
		if target == nil {
			return errors.Errorf("the reference target %q is not part of the document", uri)
		}
		actual = hashBytes(hash, canonicalizeElement(target, scopeAt(root, target)))
	default:
		// A reference of a manifest names a part of the container.
		data, ok := parts[uri]
		if !ok {
			return errors.Errorf("the referenced part %q is missing", uri)
		}
		actual = hashBytes(hash, data)
	}

	if !bytes.Equal(actual, digestValue) {
		return errors.Errorf("the content of the reference %q does not match its digest", uri)
	}
	return nil
}

// certificatesFromSignature returns the certificates the KeyInfo of a signature
// carries, in document order.
func certificatesFromSignature(signature *element) ([]*x509.Certificate, error) {
	keyInfo := firstChild(signature, "KeyInfo")
	if keyInfo == nil {
		return nil, errors.New("the signature has no KeyInfo element")
	}

	var certificates []*x509.Certificate
	for _, e := range descendants(keyInfo) {
		if e.Name.Local != "X509Certificate" {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(text(e))
		if err != nil {
			return nil, errors.Wrap(err, "Decode certificate")
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errors.Wrap(err, "Parse certificate")
		}
		certificates = append(certificates, certificate)
	}
	if len(certificates) == 0 {
		return nil, errors.New("the signature carries no certificate")
	}
	return certificates, nil
}

// checkXMLSignatureValue returns the certificate whose key made the signature,
// or an error when none of the certificates matches.
func checkXMLSignatureValue(certificates []*x509.Certificate, algorithm xmlAlgorithm, signed, value []byte) (*x509.Certificate, error) {
	for _, certificate := range certificates {
		if err := checkKeySignature(certificate.PublicKey, algorithm.Hash, signed, value); err == nil {
			return certificate, nil
		}
	}
	return nil, errors.New("the signature does not match any of the certificates it carries")
}

// checkKeySignature verifies a raw signature over the digest of a message.
func checkKeySignature(key crypto.PublicKey, hash crypto.Hash, signed, value []byte) error {
	switch public := key.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(public, hash, signed, value)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(public, signed, value) {
			return errors.New("signature verification with ECDSA failed")
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(public, signed, value) {
			return errors.New("signature verification with Ed25519 failed")
		}
		return nil
	}
	return errors.Errorf("unsupported public key type %T", key)
}

// signingTimeOf returns the signing time of a signature, or the zero time when
// the signature does not record one.
func signingTimeOf(signature *element) time.Time {
	properties := elementByID(signature, propertiesID)
	if properties == nil {
		properties = signature
	}
	for _, e := range descendants(properties) {
		if e.Name.Local != "SigningTime" {
			continue
		}
		if parsed, err := time.Parse(time.RFC3339, text(e)); err == nil {
			return parsed
		}
	}
	return time.Time{}
}
