// Package embed embeds digital signatures in files that are containers of their
// own and have a standard place for a signature, and verifies the signatures it
// finds there.
//
// The supported formats and the signature scheme each one uses are:
//
//   - .xml documents carry an enveloped XML Signature (XMLDSig) in the
//     document itself.
//   - .docx and .xlsx packages (Office Open XML / OPC) carry an XML Signature
//     in the /_xmlsignatures package part, together with the content type
//     override and the package relationship that make it discoverable.
//   - .odt documents (OpenDocument) carry an XML Signature in the
//     META-INF/documentsignatures.xml package part.
//   - .jar archives and .apk packages carry the JAR (v1) signing scheme: the
//     manifests META-INF/MANIFEST.MF and META-INF/<name>.SF and a PKCS#7/CMS
//     signature in META-INF/<name>.RSA (or .EC/.DSA for other key types).
//   - .pdf documents carry a CMS detached signature in an appended signature
//     field, as the PDF specification describes it.
//
// The XML-based schemes sign the document with the key of the smart card and
// hash the content with SHA-256 or SHA-384, whichever the key supports. The
// XML Signature is produced with exclusive canonicalization (xml-exc-c14n), as
// required by the XML Signature specification.
package embed

import (
	"crypto"
	"crypto/x509"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// Format identifies a container file format that can carry an embedded
// signature.
type Format int

// The supported formats.
const (
	// Unknown reports a file that cannot carry an embedded signature.
	Unknown Format = iota
	// XML is an XML document with an enveloped signature.
	XML
	// DOCX is an Office Open XML word processing document.
	DOCX
	// XLSX is an Office Open XML spreadsheet.
	XLSX
	// ODT is an OpenDocument text document.
	ODT
	// JAR is a Java archive.
	JAR
	// APK is an Android package.
	APK
	// PDF is a PDF document.
	PDF
)

// formatExtensions maps a file extension to the format of the file.
var formatExtensions = map[string]Format{
	"xml":  XML,
	"docx": DOCX,
	"xlsx": XLSX,
	"odt":  ODT,
	"jar":  JAR,
	"apk":  APK,
	"pdf":  PDF,
}

// SupportedExtensions returns the extensions of the supported formats, each
// with a leading dot, sorted by name.
func SupportedExtensions() []string {
	extensions := make([]string, 0, len(formatExtensions))
	for extension := range formatExtensions {
		extensions = append(extensions, "."+extension)
	}
	sort.Strings(extensions)
	return extensions
}

// String returns the name of the format.
func (f Format) String() string {
	for extension, format := range formatExtensions {
		if format == f {
			return strings.ToUpper(extension)
		}
	}
	return "unknown"
}

// Detect returns the format of the file named name, which is taken from its
// extension. It returns Unknown for a file that cannot carry an embedded
// signature.
func Detect(name string) Format {
	return formatExtensions[strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))]
}

// Embeddable reports whether a file of this format carries an embedded
// signature rather than a separate signature file.
func (f Format) Embeddable() bool {
	return f != Unknown
}

// Signer holds the key and certificate material of an embedded signature.
type Signer struct {
	// Certificate is the certificate of the signer.
	Certificate *x509.Certificate
	// Signer makes the cryptographic signature with the private key. It is the
	// key of the smart card for a real signature.
	Signer crypto.Signer
	// SigningTime is the time that is recorded in the signature.
	SigningTime time.Time
}

// Signature is a signature that was read from a file and verified.
type Signature struct {
	// Format is the format the signature was read from.
	Format Format
	// Certificate is the certificate that made the signature.
	Certificate *x509.Certificate
	// Certificates holds every certificate that was found with the signature,
	// including the signer certificate. Intermediates are added to the chain
	// that is built for the trust check.
	Certificates []*x509.Certificate
	// SigningTime is the time the signature was created. It is the zero time
	// when the file does not record one.
	SigningTime time.Time
	// SignatureAlgorithm is the algorithm the signature was made with.
	SignatureAlgorithm x509.SignatureAlgorithm
}

// Sign embeds a signature made with signer in the data of a file and returns
// the signed file. The format selects the scheme that is used.
func Sign(format Format, data []byte, signer *Signer) ([]byte, error) {
	if signer == nil || signer.Certificate == nil || signer.Signer == nil {
		return nil, errors.New("a certificate and a signer are required to embed a signature")
	}

	switch format {
	case XML:
		return signXML(data, signer)
	case DOCX, XLSX:
		return signOPC(format, data, signer)
	case ODT:
		return signODF(data, signer)
	case JAR, APK:
		return signJAR(format, data, signer)
	case PDF:
		return signPDF(data, signer)
	}
	return nil, errors.Errorf("unsupported file format %s", format)
}

// Verify extracts the embedded signature of a file and verifies it against the
// certificate it carries. The trust of that certificate is checked by the
// caller.
func Verify(format Format, data []byte) (*Signature, error) {
	switch format {
	case XML:
		return verifyXML(data)
	case DOCX, XLSX:
		return verifyOPC(format, data)
	case ODT:
		return verifyODF(data)
	case JAR, APK:
		return verifyJAR(format, data)
	case PDF:
		return verifyPDF(data)
	}
	return nil, errors.Errorf("unsupported file format %s", format)
}
