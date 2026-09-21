package pivzavr

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"strings"

	"github.com/h0tc0d3/pivzavr/pkg/cms"
	"github.com/h0tc0d3/pivzavr/pkg/i18n"
)

// SignOpts specifies the parameters required when signing data
type SignOpts struct {
	// StatusFd file descriptor to write the "status protocol" to. For more details see the [status] package
	StatusFd int
	// Detach excludes the content being signed from the signature
	Detach bool
	// Armor encodes the signature in a PEM block
	Armor bool
	// Clearsign writes a clear text signature: the message is written in
	// front of the armored signature, so that the message stays readable
	// while the signature stays recognizable.
	Clearsign bool
	// UserID identifies the user of the certificate. Can be either an email address or the certificate's fingerprint
	UserID string
	// TimestampAuthority adds a timestamp to the signature from the given URL. See RFC3161 for more details
	TimestampAuthority string
	// Message to sign
	Message io.Reader
	// Slot containing key for signing
	Slot Slot
}

// PEM block types of an armored signature. The signature of pivzavr is a CMS
// (PKCS#7) structure, and pkcs7PemHeader is the label OpenSSL uses for it, so
// the armored output is recognized by other CMS tools. The other two types are
// accepted when a signature is verified: cmsPemHeader is what the cms command
// of OpenSSL writes, and signedMessagePemHeader is what pivzavr wrote before
// the ASCII armor was made a PKCS#7 block.
const (
	pkcs7PemHeader         = "PKCS7"
	cmsPemHeader           = "CMS"
	signedMessagePemHeader = "SIGNED MESSAGE"
)

// clearTextSignatureSeparator separates the message of a clear text signature
// from the armored signature that follows it. One blank line is left between
// the two.
const clearTextSignatureSeparator = "\n\n"

// isSignaturePemHeader reports whether a PEM block type names a signature that
// VerifySignature accepts.
func isSignaturePemHeader(header string) bool {
	switch header {
	case pkcs7PemHeader, cmsPemHeader, signedMessagePemHeader:
		return true
	}
	return false
}

// clearTextSignature combines the message of a clear text signature with the
// armored signature that was made over it. The message is written verbatim, so
// that it stays readable and is recovered byte for byte by
// splitClearTextSignature, and a blank line separates it from the armored
// detached CMS signature.
func clearTextSignature(message, armoredSignature []byte) []byte {
	// The parts are appended instead of being sized up front: the sum of the
	// three lengths could overflow int, which would compute a wrong (and
	// possibly negative) allocation size. append grows the slice as needed.
	out := append([]byte(nil), message...)
	out = append(out, clearTextSignatureSeparator...)
	out = append(out, armoredSignature...)
	return out
}

// splitClearTextSignature splits the message of a clear text signature from the
// armored signature that follows it. The message is the part in front of the
// blank line that separates it from the armored signature block, so it is
// recovered byte for byte. The boolean result reports whether data holds a clear
// text signature.
//
// The armored block is looked for from the start of the data, the way pem.Decode
// reads a block, so a message that itself holds a blank line followed by the
// start of a PKCS7 block is not supported.
func splitClearTextSignature(data []byte) ([]byte, bool) {
	marker := clearTextSignatureSeparator + "-----BEGIN " + pkcs7PemHeader + "-----"
	start := bytes.Index(data, []byte(marker))
	if start < 0 {
		return nil, false
	}
	return data[:start], true
}

// emailAttributeOIDs are the distinguished-name attribute OIDs that carry an
// email address: PKCS#9 emailAddress and RFC 4519 mail.
var emailAttributeOIDs = []asn1.ObjectIdentifier{
	{1, 2, 840, 113549, 1, 9, 1},
	{0, 9, 2342, 19200300, 100, 1, 3},
}

// Sign creates a digital signature from the given data in SignOpts.Message
func Sign(tok Pivzavr, opts *SignOpts) ([]byte, error) {
	cert, err := tok.Certificate(opts.Slot)
	if err != nil {
		return nil, i18n.Wrap(err, "Get identity certificate")
	}

	if err = certificateContainsUserID(cert, opts.UserID); err != nil {
		return nil, i18n.Wrap(err, "No suitable certificate found")
	}

	SetupStatus(opts.StatusFd)
	dataBuf := new(bytes.Buffer)
	if _, err = io.Copy(dataBuf, opts.Message); err != nil {
		return nil, i18n.Wrap(err, "Read message to sign")
	}

	sd, err := cms.NewSignedData(dataBuf.Bytes())
	if err != nil {
		return nil, i18n.Wrap(err, "Create signed data")
	}

	signer, err := tok.Signer(opts.Slot)
	if err != nil {
		return nil, i18n.Wrap(err, "Load key")
	}
	if err = sd.Sign([]*x509.Certificate{cert}, signer); err != nil {
		return nil, i18n.Wrap(err, "Sign message")
	}
	// Git is looking for "\n[GNUPG:] SIG_CREATED ", meaning we need to print a
	// line before SIG_CREATED. BEGIN_SIGNING seems appropriate. GPG emits this,
	// though GPGSM does not.
	EmitBeginSigning()

	// A clear text signature is a detached signature that is always armored:
	// the message it signs is written in front of the signature instead of
	// being encapsulated in it.
	if opts.Detach || opts.Clearsign {
		sd.Detached()
	}

	if len(opts.TimestampAuthority) > 0 {
		if err = sd.AddTimestamps(opts.TimestampAuthority); err != nil {
			return nil, i18n.Wrap(err, "Add timestamp to signature")
		}
	}

	chain := []*x509.Certificate{cert}
	if err = sd.SetCertificates(chain); err != nil {
		return nil, i18n.Wrap(err, "Set certificates in signature")
	}

	der, err := sd.ToDER()
	if err != nil {
		return nil, i18n.Wrap(err, "Serialize signature")
	}

	EmitSigCreated(cert, signatureType(opts))
	if !opts.Armor && !opts.Clearsign {
		return der, nil
	}

	armored := &bytes.Buffer{}
	if err = pem.Encode(armored, &pem.Block{
		Type:  pkcs7PemHeader,
		Bytes: der,
	}); err != nil {
		return nil, i18n.New("Write signature.")
	}
	if opts.Clearsign {
		return clearTextSignature(dataBuf.Bytes(), armored.Bytes()), nil
	}
	return armored.Bytes(), nil
}

// signatureType returns the SIG_CREATED type of the signature that opts
// describes: "C" for a clear text signature, "D" for a detached signature and
// "S" for a signature that carries its content.
func signatureType(opts *SignOpts) string {
	switch {
	case opts.Clearsign:
		return "C"
	case opts.Detach:
		return "D"
	default:
		return "S"
	}
}

func certificateContainsUserID(cert *x509.Certificate, userID string) error {
	email, err := normalizeEmail(userID)
	if err != nil {
		fingerprint := normalizeFingerprint(userID)
		if !strings.EqualFold(CertHexFingerprint(cert), fingerprint) {
			return i18n.Errorf("No certificate found with fingerprint %s.", fingerprint)
		}
	} else if !certificateContainsEmail(cert, email) {
		return i18n.Errorf("No certificate found with email %s.", email)
	}

	return nil
}

// normalizeEmail extracts the email address portion from the user ID string
// or an error if the user ID string doesn't contain a valid email address.
//
// The user ID string is expected to be either:
// - An email address
// - A string containing a name, comment and email address, like "Full Name (comment) <email@example.com>"
// - A hex fingerprint
func normalizeEmail(userID string) (string, error) {
	emailStartIndex := strings.Index(userID, "<")
	if emailStartIndex != -1 {
		emailEndIndex := strings.Index(userID, ">")
		if emailEndIndex <= emailStartIndex {
			return "", i18n.New("User id doesn't contain a valid email address.")
		}
		email := userID[emailStartIndex+1 : emailEndIndex]
		if email == "" {
			return "", i18n.New("User id doesn't contain a valid email address.")
		}
		return email, nil
	}

	if strings.ContainsRune(userID, '@') {
		return userID, nil
	}

	return "", i18n.New("User id doesn't contain email address.")
}

func normalizeFingerprint(userID string) string {
	fp := strings.TrimSpace(userID)
	fp = strings.TrimPrefix(fp, "0x")
	fp = strings.TrimPrefix(fp, "0X")
	return fp
}

// certificateContainsEmail reports whether email identifies the subject of
// certificate. An address identifies the subject when it is a subject
// alternative name or a distinguished-name attribute of the subject. The
// issuer is a different party, so its name is not consulted: an address that
// only the issuer carries does not select the certificate.
func certificateContainsEmail(certificate *x509.Certificate, email string) bool {
	for _, sanEmail := range certificate.EmailAddresses {
		if strings.EqualFold(sanEmail, email) {
			return true
		}
	}

	return nameContainsEmail(certificate.Subject, email)
}

// nameContainsEmail reports whether a distinguished name contains an email
// attribute that matches email.
func nameContainsEmail(name pkix.Name, email string) bool {
	for _, atvs := range [][]pkix.AttributeTypeAndValue{name.Names, name.ExtraNames} {
		for _, atv := range atvs {
			if isEmailAttribute(atv.Type) && strings.EqualFold(attributeValue(atv.Value), email) {
				return true
			}
		}
	}
	return false
}

// isEmailAttribute reports whether oid is a distinguished-name attribute that
// carries an email address.
func isEmailAttribute(oid asn1.ObjectIdentifier) bool {
	for _, emailOID := range emailAttributeOIDs {
		if oid.Equal(emailOID) {
			return true
		}
	}
	return false
}
