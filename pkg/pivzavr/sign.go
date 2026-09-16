package pivzavr

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"strings"

	cms "github.com/github/smimesign/ietf-cms"
	"github.com/pkg/errors"
)

// SignOpts specifies the parameters required when signing data
type SignOpts struct {
	// StatusFd file descriptor to write the "status protocol" to. For more details see the [status] package
	StatusFd int
	// Detach excludes the content being signed from the signature
	Detach bool
	// Armor encodes the signature in a PEM block
	Armor bool
	// UserId identifies the user of the certificate. Can be either an email address or the certificate's fingerprint
	UserId string
	// TimestampAuthority adds a timestamp to the signature from the given URL. See RFC3161 for more details
	TimestampAuthority string
	// Message to sign
	Message io.Reader
	// Slot containing key for signing
	Slot Slot
	// Prompt where to get the pin from (only used if the token requires it)
	Prompt io.Reader
}

const signedMessagePemHeader = "SIGNED MESSAGE"

// Sign creates a digital signature from the given data in SignOpts.Message
func Sign(tok Pivzavr, opts *SignOpts) ([]byte, error) {
	cert, err := tok.Certificate(opts.Slot)
	if err != nil {
		return nil, errors.Wrap(err, "Get identity certificate")
	}

	if err = certificateContainsUserId(cert, opts.UserId); err != nil {
		return nil, errors.Wrap(err, "No suitable certificate found")
	}

	SetupStatus(opts.StatusFd)
	dataBuf := new(bytes.Buffer)
	if _, err = io.Copy(dataBuf, opts.Message); err != nil {
		return nil, errors.Wrap(err, "Read message to sign")
	}

	sd, err := cms.NewSignedData(dataBuf.Bytes())
	if err != nil {
		return nil, errors.Wrap(err, "Create signed data")
	}

	signer, err := tok.Signer(opts.Slot, opts.Prompt)
	if err != nil {
		return nil, errors.Wrap(err, "Load key")
	}
	if err = sd.Sign([]*x509.Certificate{cert}, signer); err != nil {
		return nil, errors.Wrap(err, "Sign message")
	}
	// Git is looking for "\n[GNUPG:] SIG_CREATED ", meaning we need to print a
	// line before SIG_CREATED. BEGIN_SIGNING seems appropriate. GPG emits this,
	// though GPGSM does not.
	EmitBeginSigning()
	if opts.Detach {
		sd.Detached()
	}

	if len(opts.TimestampAuthority) > 0 {
		if err = sd.AddTimestamps(opts.TimestampAuthority); err != nil {
			return nil, errors.Wrap(err, "Add timestamp to signature")
		}
	}

	chain := []*x509.Certificate{cert}
	if err = sd.SetCertificates(chain); err != nil {
		return nil, errors.Wrap(err, "Set certificates in signature")
	}

	der, err := sd.ToDER()
	if err != nil {
		return nil, errors.Wrap(err, "Serialize signature")
	}

	EmitSigCreated(cert, opts.Detach)
	if opts.Armor {
		buf := &bytes.Buffer{}
		err = pem.Encode(buf, &pem.Block{
			Type:  signedMessagePemHeader,
			Bytes: der,
		})
		if err != nil {
			return nil, errors.New("Write signature.")
		}
		return buf.Bytes(), nil
	} else {
		return der, nil
	}
}

func certificateContainsUserId(cert *x509.Certificate, userId string) error {
	email, err := normalizeEmail(userId)
	if err != nil {
		fingerprint := normalizeFingerprint(userId)
		if !strings.EqualFold(CertHexFingerprint(cert), fingerprint) {
			return errors.Errorf("No certificate found with fingerprint %s.", fingerprint)
		}
	} else {
		if !certificateContainsEmail(cert, email) {
			return errors.Errorf("No certificate found with email %s.", email)
		}
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
func normalizeEmail(userId string) (string, error) {
	emailStartIndex := strings.Index(userId, "<")
	if emailStartIndex != -1 {
		emailEndIndex := strings.Index(userId, ">")
		if emailEndIndex <= emailStartIndex {
			return "", errors.New("User id doesn't contain a valid email address.")
		}
		email := userId[emailStartIndex+1 : emailEndIndex]
		if email == "" {
			return "", errors.New("User id doesn't contain a valid email address.")
		}
		return email, nil
	}

	if strings.ContainsRune(userId, '@') {
		return userId, nil
	}

	return "", errors.New("User id doesn't contain email address.")
}

func normalizeFingerprint(userId string) string {
	fp := strings.TrimSpace(userId)
	fp = strings.TrimPrefix(fp, "0x")
	fp = strings.TrimPrefix(fp, "0X")
	return fp
}

func certificateContainsEmail(certificate *x509.Certificate, email string) bool {
	for _, sanEmail := range certificate.EmailAddresses {
		if strings.EqualFold(sanEmail, email) {
			return true
		}
	}

	return false
}
