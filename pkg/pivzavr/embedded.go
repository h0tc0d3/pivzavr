package pivzavr

import (
	"crypto/x509"
	"io"
	"time"

	"github.com/h0tc0d3/pivzavr/pkg/cms"
	"github.com/h0tc0d3/pivzavr/pkg/embed"
	"github.com/h0tc0d3/pivzavr/pkg/i18n"
)

// EmbeddedSignOpts specifies the parameters required when a signature is
// embedded in a file of a container format rather than written to a file of its
// own.
type EmbeddedSignOpts struct {
	// StatusFd file descriptor to write the "status protocol" to
	StatusFd int
	// UserID identifies the user of the certificate. Can be either an email
	// address or the certificate's fingerprint
	UserID string
	// Format is the format of the file the signature is embedded in
	Format embed.Format
	// Message is the file the signature is embedded in
	Message io.Reader
	// Output receives the signed file
	Output io.Writer
	// Slot containing key for signing
	Slot Slot
}

// SignEmbedded embeds a signature in the file read from opts.Message and writes
// the signed file to opts.Output. The file itself is not changed: the signed
// file is written to the output, which the caller may point at another file.
func SignEmbedded(tok Pivzavr, opts *EmbeddedSignOpts) error {
	if !opts.Format.Embeddable() {
		return i18n.Errorf("A signature cannot be embedded in a %s file.", opts.Format)
	}

	cert, err := tok.Certificate(opts.Slot)
	if err != nil {
		return i18n.Wrap(err, "Get identity certificate")
	}
	if err = certificateContainsUserID(cert, opts.UserID); err != nil {
		return i18n.Wrap(err, "No suitable certificate found")
	}

	SetupStatus(opts.StatusFd)
	data, err := io.ReadAll(opts.Message)
	if err != nil {
		return i18n.Wrap(err, "Read message to sign")
	}

	signer, err := tok.Signer(opts.Slot)
	if err != nil {
		return i18n.Wrap(err, "Load key")
	}
	EmitBeginSigning()

	signed, err := embed.Sign(opts.Format, data, &embed.Signer{
		Certificate: cert,
		Signer:      signer,
		SigningTime: time.Now().UTC(),
	})
	if err != nil {
		return err
	}

	// The signed content travels with the file, so the status protocol reports
	// an attached signature.
	EmitSigCreated(cert, "S")
	if _, err = opts.Output.Write(signed); err != nil {
		return i18n.Wrap(err, "Write signed file")
	}
	return nil
}

// EmbeddedVerifyOpts specifies the parameters required when the signature that
// is verified is embedded in a file.
type EmbeddedVerifyOpts struct {
	// Format is the format of the file the signature is embedded in
	Format embed.Format
	// Message is the file the signature is embedded in
	Message io.Reader
	// Slot that holds the certificate a self-signed signature is compared with
	Slot Slot
}

// VerifyEmbedded verifies the signature that is embedded in a file.
func VerifyEmbedded(tok Pivzavr, opts *EmbeddedVerifyOpts) error {
	EmitNewSign()

	data, err := io.ReadAll(opts.Message)
	if err != nil {
		return i18n.Wrap(err, "Read message file")
	}

	signature, err := embed.Verify(opts.Format, data)
	if err != nil {
		EmitErrSig()
		return err
	}
	return verifyEmbeddedSignature(tok, signature, opts.Slot)
}

// verifyEmbeddedSignature checks the trust of the certificate that made an
// embedded signature the same way a detached signature is checked: against the
// CA certificates of the trust store, against the self-signed certificate of
// the smart card when the card was never enrolled with a CA, and against the
// public keys of the trust store when the certificate names no CA at all.
func verifyEmbeddedSignature(tok Pivzavr, signature *embed.Signature, slot Slot) error {
	details := cms.SignerDetails{
		SigningTime:        signature.SigningTime,
		SignatureAlgorithm: signature.SignatureAlgorithm,
	}

	anchors := loadTrustAnchors()
	options := verifyOpts(anchors.roots)
	options.Intermediates = x509.NewCertPool()
	for _, certificate := range signature.Certificates {
		options.Intermediates.AddCert(certificate)
	}

	if chains, err := signature.Certificate.Verify(options); err == nil {
		return verifyChains([][][]*x509.Certificate{chains}, trustCA, details)
	}
	if cardCert, ok := selfSignedCardCertificate(tok, signature.Certificate, slot); ok {
		if chains, err := signature.Certificate.Verify(verifyOptsWithRoot(cardCert)); err == nil {
			return verifyChains([][][]*x509.Certificate{chains}, trustSelfSigned, details)
		}
	}
	if matchesPublicKey(signature.Certificate, anchors.keys) {
		if chains, err := signature.Certificate.Verify(verifyOptsWithRoot(signature.Certificate)); err == nil {
			return verifyChains([][][]*x509.Certificate{chains}, trustPublicKey, details)
		}
	}

	EmitErrSig()
	return i18n.New("The certificate of the embedded signature is not trusted.")
}

// selfSignedCardCertificate returns the self-signed certificate of the smart
// card in slot when it is the certificate an embedded signature was made with.
func selfSignedCardCertificate(tok Pivzavr, certificate *x509.Certificate, slot Slot) (*x509.Certificate, bool) {
	cardCert, err := tok.Certificate(slot)
	if err != nil || cardCert == nil || !isSelfSigned(cardCert) {
		return nil, false
	}
	if !samePublicKey(cardCert, certificate) {
		return nil, false
	}
	return cardCert, true
}
