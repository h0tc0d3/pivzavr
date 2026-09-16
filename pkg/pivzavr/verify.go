package pivzavr

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/certifi/gocertifi"
	cms "github.com/github/smimesign/ietf-cms"
	"github.com/pkg/errors"
)

// VerifyOpts specifies the parameters required when verifying signatures
type VerifyOpts struct {
	// Signature to verify
	Signature io.Reader
	// Message associated with the signature.
	// This option is only used when verifying a detached signature
	Message io.Reader
	// Slot containing certificate to verify with
	Slot Slot
}

// VerifySignature verifies digital signatures.
// If the given signature is detached, then read the message associated with the signature form VerifyOpts.Message
func VerifySignature(tok Pivzavr, opts *VerifyOpts) error {
	EmitNewSign()

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, opts.Signature); err != nil {
		return errors.Wrap(err, "Read signature")
	}

	var ber []byte
	if blk, _ := pem.Decode(buf.Bytes()); blk != nil {
		if blk.Type != signedMessagePemHeader {
			return fmt.Errorf("unexpected PEM header: %q", blk.Type)
		}
		ber = blk.Bytes
	} else {
		ber = buf.Bytes()
	}

	sd, err := cms.ParseSignedData(ber)
	if err != nil {
		return errors.Wrap(err, "Parse signature")
	}

	if sd.IsDetached() {
		if opts.Message == nil {
			return errors.New("Expected detached signature, but message wasn't provided.")
		}
		return verifyDetached(tok, sd, opts.Message, opts.Slot)
	}

	// An attached signature already contains the signed data, so any message
	// reader that was passed in (for example when a caller always provides the
	// data file, regardless of whether the signature is attached or detached)
	// is ignored.
	return verifyAttached(tok, sd, opts.Slot)
}

func verifyAttached(tok Pivzavr, sd *cms.SignedData, slot Slot) error {
	chains, err := sd.Verify(verifyOpts(tok, slot))
	if err != nil {
		// The CMS library returns no chains on failure, so a BADSIG status
		// (which requires the signer certificate) cannot be produced here.
		EmitErrSig()
		return errors.Wrap(err, "Verify signature")
	}

	var (
		cert = chains[0][0][0]
		fpr  = CertHexFingerprint(cert)
	)

	_, _ = fmt.Fprintf(os.Stdout, "Signature made using certificate ID 0x%s\n", fpr)
	EmitGoodSig(chains)

	// TODO: Maybe split up signature checking and certificate checking so we can
	// output something more meaningful.
	_, _ = fmt.Fprintf(os.Stdout, "Good signature from \"%s\"\n", formatName(cert.Subject))
	EmitTrustFully()

	return nil
}

func verifyDetached(tok Pivzavr, sd *cms.SignedData, data io.Reader, slot Slot) error {
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, data); err != nil {
		return errors.Wrap(err, "Read message file")
	}

	chains, err := sd.VerifyDetached(buf.Bytes(), verifyOpts(tok, slot))
	if err != nil {
		// The CMS library returns no chains on failure, so a BADSIG status
		// (which requires the signer certificate) cannot be produced here.
		EmitErrSig()
		return errors.Wrap(err, "Failed to verify signature")
	}

	var (
		cert = chains[0][0][0]
		fpr  = CertHexFingerprint(cert)
	)

	_, _ = fmt.Fprintf(os.Stdout, "Signature made using certificate ID 0x%s\n", fpr)
	EmitGoodSig(chains)

	// TODO: Maybe split up signature checking and certificate checking so we can
	// output something more meaningful.
	_, _ = fmt.Fprintf(os.Stdout, "Good signature from \"%s\"\n", formatName(cert.Subject))
	EmitTrustFully()

	return nil
}

func verifyOpts(tok Pivzavr, slot Slot) x509.VerifyOptions {
	roots, err := x509.SystemCertPool()
	if err != nil {
		// SystemCertPool isn't implemented for Windows. fall back to mozilla trust store
		roots, err = gocertifi.CACerts()
		if err != nil {
			// fall back to an empty store
			// verification will likely fail
			roots = x509.NewCertPool()
		}
	}

	cert, err := tok.Certificate(slot)
	if err == nil {
		roots.AddCert(cert)
	}

	return x509.VerifyOptions{
		Roots: roots,
		// TODO: we might want to limit signature verification to only certificates that have the right key usage extension
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
}
