package pivzavr

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/h0tc0d3/pivzavr/pkg/i18n"
)

// CertificateOpts selects the certificate that Certificate reads.
type CertificateOpts struct {
	// Slot to get certificate from
	Slot Slot
}

// CertificateOutput is a certificate that was read from a smart card together
// with the slot it came from.
type CertificateOutput struct {
	Fingerprint    string
	CertificatePem string
	// Certificate is the parsed x509 certificate the PEM was derived from.
	Certificate *x509.Certificate
	// Slot the certificate was read from.
	Slot Slot
}

// Certificate exports the certificate.
func Certificate(tok Pivzavr, opts *CertificateOpts) (*CertificateOutput, error) {
	cert, err := tok.Certificate(opts.Slot)
	if err != nil {
		return nil, i18n.Wrap(err, "Get PIV certificate")
	}

	certBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	fingerprint := CertHexFingerprint(cert)
	return &CertificateOutput{
		Fingerprint:    fingerprint,
		CertificatePem: string(certBytes),
		Certificate:    cert,
		Slot:           opts.Slot,
	}, nil
}
