package embed

import (
	"crypto/x509"

	"github.com/h0tc0d3/pivzavr/pkg/cms"
	"github.com/pkg/errors"
)

// verifyDetachedCMS verifies a detached CMS signature over content and returns
// the certificate that made it, together with the certificates the signature
// carries and the metadata of the signature.
//
// Only the cryptography is checked here: the certificate is trusted as its own
// anchor, because the signature is embedded in a file and its trust is decided
// by the caller, which knows the CA bundle of the configuration.
func verifyDetachedCMS(der, content []byte) (*x509.Certificate, []*x509.Certificate, cms.SignerDetails, error) {
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		return nil, nil, cms.SignerDetails{}, errors.Wrap(err, "Parse signature")
	}
	if !sd.IsDetached() {
		return nil, nil, cms.SignerDetails{}, errors.New("the signature is not detached")
	}

	signers, err := sd.SignerCertificates()
	if err != nil {
		return nil, nil, cms.SignerDetails{}, errors.Wrap(err, "Read signer certificate")
	}
	if len(signers) == 0 {
		return nil, nil, cms.SignerDetails{}, errors.New("the signature carries no signer certificate")
	}
	certificate := signers[0]

	certificates, err := sd.GetCertificates()
	if err != nil {
		return nil, nil, cms.SignerDetails{}, errors.Wrap(err, "Read certificates")
	}

	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	options := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := sd.VerifyDetached(content, options); err != nil {
		return nil, nil, cms.SignerDetails{}, errors.Wrap(err, "Verify signature")
	}

	details := cms.SignerDetails{}
	if signers, err := sd.Signers(); err == nil && len(signers) > 0 {
		details = signers[0]
	}
	return certificate, certificates, details, nil
}
