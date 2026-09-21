package cms

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"
)

// SignerDetails describes a single signature of a SignedData: the time it was
// created, the digest algorithm it used and the X.509 signature algorithm it
// was made with.
type SignerDetails struct {
	// SigningTime is the time at which the signature was created, taken from
	// the signing-time signed attribute. It is the zero time when the
	// attribute is absent.
	SigningTime time.Time
	// DigestAlgorithm is the digest algorithm identifier of the signature.
	DigestAlgorithm pkix.AlgorithmIdentifier
	// SignatureAlgorithm is the X.509 signature algorithm of the signature.
	SignatureAlgorithm x509.SignatureAlgorithm
}

// SignedData represents a CMS signed message, which may either embed its
// content (attached) or not (detached).
type SignedData struct {
	sd *signedData
}

// NewSignedData creates a new SignedData from the given content.
func NewSignedData(data []byte) (*SignedData, error) {
	eci, err := newDataEncapsulatedContentInfo(data)
	if err != nil {
		return nil, err
	}

	return &SignedData{sd: newSignedData(eci)}, nil
}

// ParseSignedData parses a SignedData from BER encoded data.
func ParseSignedData(ber []byte) (*SignedData, error) {
	ci, err := parseContentInfo(ber)
	if err != nil {
		return nil, err
	}

	sd, err := ci.signedDataContent()
	if err != nil {
		return nil, err
	}

	return &SignedData{sd: sd}, nil
}

// GetData returns the encapsulated content. It returns nil for a detached
// signature and an error when the SignedData encapsulates something other than
// id-data.
func (sd *SignedData) GetData() ([]byte, error) {
	if !sd.sd.EncapContentInfo.isTypeData() {
		return nil, errWrongType
	}
	return sd.sd.EncapContentInfo.contentValue()
}

// GetCertificates returns all the certificates embedded in the SignedData.
func (sd *SignedData) GetCertificates() ([]*x509.Certificate, error) {
	return sd.sd.x509Certificates()
}

// SignerCertificates returns the certificate that made each signature, in the
// order of the signatures. An error is returned when the certificate of a
// signature is not embedded in the SignedData.
func (sd *SignedData) SignerCertificates() ([]*x509.Certificate, error) {
	certs, err := sd.sd.x509Certificates()
	if err != nil {
		return nil, err
	}

	signers := make([]*x509.Certificate, 0, len(sd.sd.SignerInfos))
	for _, si := range sd.sd.SignerInfos {
		cert, err := si.findCertificate(certs)
		if err != nil {
			return nil, err
		}
		signers = append(signers, cert)
	}
	return signers, nil
}

// Signers returns the metadata of every signature, in the order of the
// signatures.
func (sd *SignedData) Signers() ([]SignerDetails, error) {
	details := make([]SignerDetails, 0, len(sd.sd.SignerInfos))
	for _, si := range sd.sd.SignerInfos {
		signingTime, err := si.signingTime()
		if err != nil {
			return nil, err
		}
		details = append(details, SignerDetails{
			SigningTime:        signingTime,
			DigestAlgorithm:    si.DigestAlgorithm,
			SignatureAlgorithm: si.x509SignatureAlgorithm(),
		})
	}
	return details, nil
}

// SetCertificates replaces the certificates embedded in the SignedData.
func (sd *SignedData) SetCertificates(certs []*x509.Certificate) error {
	sd.sd.clearCertificates()
	for _, cert := range certs {
		if err := sd.sd.addCertificate(cert); err != nil {
			return err
		}
	}
	return nil
}

// Sign adds a signature produced by signer to the SignedData. chain must
// contain the leaf certificate associated with signer; any additional
// intermediates are embedded as well.
func (sd *SignedData) Sign(chain []*x509.Certificate, signer crypto.Signer) error {
	return sd.sd.addSignerInfo(chain, signer)
}

// Detached removes the content from the SignedData, turning it into a detached
// signature. No further signatures can be added afterwards.
func (sd *SignedData) Detached() {
	sd.sd.EncapContentInfo.EContent = asn1.RawValue{}
}

// IsDetached reports whether the SignedData has no embedded content.
func (sd *SignedData) IsDetached() bool {
	return sd.sd.EncapContentInfo.EContent.Bytes == nil
}

// ToDER encodes the SignedData as a DER encoded ContentInfo.
func (sd *SignedData) ToDER() ([]byte, error) {
	return sd.sd.contentInfoDER()
}
