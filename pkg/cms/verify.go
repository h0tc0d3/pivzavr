package cms

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"

	"github.com/h0tc0d3/pivzavr/pkg/gost"
)

// Verify verifies the signatures attached to the SignedData. The certificates
// that made the signatures are verified against the provided roots; the full
// verification chains are returned, mirroring x509.Certificate.Verify.
//
// WARNING: this function does not perform any revocation checking.
func (sd *SignedData) Verify(opts x509.VerifyOptions) ([][][]*x509.Certificate, error) {
	content, err := sd.sd.EncapContentInfo.contentValue()
	if err != nil {
		return nil, err
	}
	if content == nil {
		return nil, errors.New("cms: detached signature")
	}

	return sd.verify(content, opts)
}

// VerifyDetached verifies the detached signatures in the SignedData over
// message. The certificates that made the signatures are verified against the
// provided roots; the full verification chains are returned.
//
// WARNING: this function does not perform any revocation checking.
func (sd *SignedData) VerifyDetached(message []byte, opts x509.VerifyOptions) ([][][]*x509.Certificate, error) {
	if sd.sd.EncapContentInfo.EContent.Bytes != nil {
		return nil, errors.New("cms: signature is not detached")
	}

	return sd.verify(message, opts)
}

// verify checks every SignerInfo over content.
func (sd *SignedData) verify(content []byte, opts x509.VerifyOptions) ([][][]*x509.Certificate, error) {
	if len(sd.sd.SignerInfos) == 0 {
		return nil, ASN1Error{Message: "no signatures found"}
	}

	certs, err := sd.sd.x509Certificates()
	if err != nil {
		return nil, err
	}

	if opts.Intermediates == nil {
		opts.Intermediates = x509.NewCertPool()
	}
	for _, cert := range certs {
		opts.Intermediates.AddCert(cert)
	}

	// Use the same verification options for timestamps, but require the
	// timestamping key usage.
	tsOpts := opts
	tsOpts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}

	chains := make([][][]*x509.Certificate, 0, len(sd.sd.SignerInfos))

	for _, si := range sd.sd.SignerInfos {
		signedMessage, err := signedMessageFor(si, content, sd.sd.EncapContentInfo)
		if err != nil {
			return nil, err
		}

		cert, err := si.findCertificate(certs)
		if err != nil {
			return nil, err
		}

		algo := si.x509SignatureAlgorithm()
		if gost.IsSignatureAlgorithm(si.SignatureAlgorithm.Algorithm) {
			if err := verifyGostSignature(cert, signedMessage, si.Signature, si.DigestAlgorithm.Algorithm); err != nil {
				return nil, err
			}
		} else {
			if algo == x509.UnknownSignatureAlgorithm {
				return nil, errUnsupported
			}
			if err := cert.CheckSignature(algo, signedMessage, si.Signature); err != nil {
				return nil, err
			}
		}

		// If the signer included a timestamp, use its time as the
		// verification time so that a signature can still be validated after
		// the certificate expired. A copy of the options is used because only
		// this signature should be affected.
		optsCopy := opts

		hasTS, err := hasTimestamp(si)
		if err != nil {
			return nil, err
		}
		if hasTS {
			tsti, err := getTimestamp(si, tsOpts)
			if err != nil {
				return nil, err
			}

			if !tsti.before(cert.NotAfter) || !tsti.after(cert.NotBefore) {
				return nil, x509.CertificateInvalidError{Cert: cert, Reason: x509.Expired}
			}

			if optsCopy.CurrentTime.IsZero() {
				optsCopy.CurrentTime = tsti.GenTime
			}
		}

		chain, err := cert.Verify(optsCopy)
		if err != nil {
			return nil, err
		}
		chains = append(chains, chain)
	}

	return chains, nil
}

// signedMessageFor returns the bytes the SignerInfo's signature covers. When
// signed attributes are present they are validated and their encoding is
// returned; otherwise the encapsulated content itself is signed.
func signedMessageFor(si signerInfo, content []byte, eci encapsulatedContentInfo) ([]byte, error) {
	if si.SignedAttrs == nil {
		// Signed attributes may only be absent for id-data content.
		if !eci.isTypeData() {
			return nil, ASN1Error{Message: "missing signed attributes"}
		}
		return content, nil
	}

	// Validate the mandatory ContentType attribute.
	contentType, err := si.contentTypeAttribute()
	if err != nil {
		return nil, err
	}
	if !contentType.Equal(eci.EContentType) {
		return nil, ASN1Error{Message: "invalid ContentType attribute"}
	}

	// Validate the mandatory MessageDigest attribute against the content.
	hashFunc, err := si.newHash()
	if err != nil {
		return nil, err
	}
	actualDigest := hashFunc()
	if _, err = actualDigest.Write(content); err != nil {
		return nil, err
	}

	messageDigest, err := si.messageDigestAttribute()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(messageDigest, actualDigest.Sum(nil)) {
		return nil, errors.New("cms: invalid message digest")
	}

	// The signature covers the DER encoded signed attributes.
	return si.SignedAttrs.marshaledForVerification()
}

// verifyGostSignature checks a GOST R 34.10-2012 signature of message under the
// public key of cert. Go's crypto/x509 implements neither the key type nor the
// signature, so the public key is read from the subjectPublicKeyInfo of the
// certificate and the signature is verified with pkg/gost, which computes the
// Streebog digest of the signed message and checks the signature over it.
//
// NOTE: the certificate chain itself is still verified by crypto/x509, which
// cannot check the signature of a certificate that a GOST key made. A chain
// whose certificates are signed with GOST is therefore reported as
// unsupported, even though the signature of the signer over the content is
// checked here.
func verifyGostSignature(cert *x509.Certificate, message, signature []byte, digestOID asn1.ObjectIdentifier) error {
	newHash := streebogHashFor(digestOID)
	if newHash == nil {
		return errUnsupported
	}

	key, err := gost.ParsePublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return err
	}

	h := newHash()
	if _, err := h.Write(message); err != nil {
		return err
	}

	ok, err := key.Verify(h.Sum(nil), signature)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("cms: invalid signature")
	}
	return nil
}
