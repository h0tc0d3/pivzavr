package pivzavr

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"strconv"
	"strings"

	"github.com/h0tc0d3/pivzavr/pkg/i18n"
)

// keyUsageExtensionOID and extKeyUsageExtensionOID identify the Key Usage and
// Extended Key Usage extensions of RFC 5280. The crypto/x509 package reports
// the decoded values but not whether the extensions are present at all, which
// matters because an absent extension does not restrict a certificate.
var (
	keyUsageExtensionOID    = asn1.ObjectIdentifier{2, 5, 29, 15}
	extKeyUsageExtensionOID = asn1.ObjectIdentifier{2, 5, 29, 37}
	// extKeyUsageAnyOID is the "any extended key usage" purpose (RFC 5280
	// section 4.2.1.12).
	extKeyUsageAnyOID = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
)

// signingKeyUsage is the set of Key Usage bits that permit a certificate to
// make digital signatures. contentCommitment is the former nonRepudiation bit,
// which also covers signatures.
const signingKeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment

// signingExtKeyUsages are the Extended Key Usage purposes that a certificate
// may be restricted to while it is still permitted to make digital signatures.
// A certificate without the extension, or with the "any extended key usage"
// purpose, is not restricted at all.
var signingExtKeyUsages = []x509.ExtKeyUsage{
	x509.ExtKeyUsageCodeSigning,
	x509.ExtKeyUsageEmailProtection,
	x509.ExtKeyUsageClientAuth,
	x509.ExtKeyUsageTimeStamping,
}

// signingExtKeyUsageOIDs are Extended Key Usage purposes that the crypto/x509
// package does not name itself: the Microsoft document signing and lifetime
// signing purposes, which are used by the certificates of document signing
// smart cards.
var signingExtKeyUsageOIDs = []asn1.ObjectIdentifier{
	{1, 3, 6, 1, 4, 1, 311, 10, 3, 12},
	{1, 3, 6, 1, 4, 1, 311, 10, 3, 13},
}

// isSelfSigned reports whether cert was signed by its own key, which is how a
// smart card certificate looks when the card was not enrolled with a CA.
//
// The signature is checked against the public key of the certificate itself
// rather than with CheckSignatureFrom, which rejects a certificate that does
// not carry the Basic Constraints extension of a CA. A self-signed certificate
// of a smart card is an end-entity certificate, so it is not a CA.
func isSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// samePublicKey reports whether the two certificates hold the same public key.
func samePublicKey(a, b *x509.Certificate) bool {
	return a != nil && b != nil && bytes.Equal(a.RawSubjectPublicKeyInfo, b.RawSubjectPublicKeyInfo)
}

// hasExtension reports whether cert carries the extension with the given OID.
func hasExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, ext := range cert.Extensions {
		if oid.Equal(ext.Id) {
			return true
		}
	}
	return false
}

// validateSigningCertificate checks that cert may be used to verify a digital
// signature. The certificate must be an end-entity certificate rather than a
// CA, it must permit digital signatures when its Key Usage extension restricts
// them, and its Extended Key Usage, when present, must not limit it to a
// purpose that does not sign, such as server authentication.
//
// A certificate that carries an unconstrained usage is accepted: the
// certificate of a smart card is often enrolled without either extension, and
// RFC 5280 does not restrict such a certificate.
func validateSigningCertificate(cert *x509.Certificate) error {
	if cert.IsCA {
		return i18n.Errorf("Signing certificate is a CA certificate (%s), which cannot be used to sign.", formatName(cert.Subject))
	}
	if hasExtension(cert, keyUsageExtensionOID) && cert.KeyUsage&signingKeyUsage == 0 {
		return i18n.Errorf("Signing certificate does not permit digital signatures (Key Usage: %s).", formatKeyUsage(cert.KeyUsage))
	}
	if hasExtension(cert, extKeyUsageExtensionOID) && !permitsSigning(cert) {
		return i18n.Errorf("Signing certificate is not valid for signing (Extended Key Usage: %s).", formatExtKeyUsage(cert))
	}
	return nil
}

// permitsSigning reports whether the Extended Key Usage of cert permits making
// digital signatures. An empty extension does not restrict the certificate,
// mirroring what crypto/x509 does with it.
func permitsSigning(cert *x509.Certificate) bool {
	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		return true
	}

	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageAny {
			return true
		}
		for _, signing := range signingExtKeyUsages {
			if usage == signing {
				return true
			}
		}
	}

	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(extKeyUsageAnyOID) {
			return true
		}
		for _, signing := range signingExtKeyUsageOIDs {
			if oid.Equal(signing) {
				return true
			}
		}
	}

	return false
}

// formatKeyUsage renders the Key Usage bits as a comma-separated list of the
// names RFC 5280 gives them.
func formatKeyUsage(usage x509.KeyUsage) string {
	names := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digitalSignature"},
		{x509.KeyUsageContentCommitment, "contentCommitment"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
		{x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"},
		{x509.KeyUsageCertSign, "keyCertSign"},
		{x509.KeyUsageCRLSign, "cRLSign"},
		{x509.KeyUsageEncipherOnly, "encipherOnly"},
		{x509.KeyUsageDecipherOnly, "decipherOnly"},
	}

	var used []string
	for _, name := range names {
		if usage&name.bit != 0 {
			used = append(used, name.name)
		}
	}
	return joinOrNone(used)
}

// formatExtKeyUsage renders the Extended Key Usage purposes of cert as a
// comma-separated list. A purpose the crypto/x509 package does not name is
// rendered as its dotted-decimal OID.
func formatExtKeyUsage(cert *x509.Certificate) string {
	var used []string
	for _, usage := range cert.ExtKeyUsage {
		used = append(used, extKeyUsageName(usage))
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		used = append(used, oid.String())
	}
	return joinOrNone(used)
}

// extKeyUsageName returns the RFC 5280 name of an Extended Key Usage purpose.
func extKeyUsageName(usage x509.ExtKeyUsage) string {
	switch usage {
	case x509.ExtKeyUsageAny:
		return "any"
	case x509.ExtKeyUsageServerAuth:
		return "serverAuth"
	case x509.ExtKeyUsageClientAuth:
		return "clientAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "codeSigning"
	case x509.ExtKeyUsageEmailProtection:
		return "emailProtection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "ipsecEndSystem"
	case x509.ExtKeyUsageIPSECTunnel:
		return "ipsecTunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "ipsecUser"
	case x509.ExtKeyUsageTimeStamping:
		return "timeStamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "ocspSigning"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "microsoftServerGatedCrypto"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "netscapeServerGatedCrypto"
	case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
		return "microsoftCommercialCodeSigning"
	case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
		return "microsoftKernelCodeSigning"
	default:
		return "usage(" + strconv.Itoa(int(usage)) + ")"
	}
}

// joinOrNone renders a list of usage names, or "none" when it is empty.
func joinOrNone(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}
