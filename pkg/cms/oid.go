package cms

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"hash"

	"github.com/h0tc0d3/pivzavr/pkg/gost"
)

// Object identifiers used by CMS (RFC 5652), RFC 3161 timestamping, the PKCS#9
// attributes and the X9.62/NIST public-key and signature algorithms.
var (
	oidContentTypeData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidContentTypeSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentTypeTSTInfo    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

	oidAttrContentType    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningTime    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidAttrTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

	oidPublicKeyRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

	// Only the SHA-2 family is supported; MD5 and SHA-1 are deliberately not
	// implemented because they are cryptographically broken.
	oidDigestSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidDigestSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidDigestSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidSigSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSigSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSigSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSigECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSigECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSigECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	oidExtensionSubjectKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 14}
)

// streebogHashFor returns the Streebog hash function of a digest algorithm OID,
// or nil for an OID that names no Streebog hash. The object identifiers are the
// ones of pkg/gost, which owns the GOST algorithms and also parses such a key.
func streebogHashFor(oid asn1.ObjectIdentifier) func() hash.Hash {
	switch {
	case oid.Equal(gost.OIDDigest256):
		return gost.New256
	case oid.Equal(gost.OIDDigest512):
		return gost.New512
	default:
		return nil
	}
}

// digestToHash maps digest algorithm OIDs onto crypto.Hash values.
var digestToHash = map[string]crypto.Hash{
	oidDigestSHA256.String(): crypto.SHA256,
	oidDigestSHA384.String(): crypto.SHA384,
	oidDigestSHA512.String(): crypto.SHA512,
}

// hashToDigest maps crypto.Hash values onto digest algorithm OIDs.
var hashToDigest = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA256: oidDigestSHA256,
	crypto.SHA384: oidDigestSHA384,
	crypto.SHA512: oidDigestSHA512,
}

// sigAlgToX509 maps standalone signature algorithm OIDs onto
// x509.SignatureAlgorithm values.
var sigAlgToX509 = map[string]x509.SignatureAlgorithm{
	oidSigSHA256WithRSA.String():   x509.SHA256WithRSA,
	oidSigSHA384WithRSA.String():   x509.SHA384WithRSA,
	oidSigSHA512WithRSA.String():   x509.SHA512WithRSA,
	oidSigECDSAWithSHA256.String(): x509.ECDSAWithSHA256,
	oidSigECDSAWithSHA384.String(): x509.ECDSAWithSHA384,
	oidSigECDSAWithSHA512.String(): x509.ECDSAWithSHA512,
}

// pubKeyAndDigestToX509 maps public-key algorithm OIDs (as used by signature
// algorithm identifiers) and digest algorithm OIDs onto
// x509.SignatureAlgorithm values.
var pubKeyAndDigestToX509 = map[string]map[string]x509.SignatureAlgorithm{
	oidPublicKeyRSA.String(): {
		oidDigestSHA256.String(): x509.SHA256WithRSA,
		oidDigestSHA384.String(): x509.SHA384WithRSA,
		oidDigestSHA512.String(): x509.SHA512WithRSA,
	},
	oidPublicKeyECDSA.String(): {
		oidDigestSHA256.String(): x509.ECDSAWithSHA256,
		oidDigestSHA384.String(): x509.ECDSAWithSHA384,
		oidDigestSHA512.String(): x509.ECDSAWithSHA512,
	},
}

// x509PubKeyAndDigestToSig maps an X.509 public-key algorithm and a digest
// algorithm OID onto the signature algorithm OID to use when signing.
var x509PubKeyAndDigestToSig = map[x509.PublicKeyAlgorithm]map[string]asn1.ObjectIdentifier{
	x509.RSA: {
		oidDigestSHA256.String(): oidSigSHA256WithRSA,
		oidDigestSHA384.String(): oidSigSHA384WithRSA,
		oidDigestSHA512.String(): oidSigSHA512WithRSA,
	},
	x509.ECDSA: {
		oidDigestSHA256.String(): oidSigECDSAWithSHA256,
		oidDigestSHA384.String(): oidSigECDSAWithSHA384,
		oidDigestSHA512.String(): oidSigECDSAWithSHA512,
	},
}
