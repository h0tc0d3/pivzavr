package gost

import (
	"encoding/asn1"
	"errors"
	"hash"
	"math/big"

	"crypto/x509/pkix"
)

// The object identifiers of GOST R 34.10-2012 and GOST R 34.11-2012, as they
// appear in a certificate (RFC 9215) and in CMS (RFC 4490).
var (
	// OIDPublicKey256 is id-tc26-gost3410-2012-256, the algorithm of a public
	// key over a 256-bit curve.
	OIDPublicKey256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}
	// OIDPublicKey512 is id-tc26-gost3410-2012-512, the algorithm of a public
	// key over a 512-bit curve.
	OIDPublicKey512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 2}

	// OIDDigest256 is id-tc26-gost3411-12-256, the 256-bit Streebog hash.
	OIDDigest256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
	// OIDDigest512 is id-tc26-gost3411-12-512, the 512-bit Streebog hash.
	OIDDigest512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 3}

	// OIDSig256 is id-tc26-signwithdigest-gost3410-12-256, the signature of a
	// 256-bit private key over a 256-bit digest.
	OIDSig256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 2}
	// OIDSig512 is id-tc26-signwithdigest-gost3410-12-512, the signature of a
	// 512-bit private key over a 512-bit digest.
	OIDSig512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 3}
)

// IsPublicKeyAlgorithm reports whether oid names the public key algorithm of a
// GOST R 34.10-2012 key. Such a key is not one of the types that Go's
// crypto/x509 understands, which leaves PublicKey of a parsed certificate nil
// and PublicKeyAlgorithm UnknownPublicKeyAlgorithm.
func IsPublicKeyAlgorithm(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(OIDPublicKey256) || oid.Equal(OIDPublicKey512)
}

// IsDigestAlgorithm reports whether oid names a Streebog hash function.
func IsDigestAlgorithm(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(OIDDigest256) || oid.Equal(OIDDigest512)
}

// IsSignatureAlgorithm reports whether oid names a GOST R 34.10-2012 signature.
func IsSignatureAlgorithm(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(OIDSig256) || oid.Equal(OIDSig512)
}

// PublicKey is a GOST R 34.10-2012 public key: the point (X, Y) of a curve.
type PublicKey struct {
	Curve *Curve
	X, Y  *big.Int
}

// NewHash returns the hash function that the curve pairs a key with, which is
// the Streebog hash whose code has the size of a field element.
func (c *Curve) NewHash() hash.Hash {
	if c.HashSize == Size256 {
		return New256()
	}
	return New512()
}

// subjectPublicKeyInfo is the SubjectPublicKeyInfo of RFC 5280 as far as GOST
// keys use it: the algorithm, whose parameters name the curve, and the public
// key itself.
type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// errUnsupportedKey is returned for a subjectPublicKeyInfo that does not
// describe a GOST public key of a known parameter set.
var errUnsupportedKey = errors.New("gost: unsupported public key")

// ParsePublicKey parses the SubjectPublicKeyInfo of a GOST R 34.10-2012 public
// key. The algorithm names the curve in its parameters, and the key itself is
// an OCTET STRING that holds the x and the y coordinate, each in little-endian
// byte order (RFC 9215, Section 4.3).
func ParsePublicKey(der []byte) (*PublicKey, error) {
	var info subjectPublicKeyInfo
	if rest, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, errUnsupportedKey
	}
	if !IsPublicKeyAlgorithm(info.Algorithm.Algorithm) {
		return nil, errUnsupportedKey
	}

	// The parameters of the algorithm are the object identifier of the curve.
	var curveOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &curveOID); err != nil {
		return nil, errUnsupportedKey
	}
	curve := CurveByOID(curveOID)
	if curve == nil {
		return nil, errUnsupportedKey
	}

	// The bit string holds the DER of an OCTET STRING with both coordinates.
	var coordinates []byte
	if _, err := asn1.Unmarshal(info.PublicKey.Bytes, &coordinates); err != nil {
		return nil, errUnsupportedKey
	}
	if len(coordinates) != 2*curve.KeySize {
		return nil, errUnsupportedKey
	}

	return &PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(reverseBytes(coordinates[:curve.KeySize])),
		Y:     new(big.Int).SetBytes(reverseBytes(coordinates[curve.KeySize:])),
	}, nil
}

// Verify reports whether signature is a valid GOST R 34.10-2012 signature of
// digest under the public key. The digest is treated as a big-endian integer
// and the signature holds s and then r, each big-endian, as RFC 4491 and
// RFC 9215 prescribe for a certificate and for CMS.
func (k *PublicKey) Verify(digest, signature []byte) (bool, error) {
	if k == nil || k.Curve == nil || k.X == nil || k.Y == nil {
		return false, errUnsupportedKey
	}
	keySize := k.Curve.KeySize
	if len(signature) != 2*keySize {
		return false, errors.New("gost: unexpected signature length")
	}

	s := new(big.Int).SetBytes(signature[:keySize])
	r := new(big.Int).SetBytes(signature[keySize:])
	e := new(big.Int).SetBytes(digest)

	return k.Curve.Verify(&point{x: k.X, y: k.Y}, e, r, s)
}
