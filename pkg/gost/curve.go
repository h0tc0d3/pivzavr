package gost

import (
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
)

// Curve is an elliptic curve of GOST R 34.10-2012 in the canonical (short
// Weierstrass) form y^2 = x^3 + a*x + b over the prime field of characteristic
// P, together with the generator G of the subgroup of order N. KeySize is the
// size in bytes of a field element and HashSize the size in bytes of the hash
// code that the signature is computed over.
type Curve struct {
	// Name is the name under which RFC 9215 lists the parameter set.
	Name string
	// OID identifies the parameter set in the parameters of a
	// subjectPublicKeyInfo.
	OID asn1.ObjectIdentifier

	P, A, B *big.Int
	N       *big.Int
	Gx, Gy  *big.Int

	KeySize  int
	HashSize int
}

// The parameter sets of GOST R 34.10-2012 with a prime modulus in the canonical
// form: the 256-bit and the 512-bit parameter set A of RFC 7836. They are the
// ones that GOST certificates and smart cards use.
var (
	// Curve256ParamSetA is id-tc26-gost-3410-2012-256-paramSetA. Its modulus
	// and its first coefficient are 2^256-617 and 2^256-620.
	Curve256ParamSetA = &Curve{
		Name:     "id-tc26-gost-3410-2012-256-paramSetA",
		OID:      asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1},
		P:        bigFromHex(strings.Repeat("F", 60) + "FD97"),
		A:        bigFromHex(strings.Repeat("F", 60) + "FD94"),
		B:        bigFromHex("A6"),
		N:        bigFromHex(strings.Repeat("F", 32) + "6C611070995AD10045841B09B761B893"),
		Gx:       big.NewInt(1),
		Gy:       bigFromHex("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"),
		KeySize:  32,
		HashSize: Size256,
	}

	// Curve512ParamSetA is id-tc26-gost-3410-12-512-paramSetA. Its modulus
	// and its first coefficient are 2^512-569 and 2^512-572.
	Curve512ParamSetA = &Curve{
		Name:     "id-tc26-gost-3410-12-512-paramSetA",
		OID:      asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 1},
		P:        bigFromHex(strings.Repeat("F", 124) + "FDC7"),
		A:        bigFromHex(strings.Repeat("F", 124) + "FDC4"),
		B:        bigFromHex("E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760"),
		N:        bigFromHex(strings.Repeat("F", 64) + "27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275"),
		Gx:       big.NewInt(3),
		Gy:       bigFromHex("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4"),
		KeySize:  64,
		HashSize: Size512,
	}
)

// curves lists the parameter sets that a public key may name, keyed by the
// dotted-decimal form of their object identifier.
var curves = func() map[string]*Curve {
	byOID := make(map[string]*Curve)
	for _, curve := range []*Curve{Curve256ParamSetA, Curve512ParamSetA} {
		byOID[curve.OID.String()] = curve
	}
	return byOID
}()

// CurveByOID returns the parameter set that oid names, or nil.
func CurveByOID(oid asn1.ObjectIdentifier) *Curve {
	return curves[oid.String()]
}

// bigFromHex returns the number that the hexadecimal string s represents. A
// string that does not decode is a mistake in this package.
func bigFromHex(s string) *big.Int {
	if len(s) == 0 || len(s)%2 != 0 {
		panic("gost: invalid hexadecimal constant " + s)
	}
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("gost: invalid hexadecimal constant " + s)
	}
	return n
}

// point is a point of a curve, or the point at infinity when the pointer is nil.
type point struct {
	x, y *big.Int
}

// errNotOnCurve is returned for a public key that is not a point of its curve.
var errNotOnCurve = errors.New("gost: public key is not on the curve")

// isOnCurve reports whether p, including the point at infinity, lies on the
// curve.
func (c *Curve) isOnCurve(p *point) bool {
	if p == nil {
		return true
	}
	if p.x.Sign() < 0 || p.x.Cmp(c.P) >= 0 || p.y.Sign() < 0 || p.y.Cmp(c.P) >= 0 {
		return false
	}

	// y^2 == x^3 + a*x + b (mod P)
	left := new(big.Int).Mul(p.y, p.y)
	left.Mod(left, c.P)

	right := new(big.Int).Mul(p.x, p.x)
	right.Mul(right, p.x)
	right.Add(right, new(big.Int).Mul(c.A, p.x))
	right.Add(right, c.B)
	right.Mod(right, c.P)

	return left.Cmp(right) == 0
}

// add returns the sum of p and q. The point at infinity is represented by nil
// and is the neutral element.
func (c *Curve) add(p, q *point) *point {
	if p == nil {
		return q
	}
	if q == nil {
		return p
	}

	// Two points that share their x coordinate are either the same point or
	// opposites, which add up to the point at infinity.
	if p.x.Cmp(q.x) == 0 {
		if new(big.Int).Add(p.y, q.y).Mod(new(big.Int).Add(p.y, q.y), c.P).Sign() == 0 {
			return nil
		}
		return c.double(p)
	}

	// lambda = (q.y - p.y) / (q.x - p.x)
	lambda := new(big.Int).Sub(q.y, p.y)
	denominator := new(big.Int).Sub(q.x, p.x)
	lambda.Mul(lambda, new(big.Int).ModInverse(denominator, c.P))
	lambda.Mod(lambda, c.P)

	return c.newPoint(lambda, p.x, p.y, q.x)
}

// double returns the sum of p with itself.
func (c *Curve) double(p *point) *point {
	if p == nil || p.y.Sign() == 0 {
		return nil
	}

	// lambda = (3*x^2 + a) / (2*y)
	lambda := new(big.Int).Mul(p.x, p.x)
	lambda.Mul(lambda, big.NewInt(3))
	lambda.Add(lambda, c.A)
	lambda.Mul(lambda, new(big.Int).ModInverse(new(big.Int).Lsh(p.y, 1), c.P))
	lambda.Mod(lambda, c.P)

	return c.newPoint(lambda, p.x, p.y, p.x)
}

// newPoint returns the third point of the line with slope lambda through
// (x1, y1) and (x2, y2): x3 = lambda^2 - x1 - x2, y3 = lambda*(x1 - x3) - y1.
func (c *Curve) newPoint(lambda, x1, y1, x2 *big.Int) *point {
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, c.P)

	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, lambda)
	y3.Sub(y3, y1)
	y3.Mod(y3, c.P)

	return &point{x: x3, y: y3}
}

// scalarMult returns the multiple k*p, which is the point at infinity when k is
// zero or a multiple of the order of p.
func (c *Curve) scalarMult(k *big.Int, p *point) *point {
	var result *point
	for i := k.BitLen() - 1; i >= 0; i-- {
		result = c.double(result)
		if k.Bit(i) != 0 {
			result = c.add(result, p)
		}
	}
	return result
}

// Verify reports whether (r, s) is a valid GOST R 34.10-2012 signature of the
// integer e under the public key that q is. The check follows Algorithm II of
// RFC 7091, Section 6.2: r and s must be in the range 1..N-1, and the x
// coordinate of C = (s/e)*G + (-r/e)*Q, reduced modulo N, must equal r.
func (c *Curve) Verify(q *point, e, r, s *big.Int) (bool, error) {
	if !c.isOnCurve(q) {
		return false, errNotOnCurve
	}
	if r.Sign() <= 0 || r.Cmp(c.N) >= 0 || s.Sign() <= 0 || s.Cmp(c.N) >= 0 {
		return false, nil
	}

	eMod := new(big.Int).Mod(e, c.N)
	if eMod.Sign() == 0 {
		return false, nil
	}
	v := new(big.Int).ModInverse(eMod, c.N)
	if v == nil {
		return false, nil
	}

	z1 := new(big.Int).Mul(s, v)
	z1.Mod(z1, c.N)

	// z2 = -r*v (mod N)
	z2 := new(big.Int).Mul(r, v)
	z2.Neg(z2)
	z2.Mod(z2, c.N)

	g := &point{x: c.Gx, y: c.Gy}
	sum := c.add(c.scalarMult(z1, g), c.scalarMult(z2, q))
	if sum == nil {
		return false, nil
	}

	x := new(big.Int).Mod(sum.x, c.N)
	return x.Cmp(r) == 0, nil
}
