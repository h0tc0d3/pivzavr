package gost

import (
	"math/big"
	"testing"
)

// TestCurveParameters checks the parameter sets of the package: the generator
// must be a point of the curve and its order must be exactly N, which fails for
// any wrong constant.
func TestCurveParameters(t *testing.T) {
	for _, curve := range []*Curve{Curve256ParamSetA, Curve512ParamSetA} {
		if curve.P.BitLen() != curve.KeySize*8 {
			t.Errorf("%s: modulus has %d bits, want %d", curve.Name, curve.P.BitLen(), curve.KeySize*8)
		}
		if curve.N.BitLen() != curve.KeySize*8 {
			t.Errorf("%s: order has %d bits, want %d", curve.Name, curve.N.BitLen(), curve.KeySize*8)
		}
		if !curve.isOnCurve(&point{x: curve.Gx, y: curve.Gy}) {
			t.Errorf("%s: the generator is not on the curve", curve.Name)
		}
		if infinity := curve.scalarMult(curve.N, &point{x: curve.Gx, y: curve.Gy}); infinity != nil {
			t.Errorf("%s: N*G is not the point at infinity", curve.Name)
		}
	}
}

// TestCurveByOID checks the registry of parameter sets.
func TestCurveByOID(t *testing.T) {
	if got := CurveByOID(Curve256ParamSetA.OID); got != Curve256ParamSetA {
		t.Errorf("CurveByOID(%v) = %v, want the 256-bit parameter set A", Curve256ParamSetA.OID, got)
	}
	if got := CurveByOID(Curve512ParamSetA.OID); got != Curve512ParamSetA {
		t.Errorf("CurveByOID(%v) = %v, want the 512-bit parameter set A", Curve512ParamSetA.OID, got)
	}
	if got := CurveByOID([]int{1, 2, 840}); got != nil {
		t.Errorf("CurveByOID(1.2.840) = %v, want nil", got)
	}
}

// TestVerifyExample verifies the signature of the example of RFC 7091, Section
// 7. The example uses the test curve of the standard, which differs from the
// parameter sets of the package, so it is spelled out here.
func TestVerifyExample(t *testing.T) {
	testCurve := &Curve{
		Name: "id-tc26-gost-3410-2012-512-paramSetTest",
		P:    bigFromHex("8000000000000000000000000000000000000000000000000000000000000431"),
		A:    big.NewInt(7),
		B:    bigFromHex("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E"),
		N:    bigFromHex("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"),
		Gx:   big.NewInt(2),
		Gy:   bigFromHex("08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8"),
	}

	q := &point{
		x: bigFromHex("7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B"),
		y: bigFromHex("26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA"),
	}
	e := bigFromHex("2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5")
	r := bigFromHex("41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493")
	s := bigFromHex("01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40")

	ok, err := testCurve.Verify(q, e, r, s)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("the signature of the RFC 7091 example was rejected")
	}

	// A different message must be rejected.
	other := new(big.Int).Add(e, big.NewInt(1))
	if ok, err := testCurve.Verify(q, other, r, s); err != nil || ok {
		t.Errorf("Verify with a changed digest = %v, %v, want false and no error", ok, err)
	}
}

// TestVerifyChecksRange checks that the range of r and s is enforced and that a
// public key outside the curve is rejected.
func TestVerifyChecksRange(t *testing.T) {
	curve := Curve256ParamSetA
	q := &point{x: curve.Gx, y: curve.Gy}
	one := big.NewInt(1)
	zero := big.NewInt(0)

	if ok, err := curve.Verify(q, one, zero, one); err != nil || ok {
		t.Errorf("Verify with r = 0 = %v, %v, want false and no error", ok, err)
	}
	if ok, err := curve.Verify(q, one, one, new(big.Int).Set(curve.N)); err != nil || ok {
		t.Errorf("Verify with s = N = %v, %v, want false and no error", ok, err)
	}
	if _, err := curve.Verify(&point{x: big.NewInt(0), y: big.NewInt(0)}, one, one, one); err == nil {
		t.Error("Verify accepted a public key that is not on the curve")
	}
}

// TestPublicKeyDerivation checks the 512-bit parameter set against a public key
// that RFC 7836 derives from a private key, which pins the parameters to an
// independent source.
func TestPublicKeyDerivation(t *testing.T) {
	private := bigFromHex("C990ECD972FCE84EC4DB022778F50FCAC726F46708384B8D458304962D7147F8" +
		"C2DB41CEF22C90B102F2968404F9B9BE6D47C79692D81826B32B8DACA43CB667")

	public := mustHex(t, "aab0eda4abff21208d18799fb9a85566"+
		"54ba783070eba10cb9abb253ec56dcf5"+
		"d3ccba6192e464e6e5bcb6dea137792f"+
		"2431f6c897eb1b3c0cc14327b1adc0a7"+
		"914613a3074e363aedb204d38d356397"+
		"1bd8758e878c9db11403721b48002d38"+
		"461f92472d40ea92f9958c0ffa4c9375"+
		"6401b97f89fdbe0b5e46e4a4631cdb5a")

	curve := Curve512ParamSetA

	half := len(public) / 2
	// The public key of the appendix is the point (X, Y) with each
	// coordinate in little-endian byte order, which is the order that RFC 9215
	// prescribes for a subjectPublicKey. The private key is printed in the same
	// order.
	pointLE := &point{
		x: new(big.Int).SetBytes(reverseBytes(public[:half])),
		y: new(big.Int).SetBytes(reverseBytes(public[half:])),
	}
	if !curve.isOnCurve(pointLE) {
		t.Fatal("the public key of RFC 7836 is not a point of the 512-bit parameter set A")
	}

	for _, privateOrder := range []struct {
		name   string
		scalar *big.Int
	}{
		{"little-endian", new(big.Int).SetBytes(reverseBytes(private.Bytes()))},
		{"big-endian", private},
	} {
		got := curve.scalarMult(privateOrder.scalar, &point{x: curve.Gx, y: curve.Gy})
		if got != nil && got.x.Cmp(pointLE.x) == 0 && got.y.Cmp(pointLE.y) == 0 {
			t.Logf("RFC 7836 prints the private and public keys in %s byte order", privateOrder.name)
			return
		}
	}
	t.Errorf("no byte order of the private key derives the published public key")
}

// TestScalarMultBasics checks the group law on small multiples of the generator.
func TestScalarMultBasics(t *testing.T) {
	curve := Curve256ParamSetA
	g := &point{x: curve.Gx, y: curve.Gy}

	if got := curve.scalarMult(big.NewInt(1), g); got == nil || got.x.Cmp(g.x) != 0 || got.y.Cmp(g.y) != 0 {
		t.Error("1*G is not G")
	}
	if got := curve.scalarMult(big.NewInt(0), g); got != nil {
		t.Error("0*G is not the point at infinity")
	}

	two := curve.double(g)
	if !curve.isOnCurve(two) {
		t.Error("2*G is not on the curve")
	}
	if sum := curve.add(g, g); sum.x.Cmp(two.x) != 0 || sum.y.Cmp(two.y) != 0 {
		t.Error("G + G is not 2*G")
	}
	opposite := &point{x: g.x, y: new(big.Int).Sub(curve.P, g.y)}
	if sum := curve.add(g, opposite); sum != nil {
		t.Error("G + (-G) is not the point at infinity")
	}

	// (N-1)*G must be the opposite of G.
	got := curve.scalarMult(new(big.Int).Sub(curve.N, big.NewInt(1)), g)
	if got == nil || got.x.Cmp(g.x) != 0 || got.y.Cmp(opposite.y) != 0 {
		t.Errorf("(N-1)*G = %v, want the opposite of G", got)
	}
}
