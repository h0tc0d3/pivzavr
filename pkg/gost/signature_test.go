package gost

import (
	"encoding/asn1"
	"math/big"
	"testing"
)

// testCurve is the test curve of GOST R 34.10-2012 that the example of
// RFC 7091, Section 7 uses. It is not one of the parameter sets of the package,
// so it is spelled out where a test needs it.
func testCurve() *Curve {
	return &Curve{
		Name:     "id-tc26-gost-3410-2012-512-paramSetTest",
		P:        bigFromHex("8000000000000000000000000000000000000000000000000000000000000431"),
		A:        big.NewInt(7),
		B:        bigFromHex("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E"),
		N:        bigFromHex("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"),
		Gx:       big.NewInt(2),
		Gy:       bigFromHex("08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8"),
		KeySize:  32,
		HashSize: Size256,
	}
}

// TestVerifyExampleSignature checks the whole verification path with the example
// signature of RFC 7091, Section 7: the digest becomes e, and the signature
// holds s followed by r, each big-endian, as RFC 4491 prescribes.
func TestVerifyExampleSignature(t *testing.T) {
	curve := testCurve()

	// e is the integer of the example; the digest is its big-endian form.
	e := bigFromHex("2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5")
	digest := make([]byte, curve.KeySize)
	e.FillBytes(digest)

	r := bigFromHex("41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493")
	s := bigFromHex("01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40")

	signature := make([]byte, 2*curve.KeySize)
	s.FillBytes(signature[:curve.KeySize])
	r.FillBytes(signature[curve.KeySize:])

	key := &PublicKey{
		Curve: curve,
		X:     bigFromHex("7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B"),
		Y:     bigFromHex("26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA"),
	}

	ok, err := key.Verify(digest, signature)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("the example signature of RFC 7091 was rejected")
	}

	// A digest that differs in one byte must be rejected.
	digest[0] ^= 0x01
	if ok, err := key.Verify(digest, signature); err != nil || ok {
		t.Errorf("Verify with a changed digest = %v, %v, want false and no error", ok, err)
	}

	// A signature of the wrong length is an error rather than a rejection.
	if _, err := key.Verify(digest, signature[:len(signature)-1]); err == nil {
		t.Error("Verify accepted a signature of the wrong length")
	}
}

// TestParsePublicKey checks that a subjectPublicKeyInfo of a GOST key is parsed
// into the point that it holds.
func TestParsePublicKey(t *testing.T) {
	curve := Curve512ParamSetA

	// The public key of RFC 7836, Appendix A, which is a point of the 512-bit
	// parameter set A, held in little-endian byte order as RFC 9215 prescribes.
	coordinates := mustHex(t, "aab0eda4abff21208d18799fb9a85566"+
		"54ba783070eba10cb9abb253ec56dcf5"+
		"d3ccba6192e464e6e5bcb6dea137792f"+
		"2431f6c897eb1b3c0cc14327b1adc0a7"+
		"914613a3074e363aedb204d38d356397"+
		"1bd8758e878c9db11403721b48002d38"+
		"461f92472d40ea92f9958c0ffa4c9375"+
		"6401b97f89fdbe0b5e46e4a4631cdb5a")

	octets, err := asn1.Marshal(coordinates)
	if err != nil {
		t.Fatalf("marshal coordinates: %v", err)
	}
	spki, err := asn1.Marshal(struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}{
		Algorithm: struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.ObjectIdentifier
		}{OIDPublicKey512, curve.OID},
		PublicKey: asn1.BitString{Bytes: octets, BitLength: 8 * len(octets)},
	})
	if err != nil {
		t.Fatalf("marshal subjectPublicKeyInfo: %v", err)
	}

	key, err := ParsePublicKey(spki)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if key.Curve != curve {
		t.Errorf("curve = %v, want %v", key.Curve, curve)
	}

	wantX := new(big.Int).SetBytes(reverseBytes(coordinates[:curve.KeySize]))
	wantY := new(big.Int).SetBytes(reverseBytes(coordinates[curve.KeySize:]))
	if key.X.Cmp(wantX) != 0 || key.Y.Cmp(wantY) != 0 {
		t.Errorf("parsed point = (%x, %x), want (%x, %x)", key.X, key.Y, wantX, wantY)
	}

	// The point must verify as a key of its curve, which the derivation test of
	// curve_test.go checks, and a structure that names no GOST algorithm must be
	// rejected.
	if !curve.isOnCurve(&point{x: key.X, y: key.Y}) {
		t.Error("the parsed point is not on the curve")
	}
	if _, err := ParsePublicKey([]byte{0x30, 0x00}); err == nil {
		t.Error("ParsePublicKey accepted an empty structure")
	}
}

// TestOIDHelpers checks the classification of the object identifiers.
func TestOIDHelpers(t *testing.T) {
	if !IsPublicKeyAlgorithm(OIDPublicKey256) || !IsPublicKeyAlgorithm(OIDPublicKey512) {
		t.Error("IsPublicKeyAlgorithm did not recognise a GOST public key algorithm")
	}
	if IsPublicKeyAlgorithm(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}) {
		t.Error("IsPublicKeyAlgorithm accepted RSA")
	}
	if !IsDigestAlgorithm(OIDDigest256) || !IsDigestAlgorithm(OIDDigest512) {
		t.Error("IsDigestAlgorithm did not recognise a Streebog digest")
	}
	if !IsSignatureAlgorithm(OIDSig256) || !IsSignatureAlgorithm(OIDSig512) {
		t.Error("IsSignatureAlgorithm did not recognise a GOST signature algorithm")
	}
}

// TestNewHash checks that a curve is paired with the Streebog hash whose code
// has the size of a field element.
func TestNewHash(t *testing.T) {
	if got := Curve256ParamSetA.NewHash().Size(); got != Size256 {
		t.Errorf("the 256-bit curve uses a %d-byte hash, want %d", got, Size256)
	}
	if got := Curve512ParamSetA.NewHash().Size(); got != Size512 {
		t.Errorf("the 512-bit curve uses a %d-byte hash, want %d", got, Size512)
	}
}
