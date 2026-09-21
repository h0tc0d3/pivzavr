package gost

import (
	"bytes"
	"crypto/hmac"
	"encoding/hex"
	"hash"
	"testing"
)

// The test vectors of GOST R 34.11-2012.

// messageM1Hex is the message M1 of RFC 6986, Section 10.1, in the byte order
// that the RFC prints. The hash function is defined over bit strings that the
// RFC writes from their most significant bit, so a message and a hash code are
// read from their last byte first.
const messageM1Hex = "32313039383736353433323130393837" +
	"36353433323130393837363534333231" +
	"30393837363534333231303938373635" +
	"343332313039383736353433323130"

// messageM2Hex is the message M2 of RFC 6986, Section 10.2, in the byte order
// that the RFC prints.
const messageM2Hex = "fbe2e5f0eee3c820fbeafaebef20fffb" +
	"f0e1e0f0f520e0ed20e8ece0ebe5f0f2" +
	"f120fff0eeec20f120faf2fee5e2202c" +
	"e8f6f3ede220e8e6eee1e8f0f2d1202c" +
	"e8f0f2e5e220e5d1"

// mustHex decodes a hexadecimal test vector.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode test vector: %v", err)
	}
	return b
}

// rfcVector turns a message or a hash code of RFC 6986 into the byte order that
// the hash function uses. The transformation is its own inverse.
func rfcVector(t *testing.T, s string) []byte {
	t.Helper()
	return reverseBytes(mustHex(t, s))
}

// TestEmptyMessage checks the hash codes of the empty message, which the
// standard documents and which the digest has to produce from its padding alone.
func TestEmptyMessage(t *testing.T) {
	sum256 := Sum256(nil)
	sum512 := Sum512(nil)
	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{"Sum256", sum256[:], "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb"},
		{"Sum512", sum512[:], "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7" +
			"362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a"},
	}
	for _, c := range cases {
		if want := mustHex(t, c.want); !bytes.Equal(c.got, want) {
			t.Errorf("%s(empty) = %x, want %x", c.name, c.got, want)
		}
	}
}

// TestQuickBrownFox checks the 256-bit hash code of a short message, which is
// absorbed as a single padded block.
func TestQuickBrownFox(t *testing.T) {
	message := []byte("The quick brown fox jumps over the lazy dog")
	got := Sum256(message)
	want := mustHex(t, "3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4")
	if !bytes.Equal(got[:], want) {
		t.Errorf("H256(fox) = %x, want %x", got, want)
	}
}

// TestRFC6986Example1 checks both hash codes of the example message M1 of
// RFC 6986, Section 10.1.
func TestRFC6986Example1(t *testing.T) {
	message := rfcVector(t, messageM1Hex)

	got256 := Sum256(message)
	want256 := rfcVector(t, "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d")
	if !bytes.Equal(got256[:], want256) {
		t.Errorf("H256(M1) = %x, want %x", got256, want256)
	}

	got512 := Sum512(message)
	want512 := rfcVector(t, "486f64c1917879417fef082b3381a4e2"+
		"11c324f074654c38823a7b76f830ad00"+
		"fa1fbae42b1285c0352f227524bc9ab1"+
		"6254288dd6863dccd5b9f54a1ad0541b")
	if !bytes.Equal(got512[:], want512) {
		t.Errorf("H512(M1) = %x, want %x", got512, want512)
	}
}

// TestRFC6986Example2 checks both hash codes of the example message M2 of
// RFC 6986, Section 10.2. M2 is longer than one block, so the example exercises
// the absorption of a full block followed by a partial one.
func TestRFC6986Example2(t *testing.T) {
	message := rfcVector(t, messageM2Hex)

	got256 := Sum256(message)
	want256 := rfcVector(t, "508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d")
	if !bytes.Equal(got256[:], want256) {
		t.Errorf("H256(M2) = %x, want %x", got256, want256)
	}

	got512 := Sum512(message)
	want512 := rfcVector(t, "28fbc9bada033b1460642bdcddb90c3f"+
		"b3e56c497ccd0f62b8a2ad4935e85f03"+
		"7613966de4ee00531ae60f3b5a47f8da"+
		"e06915d5f2f194996fcabf2622e6881e")
	if !bytes.Equal(got512[:], want512) {
		t.Errorf("H512(M2) = %x, want %x", got512, want512)
	}
}

// TestHMAC checks the HMAC construction against the test vectors of RFC 7836,
// Appendix B. The vectors cover messages of several lengths, including one that
// is a multiple of the block size.
func TestHMAC(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	data := []byte{
		0x01, 0x26, 0xbd, 0xb8, 0x78, 0x00, 0xaf, 0x21,
		0x43, 0x41, 0x45, 0x65, 0x63, 0x78, 0x01, 0x00,
	}

	cases := []struct {
		name string
		new  func() hash.Hash
		want string
	}{
		{"HMAC_GOSTR3411_2012_256", New256, "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"},
		{"HMAC_GOSTR3411_2012_512", New512, "a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a77" +
			"3d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6"},
	}
	for _, c := range cases {
		mac := hmac.New(c.new, key)
		if _, err := mac.Write(data); err != nil {
			t.Fatalf("%s: Write: %v", c.name, err)
		}
		if want := mustHex(t, c.want); !bytes.Equal(mac.Sum(nil), want) {
			t.Errorf("%s = %x, want %x", c.name, mac.Sum(nil), want)
		}
	}
}

// TestHashStreaming checks that the message may be written in pieces of any
// size: the result must not depend on how the message is split.
func TestHashStreaming(t *testing.T) {
	message := rfcVector(t, messageM2Hex)
	want := rfcVector(t, "28fbc9bada033b1460642bdcddb90c3f"+
		"b3e56c497ccd0f62b8a2ad4935e85f03"+
		"7613966de4ee00531ae60f3b5a47f8da"+
		"e06915d5f2f194996fcabf2622e6881e")

	for _, size := range []int{1, 5, 32, 63, 64, 65, 71, 72, 128, 129} {
		h := New512()
		for start := 0; start < len(message); start += size {
			end := min(start+size, len(message))
			if _, err := h.Write(message[start:end]); err != nil {
				t.Fatalf("Write: %v", err)
			}
		}
		if got := h.Sum(nil); !bytes.Equal(got, want) {
			t.Errorf("H512 in %d-byte pieces = %x, want %x", size, got, want)
		}
	}
}

// TestBlockMultiple checks a message whose length is an exact multiple of the
// block size. Such a message is completed with a whole block of padding, which
// is the case that the RFC 6986 examples do not exercise; the HMAC-512 test
// vector covers it too, because its inner message is 128 bytes long.
func TestBlockMultiple(t *testing.T) {
	for _, blocks := range []int{1, 2, 3} {
		message := bytes.Repeat([]byte{0x01}, blocks*BlockSize)

		// The one-shot and the streaming computation must agree, and adding
		// the padding must change the result, which it would not if the block
		// were absorbed without its trailing padding block.
		one := Sum256(message)
		h := New256()
		if _, err := h.Write(message); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if streamed := h.Sum(nil); !bytes.Equal(streamed, one[:]) {
			t.Errorf("%d blocks: streaming = %x, one-shot = %x", blocks, streamed, one)
		}
		if short := Sum256(message[:len(message)-1]); bytes.Equal(short[:], one[:]) {
			t.Errorf("%d blocks: a shortened message hashes to the same value", blocks)
		}
	}
}

// TestHashIsSensitive checks that a message and its extension do not collide,
// which a missing or misplaced padding bit would cause.
func TestHashIsSensitive(t *testing.T) {
	base := mustHex(t, messageM1Hex)
	extended := append(append([]byte{}, base...), 0x00)
	if Sum256(base) == Sum256(extended) {
		t.Error("a message and its extension hash to the same value")
	}
}

// TestSumDoesNotChangeState checks that Sum can be called more than once and
// that the hash code of a message follows from the state that was summed before,
// as the hash.Hash interface requires.
func TestSumDoesNotChangeState(t *testing.T) {
	first := mustHex(t, messageM2Hex)[:32]
	h := New256()
	if _, err := h.Write(first); err != nil {
		t.Fatalf("Write: %v", err)
	}
	before := h.Sum(nil)
	after := h.Sum(nil)
	if !bytes.Equal(before, after) {
		t.Errorf("Sum changed the state: %x then %x", before, after)
	}
	if got := Sum256(first); !bytes.Equal(got[:], before) {
		t.Errorf("streaming and one-shot hashes differ: %x and %x", before, got)
	}
}

// TestSizes checks the sizes a caller reads from the hash.Hash interface.
func TestSizes(t *testing.T) {
	if got := New256().Size(); got != Size256 {
		t.Errorf("New256().Size() = %d, want %d", got, Size256)
	}
	if got := New512().Size(); got != Size512 {
		t.Errorf("New512().Size() = %d, want %d", got, Size512)
	}
	if got := New256().BlockSize(); got != BlockSize {
		t.Errorf("New256().BlockSize() = %d, want %d", got, BlockSize)
	}
}
