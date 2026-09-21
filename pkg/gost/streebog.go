// Package gost implements the Russian GOST cryptographic algorithms that
// pivzavr needs for GOST smart cards: the Streebog hash function of GOST R
// 34.11-2012 (RFC 6986) and the digital signature of GOST R 34.10-2012
// (RFC 7091) over the elliptic curves of RFC 7836.
//
// The algorithms are implemented here instead of being taken from a
// dependency so that the package stays free of cgo and of a C toolchain, and
// they are validated against the test vectors of the specifications.
package gost

import (
	"encoding/binary"
	"encoding/hex"
	"hash"
)

// The Streebog hash function of GOST R 34.11-2012, as specified by RFC 6986.
const (
	// Size256 is the size of a Streebog-256 hash code in bytes.
	Size256 = 32
	// Size512 is the size of a Streebog-512 hash code in bytes.
	Size512 = 64
	// BlockSize is the block size of the hash function in bytes.
	BlockSize = 64
)

// pi is the nonlinear bijection Pi over the byte set of RFC 6986, Section 6.2.
var pi = [256]byte{
	252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
	233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
	249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
	5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
	235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
	181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
	21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
	50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
	223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
	224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
	167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
	173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
	7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
	225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
	32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
	89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
}

// tau is the byte permutation Tau of RFC 6986, Section 6.3.
var tau = [64]byte{
	0, 8, 16, 24, 32, 40, 48, 56,
	1, 9, 17, 25, 33, 41, 49, 57,
	2, 10, 18, 26, 34, 42, 50, 58,
	3, 11, 19, 27, 35, 43, 51, 59,
	4, 12, 20, 28, 36, 44, 52, 60,
	5, 13, 21, 29, 37, 45, 53, 61,
	6, 14, 22, 30, 38, 46, 54, 62,
	7, 15, 23, 31, 39, 47, 55, 63,
}

// matrixA holds the rows of the matrix A of the linear transformation l of
// RFC 6986, Section 6.4, in the order the document lists them.
var matrixA = [64]uint64{
	0x8e20faa72ba0b470, 0x47107ddd9b505a38, 0xad08b0e0c3282d1c, 0xd8045870ef14980e,
	0x6c022c38f90a4c07, 0x3601161cf205268d, 0x1b8e0b0e798c13c8, 0x83478b07b2468764,
	0xa011d380818e8f40, 0x5086e740ce47c920, 0x2843fd2067adea10, 0x14aff010bdd87508,
	0x0ad97808d06cb404, 0x05e23c0468365a02, 0x8c711e02341b2d01, 0x46b60f011a83988e,
	0x90dab52a387ae76f, 0x486dd4151c3dfdb9, 0x24b86a840e90f0d2, 0x125c354207487869,
	0x092e94218d243cba, 0x8a174a9ec8121e5d, 0x4585254f64090fa0, 0xaccc9ca9328a8950,
	0x9d4df05d5f661451, 0xc0a878a0a1330aa6, 0x60543c50de970553, 0x302a1e286fc58ca7,
	0x18150f14b9ec46dd, 0x0c84890ad27623e0, 0x0642ca05693b9f70, 0x0321658cba93c138,
	0x86275df09ce8aaa8, 0x439da0784e745554, 0xafc0503c273aa42a, 0xd960281e9d1d5215,
	0xe230140fc0802984, 0x71180a8960409a42, 0xb60c05ca30204d21, 0x5b068c651810a89e,
	0x456c34887a3805b9, 0xac361a443d1c8cd2, 0x561b0d22900e4669, 0x2b838811480723ba,
	0x9bcf4486248d9f5d, 0xc3e9224312c8c1a0, 0xeffa11af0964ee50, 0xf97d86d98a327728,
	0xe4fa2054a80b329c, 0x727d102a548b194e, 0x39b008152acb8227, 0x9258048415eb419d,
	0x492c024284fbaec0, 0xaa16012142f35760, 0x550b8e9e21f7a530, 0xa48b474f9ef5dc18,
	0x70a6a56e2440598e, 0x3853dc371220a247, 0x1ca76e95091051ad, 0x0edd37c48a08a6d8,
	0x07e095624504536c, 0x8d70c431ac02a736, 0xc83862965601dd1b, 0x641c314b2b8ee083,
}

// iterationConstantsHex holds the twelve iteration constants C[1]..C[12] of
// RFC 6986, Section 6.5, as the document prints them: one 512-bit constant per
// string, in the order the round function uses them.
var iterationConstantsHex = [...]string{
	"b1085bda1ecadae9ebcb2f81c0657c1f2f6a76432e45d016714eb88d7585c4fc4b7ce09192676901a2422a08a460d31505767436cc744d23dd806559f2a64507",
	"6fa3b58aa99d2f1a4fe39d460f70b5d7f3feea720a232b9861d55e0f16b501319ab5176b12d699585cb561c2db0aa7ca55dda21bd7cbcd56e679047021b19bb7",
	"f574dcac2bce2fc70a39fc286a3d843506f15e5f529c1f8bf2ea7514b1297b7bd3e20fe490359eb1c1c93a376062db09c2b6f443867adb31991e96f50aba0ab2",
	"ef1fdfb3e81566d2f948e1a05d71e4dd488e857e335c3c7d9d721cad685e353fa9d72c82ed03d675d8b71333935203be3453eaa193e837f1220cbebc84e3d12e",
	"4bea6bacad4747999a3f410c6ca923637f151c1f1686104a359e35d7800fffbdbfcd1747253af5a3dfff00b723271a167a56a27ea9ea63f5601758fd7c6cfe57",
	"ae4faeae1d3ad3d96fa4c33b7a3039c02d66c4f95142a46c187f9ab49af08ec6cffaa6b71c9ab7b40af21f66c2bec6b6bf71c57236904f35fa68407a46647d6e",
	"f4c70e16eeaac5ec51ac86febf240954399ec6c7e6bf87c9d3473e33197a93c90992abc52d822c3706476983284a05043517454ca23c4af38886564d3a14d493",
	"9b1f5b424d93c9a703e7aa020c6e41414eb7f8719c36de1e89b4443b4ddbc49af4892bcb929b069069d18d2bd1a5c42f36acc2355951a8d9a47f0dd4bf02e71e",
	"378f5a541631229b944c9ad8ec165fde3a7d3a1b258942243cd955b7e00d0984800a440bdbb2ceb17b2b8a9aa6079c540e38dc92cb1f2a607261445183235adb",
	"abbedea680056f52382ae548b2e4f3f38941e71cff8a78db1fffe18a1b3361039fe76702af69334b7a1e6c303b7652f43698fad1153bb6c374b4c7fb98459ced",
	"7bcd9ed0efc889fb3002c6cd635afe94d8fa6bbbebab076120018021148466798a1d71efea48b9caefbacd1d7d476e98dea2594ac06fd85d6bcaa4cd81f32d1b",
	"378ee767f11631bad21380b00449b17acda43c32bcdf1d77f82012d430219f9b5d80ef9d1891cc86e71da4aa88e12852faf417d5d9b21b9948bc924af11bd720",
}

// iterationConstants holds C[1]..C[12], decoded from iterationConstantsHex.
var iterationConstants = decodeIterationConstants()

// decodeIterationConstants turns the hexadecimal iteration constants into the
// 512-bit blocks the round function XORs into its key. A constant that does not
// decode is a mistake in this package rather than a condition of a runtime.
func decodeIterationConstants() [12][BlockSize]byte {
	var constants [12][BlockSize]byte
	for i, s := range iterationConstantsHex {
		decoded, err := hex.DecodeString(s)
		if err != nil {
			panic("gost: invalid Streebog iteration constant " + string(rune('0'+i)) + ": " + err.Error())
		}
		copy(constants[i][:], decoded)
	}
	return constants
}

// lps applies the composition LPS of RFC 6986, Section 7 to a 512-bit block:
// the nonlinear bijection S, the byte permutation P and the linear
// transformation L.
func lps(b *[BlockSize]byte) {
	// S: substitute every byte through Pi.
	for i := range b {
		b[i] = pi[b[i]]
	}

	// P: out[i] = in[63 - Tau[63-i]], which is the permutation of the block
	// whose components are numbered from the right.
	var permuted [BlockSize]byte
	for i := range permuted {
		permuted[i] = b[BlockSize-1-tau[BlockSize-1-i]]
	}

	// L: multiply every 64-bit word of the block by the matrix A over GF(2).
	binary.BigEndian.PutUint64(b[0:8], linearTransform(binary.BigEndian.Uint64(permuted[0:8])))
	binary.BigEndian.PutUint64(b[8:16], linearTransform(binary.BigEndian.Uint64(permuted[8:16])))
	binary.BigEndian.PutUint64(b[16:24], linearTransform(binary.BigEndian.Uint64(permuted[16:24])))
	binary.BigEndian.PutUint64(b[24:32], linearTransform(binary.BigEndian.Uint64(permuted[24:32])))
	binary.BigEndian.PutUint64(b[32:40], linearTransform(binary.BigEndian.Uint64(permuted[32:40])))
	binary.BigEndian.PutUint64(b[40:48], linearTransform(binary.BigEndian.Uint64(permuted[40:48])))
	binary.BigEndian.PutUint64(b[48:56], linearTransform(binary.BigEndian.Uint64(permuted[48:56])))
	binary.BigEndian.PutUint64(b[56:64], linearTransform(binary.BigEndian.Uint64(permuted[56:64])))
}

// linearTransform multiplies the 64-bit word b by the matrix A: bit i of b
// selects row 63-i of the matrix, and the selected rows are XORed together.
func linearTransform(b uint64) uint64 {
	var out uint64
	for i := 0; i < 64; i++ {
		if b&(uint64(1)<<i) != 0 {
			out ^= matrixA[63-i]
		}
	}
	return out
}

// addUint adds v to a 512-bit big-endian number in place. It is used for the
// message-length counter N, which RFC 6986 keeps in V_512.
func addUint(d *[BlockSize]byte, v uint64) {
	carry := v
	for i := BlockSize - 1; i >= 0; i-- {
		sum := uint64(d[i]) + carry&0xff
		d[i] = byte(sum) // #nosec G115 -- the low byte is stored and the carry keeps the rest.
		carry = carry>>8 + sum>>8
		if carry == 0 {
			return
		}
	}
}

// addBlock adds the 512-bit big-endian number m to d in place. It is used for
// the message checksum EPSILON, which RFC 6986 keeps in V_512.
func addBlock(d *[BlockSize]byte, m *[BlockSize]byte) {
	var carry uint16
	for i := BlockSize - 1; i >= 0; i-- {
		sum := uint16(d[i]) + uint16(m[i]) + carry
		d[i] = byte(sum) // #nosec G115 -- the low byte is stored and the carry keeps the rest.
		carry = sum >> 8
	}
}

// g applies the compression function g_N(h, m) of RFC 6986, Section 8 to the
// state h in place: g_N(h, m) = E(LPS(h xor N), m) xor h xor m.
func g(h *[BlockSize]byte, n *[BlockSize]byte, m *[BlockSize]byte) {
	// K[1] = LPS(h xor N) is the first round key.
	var key, state [BlockSize]byte
	for i := range key {
		key[i] = h[i] ^ n[i]
	}
	lps(&key)

	// E(K, m) is twelve rounds of XOR with a round key and LPS, followed by
	// a final XOR with the thirteenth key. Every round advances the key with
	// K[i+1] = LPS(K[i] xor C[i]).
	state = *m
	for round := range iterationConstants {
		for i := range state {
			state[i] ^= key[i]
		}
		lps(&state)

		for i := range key {
			key[i] ^= iterationConstants[round][i]
		}
		lps(&key)
	}
	for i := range state {
		state[i] ^= key[i]
	}

	for i := range h {
		h[i] ^= state[i] ^ m[i]
	}
}

// digest is the running state of a Streebog hash function: h is the hash state,
// n the number of message bits that have been processed and eps the sum of the
// message blocks. The state is kept in the byte order of RFC 6986, which is the
// reverse of the byte order of the hash code itself.
type digest struct {
	h    [BlockSize]byte
	n    [BlockSize]byte
	eps  [BlockSize]byte
	buf  [BlockSize]byte
	nbuf int
	size int
}

// Size returns the length in bytes of the hash code that the digest produces.
func (d *digest) Size() int { return d.size }

// BlockSize returns the block size of the hash function in bytes.
func (d *digest) BlockSize() int { return BlockSize }

// Reset returns the digest to its initial state. The initializing value is
// 0^512 for a 512-bit hash code and (00000001)^64 for a 256-bit one.
func (d *digest) Reset() {
	size := d.size
	*d = digest{size: size}
	if size == Size256 {
		for i := range d.h {
			d.h[i] = 0x01
		}
	}
}

// Write adds p to the message being hashed. It never returns an error.
func (d *digest) Write(p []byte) (int, error) {
	written := len(p)

	for len(p) > 0 {
		n := copy(d.buf[d.nbuf:], p)
		d.nbuf += n
		p = p[n:]
		if d.nbuf == BlockSize {
			d.compress(&d.buf)
			d.nbuf = 0
		}
	}

	return written, nil
}

// compress absorbs one full block of the message: it applies the compression
// function g to the block and then advances the length counter N by 512 bits
// and adds the block to the checksum, in the order of the procedure of
// RFC 6986, Section 9.
func (d *digest) compress(block *[BlockSize]byte) {
	z := rfcOrder(block)
	g(&d.h, &d.n, &z)
	addUint(&d.n, BlockSize*8)
	addBlock(&d.eps, &z)
}

// Sum appends the hash code of the message that was written so far to in and
// returns the result. The digest is not changed, so more data can be added
// afterwards, which is what the hash.Hash contract requires.
func (d *digest) Sum(in []byte) []byte {
	c := *d

	// Complete the message with a single 1 bit followed by zeros. A message
	// whose length is a multiple of the block size gets a whole block of
	// padding, which is the case the standard describes as the empty block
	// m = 0^511 || 1.
	var block [BlockSize]byte
	copy(block[:], c.buf[:c.nbuf])
	block[c.nbuf] = 0x01 // #nosec G602 -- nbuf is below BlockSize.

	z := rfcOrder(&block)
	g(&c.h, &c.n, &z)
	addUint(&c.n, uint64(c.nbuf)*8) // #nosec G115 -- nbuf is below BlockSize.
	addBlock(&c.eps, &z)

	// Two final applications of g_0 fold in the length of the message and the
	// checksum of its blocks.
	var zero [BlockSize]byte
	g(&c.h, &zero, &c.n)
	g(&c.h, &zero, &c.eps)

	return append(in, reverseBytes(c.h[:d.size])...)
}

// rfcOrder returns block in the byte order that the compression function and
// the definitions of RFC 6986 use. The hash code of GOST R 34.11-2012 is
// defined over bit strings that the RFC writes from their most significant bit,
// while a byte string is fed to the hash function from its first byte, so the
// two orders are the reverse of each other.
func rfcOrder(block *[BlockSize]byte) [BlockSize]byte {
	var out [BlockSize]byte
	for i := range out {
		out[i] = block[BlockSize-1-i]
	}
	return out
}

// reverseBytes returns b in reverse byte order.
func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

// New256 returns a hash.Hash computing a 256-bit Streebog hash code
// (GOST R 34.11-2012 with a 256-bit output).
func New256() hash.Hash {
	d := &digest{size: Size256}
	d.Reset()
	return d
}

// New512 returns a hash.Hash computing a 512-bit Streebog hash code
// (GOST R 34.11-2012 with a 512-bit output).
func New512() hash.Hash {
	d := &digest{size: Size512}
	d.Reset()
	return d
}

// Sum256 returns the 256-bit Streebog hash code of data.
func Sum256(data []byte) [Size256]byte {
	var out [Size256]byte
	h := New256()
	_, _ = h.Write(data)
	copy(out[:], h.Sum(nil))
	return out
}

// Sum512 returns the 512-bit Streebog hash code of data.
func Sum512(data []byte) [Size512]byte {
	var out [Size512]byte
	h := New512()
	_, _ = h.Write(data)
	copy(out[:], h.Sum(nil))
	return out
}
