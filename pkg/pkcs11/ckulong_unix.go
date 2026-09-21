//go:build !windows

package pkcs11

// CK_ULONG is the one type of the PKCS#11 specification whose width is not
// fixed: it is the unsigned long of C, which is pointer-sized on the Unix
// systems and four bytes wide on Windows. Every structure of the specification
// that carries a CK_ULONG is declared with ckULong, so the Go structures have
// the same layout as the C ones on every platform.
type ckULong = uint
