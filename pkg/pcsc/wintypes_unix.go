//go:build !windows && !darwin

package pcsc

// The PC/SC implementation of the Unix systems other than macOS follows the
// Windows types of the original API: DWORD is an unsigned long and LONG a long.
// Both are pointer-sized on a 64-bit system and four bytes on a 32-bit one,
// which is why they are spelled as uint and int here. The types are shared
// with the build of macOS, which uses fixed-width ones of the same width.
type (
	// scardDWORD is the DWORD of the PC/SC API: an argument or a length.
	scardDWORD = uint
	// scardLONG is the LONG of the PC/SC API: the type the calls report
	// their status in.
	scardLONG = int
	// scardHandle is a SCARDCONTEXT or a SCARDHANDLE of the PC/SC API, both
	// of which pcsc-lite defines as a LONG.
	scardHandle = uint
)
