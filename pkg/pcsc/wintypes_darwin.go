//go:build darwin

package pcsc

// The PC/SC implementation of macOS uses fixed-width types: DWORD is a
// uint32_t and LONG an int32_t, so the handles and the sizes of the API are
// four bytes wide. The types are spelled like the ones the other Unix systems
// use, so that the code that calls the API is the same on every system.
type (
	// scardDWORD is the DWORD of the PC/SC API: an argument or a length.
	scardDWORD = uint32
	// scardLONG is the LONG of the PC/SC API: the type the calls report
	// their status in.
	scardLONG = int32
	// scardHandle is a SCARDCONTEXT or a SCARDHANDLE of the PC/SC API, both
	// of which macOS defines as a 32-bit value.
	scardHandle = uint32
)
