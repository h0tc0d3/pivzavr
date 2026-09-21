//go:build darwin || freebsd || linux || netbsd

package pcsc

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// The Unix implementation loads the PC/SC library at run time with purego, so
// a build needs neither cgo nor the development headers of the library, and
// the same source builds on every system that provides it. On Linux and the
// other pcsc-lite systems the library is libpcsclite.so.1, on macOS it is the
// PC/SC framework.
//
// A PC/SC call reports its status in the return value rather than through
// errno, which is why the wrappers below turn the return value into an error
// and the results of a call travel in its arguments.

// scardLibrary is the loaded PC/SC library together with the entry points this
// package uses.
type scardLibrary struct {
	handle uintptr

	establishContext func(scope scardDWORD, reserved1, reserved2 unsafe.Pointer, context *scardHandle) scardLONG
	releaseContext   func(context scardHandle) scardLONG
	listReaders      func(context scardHandle, groups, readers *byte, length *scardDWORD) scardLONG
	connect          func(context scardHandle, reader *byte, share, proto scardDWORD, card *scardHandle, active *scardDWORD) scardLONG
	disconnect       func(card scardHandle, disposition scardDWORD) scardLONG
	transmit         func(card scardHandle, sendPci *scardIOPciRequest, send *byte, sendLength scardDWORD, recvPci *scardIOPciRequest, recv *byte, recvLength *scardDWORD) scardLONG
}

// scardIOPciRequest is the SCARD_IO_REQUEST of the PC/SC API: the protocol a
// request uses and the size of the structure itself. The size is a DWORD, so
// the structure is two DWORDs wide, which is what the send and receive PCI
// structures of a transmission have to report.
type scardIOPciRequest struct {
	protocol  scardDWORD
	pciLength scardDWORD
}

// scardLibraryNames returns the names the PC/SC library is looked for under.
// macOS ships the API as the PC/SC framework, which is preferred there; the
// dylib names cover a pcsc-lite that was installed with a package manager. The
// other systems name the shared library of pcsc-lite after its major version,
// so the plain name is only a fallback for a system that links it unversioned.
func scardLibraryNames() []string {
	if runtime.GOOS == "darwin" {
		return []string{
			"/System/Library/Frameworks/PCSC.framework/PCSC",
			"libpcsclite.1.dylib",
			"libpcsclite.dylib",
		}
	}
	return []string{"libpcsclite.so.1", "libpcsclite.so"}
}

// The library is loaded once, on the first use of the package, and the error of
// the load is reported by every operation until it has succeeded.
var (
	loadOnce sync.Once
	scardLib *scardLibrary
	loadErr  error
)

// library returns the loaded PC/SC library, loading it on the first call.
func library() (*scardLibrary, error) {
	loadOnce.Do(func() {
		scardLib, loadErr = loadLibrary()
	})
	return scardLib, loadErr
}

// loadLibrary loads the first of the PC/SC libraries that is present and
// resolves the entry points this package uses.
func loadLibrary() (*scardLibrary, error) {
	var lastErr error
	for _, name := range scardLibraryNames() {
		handle, err := purego.Dlopen(name, purego.RTLD_LAZY)
		if err != nil {
			lastErr = err
			continue
		}
		lib, err := openLibrary(handle)
		if err == nil {
			return lib, nil
		}
		// The library is present but is not one this package can use, so it
		// is released again before the next name is tried.
		lastErr = err
		_ = purego.Dlclose(handle)
	}
	return nil, fmt.Errorf("load the PC/SC library: %w", lastErr)
}

// openLibrary resolves the entry points this package uses in the library that
// handle belongs to.
func openLibrary(handle uintptr) (*scardLibrary, error) {
	lib := &scardLibrary{handle: handle}
	entryPoints := []struct {
		name   string
		target any
	}{
		{"SCardEstablishContext", &lib.establishContext},
		{"SCardReleaseContext", &lib.releaseContext},
		{"SCardListReaders", &lib.listReaders},
		{"SCardConnect", &lib.connect},
		{"SCardDisconnect", &lib.disconnect},
		{"SCardTransmit", &lib.transmit},
	}
	for _, entryPoint := range entryPoints {
		address, err := purego.Dlsym(handle, entryPoint.name)
		if err != nil {
			return nil, fmt.Errorf("resolve %s of the PC/SC library: %w", entryPoint.name, err)
		}
		purego.RegisterFunc(entryPoint.target, address)
	}
	return lib, nil
}

// scardStatus converts the value that a PC/SC call returned into the 32-bit
// status word that scardError takes. A call reports its status in a LONG, which
// is wider than a status word on a 64-bit system.
func scardStatus(code scardLONG) int32 {
	return int32(code) // #nosec G115 -- the status word of a PC/SC call is a 32-bit value.
}

// scardLength converts the length that a PC/SC call reported into the uint32
// that the package works with. A PC/SC buffer holds at most
// MAX_BUFFER_SIZE_EXTENDED bytes, which is far below the range of the type.
func scardLength(length scardDWORD) uint32 {
	return uint32(length) // #nosec G115 -- a PC/SC buffer of at most 64 KiB is far below 4 GiB.
}

// scardEstablishContext opens a session with the smart card service and returns
// its handle.
func scardEstablishContext() (uintptr, error) {
	lib, err := library()
	if err != nil {
		return 0, err
	}
	var context scardHandle
	if err := scardError(scardStatus(lib.establishContext(scopeSystem, nil, nil, &context))); err != nil {
		return 0, err
	}
	return uintptr(context), nil
}

// scardReleaseContext closes the session.
func scardReleaseContext(ctx uintptr) error {
	lib, err := library()
	if err != nil {
		return err
	}
	return scardError(scardStatus(lib.releaseContext(scardHandle(ctx))))
}

// scardListReaders fills buf with the NUL-terminated names of the readers that
// are present and reports the number of bytes that were written. A nil buffer
// asks for the size the names need instead.
func scardListReaders(ctx uintptr, buf []byte) (uint32, error) {
	lib, err := library()
	if err != nil {
		return 0, err
	}

	length := scardDWORD(len(buf))
	// #nosec G103 -- the buffer is passed to SCardListReaders, which only writes into it for the duration of the call.
	readers := unsafe.SliceData(buf)
	if err := scardError(scardStatus(lib.listReaders(scardHandle(ctx), nil, readers, &length))); err != nil {
		return 0, err
	}
	return scardLength(length), nil
}

// scardConnect connects to the smart card in reader and reports the protocol
// the card negotiated.
func scardConnect(ctx uintptr, reader string, share ShareMode, proto Protocol) (uintptr, Protocol, error) {
	lib, err := library()
	if err != nil {
		return 0, 0, err
	}

	name := nulTerminated(reader)
	var card scardHandle
	var active scardDWORD
	// #nosec G103 -- the NUL-terminated reader name is passed to SCardConnect for the duration of the call.
	code := lib.connect(scardHandle(ctx), unsafe.SliceData(name), scardDWORD(share), scardDWORD(proto), &card, &active)
	if err := scardError(scardStatus(code)); err != nil {
		return 0, 0, err
	}
	return uintptr(card), Protocol(active), nil
}

// scardDisconnect ends a connection to a card and applies the disposition.
func scardDisconnect(handle uintptr, d Disposition) error {
	lib, err := library()
	if err != nil {
		return err
	}
	return scardError(scardStatus(lib.disconnect(scardHandle(handle), scardDWORD(d))))
}

// scardTransmit sends cmd to the card and writes the response to rsp, whose
// length is reported. The protocol of the connection selects the protocol of
// the request, which is why only the card protocols are accepted.
func scardTransmit(handle uintptr, proto Protocol, cmd, rsp []byte) (uint32, error) {
	if proto != ProtocolT0 && proto != ProtocolT1 {
		return 0, ErrProtoMismatch
	}

	lib, err := library()
	if err != nil {
		return 0, err
	}

	send := scardIOPciRequest{protocol: scardDWORD(proto), pciLength: scardDWORD(unsafe.Sizeof(scardIOPciRequest{}))}
	var recv scardIOPciRequest
	length := scardDWORD(len(rsp))

	// #nosec G103 -- the command and the response slices are passed to SCardTransmit for the duration of the call.
	code := lib.transmit(scardHandle(handle), &send, unsafe.SliceData(cmd), scardDWORD(len(cmd)), &recv, unsafe.SliceData(rsp), &length)
	if err := scardError(scardStatus(code)); err != nil {
		return 0, err
	}
	return scardLength(length), nil
}
