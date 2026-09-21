//go:build windows

package pcsc

import (
	"syscall"
	"unsafe"
)

// The Windows implementation talks to winscard.dll through the syscall package
// rather than through cgo, so that a Windows build does not need a C
// toolchain. The functions of the library report their status as a LONG, which
// is why the value a call returns is used instead of the error of the syscall.
var (
	winscard = syscall.NewLazyDLL("winscard.dll")

	procEstablishContext = winscard.NewProc("SCardEstablishContext")
	procReleaseContext   = winscard.NewProc("SCardReleaseContext")
	procListReaders      = winscard.NewProc("SCardListReadersW")
	procConnect          = winscard.NewProc("SCardConnectW")
	procDisconnect       = winscard.NewProc("SCardDisconnect")
	procTransmit         = winscard.NewProc("SCardTransmit")
)

// scardIOPciRequest is the SCARD_IO_REQUEST of the PC/SC API: the protocol a
// request uses and the size of the structure.
type scardIOPciRequest struct {
	protocol  uint32
	pciLength uint32
}

// scardEstablishContext opens a session with the smart card service and
// returns its handle.
func scardEstablishContext() (uintptr, error) {
	var ctx uintptr
	code, _, _ := procEstablishContext.Call(uintptr(scopeSystem), 0, 0, uintptr(unsafe.Pointer(&ctx)))
	if err := scardError(int32(code)); err != nil {
		return 0, err
	}
	return ctx, nil
}

// scardReleaseContext closes the session.
func scardReleaseContext(ctx uintptr) error {
	code, _, _ := procReleaseContext.Call(ctx)
	return scardError(int32(code))
}

// scardListReaders fills buf with the NUL-terminated names of the readers that
// are present and reports the number of bytes that were written. A nil buffer
// asks for the size the names need instead.
func scardListReaders(ctx uintptr, buf []byte) (uint32, error) {
	length := uint32(len(buf))
	var ptr uintptr
	if len(buf) > 0 {
		ptr = uintptr(unsafe.Pointer(&buf[0]))
	}

	code, _, _ := procListReaders.Call(ctx, 0, ptr, uintptr(unsafe.Pointer(&length)))
	if err := scardError(int32(code)); err != nil {
		return 0, err
	}
	return length, nil
}

// scardConnect connects to the smart card in reader and reports the protocol
// the card negotiated. Reader names are UTF-16 strings on Windows.
func scardConnect(ctx uintptr, reader string, share ShareMode, proto Protocol) (uintptr, Protocol, error) {
	name, err := syscall.UTF16PtrFromString(reader)
	if err != nil {
		return 0, 0, err
	}

	var handle uintptr
	var active uint32
	code, _, _ := procConnect.Call(ctx, uintptr(unsafe.Pointer(name)), uintptr(share), uintptr(proto), uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&active)))
	if err := scardError(int32(code)); err != nil {
		return 0, 0, err
	}
	return handle, Protocol(active), nil
}

// scardDisconnect ends a connection to a card and applies the disposition.
func scardDisconnect(handle uintptr, d Disposition) error {
	code, _, _ := procDisconnect.Call(handle, uintptr(d))
	return scardError(int32(code))
}

// scardTransmit sends cmd to the card and writes the response to rsp, whose
// length is reported.
func scardTransmit(handle uintptr, proto Protocol, cmd, rsp []byte) (uint32, error) {
	if proto != ProtocolT0 && proto != ProtocolT1 {
		return 0, ErrProtoMismatch
	}

	send := scardIOPciRequest{protocol: uint32(proto), pciLength: uint32(unsafe.Sizeof(scardIOPciRequest{}))}
	var recv scardIOPciRequest
	length := uint32(len(rsp))

	code, _, _ := procTransmit.Call(handle, uintptr(unsafe.Pointer(&send)), uintptr(unsafe.Pointer(&cmd[0])), uintptr(len(cmd)), uintptr(unsafe.Pointer(&recv)), uintptr(unsafe.Pointer(&rsp[0])), uintptr(unsafe.Pointer(&length)))
	if err := scardError(int32(code)); err != nil {
		return 0, err
	}
	return length, nil
}

// readerNames returns the names of the readers that are held in the
// NUL-terminated multi-string a reader list call returned. The reader list call
// of Windows is the wide-character one, so the names are UTF-16.
func readerNames(buf []byte) []string {
	return splitUTF16ReaderNames(buf)
}
