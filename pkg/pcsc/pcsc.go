// Package pcsc is a small, self-contained PC/SC client for the operations
// pivzavr needs: opening a smart card reader, connecting to the card in it and
// exchanging APDUs with the card.
//
// The package talks to the platform smart card service directly instead of
// depending on a third-party binding, and it loads the library of the service
// at run time instead of linking against it, so a build needs neither cgo nor
// the development headers of the library. On Linux and the other Unix systems
// it uses pcsc-lite (libpcsclite), on macOS the PC/SC framework and on Windows
// winscard.dll. The API is deliberately narrow: a Context enumerates the
// readers that are present, a Card is a connection to one of them, and
// Transmit exchanges an APDU. The parts of the PC/SC API that a general-purpose
// binding exposes but pivzavr does not use are left out.
package pcsc

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"unicode/utf16"
)

// scopeSystem asks for a context that is shared with the other users of the
// smart card service, which is the scope the PC/SC specification recommends.
const scopeSystem = 0x0002

// maxResponseSize is the size of the buffer an APDU response is received in.
// It is MAX_BUFFER_SIZE_EXTENDED of the PC/SC specification, which fits a
// response of up to 64 KiB together with the APDU header and the status word.
const maxResponseSize = 4 + 3 + (1 << 16) + 3 + 2

// responsePool reuses the large receive buffers of Transmit, which are drawn
// from the pool and returned to it once the response was copied out.
var responsePool = sync.Pool{
	New: func() any {
		buf := make([]byte, maxResponseSize)
		return &buf
	},
}

// ShareMode reports how a connection shares the smart card with other
// applications.
type ShareMode uint32

const (
	// ShareExclusive asks for exclusive access to the smart card.
	ShareExclusive ShareMode = 0x0001
	// ShareShared shares the card with the other applications that use it,
	// which is what pivzavr needs so that it can run next to gpg-agent and
	// ssh-agent.
	ShareShared ShareMode = 0x0002
	// ShareDirect connects to the reader without claiming the card.
	ShareDirect ShareMode = 0x0003
)

// Protocol is a transmission protocol that a connection can use.
type Protocol uint32

const (
	// ProtocolUndefined lets the service pick the protocol.
	ProtocolUndefined Protocol = 0x0000
	// ProtocolT0 is the character protocol of the ISO/IEC 7816 specification.
	ProtocolT0 Protocol = 0x0001
	// ProtocolT1 is the block protocol of the ISO/IEC 7816 specification.
	ProtocolT1 Protocol = 0x0002
	// ProtocolRaw is the protocol used to talk to the reader itself.
	ProtocolRaw Protocol = 0x0004
	// ProtocolAny accepts either of the card protocols.
	ProtocolAny Protocol = ProtocolT0 | ProtocolT1
)

// Disposition reports what happens to the card when a connection is closed.
type Disposition uint32

const (
	// LeaveCard leaves the card powered and as it is.
	LeaveCard Disposition = 0x0000
	// ResetCard resets the card.
	ResetCard Disposition = 0x0001
	// UnpowerCard powers the card down.
	UnpowerCard Disposition = 0x0002
	// EjectCard ejects the card from the reader.
	EjectCard Disposition = 0x0003
)

// Context is a session with the PC/SC smart card service. A context is opened
// with EstablishContext and released with Close.
type Context struct {
	handle uintptr
	closed bool
}

// Card is a connection to the smart card in a reader. A card is opened with
// Connect and closed with Disconnect.
type Card struct {
	handle   uintptr
	protocol Protocol
	closed   bool
}

// EstablishContext opens a session with the smart card service. The session is
// shared with the other applications that use the service.
func EstablishContext() (*Context, error) {
	handle, err := scardEstablishContext()
	if err != nil {
		return nil, fmt.Errorf("establish PC/SC context: %w", err)
	}
	return &Context{handle: handle}, nil
}

// Close releases the session. Closing a session that was already closed is not
// an error, so that it can be deferred without tracking the state.
func (c *Context) Close() error {
	if c == nil || c.closed {
		return nil
	}
	c.closed = true
	// A context that was never established holds no handle, so there is
	// nothing to release. This keeps a deferred Close safe.
	if c.handle == 0 {
		return nil
	}
	if err := scardReleaseContext(c.handle); err != nil {
		return fmt.Errorf("release PC/SC context: %w", err)
	}
	return nil
}

// Readers returns the names of the smart card readers that are present. A
// system without a reader reports an empty list rather than an error, so that
// callers can treat it like a reader that holds no card.
func (c *Context) Readers() ([]string, error) {
	if err := c.check(); err != nil {
		return nil, err
	}

	// The first call asks for the size of the multi-string, the second one
	// fills a buffer of that size.
	size, err := scardListReaders(c.handle, nil)
	if err != nil {
		if isNoReader(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list smart card readers: %w", err)
	}
	if size == 0 {
		return nil, nil
	}

	buf := make([]byte, size)
	length, err := scardListReaders(c.handle, buf)
	if err != nil {
		return nil, fmt.Errorf("list smart card readers: %w", err)
	}
	if int(length) > len(buf) {
		length = uint32(len(buf)) // #nosec G115 -- buf has the size the first call reported.
	}
	return readerNames(buf[:length]), nil
}

// Connect opens the smart card in reader with the given sharing mode and
// protocol. The protocol the card negotiated is reported by the connection.
func (c *Context) Connect(reader string, share ShareMode, proto Protocol) (*Card, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	handle, active, err := scardConnect(c.handle, reader, share, proto)
	if err != nil {
		return nil, fmt.Errorf("connect to smart card reader %q: %w", reader, err)
	}
	return &Card{handle: handle, protocol: active}, nil
}

// check reports whether the context can be used. It keeps a call on a context
// that was never opened or already released from reaching the PC/SC library.
func (c *Context) check() error {
	switch {
	case c == nil:
		return errors.New("pcsc: no context")
	case c.closed:
		return errors.New("pcsc: context is closed")
	case c.handle == 0:
		return errors.New("pcsc: context is not established")
	}
	return nil
}

// Disconnect ends the connection to the smart card and applies the given
// disposition to it. Disconnecting a card that was already disconnected is not
// an error.
func (card *Card) Disconnect(d Disposition) error {
	if card == nil || card.closed {
		return nil
	}
	card.closed = true
	if err := scardDisconnect(card.handle, d); err != nil {
		return fmt.Errorf("disconnect from smart card: %w", err)
	}
	return nil
}

// Transmit sends an APDU to the smart card and returns the response, which
// includes the status word. The response is a fresh slice that the caller owns,
// so it stays valid when the next APDU is sent.
func (card *Card) Transmit(apdu []byte) ([]byte, error) {
	if card == nil || card.closed {
		return nil, errors.New("pcsc: card is not connected")
	}
	if len(apdu) == 0 {
		return nil, errors.New("pcsc: cannot transmit an empty APDU")
	}

	bufp := responsePool.Get().(*[]byte)
	defer responsePool.Put(bufp)
	buf := *bufp

	length, err := scardTransmit(card.handle, card.protocol, apdu, buf)
	if err != nil {
		return nil, fmt.Errorf("transmit APDU: %w", err)
	}
	if int(length) > len(buf) {
		return nil, fmt.Errorf("pcsc: smart card response of %d bytes exceeds the %d byte buffer", length, len(buf))
	}

	response := make([]byte, length)
	copy(response, buf[:length])
	return response, nil
}

// splitReaderNames splits the multi-string that the reader list call returns
// into the individual reader names. The string is a sequence of NUL-terminated
// names that is closed by an empty name; a name that is not terminated is used
// as it is.
func splitReaderNames(buf []byte) []string {
	var names []string
	for len(buf) > 0 && buf[0] != 0 {
		end := bytes.IndexByte(buf, 0)
		if end < 0 {
			names = append(names, string(buf))
			break
		}
		names = append(names, string(buf[:end]))
		buf = buf[end+1:]
	}
	return names
}

// splitUTF16ReaderNames splits the multi-string that the wide-character reader
// list call of Windows returns into the individual reader names. The string is
// a sequence of NUL-terminated UTF-16 names that is closed by an empty name; a
// name that is not terminated is used as it is. The names are decoded to UTF-8,
// which is the form the rest of the package works with.
func splitUTF16ReaderNames(buf []byte) []string {
	var names []string
	var units []uint16
	for i := 0; i+1 < len(buf); i += 2 {
		unit := uint16(buf[i]) | uint16(buf[i+1])<<8
		if unit != 0 {
			units = append(units, unit)
			continue
		}
		if len(units) == 0 {
			// The empty name that closes the list.
			break
		}
		names = append(names, string(utf16.Decode(units)))
		units = units[:0]
	}
	// A list that is not closed by an empty name still holds its last name.
	if len(units) > 0 {
		names = append(names, string(utf16.Decode(units)))
	}
	return names
}

// nulTerminated returns s as a NUL-terminated byte string, which is the form
// the PC/SC functions of the Unix systems expect a reader name in.
func nulTerminated(s string) []byte {
	buf := make([]byte, len(s)+1)
	copy(buf, s)
	return buf
}
