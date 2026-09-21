package pcsc

import (
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitReaderNames(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want []string
	}{
		{name: "empty buffer", buf: nil, want: nil},
		{name: "no readers", buf: []byte{0x00}, want: nil},
		{
			name: "one reader",
			buf:  []byte("Yubico YubiKey OTP+FIDO+CCID 0\x00\x00"),
			want: []string{"Yubico YubiKey OTP+FIDO+CCID 0"},
		},
		{
			name: "several readers",
			buf:  []byte("reader one\x00reader two\x00\x00"),
			want: []string{"reader one", "reader two"},
		},
		{
			name: "unterminated name",
			buf:  []byte("reader one\x00reader two"),
			want: []string{"reader one", "reader two"},
		},
		{
			name: "empty name in the middle",
			buf:  []byte("reader one\x00\x00reader two\x00\x00"),
			want: []string{"reader one"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, splitReaderNames(tt.buf))
		})
	}
}

func TestNulTerminated(t *testing.T) {
	assert.Equal(t, []byte("reader\x00"), nulTerminated("reader"))
	assert.Equal(t, []byte{0x00}, nulTerminated(""))
}

// utf16MultiString encodes names the way the wide-character reader list call of
// Windows reports them: every name is NUL-terminated, and a name of length zero
// closes the list.
func utf16MultiString(names ...string) []byte {
	var buf []byte
	for _, name := range names {
		for _, unit := range utf16.Encode([]rune(name)) {
			buf = append(buf, byte(unit), byte(unit>>8))
		}
		buf = append(buf, 0x00, 0x00)
	}
	return buf
}

func TestSplitUTF16ReaderNames(t *testing.T) {
	assert.Equal(t,
		[]string{"reader one", "reader two"},
		splitUTF16ReaderNames(utf16MultiString("reader one", "reader two")))
	assert.Equal(t,
		[]string{"Yubico YubiKey OTP+FIDO+CCID 0"},
		splitUTF16ReaderNames(utf16MultiString("Yubico YubiKey OTP+FIDO+CCID 0")))

	// The names are UTF-16, so a name that is not ASCII survives the decoding.
	assert.Equal(t,
		[]string{"\u00dcn\u00efc\u00f6d\u00e9 reader 0", "reader \u2116 1"},
		splitUTF16ReaderNames(utf16MultiString("\u00dcn\u00efc\u00f6d\u00e9 reader 0", "reader \u2116 1")))

	assert.Nil(t, splitUTF16ReaderNames(nil))
	assert.Nil(t, splitUTF16ReaderNames([]byte{0x00, 0x00}))

	// An unterminated name is used as it is.
	unterminated := utf16MultiString("reader one")
	assert.Equal(t, []string{"reader one"}, splitUTF16ReaderNames(unterminated[:len(unterminated)-2]))
}

func TestErrorName(t *testing.T) {
	assert.Equal(t, "SCARD_E_NO_READERS_AVAILABLE", ErrNoReadersAvailable.Name())
	assert.Equal(t, "SCARD_W_REMOVED_CARD", ErrRemovedCard.Name())
	assert.Empty(t, Error(0x0BADF00D).Name())
}

func TestErrorString(t *testing.T) {
	assert.Equal(t, "pcsc: SCARD_E_NO_READERS_AVAILABLE", ErrNoReadersAvailable.Error())
	assert.Equal(t, "pcsc: unknown error 0x0BADF00D", Error(0x0BADF00D).Error())
}

func TestScardError(t *testing.T) {
	assert.NoError(t, scardError(0))

	// The service reports a status code through a signed 32-bit LONG, which is
	// why scardError takes one.
	noReaders := ErrNoReadersAvailable
	err := scardError(int32(noReaders))
	require.Error(t, err)

	var got Error
	require.ErrorAs(t, err, &got)
	assert.Equal(t, ErrNoReadersAvailable, got)
	assert.True(t, isNoReader(err))

	removed := ErrRemovedCard
	assert.False(t, isNoReader(scardError(int32(removed))))
}

func TestContextRejectsUseWithoutAHandle(t *testing.T) {
	ctx := &Context{}
	_, err := ctx.Readers()
	require.Error(t, err)

	_, err = ctx.Connect("reader", ShareShared, ProtocolAny)
	require.Error(t, err)

	// A context that was never opened has nothing to release, so closing it is
	// not an error, which keeps a deferred Close safe.
	assert.NoError(t, ctx.Close())

	var nilContext *Context
	_, err = nilContext.Readers()
	assert.Error(t, err)
	assert.NoError(t, nilContext.Close())
}

func TestTransmitRejectsEmptyAPDU(t *testing.T) {
	card := &Card{}
	_, err := card.Transmit(nil)
	assert.Error(t, err)

	_, err = card.Transmit([]byte{})
	assert.Error(t, err)

	// A card that is not connected is rejected before the APDU is looked at.
	var nilCard *Card
	_, err = nilCard.Transmit([]byte{0x00, 0xA4, 0x04, 0x00})
	assert.Error(t, err)
}

func TestDisconnectWithoutAConnection(t *testing.T) {
	var card *Card
	assert.NoError(t, card.Disconnect(LeaveCard))
	assert.NoError(t, (&Card{closed: true}).Disconnect(LeaveCard))
}
