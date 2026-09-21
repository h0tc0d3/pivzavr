package pivzavr

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDataObjectValue(t *testing.T) {
	value := mustHex(t, "3019D4E739DA739CED39CE739D836858210842108421C84210C3EB3410FBEDB59200284620879463C6CE2569D0350832303330303130313E00FE00")
	wrapped := append([]byte{0x53, byte(len(value))}, value...)

	got, ok := dataObjectValue(wrapped)
	assert.True(t, ok)
	assert.Equal(t, value, got)

	// Long-form BER length.
	long := append([]byte{0x53, 0x81, byte(len(value))}, value...)
	got, ok = dataObjectValue(long)
	assert.True(t, ok)
	assert.Equal(t, value, got)

	_, ok = dataObjectValue([]byte{0x00, 0x01})
	assert.False(t, ok)

	_, ok = dataObjectValue([]byte{0x53, 0x05, 0x01})
	assert.False(t, ok)
}

func TestTLVRetries(t *testing.T) {
	got, ok := tlvRetries(mustHex(t, "0101FF05010006020303"))
	assert.True(t, ok)
	assert.Equal(t, 3, got)

	got, ok = tlvRetries(mustHex(t, "06020001"))
	assert.True(t, ok)
	assert.Equal(t, 1, got)

	_, ok = tlvRetries(mustHex(t, "050100"))
	assert.False(t, ok)

	_, ok = tlvRetries(mustHex(t, "0603"))
	assert.False(t, ok)
}

func TestParseVerifyRetries(t *testing.T) {
	testCases := []struct {
		name   string
		sw     int
		want   int
		wantOK bool
	}{
		{name: "three left", sw: 0x63C3, want: 3, wantOK: true},
		{name: "one left", sw: 0x63C1, want: 1, wantOK: true},
		{name: "blocked", sw: 0x6983, want: 0, wantOK: true},
		{name: "non 63Cx counter", sw: 0x6305, want: 5, wantOK: true},
		{name: "success", sw: 0x9000, wantOK: false},
		{name: "wrong data", sw: 0x6A80, wantOK: false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseVerifyRetries(tc.sw)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestFormatRetries(t *testing.T) {
	assert.Equal(t, "3", formatRetries(3))
	assert.Equal(t, "0", formatRetries(0))
	assert.Equal(t, "(unavailable)", formatRetries(RetriesUnknown))
}

func TestCoalesceRetries(t *testing.T) {
	t.Run("both readable", func(t *testing.T) {
		pin, puk, ok := coalesceRetries(3, true, 2, true)
		assert.True(t, ok)
		assert.Equal(t, 3, pin)
		assert.Equal(t, 2, puk)
	})

	t.Run("only PUK readable", func(t *testing.T) {
		pin, puk, ok := coalesceRetries(0, false, 2, true)
		assert.True(t, ok)
		assert.Equal(t, RetriesUnknown, pin)
		assert.Equal(t, 2, puk)
	})

	t.Run("only PIN readable", func(t *testing.T) {
		pin, puk, ok := coalesceRetries(3, true, 0, false)
		assert.True(t, ok)
		assert.Equal(t, 3, pin)
		assert.Equal(t, RetriesUnknown, puk)
	})

	t.Run("neither readable", func(t *testing.T) {
		pin, puk, ok := coalesceRetries(0, false, 0, false)
		assert.False(t, ok)
		assert.Equal(t, RetriesUnknown, pin)
		assert.Equal(t, RetriesUnknown, puk)
	})
}

// fakeCard answers the APDUs a PIV command sequence sends with scripted
// responses, so that the sequence can be tested without a smart card. Each
// response is a whole APDU response: the response data followed by the two
// status word bytes.
type fakeCard struct {
	responses [][]byte
	apdus     [][]byte
	err       error
}

func (f *fakeCard) Transmit(apdu []byte) ([]byte, error) {
	f.apdus = append(f.apdus, apdu)
	if f.err != nil {
		return nil, f.err
	}
	if len(f.responses) == 0 {
		return nil, errors.New("no scripted response")
	}
	response := f.responses[0]
	f.responses = f.responses[1:]
	return response, nil
}

func TestBlockPIN(t *testing.T) {
	card := &fakeCard{responses: [][]byte{
		{0x63, 0xC3},
		{0x63, 0xC2},
		{0x63, 0xC1},
		{0x69, 0x83},
	}}

	require.NoError(t, blockPIN(card))

	// The attempts are used up one by one: the card is asked for the PIN with
	// a PIN that it rejects until it reports that the PIN is blocked.
	apdu := blockAPDU(insVerify, 1)
	assert.Equal(t, [][]byte{apdu, apdu, apdu, apdu}, card.apdus)
}

func TestBlockPUK(t *testing.T) {
	// A PUK that is blocked already is reported without an attempt being used.
	card := &fakeCard{responses: [][]byte{{0x69, 0x83}}}

	require.NoError(t, blockPUK(card))
	assert.Equal(t, [][]byte{blockAPDU(insResetRetry, 2)}, card.apdus)
}

// blockAPDU returns the APDU that uses up an attempt of blockPIN (one PIN
// field) or of blockPUK (the PUK field followed by the new PIN field): the
// instruction with a secret that cannot be the PIN or PUK of a card.
func blockAPDU(ins byte, fields int) []byte {
	pin := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	data := make([]byte, 0, len(pin)*fields)
	for i := 0; i < fields; i++ {
		data = append(data, pin...)
	}
	apdu := []byte{0x00, ins, 0x00, pinRef, byte(len(data))} // #nosec G115 -- fields is one or two.
	return append(apdu, data...)
}

// selectPIVAPDU returns the APDU that selects the PIV application.
func selectPIVAPDU() []byte {
	apdu := []byte{0x00, insSelect, 0x04, 0x00, byte(len(pivAID))} // #nosec G115 -- pivAID is a fixed-size array.
	return append(apdu, pivAID[:]...)
}

func TestBlockReference(t *testing.T) {
	t.Run("reports a card that does not check the PIN", func(t *testing.T) {
		// A card that considers the PIN verified does not check it, so it
		// cannot be used up.
		card := &fakeCard{responses: [][]byte{{0x90, 0x00}}}

		err := blockPIN(card)
		assert.ErrorContains(t, err, "does not check its PIN")
		assert.ErrorContains(t, err, "0x9000")
	})

	t.Run("reports a card that does not use up attempts", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x63, 0xC3}, {0x63, 0xC3}}}

		assert.ErrorContains(t, blockPIN(card), "did not use up its PIN attempts")
	})

	t.Run("reports a transmit error", func(t *testing.T) {
		card := &fakeCard{err: errors.New("no card")}

		assert.ErrorContains(t, blockPIN(card), "no card")
	})
}

func TestCardReset(t *testing.T) {
	// The PIN has an attempt left, the PUK is blocked already, and the card
	// resets itself once both are blocked.
	card := &fakeCard{responses: [][]byte{
		{0x90, 0x00}, // SELECT: the PIV application is selected
		{0x90, 0x00}, // VERIFY with P1=0xFF: the PIN verification is cleared
		{0x63, 0xC1}, // VERIFY: the last PIN attempt is used up
		{0x69, 0x83}, // VERIFY: the PIN is blocked
		{0x69, 0x83}, // RESET RETRY COUNTER: the PUK is blocked already
		{0x90, 0x00}, // RESET: the card is restored to its factory state
	}}

	require.NoError(t, cardReset(card))
	assert.Equal(t, [][]byte{
		selectPIVAPDU(),
		{0x00, insVerify, 0xFF, pinRef},
		blockAPDU(insVerify, 1),
		blockAPDU(insVerify, 1),
		blockAPDU(insResetRetry, 2),
		{0x00, insReset, 0x00, 0x00},
	}, card.apdus)
}

func TestCardResetFailure(t *testing.T) {
	t.Run("reports a card without the PIV application", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x6A, 0x82}}}

		err := cardReset(card)
		assert.ErrorContains(t, err, "does not run the PIV application")
		assert.Len(t, card.apdus, 1)
	})

	t.Run("does not reset a card whose PIN cannot be blocked", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{
			{0x90, 0x00}, // SELECT
			{0x6A, 0x86}, // VERIFY with P1=0xFF is not supported, which is ignored
			{0x90, 0x00}, // VERIFY: the card does not check the PIN
		}}

		err := cardReset(card)
		assert.ErrorContains(t, err, "Block PIN")
		assert.ErrorContains(t, err, "does not check its PIN")
		assert.Len(t, card.apdus, 3)
	})

	t.Run("reports a failed reset", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{
			{0x90, 0x00}, // SELECT
			{0x90, 0x00}, // VERIFY with P1=0xFF
			{0x69, 0x83}, // the PIN is blocked already
			{0x69, 0x83}, // the PUK is blocked already
			{0x6A, 0x82}, // RESET failed
		}}

		assert.ErrorContains(t, cardReset(card), "RESET failed with status 0x6A82")
	})
}
