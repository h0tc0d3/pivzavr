package pivzavr

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
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
