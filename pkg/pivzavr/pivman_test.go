package pivzavr

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The reference values are the encodings of the PIV management data: the flag
// for a protected management key, the salt 00..0f and the PIN timestamp 256, and
// the object that holds the key 00..17.
const (
	referencePivmanData      = "801b8101028210000102030405060708090a0b0c0d0e0f830400000100"
	referencePivmanFlags     = "8003810102"
	referencePivmanProtected = "881a8918000102030405060708090a0b0c0d0e0f1011121314151617"
)

func TestParsePivmanData(t *testing.T) {
	data, err := parsePivmanData(mustHex(t, referencePivmanData))
	require.NoError(t, err)

	assert.True(t, data.mgmKeyProtected())
	assert.Equal(t, mustHex(t, "000102030405060708090A0B0C0D0E0F"), data.salt)
	assert.Equal(t, mustHex(t, "00000100"), data.pinTime)

	// The data object is written back unchanged.
	assert.Equal(t, referencePivmanData, hex.EncodeToString(data.bytes()))
}

func TestParsePivmanData_flagsOnly(t *testing.T) {
	data, err := parsePivmanData(mustHex(t, referencePivmanFlags))
	require.NoError(t, err)

	assert.True(t, data.mgmKeyProtected())
	assert.Nil(t, data.salt)
	assert.Nil(t, data.pinTime)
	assert.Equal(t, referencePivmanFlags, hex.EncodeToString(data.bytes()))
}

func TestParsePivmanData_empty(t *testing.T) {
	// An empty data object is a card that does not report anything, which
	// includes an object that was not read at all.
	for _, raw := range [][]byte{nil, {}, {tagPivmanData, 0x00}} {
		data, err := parsePivmanData(raw)
		require.NoError(t, err)
		assert.False(t, data.mgmKeyProtected())
		assert.Nil(t, data.bytes())
	}

	_, err := parsePivmanData(mustHex(t, "800481020102"))
	assert.ErrorContains(t, err, "Malformed PIV management data")

	_, err = parsePivmanData(mustHex(t, "810102"))
	assert.ErrorContains(t, err, "Malformed PIV management data")
}

func TestPivmanDataSetMgmKeyProtected(t *testing.T) {
	// A card that reports nothing is left empty, so that the data object does
	// not have to be written for a key that is not stored.
	var empty pivmanData
	empty.setMgmKeyProtected(false)
	assert.Nil(t, empty.bytes())

	empty.setMgmKeyProtected(true)
	assert.True(t, empty.mgmKeyProtected())
	assert.Equal(t, referencePivmanFlags, hex.EncodeToString(empty.bytes()))

	// Clearing the flag keeps the object, so that the other fields stay.
	data, err := parsePivmanData(mustHex(t, referencePivmanData))
	require.NoError(t, err)
	data.setMgmKeyProtected(false)
	assert.False(t, data.mgmKeyProtected())
	assert.Equal(t, "801b8101008210000102030405060708090a0b0c0d0e0f830400000100", hex.EncodeToString(data.bytes()))
}

func TestParsePivmanProtectedData(t *testing.T) {
	data, err := parsePivmanProtectedData(mustHex(t, referencePivmanProtected))
	require.NoError(t, err)

	assert.Equal(t, mustHex(t, "000102030405060708090A0B0C0D0E0F1011121314151617"), data.key)
	assert.Equal(t, referencePivmanProtected, hex.EncodeToString(data.bytes()))

	// An empty object is what a card holds after a stored key was removed.
	data, err = parsePivmanProtectedData(nil)
	require.NoError(t, err)
	assert.Nil(t, data.key)
	assert.Nil(t, data.bytes())

	_, err = parsePivmanProtectedData(mustHex(t, "8903000102"))
	assert.ErrorContains(t, err, "Malformed protected PIV management data")
}

func TestFakeManagementKey(t *testing.T) {
	// The fake smart card uses the factory default management key.
	assert.Equal(t, DefaultManagementKey, hex.EncodeToString(fakeManagementKey))
}
