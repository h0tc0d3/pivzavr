package pivzavr

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResetToken(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)

	// A card that was used: a PIN of its own, no PIN attempt left, one PUK
	// attempt used up, and a certificate in a slot.
	tok.pin = "87654321"
	tok.pinRetries = 0
	tok.pukRetries = fakeAttempts - 1
	if _, err := generateKeyAndCertificate(tok, SlotSignature); err != nil {
		t.Fatal(err)
	}

	require.NoError(t, ResetToken(tok))

	// The factory state is back: the default PIN and PUK, the full number of
	// PIN and PUK attempts, and no keys or certificates.
	assert.Equal(t, DefaultPIN, tok.pin)
	assert.Equal(t, DefaultPUK, tok.puk)
	assert.Equal(t, fakeAttempts, tok.pinRetries)
	assert.Equal(t, fakeAttempts, tok.pukRetries)

	slots, err := tok.Slots()
	require.NoError(t, err)
	assert.Empty(t, slots)
}

type resetFailToken struct{ *fakeToken }

func (f *resetFailToken) Reset() error {
	return errors.New("reset failed")
}

func TestResetToken_resetError(t *testing.T) {
	tok := &resetFailToken{fakeToken: &fakeToken{pin: DefaultPIN, slots: make(map[Slot]*slotContent)}}

	err := ResetToken(tok)
	assert.ErrorContains(t, err, "Reset token")
	assert.ErrorContains(t, err, "reset failed")
}
