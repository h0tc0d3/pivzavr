package pivzavr

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnlockToken(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)
	tok.pukRetries = fakeAttempts

	// The first dialog asks for the PIN to install, the second for the PUK.
	t.Setenv(fakePinentrySeqEnv, filepath.Join(t.TempDir(), "pinentry-state"))
	t.Setenv(fakePinentryEnv, "87654321,"+DefaultPUK)
	t.Setenv(pinentryEnv, os.Args[0])

	require.NoError(t, UnlockToken(tok))

	// The PIN that was entered is installed, and unlocking restores the PIN
	// and PUK attempts of the card.
	assert.Equal(t, "87654321", tok.pin)
	assert.Equal(t, fakeAttempts, tok.pukRetries)
}

func TestUnlockToken_invalidPIN(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)
	tok.pukRetries = fakeAttempts

	// A PIN that cannot be one is reported in the dialog, which is shown
	// again; the card is not asked before a valid PIN was entered.
	ask := &stubAsk{secrets: []string{"1234", "87654321", DefaultPUK}}

	require.NoError(t, unlockToken(tok, ask.ask))
	assert.Equal(t, "87654321", tok.pin)
	assert.Equal(t, []string{errInvalidPIN.Error()}, ask.messages())

	require.Len(t, ask.prompts, 3)
	assert.Equal(t, "Enter the new smart card PIN", ask.prompts[0].Description)
	assert.Equal(t, "Enter the new smart card PIN", ask.prompts[1].Description)
	assert.Equal(t, "Enter smart card PUK to unlock the PIN", ask.prompts[2].Description)
}

func TestUnlockToken_prompt(t *testing.T) {
	t.Run("accepts the PUK after a wrong one", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		tok.pukRetries = fakeAttempts

		ask := &stubAsk{secrets: []string{"87654321", "11111111", DefaultPUK}}

		require.NoError(t, unlockToken(tok, ask.ask))
		assert.Equal(t, "87654321", tok.pin)
		assert.Equal(t, []string{"PUK incorrect."}, ask.messages())
	})

	t.Run("shows the attempts that are left for the PUK", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		tok.pukRetries = fakeAttempts

		ask := &stubAsk{secrets: []string{"87654321", "11111111", DefaultPUK}}

		require.NoError(t, unlockToken(tok, ask.ask))
		require.Len(t, ask.prompts, 3)
		// The PIN prompt is not checked against the card, so the attempts of
		// the PUK are shown by the PUK dialog only.
		assert.Equal(t, RetriesUnknown, ask.prompts[0].Attempts)
		assert.Equal(t, fakeAttempts, ask.prompts[1].Attempts)
		assert.Equal(t, fakeAttempts-1, ask.prompts[2].Attempts)
	})

	t.Run("reports a blocked PUK after the last attempt", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		tok.pukRetries = 2

		ask := &stubAsk{secrets: []string{"87654321", "11111111", "22222222"}}

		err = unlockToken(tok, ask.ask)
		assert.Equal(t, errPUKBlocked, err)
		assert.Equal(t, []string{"PUK incorrect."}, ask.messages())
		assert.Equal(t, DefaultPIN, tok.pin)
	})

	t.Run("reports a PUK that is blocked already", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		tok.pukRetries = 0

		ask := &stubAsk{secrets: []string{"87654321", DefaultPUK}}

		err = unlockToken(tok, ask.ask)
		assert.Equal(t, errPUKBlocked, err)
		assert.Len(t, ask.prompts, 2)
		assert.Equal(t, DefaultPIN, tok.pin)
	})

	t.Run("rejects a PUK of the wrong length without asking the card", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		tok.pukRetries = fakeAttempts

		ask := &stubAsk{secrets: []string{"87654321", "1234", DefaultPUK}}

		require.NoError(t, unlockToken(tok, ask.ask))
		assert.Equal(t, fakeAttempts, tok.pukRetries)
		assert.Equal(t, []string{errInvalidPUK.Error()}, ask.messages())
	})

	t.Run("leaves the card alone when the PIN dialog is cancelled", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		tok.pukRetries = fakeAttempts

		ask := &stubAsk{}

		assert.Equal(t, errCancelled, unlockToken(tok, ask.ask))
		assert.Len(t, ask.prompts, 1)
		assert.Equal(t, DefaultPIN, tok.pin)
		assert.Equal(t, fakeAttempts, tok.pukRetries)
	})

	t.Run("leaves the card alone when the PUK dialog is cancelled", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		tok.pukRetries = fakeAttempts

		ask := &stubAsk{secrets: []string{"87654321"}}

		assert.Equal(t, errCancelled, unlockToken(tok, ask.ask))
		assert.Len(t, ask.prompts, 2)
		assert.Equal(t, DefaultPIN, tok.pin)
		assert.Equal(t, fakeAttempts, tok.pukRetries)
	})
}

func TestUnlockToken_pinentryRetry(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)
	tok.puk = "22222222"
	tok.pukRetries = fakeAttempts

	// The fake pinentry hands out one response per process, so the first PUK
	// is rejected and the dialog is shown again for the second one.
	state := filepath.Join(t.TempDir(), "pinentry-state")
	t.Setenv(fakePinentryEnv, "87654321,11111111,22222222")
	t.Setenv(fakePinentrySeqEnv, state)
	t.Setenv(pinentryEnv, os.Args[0])

	require.NoError(t, UnlockToken(tok))
	assert.Equal(t, "87654321", tok.pin)

	// Unlocking the PIN restores the PUK attempts of the card.
	assert.Equal(t, fakeAttempts, tok.pukRetries)

	// Every dialog was shown: the PIN once and the PUK until it was accepted.
	data, err := os.ReadFile(state)
	require.NoError(t, err)
	assert.Equal(t, "3", string(data))
}

func TestUnlockToken_pinentryCancel(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)
	tok.pukRetries = fakeAttempts

	t.Setenv(fakePinentryEnv, "cancel")
	t.Setenv(pinentryEnv, os.Args[0])

	assert.Equal(t, errCancelled, UnlockToken(tok))
	assert.Equal(t, DefaultPIN, tok.pin)
	assert.Equal(t, fakeAttempts, tok.pukRetries)
}

type unlockFailToken struct{ *fakeToken }

func (f *unlockFailToken) Unlock(string, string) error {
	return errors.New("unlock failed")
}

func TestUnlockToken_unlockError(t *testing.T) {
	tok := &unlockFailToken{fakeToken: &fakeToken{pin: DefaultPIN, puk: DefaultPUK, slots: make(map[Slot]*slotContent)}}
	ask := &stubAsk{secrets: []string{"87654321", DefaultPUK}}

	err := unlockToken(tok, ask.ask)
	assert.ErrorContains(t, err, "unlock failed")
}
