package pivzavr

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReset(t *testing.T) {
	tok, err := testToken()
	if err != nil {
		t.Fatal(err)
	}

	err = ResetToken(tok, &ResetOpts{
		Pin: "87654321",
	})
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "87654321", tok.pin)
}

func TestResetToken_invalidPIN(t *testing.T) {
	tok, err := testToken()
	if err != nil {
		t.Fatal(err)
	}

	assert.Error(t, ResetToken(tok, &ResetOpts{Pin: "12345"}))
}

type resetFailToken struct{ *fakeToken }

func (f *resetFailToken) Reset() error {
	return errors.New("reset failed")
}

func TestResetToken_resetError(t *testing.T) {
	tok := &resetFailToken{fakeToken: &fakeToken{pin: DefaultPIN, slots: make(map[Slot]*slotContent)}}

	assert.Error(t, ResetToken(tok, &ResetOpts{Pin: "87654321"}))
}

type setPINFailToken struct{ *fakeToken }

func (f *setPINFailToken) SetPIN(oldPIN, newPIN string) error {
	return errors.New("set pin failed")
}

func TestResetToken_setPINError(t *testing.T) {
	tok := &setPINFailToken{fakeToken: &fakeToken{pin: DefaultPIN, slots: make(map[Slot]*slotContent)}}

	assert.Error(t, ResetToken(tok, &ResetOpts{Pin: "87654321"}))
}

func TestSetPIN(t *testing.T) {
	tok, err := testToken()
	if err != nil {
		t.Fatal(err)
	}

	assert.NoError(t, tok.SetPIN(DefaultPIN, "87654321"))
	assert.Equal(t, "87654321", tok.pin)
	assert.Error(t, tok.SetPIN(DefaultPIN, "11111111"))
}
