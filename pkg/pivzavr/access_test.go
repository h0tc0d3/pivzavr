package pivzavr

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newPIN, newPUK and newManagementKeyHex are the secrets the tests install.
const (
	newPIN              = "87654321"
	newPUK              = "87654321"
	newManagementKeyHex = "0F0E0D0C0B0A09080706050403020100F1F2F3F4F5F6F7F8"
)

// protectCard makes the fake smart card of a token store its management key
// protected by the PIN and takes the key it stores.
func protectCard(t *testing.T, card *fakePIVCard, key []byte) {
	t.Helper()

	card.mgmKey = append([]byte(nil), key...)
	card.objects[string(oidPivman)] = pivmanData{flags: []byte{pivmanMgmKeyProtected}}.bytes()
	card.objects[string(oidPivmanProtected)] = pivmanProtectedData{key: key}.bytes()
}

func TestSetPIN(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)

	ask := &stubAsk{secrets: []string{DefaultPIN, newPIN, newPIN}}

	require.NoError(t, setPIN(tok, ask.ask))

	assert.Equal(t, newPIN, tok.card.pin)
	assert.Equal(t, fakeAttempts, tok.card.pinRetries)

	require.Len(t, ask.prompts, 3)
	assert.Equal(t, "Enter the current smart card PIN", ask.prompts[0].Description)
	assert.Equal(t, fakeAttempts, ask.prompts[0].Attempts)
	assert.Equal(t, "Enter the new smart card PIN", ask.prompts[1].Description)
	assert.Equal(t, "Enter the new smart card PIN again", ask.prompts[2].Description)
}

func TestSetPIN_wrongCurrentPIN(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)

	ask := &stubAsk{secrets: []string{"654321", newPIN, newPIN, DefaultPIN, newPIN, newPIN}}

	require.NoError(t, setPIN(tok, ask.ask))

	assert.Equal(t, newPIN, tok.card.pin)
	assert.Equal(t, []string{"PIN incorrect."}, ask.messages())

	// The dialog that follows the rejected PIN reports the attempts that are
	// left before the user types.
	require.Len(t, ask.prompts, 6)
	assert.Equal(t, fakeAttempts-1, ask.prompts[3].Attempts)
}

func TestSetPIN_blockedPIN(t *testing.T) {
	t.Run("reports a PIN that is blocked already", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		tok.card.pinRetries = 0

		ask := &stubAsk{}

		assert.Equal(t, errPINBlocked, setPIN(tok, ask.ask))
		assert.Empty(t, ask.prompts)
	})

	t.Run("reports a PIN that is blocked by the last attempt", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		tok.card.pinRetries = 1

		ask := &stubAsk{secrets: []string{"654321", newPIN, newPIN}}

		assert.Equal(t, errPINBlocked, setPIN(tok, ask.ask))
		assert.Equal(t, DefaultPIN, tok.card.pin)
	})
}

func TestSetPIN_prompt(t *testing.T) {
	t.Run("shows the dialog again when the new PIN is entered twice differently", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)

		ask := &stubAsk{secrets: []string{DefaultPIN, newPIN, "87654322", newPIN, newPIN}}

		require.NoError(t, setPIN(tok, ask.ask))
		assert.Equal(t, newPIN, tok.card.pin)
		assert.Equal(t, []string{"The two entries did not match."}, ask.messages())
	})

	t.Run("rejects a new PIN that cannot be one", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)

		ask := &stubAsk{secrets: []string{DefaultPIN, "1234", newPIN, newPIN}}

		require.NoError(t, setPIN(tok, ask.ask))
		assert.Equal(t, newPIN, tok.card.pin)
		assert.Equal(t, []string{errInvalidPIN.Error()}, ask.messages())
	})

	t.Run("leaves the card alone when the dialog is cancelled", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)

		ask := &stubAsk{}

		assert.Equal(t, errCancelled, setPIN(tok, ask.ask))
		assert.Equal(t, DefaultPIN, tok.card.pin)
		assert.Len(t, ask.prompts, 1)
	})
}

func TestSetPUK(t *testing.T) {
	tok, err := testToken()
	require.NoError(t, err)

	ask := &stubAsk{secrets: []string{DefaultPUK, newPUK, newPUK}}

	require.NoError(t, setPUK(tok, ask.ask))

	assert.Equal(t, newPUK, tok.card.puk)
	require.Len(t, ask.prompts, 3)
	assert.Equal(t, "Enter the current smart card PUK", ask.prompts[0].Description)
	assert.Equal(t, "Enter the new smart card PUK", ask.prompts[1].Description)
	assert.Equal(t, "Enter the new smart card PUK again", ask.prompts[2].Description)
}

func TestSetPUK_failures(t *testing.T) {
	t.Run("reports a blocked PUK", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		tok.card.pukRetries = 0

		ask := &stubAsk{}

		assert.Equal(t, errPUKBlocked, setPUK(tok, ask.ask))
		assert.Empty(t, ask.prompts)
	})

	t.Run("reports a rejected PUK", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)

		ask := &stubAsk{secrets: []string{"11111111", newPUK, newPUK, DefaultPUK, newPUK, newPUK}}

		require.NoError(t, setPUK(tok, ask.ask))
		assert.Equal(t, newPUK, tok.card.puk)
		assert.Equal(t, []string{"PUK incorrect."}, ask.messages())
	})

	t.Run("rejects a new PUK that cannot be one", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)

		ask := &stubAsk{secrets: []string{DefaultPUK, "1234", newPUK, newPUK}}

		require.NoError(t, setPUK(tok, ask.ask))
		assert.Equal(t, []string{errInvalidPUK.Error()}, ask.messages())
	})
}

func TestSetObject(t *testing.T) {
	t.Run("writes an object with the management key of the card", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)

		// An empty entry selects the factory default key.
		ask := &stubAsk{secrets: []string{""}}

		stored, err := setObject(tok, ask.ask, oidCHUID, "CHUID", generateCHUID)
		require.NoError(t, err)

		value, ok := tok.card.objects[string(oidCHUID)]
		require.True(t, ok)
		assert.Equal(t, value, stored)
		assert.Equal(t, "3019d4e739da739ced39ce739d836858210842108421c84210c3eb", hex.EncodeToString(value[:27]))

		require.Len(t, ask.prompts, 1)
		assert.Equal(t, "Key (hex):", ask.prompts[0].Prompt)
	})

	t.Run("asks for the PIN when the card stores its key", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		protectCard(t, tok.card, bytes.Repeat([]byte{0x11}, 24))

		ask := &stubAsk{secrets: []string{DefaultPIN}}

		stored, err := setObject(tok, ask.ask, oidCCC, "CCC", generateCCC)
		require.NoError(t, err)

		value, ok := tok.card.objects[string(oidCCC)]
		require.True(t, ok)
		assert.Equal(t, value, stored)
		assert.Equal(t, "f015a000000116ff02", hex.EncodeToString(value[:9]))

		require.Len(t, ask.prompts, 1)
		assert.Equal(t, "Enter smart card PIN to unlock the stored management key", ask.prompts[0].Description)
	})

	t.Run("reports an object that cannot be generated", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		ask := &stubAsk{}

		_, err = setObject(tok, ask.ask, oidCCC, "CCC", func() ([]byte, error) {
			return nil, errors.New("no entropy")
		})
		assert.ErrorContains(t, err, "Generate CCC")
		assert.ErrorContains(t, err, "no entropy")

		// The smart card is not asked before the data was generated.
		assert.Empty(t, ask.prompts)
	})

	t.Run("reports a failed write", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		card := &cardToken{fakeToken: tok, pivCard: &writeFailCard{tok.card}}

		_, err = setObject(card, (&stubAsk{secrets: []string{""}}).ask, oidCCC, "CCC", generateCCC)
		assert.ErrorContains(t, err, "Write CCC")
		assert.ErrorContains(t, err, "write failed")
	})

	t.Run("reports a card that cannot be read", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		card := &cardToken{fakeToken: tok, pivCard: &readFailCard{tok.card}}

		_, err = setObject(card, (&stubAsk{}).ask, oidCCC, "CCC", generateCCC)
		assert.ErrorContains(t, err, "Read PIV management data")
	})

	t.Run("reports a card that does not keep the object", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		// The card holds an object, but a write leaves it as it is.
		tok.card.objects[string(oidCCC)] = []byte{0xF0, 0x15}
		card := &cardToken{fakeToken: tok, pivCard: &forgetfulCard{tok.card}}

		_, err = setObject(card, (&stubAsk{secrets: []string{""}}).ask, oidCCC, "CCC", generateCCC)
		assert.ErrorContains(t, err, "stored a different CCC")
	})

	t.Run("reports an object that cannot be read back", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		card := &cardToken{fakeToken: tok, pivCard: &readBackFailCard{tok.card}}

		_, err = setObject(card, (&stubAsk{secrets: []string{""}}).ask, oidCCC, "CCC", generateCCC)
		assert.ErrorContains(t, err, "Read back CCC")
	})
}

// writeFailCard is a fake smart card that rejects every write.
type writeFailCard struct{ *fakePIVCard }

func (c *writeFailCard) PutObject([]byte, []byte) error {
	return errors.New("write failed")
}

// readFailCard is a fake smart card that rejects every read.
type readFailCard struct{ *fakePIVCard }

func (c *readFailCard) GetObject([]byte) ([]byte, error) {
	return nil, errors.New("read failed")
}

// forgetfulCard is a fake smart card that reports a successful write without
// keeping the object, which is what a card that stores no data does.
type forgetfulCard struct{ *fakePIVCard }

func (c *forgetfulCard) PutObject([]byte, []byte) error {
	return nil
}

// readBackFailCard is a fake smart card that keeps a written object but cannot
// read it back.
type readBackFailCard struct{ *fakePIVCard }

func (c *readBackFailCard) GetObject(oid []byte) ([]byte, error) {
	if bytes.Equal(oid, oidCCC) {
		return nil, errors.New("read back failed")
	}
	return c.fakePIVCard.GetObject(oid)
}

// cardToken is a token that hands out the given PIV card, so that a smart card
// that fails a command can be tested.
type cardToken struct {
	*fakeToken
	pivCard PIVCard
}

func (t *cardToken) Card() (PIVCard, error) {
	return t.pivCard, nil
}

func TestSetManagementKey(t *testing.T) {
	t.Run("asks for the current and the new key", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)

		// The current key is the factory default, and the new key is entered
		// twice, once in upper and once in lower case.
		ask := &stubAsk{secrets: []string{"", newManagementKeyHex, strings.ToLower(newManagementKeyHex)}}

		generated, err := setManagementKey(tok, "AES192", false, false, ask.ask)
		require.NoError(t, err)
		assert.Nil(t, generated)

		expected, err := hex.DecodeString(newManagementKeyHex)
		require.NoError(t, err)
		assert.Equal(t, ManagementKeyAES192, tok.card.mgmAlgorithm)
		assert.Equal(t, expected, tok.card.mgmKey)

		// Nothing is stored on the card, so it does not report a key.
		assert.Nil(t, tok.card.objects[string(oidPivman)])
		assert.Nil(t, tok.card.objects[string(oidPivmanProtected)])

		require.Len(t, ask.prompts, 3)
		assert.Equal(t, "Key (hex):", ask.prompts[0].Prompt)
		assert.Equal(t, "Enter the new AES192 card management key", ask.prompts[1].Description)
		assert.Equal(t, "Enter the new AES192 card management key again", ask.prompts[2].Description)
	})

	t.Run("generates a random key that is not stored", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)

		ask := &stubAsk{secrets: []string{""}}

		generated, err := setManagementKey(tok, "AES256", false, true, ask.ask)
		require.NoError(t, err)

		// The key is returned so that the caller can show it, and it is the
		// key the card holds.
		require.Len(t, generated, 32)
		assert.Equal(t, ManagementKeyAES256, tok.card.mgmAlgorithm)
		assert.Equal(t, generated, tok.card.mgmKey)
		assert.Nil(t, tok.card.objects[string(oidPivmanProtected)])
	})

	t.Run("stores the key on the card when it is protected", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)

		ask := &stubAsk{secrets: []string{"", DefaultPIN}}

		generated, err := setManagementKey(tok, "AES128", true, true, ask.ask)
		require.NoError(t, err)

		// A key that is stored on the card is not returned, because it cannot
		// be lost.
		assert.Nil(t, generated)

		stored, err := parsePivmanProtectedData(tok.card.objects[string(oidPivmanProtected)])
		require.NoError(t, err)
		assert.Equal(t, tok.card.mgmKey, stored.key)
		assert.Len(t, stored.key, 16)

		pivman, err := parsePivmanData(tok.card.objects[string(oidPivman)])
		require.NoError(t, err)
		assert.True(t, pivman.mgmKeyProtected())

		// The PIN protects the object the key is kept in.
		require.Len(t, ask.prompts, 2)
		assert.Equal(t, "Enter smart card PIN to write the stored management key", ask.prompts[1].Description)
	})

	t.Run("removes a key that the card stores", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		protectCard(t, tok.card, append([]byte(nil), fakeManagementKey...))

		ask := &stubAsk{secrets: []string{DefaultPIN, newManagementKeyHex, newManagementKeyHex}}

		generated, err := setManagementKey(tok, "AES192", false, false, ask.ask)
		require.NoError(t, err)
		assert.Nil(t, generated)

		// The object that held the key is emptied, and the card does not
		// report a stored key any more.
		assert.Empty(t, tok.card.objects[string(oidPivmanProtected)])
		pivman, err := parsePivmanData(tok.card.objects[string(oidPivman)])
		require.NoError(t, err)
		assert.False(t, pivman.mgmKeyProtected())
		assert.Nil(t, pivman.salt)
		assert.Equal(t, newManagementKeyHex, strings.ToUpper(hex.EncodeToString(tok.card.mgmKey)))
	})

	t.Run("drops the salt of a key that is derived from the PIN", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		tok.card.objects[string(oidPivman)] = pivmanData{salt: mustHex(t, "000102030405060708090A0B0C0D0E0F")}.bytes()

		ask := &stubAsk{secrets: []string{"", newManagementKeyHex, newManagementKeyHex}}

		_, err = setManagementKey(tok, "AES192", false, false, ask.ask)
		require.NoError(t, err)

		// The card does not report a derived key any more.
		value, ok := tok.card.objects[string(oidPivman)]
		require.True(t, ok)
		assert.Empty(t, value)

		pivman, err := parsePivmanData(value)
		require.NoError(t, err)
		assert.Nil(t, pivman.salt)
		assert.False(t, pivman.mgmKeyProtected())
	})

	t.Run("selects AES256 by default", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)

		// The current key is the factory default, and the new key is
		// generated.
		ask := &stubAsk{secrets: []string{""}}

		generated, err := setManagementKey(tok, "", false, true, ask.ask)
		require.NoError(t, err)

		require.Len(t, generated, 32)
		assert.Equal(t, ManagementKeyAES256, tok.card.mgmAlgorithm)
		assert.Equal(t, generated, tok.card.mgmKey)
	})
}

func TestSetManagementKey_errors(t *testing.T) {
	t.Run("reports a current key that the card rejects", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)

		ask := &stubAsk{secrets: []string{
			newManagementKeyHex, // not the key the card holds
			"",                  // the factory default key
			newManagementKeyHex, newManagementKeyHex,
		}}

		_, err = setManagementKey(tok, "AES192", false, false, ask.ask)
		require.NoError(t, err)
		assert.Equal(t, []string{"Management key incorrect."}, ask.messages())
	})

	t.Run("reports a current key that cannot be parsed", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)

		ask := &stubAsk{secrets: []string{"nonsense", ""}}

		_, err = setManagementKey(tok, "AES192", false, false, ask.ask)
		assert.Equal(t, errCancelled, err)
		assert.Equal(t, []string{"The management key must be hexadecimal."}, ask.messages())
	})

	t.Run("reports a current key of the wrong length", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)

		// The card still holds its factory default key, which is a Triple-DES
		// key, so the current key is measured against TDES even though the new
		// key is an AES one.
		ask := &stubAsk{secrets: []string{"0F0E", ""}}

		_, err = setManagementKey(tok, "AES192", false, false, ask.ask)
		assert.Equal(t, errCancelled, err)
		assert.Equal(t, []string{"TDES management key is 24 bytes (48 hexadecimal digits) long."}, ask.messages())
	})

	t.Run("reports an unknown algorithm", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)

		ask := &stubAsk{}

		_, err = setManagementKey(tok, "AES64", false, false, ask.ask)
		assert.ErrorContains(t, err, "Unknown management key algorithm")
		assert.Empty(t, ask.prompts)
	})

	t.Run("reports a card that does not hold the key it reports", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		tok.card.objects[string(oidPivman)] = pivmanData{flags: []byte{pivmanMgmKeyProtected}}.bytes()

		ask := &stubAsk{secrets: []string{DefaultPIN}}

		_, err = setManagementKey(tok, "AES192", false, false, ask.ask)
		assert.ErrorContains(t, err, "Read stored management key")
	})

	t.Run("reports a card whose stored key is empty", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		tok.card.objects[string(oidPivman)] = pivmanData{flags: []byte{pivmanMgmKeyProtected}}.bytes()
		tok.card.objects[string(oidPivmanProtected)] = nil

		ask := &stubAsk{secrets: []string{DefaultPIN}}

		_, err = setManagementKey(tok, "AES192", false, false, ask.ask)
		assert.ErrorContains(t, err, "does not hold one")
	})

	t.Run("reports a blocked PIN", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		protectCard(t, tok.card, append([]byte(nil), fakeManagementKey...))
		tok.card.pinRetries = 0

		ask := &stubAsk{}

		_, err = setManagementKey(tok, "AES192", false, false, ask.ask)
		assert.Equal(t, errPINBlocked, err)
		assert.Empty(t, ask.prompts)
	})

	t.Run("reports a blocked PIN before the key is set", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		tok.card.pinRetries = 0

		ask := &stubAsk{secrets: []string{""}}

		_, err = setManagementKey(tok, "AES192", true, true, ask.ask)
		assert.Equal(t, errPINBlocked, err)

		// The key the card holds is the one it had before.
		assert.Equal(t, fakeManagementKey, tok.card.mgmKey)
		assert.Nil(t, tok.card.objects[string(oidPivman)])
	})

	t.Run("reports a card that does not accept a new key", func(t *testing.T) {
		tok, err := testToken()
		require.NoError(t, err)
		card := &cardToken{fakeToken: tok, pivCard: &keyFailCard{tok.card}}

		ask := &stubAsk{secrets: []string{"", newManagementKeyHex, newManagementKeyHex}}

		_, err = setManagementKey(card, "AES192", false, false, ask.ask)
		assert.ErrorContains(t, err, "Set management key")
		assert.ErrorContains(t, err, "rejected")
	})
}

// keyFailCard is a fake smart card that rejects a new management key.
type keyFailCard struct{ *fakePIVCard }

func (c *keyFailCard) SetManagementKey(ManagementKeyAlgorithm, []byte) error {
	return errors.New("rejected")
}
