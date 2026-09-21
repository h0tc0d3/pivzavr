package pivzavr

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"strings"

	"github.com/h0tc0d3/pivzavr/pkg/i18n"
	"github.com/pkg/errors"
)

// SetPIN replaces the user PIN of the smart card.
//
// The current PIN and the new PIN are asked for through pinentry. A wrong
// current PIN is reported in the dialog, which is shown again with the number of
// attempts the card has left, so that a typo does not leave the command. A PIN
// that is blocked cannot be replaced; it is unlocked with the PUK through
// "pivzavr --unlock".
func SetPIN(tok Pivzavr) error {
	return setPIN(tok, getSecret)
}

// setPIN replaces the user PIN of the smart card, asking for the secrets with
// ask, which is pinentry outside of tests.
func setPIN(tok Pivzavr, ask func(pinPrompt) (string, error)) error {
	card, err := tok.Card()
	if err != nil {
		return err
	}
	defer func() { _ = card.Close() }()

	if pin, _ := card.RetryCounts(); pin == 0 {
		return errPINBlocked
	}

	_, err = (secretPrompt{
		Name:     "PIN",
		Prompt:   pinPrompt{Description: i18n.Sprintf("Enter the current smart card PIN"), Prompt: "PIN:"},
		Ask:      ask,
		Validate: validatePIN,
		Verify: func(current string) error {
			entered, err := askNewSecret(ask, pinPrompt{
				Description: i18n.Sprintf("Enter the new smart card PIN"),
				Prompt:      "PIN:",
			}, checkSecret(validatePIN))
			if err != nil {
				return err
			}
			return card.ChangePIN(current, entered)
		},
		Attempts: func() int {
			pin, _ := card.RetryCounts()
			return pin
		},
		Blocked: errPINBlocked,
	}).ask()
	return err
}

// SetPUK replaces the PUK of the smart card.
//
// The current PUK and the new one are asked for through pinentry, and a wrong
// PUK is reported in the dialog together with the attempts that are left. The
// PUK of a card that has no attempt left cannot be replaced; only a factory
// reset restores such a card.
func SetPUK(tok Pivzavr) error {
	return setPUK(tok, getSecret)
}

// setPUK replaces the PUK of the smart card, asking for the secrets with ask,
// which is pinentry outside of tests.
func setPUK(tok Pivzavr, ask func(pinPrompt) (string, error)) error {
	card, err := tok.Card()
	if err != nil {
		return err
	}
	defer func() { _ = card.Close() }()

	if _, puk := card.RetryCounts(); puk == 0 {
		return errPUKBlocked
	}

	_, err = (secretPrompt{
		Name:     "PUK",
		Prompt:   pinPrompt{Description: i18n.Sprintf("Enter the current smart card PUK"), Prompt: "PUK:"},
		Ask:      ask,
		Validate: validatePUK,
		Verify: func(current string) error {
			newPUK, err := askNewSecret(ask, pinPrompt{
				Description: i18n.Sprintf("Enter the new smart card PUK"),
				Prompt:      "PUK:",
			}, checkSecret(validatePUK))
			if err != nil {
				return err
			}
			return card.ChangePUK(current, newPUK)
		},
		Attempts: func() int {
			_, puk := card.RetryCounts()
			return puk
		},
		Blocked: errPUKBlocked,
	}).ask()
	return err
}

// checkSecret adapts a validator to the check function of askNewSecret: a
// secret that the validator accepts is returned unchanged.
func checkSecret(validate func(string) error) func(string) (string, error) {
	return func(secret string) (string, error) {
		if err := validate(secret); err != nil {
			return "", err
		}
		return secret, nil
	}
}

// askNewSecret asks for a new secret twice and returns it once the two entries
// match, so that a typo cannot install a secret that the user did not intend.
// check converts the secret to the form the smart card expects; a secret that
// check rejects is reported in the dialog, which is shown again.
func askNewSecret(ask func(pinPrompt) (string, error), prompt pinPrompt, check func(secret string) (string, error)) (string, error) {
	for {
		secret, err := ask(prompt)
		if err != nil {
			return "", err
		}
		checked, err := check(secret)
		if err != nil {
			prompt.Message = err.Error()
			continue
		}

		// The same prompt is shown again for the second entry, which is how
		// pinentry confirms a secret. The message of a previous attempt
		// belongs to the first entry, so it is left out of the confirmation.
		confirmation := prompt
		confirmation.Description = i18n.Sprintf("%s again", prompt.Description)
		confirmation.Message = ""
		again, err := ask(confirmation)
		if err != nil {
			return "", err
		}

		checkedAgain, err := check(again)
		if err != nil || checkedAgain != checked {
			prompt.Message = i18n.Sprintf("The two entries did not match.")
			continue
		}
		return checked, nil
	}
}

// SetCHUID writes a new Card Holder Unique Identifier to the smart card: a card
// that is not issued by a federal agency, with a random identifier, in the
// format a PIV card is initialized with. The value the card stored is returned.
//
// Writing a data object needs the card management key; the PIN is only asked for
// when the key is stored on the smart card.
func SetCHUID(tok Pivzavr) ([]byte, error) {
	return setObject(tok, getSecret, oidCHUID, "CHUID", generateCHUID)
}

// SetCCC writes a new Card Capability Container to the smart card, which
// describes the capabilities of the card, with a random card identifier, in the
// format a PIV card is initialized with. The value the card stored is returned.
func SetCCC(tok Pivzavr) ([]byte, error) {
	return setObject(tok, getSecret, oidCCC, "CCC", generateCCC)
}

// setObject generates the value of the PIV data object oid, which is named name
// in the messages shown to the user, writes it to the smart card and returns the
// value the card stored.
//
// The data is generated before the smart card is touched, so that a failure
// leaves the card as it is. Writing the object needs the card management key,
// which is asked for with ask.
func setObject(tok Pivzavr, ask func(pinPrompt) (string, error), oid []byte, name string, generate func() ([]byte, error)) ([]byte, error) {
	value, err := generate()
	if err != nil {
		return nil, i18n.Wrapf(err, "Generate %s", name)
	}

	card, err := tok.Card()
	if err != nil {
		return nil, err
	}
	defer func() { _ = card.Close() }()

	if _, err := authenticate(card, ask); err != nil {
		return nil, err
	}
	if err := card.PutObject(oid, value); err != nil {
		return nil, i18n.Wrapf(err, "Write %s", name)
	}

	// The card is the only authority on what it holds, so the object is read
	// back instead of trusting the write: a card that reports the write without
	// storing the data is reported instead of looking like a success.
	stored, err := card.GetObject(oid)
	if err != nil {
		return nil, i18n.Wrapf(err, "Read back %s", name)
	}
	if !bytes.Equal(stored, value) {
		return nil, i18n.Errorf("The smart card stored a different %s than the one that was written.", name)
	}
	return stored, nil
}

// authenticate verifies the card management key on card, which the commands that
// write to the smart card require, and returns the key that was used.
//
// A key that the smart card stores protected by the PIN is read from the card,
// which the user has to enter the PIN for first; otherwise the key is asked for,
// where an empty entry selects the factory default key.
func authenticate(card PIVCard, ask func(pinPrompt) (string, error)) ([]byte, error) {
	pivman, err := readPivmanData(card)
	if err != nil {
		return nil, err
	}

	algorithm, err := card.ManagementKeyAlgorithm()
	if err != nil {
		return nil, err
	}

	key, err := currentManagementKey(card, pivman, algorithm, ask)
	if err != nil {
		return nil, err
	}
	if err := card.Authenticate(key, algorithm); err != nil {
		return nil, err
	}
	return key, nil
}

// currentManagementKey returns the management key that is currently set on the
// smart card: the key the card stores protected by the PIN when it holds one,
// and a key the user enters otherwise. algorithm is the algorithm of the key
// that is expected.
func currentManagementKey(card PIVCard, pivman pivmanData, algorithm ManagementKeyAlgorithm, ask func(pinPrompt) (string, error)) ([]byte, error) {
	if pivman.mgmKeyProtected() {
		return protectedManagementKey(card, ask)
	}
	return askManagementKey(card, algorithm, ask)
}

// protectedManagementKey reads the management key that the smart card stores
// protected by the PIN. The PIN is asked for and verified first, because the
// card only hands the key out to a user who entered it.
func protectedManagementKey(card PIVCard, ask func(pinPrompt) (string, error)) ([]byte, error) {
	if err := verifyPIN(card, ask, i18n.Sprintf("Enter smart card PIN to unlock the stored management key")); err != nil {
		return nil, err
	}

	data, err := card.GetObject(oidPivmanProtected)
	if err != nil {
		return nil, i18n.Wrap(err, "Read stored management key")
	}
	protected, err := parsePivmanProtectedData(data)
	if err != nil {
		return nil, err
	}
	if len(protected.key) == 0 {
		return nil, i18n.New("The smart card reports a stored management key, but does not hold one.")
	}
	return protected.key, nil
}

// askManagementKey asks the user for the card management key and verifies it
// against the smart card. An empty entry selects the factory default key.
func askManagementKey(card PIVCard, algorithm ManagementKeyAlgorithm, ask func(pinPrompt) (string, error)) ([]byte, error) {
	secret, err := (secretPrompt{
		Name: i18n.Sprintf("Management key"),
		Prompt: pinPrompt{
			Description: i18n.Sprintf("Enter the current card management key, use the factory default when it is empty"),
			Prompt:      i18n.Sprintf("Key (hex):"),
		},
		Ask: ask,
		Validate: func(secret string) error {
			_, err := parseManagementKey(secret, algorithm)
			return err
		},
		Verify: func(secret string) error {
			key, err := parseManagementKey(secret, algorithm)
			if err != nil {
				return err
			}
			return card.Authenticate(key, algorithm)
		},
	}).ask()
	if err != nil {
		return nil, err
	}
	return parseManagementKey(secret, algorithm)
}

// parseManagementKey parses a card management key in hexadecimal. An empty
// value selects the factory default key.
func parseManagementKey(value string, algorithm ManagementKeyAlgorithm) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = DefaultManagementKey
	}

	key, err := hex.DecodeString(value)
	if err != nil {
		return nil, i18n.New("The management key must be hexadecimal.")
	}
	if len(key) != algorithm.keyLen() {
		return nil, i18n.Errorf(
			"%s management key is %d bytes (%d hexadecimal digits) long.", algorithm, algorithm.keyLen(), algorithm.keyLen()*2)
	}
	return key, nil
}

// verifyPIN asks the user for the smart card PIN and verifies it on the card.
// description explains in the dialog why the PIN is needed.
func verifyPIN(card PIVCard, ask func(pinPrompt) (string, error), description string) error {
	if pin, _ := card.RetryCounts(); pin == 0 {
		return errPINBlocked
	}

	_, err := (secretPrompt{
		Name:     "PIN",
		Prompt:   pinPrompt{Description: description, Prompt: "PIN:"},
		Ask:      ask,
		Validate: validatePIN,
		Verify: func(pin string) error {
			return card.VerifyPIN(pin)
		},
		Attempts: func() int {
			pin, _ := card.RetryCounts()
			return pin
		},
		Blocked: errPINBlocked,
	}).ask()
	return err
}

// readPivmanData returns the PIV management data of the smart card, which
// reports how the card management key is kept. A card that does not hold the
// data object reports empty data.
func readPivmanData(card PIVCard) (pivmanData, error) {
	data, err := card.GetObject(oidPivman)
	if errors.Is(err, errObjectNotFound) {
		return pivmanData{}, nil
	}
	if err != nil {
		return pivmanData{}, i18n.Wrap(err, "Read PIV management data")
	}
	return parsePivmanData(data)
}

// SetManagementKey replaces the card management key of the smart card.
//
// algorithm is the algorithm of the new key: AES128, AES192 or AES256. An empty
// algorithm selects AES256. The new key is asked for in hexadecimal, unless
// random asks for a generated key instead. When protect is set, the new key is
// stored on the smart card protected by the PIN; the key is removed from the
// card when protect is not set and the card holds one.
//
// The generated key is returned when a random key was used and it is not stored
// on the smart card, so that the caller can show it to the user; nil is returned
// otherwise.
func SetManagementKey(tok Pivzavr, algorithm string, protect, random bool) ([]byte, error) {
	return setManagementKey(tok, algorithm, protect, random, getSecret)
}

// managementKeyAlgorithm returns the algorithm of a new card management key.
// name selects the algorithm; an empty name selects AES256, which every
// supported YubiKey holds.
func managementKeyAlgorithm(name string) (ManagementKeyAlgorithm, error) {
	if strings.TrimSpace(name) != "" {
		return ParseManagementKeyAlgorithm(name)
	}
	return ManagementKeyAES256, nil
}

// setManagementKey replaces the card management key, asking for the secrets with
// ask, which is pinentry outside of tests.
func setManagementKey(tok Pivzavr, name string, protect, random bool, ask func(pinPrompt) (string, error)) ([]byte, error) {
	algorithm, err := managementKeyAlgorithm(name)
	if err != nil {
		return nil, err
	}

	card, err := tok.Card()
	if err != nil {
		return nil, err
	}
	defer func() { _ = card.Close() }()

	pivman, err := readPivmanData(card)
	if err != nil {
		return nil, err
	}

	// The smart card only accepts a new management key once the current one is
	// verified. The new key has the algorithm that was asked for, while the
	// current one may use a different one.
	currentAlgorithm, err := card.ManagementKeyAlgorithm()
	if err != nil {
		return nil, err
	}
	currentKey, err := currentManagementKey(card, pivman, currentAlgorithm, ask)
	if err != nil {
		return nil, err
	}
	if err := card.Authenticate(currentKey, currentAlgorithm); err != nil {
		return nil, err
	}

	// The new key is generated or entered by the user.
	generated := false
	var newKey []byte
	if random {
		if newKey, err = randomManagementKey(algorithm); err != nil {
			return nil, err
		}
		generated = true
	} else {
		secret, err := askNewManagementKey(ask, algorithm)
		if err != nil {
			return nil, err
		}
		if newKey, err = hex.DecodeString(secret); err != nil {
			return nil, i18n.Wrap(err, "Parse new management key")
		}
	}

	// Storing the key on the card needs the PIN that protects the object the
	// key is kept in. It is verified before the new key is set, so that a PIN
	// that cannot be entered leaves the card as it is. A key that is already
	// stored was read with the PIN, which verified it as well.
	if protect && !pivman.mgmKeyProtected() {
		if err := verifyPIN(card, ask, i18n.Sprintf("Enter smart card PIN to write the stored management key")); err != nil {
			return nil, err
		}
	}

	// The card keeps the old key when the new one cannot be set.
	if err := card.SetManagementKey(algorithm, newKey); err != nil {
		return nil, i18n.Wrap(err, "Set management key")
	}

	// A management key that is derived from the PIN is replaced by the key
	// that was just set, so its salt is dropped.
	updated := pivman
	updated.salt = nil

	if protect || updated.mgmKeyProtected() {
		stored := pivmanProtectedData{}
		if protect {
			stored.key = newKey
		}
		if err := card.PutObject(oidPivmanProtected, stored.bytes()); err != nil {
			if protect {
				return nil, i18n.Wrap(err, "Store management key on the smart card")
			}
			return nil, i18n.Wrap(err, "Remove the stored management key")
		}
		updated.setMgmKeyProtected(protect)
	}

	if !bytes.Equal(pivman.bytes(), updated.bytes()) {
		if err := card.PutObject(oidPivman, updated.bytes()); err != nil {
			return nil, i18n.Wrap(err, "Update PIV management data")
		}
	}

	if generated && !protect {
		return newKey, nil
	}
	return nil, nil
}

// askNewManagementKey asks for the card management key in hexadecimal, twice, so
// that the key that is set is the key that was meant.
func askNewManagementKey(ask func(pinPrompt) (string, error), algorithm ManagementKeyAlgorithm) (string, error) {
	return askNewSecret(ask, pinPrompt{
		Description: i18n.Sprintf("Enter the new %s card management key", algorithm),
		Prompt:      i18n.Sprintf("Key (hex):"),
	}, func(secret string) (string, error) {
		key, err := parseManagementKey(secret, algorithm)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(key), nil
	})
}

// randomManagementKey returns a new random card management key of the algorithm.
func randomManagementKey(algorithm ManagementKeyAlgorithm) ([]byte, error) {
	key := make([]byte, algorithm.keyLen())
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, i18n.Wrap(err, "Generate management key")
	}
	return key, nil
}
