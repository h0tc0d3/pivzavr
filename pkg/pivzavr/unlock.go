package pivzavr

import "github.com/h0tc0d3/pivzavr/pkg/i18n"

// UnlockToken unlocks the token's user PIN with its PUK.
//
// Unlocking leaves the keys and certificates of the token alone. It does not
// reset the PIN to its factory default either: it resets the PIN and the PUK
// retry counters of the card and installs the PIN the user enters. The PIN and
// the PUK are asked for through pinentry.
//
// A PUK that the card rejects is reported in the dialog, which is shown again
// with the number of attempts the card has left. Once the card has no PUK
// attempts left, errPUKBlocked is returned, which tells the user to restore the
// card with "pivzavr --reset".
func UnlockToken(tok Pivzavr) error {
	return unlockToken(tok, getSecret)
}

// unlockToken unlocks the token's user PIN with the PUK and resets the PIN and
// PUK retry counters of the token. The PIN to install and the PUK are asked for
// with ask, which is pinentry outside of tests.
func unlockToken(tok Pivzavr, ask func(pinPrompt) (string, error)) error {
	// The PIN is asked for first, so that a cancelled dialog leaves the
	// token untouched.
	pin, err := (secretPrompt{
		Name:     "PIN",
		Prompt:   pinPrompt{Description: i18n.Sprintf("Enter the new smart card PIN"), Prompt: "PIN:"},
		Ask:      ask,
		Validate: validatePIN,
	}).ask()
	if err != nil {
		return err
	}

	// Pinentry sizes its dialog to fit the text it is given, so the PUK dialog
	// is described with a slightly longer text than the PIN dialog. That makes
	// it a little larger, which helps to tell the two dialogs apart.
	_, err = (secretPrompt{
		Name:     "PUK",
		Prompt:   pinPrompt{Description: i18n.Sprintf("Enter smart card PUK to unlock the PIN"), Prompt: "PUK:"},
		Ask:      ask,
		Validate: validatePUK,
		Verify: func(puk string) error {
			return tok.Unlock(puk, pin)
		},
		Attempts: func() int {
			_, puk := tok.RetryCounts()
			return puk
		},
		Blocked: errPUKBlocked,
	}).ask()
	return err
}
