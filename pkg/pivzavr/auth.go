package pivzavr

import (
	"github.com/h0tc0d3/pivzavr/pkg/i18n"
	"github.com/pkg/errors"
)

// errSecretIncorrect is returned by the token operations used while a PIN or
// PUK is checked to report that the secret was wrong.
var errSecretIncorrect = i18n.Message("Incorrect secret.")

// errPINBlocked is returned when the smart card rejects every PIN, which means
// that no attempt is left for it. The PUK unlocks the PIN.
var errPINBlocked = i18n.Message("PIN blocked, no attempts left. Unlock it with the PUK using \"pivzavr --unlock\".")

// errPUKBlocked is returned when the smart card rejects every PUK, which means
// that no attempt is left for it. Only a reset restores the card.
var errPUKBlocked = i18n.Message("PUK blocked, no attempts left. Restore the smart card with \"pivzavr --reset\".")

// secretPrompt asks the user for a secret such as a PIN or PUK and verifies it
// against the smart card.
//
// The dialog reports how many attempts the card has left for the secret before
// the user types, so that the count is visible for every attempt and not only
// after a rejected one. A wrong secret does not end the prompt either: the
// dialog is shown again with the number of attempts the card has left until the
// secret is accepted, the user cancels the dialog, or the card reports that it
// is out of attempts.
type secretPrompt struct {
	// Name identifies the secret in the messages shown to the user, for
	// example "PIN" or "PUK".
	Name string
	// Prompt describes the pinentry dialog used to ask for the secret.
	Prompt pinPrompt
	// Ask shows the dialog and returns the secret entered by the user. It
	// defaults to getSecret, which uses pinentry; tests replace it with a
	// stub.
	Ask func(prompt pinPrompt) (string, error)
	// Validate rejects input that cannot be a valid secret before it reaches
	// the card, so that a typo does not consume an attempt. It may be nil.
	Validate func(secret string) error
	// Verify checks the secret against the card. It returns
	// errSecretIncorrect when the secret was wrong, and the Blocked error
	// when the card refuses every further attempt. A nil Verify accepts
	// every secret that passes Validate, which is used for a secret that is
	// not checked against the card.
	Verify func(secret string) error
	// Attempts returns the number of attempts the card has left for the
	// secret, or RetriesUnknown when the count cannot be read.
	Attempts func() int
	// Blocked is returned when the card has no attempts left for the secret.
	Blocked error
}

// ask returns the secret entered by the user once the card has accepted it.
func (p secretPrompt) ask() (string, error) {
	ask := p.Ask
	if ask == nil {
		ask = getSecret
	}

	for {
		// Show the attempts that are left before the user types as well.
		p.Prompt.Attempts = p.attempts()

		secret, err := ask(p.Prompt)
		if err != nil {
			return "", err
		}
		if p.Validate != nil {
			if err := p.Validate(secret); err != nil {
				p.Prompt.Message = err.Error()
				continue
			}
		}
		if p.Verify == nil {
			return secret, nil
		}

		err = p.Verify(secret)
		if err == nil {
			return secret, nil
		}
		if !errors.Is(err, errSecretIncorrect) {
			return "", err
		}

		// The rejected attempt is used up, so the count has to be read
		// again: the next dialog shows it, and a count of zero means that
		// the card is out of attempts.
		if p.attempts() == 0 {
			return "", p.Blocked
		}
		p.Prompt.Message = retryMessage(p.Name)
	}
}

// attempts returns the number of attempts the card has left for the secret, or
// RetriesUnknown when the count is not known.
func (p secretPrompt) attempts() int {
	if p.Attempts == nil {
		return RetriesUnknown
	}
	return p.Attempts()
}

// retryMessage tells the user that the secret was rejected. The attempts that
// are left are shown by the dialog itself.
func retryMessage(name string) string {
	return i18n.Sprintf("%s incorrect.", name)
}

// attemptsMessage tells the user how many attempts the card has left for a
// secret. A count that is not known, and a card that has no attempt left, are
// left out because the card reports them itself.
func attemptsMessage(attempts int) string {
	switch {
	case attempts == 1:
		return i18n.Sprintf("1 attempt left.")
	case attempts > 1:
		return i18n.Sprintf("%d attempts left.", attempts)
	default:
		return ""
	}
}

// classifySecret maps err, which was returned while a PIN or PUK was checked,
// to the sentinel errors used by secretPrompt. wrong is returned when the
// secret was incorrect and blocked when the card has no attempts left for it.
// Any other error is wrapped with operation.
//
// The YubiKey PKCS#11 module maps the PIV status words that report a wrong PIN
// or PUK to CKR_PIN_INCORRECT and a blocked reference to CKR_PIN_LOCKED.
func classifySecret(err error, wrong, blocked error, operation string) error {
	switch {
	case err == nil:
		return nil
	case isPKCS11Error(err, pkcs11PINIncorrect):
		return wrong
	case isPKCS11Error(err, pkcs11PINLocked):
		return blocked
	default:
		return i18n.Wrap(err, operation)
	}
}

// isPKCS11Error reports whether err carries the given PKCS#11 status code.
func isPKCS11Error(err error, code uint) bool {
	got, ok := pkcs11ErrorCode(err)
	return ok && got == code
}
