package pivzavr

import (
	"crypto/sha3"
	"crypto/x509"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"syscall"

	"github.com/h0tc0d3/pivzavr/pkg/config"
	"github.com/h0tc0d3/pivzavr/pkg/i18n"
	"github.com/h0tc0d3/pivzavr/pkg/pinentry"
	"github.com/pkg/errors"
)

// CertHexFingerprint returns checksum of a certificate's raw bytes
func CertHexFingerprint(certificate *x509.Certificate) string {
	fpr := sha3.Sum256(certificate.Raw)
	return strings.ToUpper(hex.EncodeToString(fpr[:16]))
}

// errCancelled is returned when the user cancels the pinentry dialog.
var errCancelled = i18n.Message("Entry cancelled.")

// getSecret asks the user for a secret with the pinentry dialog described by
// prompt.
func getSecret(prompt pinPrompt) (string, error) {
	path, err := config.PinentryPath()
	if err != nil {
		return "", err
	}

	secret, err := askPinentry(path, prompt)
	if err != nil && isPinentryDown(err) {
		// A pinentry process can end before it answers, for example when it
		// cannot attach to a terminal, which would abort the command over
		// something that a second process usually gets right. A dialog the
		// user cancelled is reported as such and is not retried.
		secret, err = askPinentry(path, prompt)
	}

	return secret, err
}

// askPinentry runs a single pinentry process and asks it for the secret
// described by prompt. A cancelled dialog is reported as errCancelled.
func askPinentry(path string, prompt pinPrompt) (string, error) {
	secret, err := pinentry.Ask(path, pinentry.Prompt{
		Description: prompt.dialogDescription(),
		Prompt:      prompt.Prompt,
		Message:     prompt.Message,
	})
	if err != nil {
		if errors.Is(err, pinentry.ErrCancelled) {
			return "", errCancelled
		}
		return "", i18n.Wrap(err, "Get secret from pinentry")
	}

	return secret, nil
}

// isPinentryDown reports whether err was caused by the pinentry process ending
// before it answered, rather than by a response it sent. A dialog the user
// cancelled is a response and is not reported as a crash.
func isPinentryDown(err error) bool {
	return errors.Is(err, syscall.EPIPE) || errors.Is(err, io.EOF)
}

// errInvalidPIN describes the PIN requirements enforced by validPIN.
var errInvalidPIN = i18n.Message("PIN must be 6 to 8 characters long and may contain letters, digits, and symbols.")

// errInvalidPUK describes the PUK requirements enforced by validPUK.
var errInvalidPUK = i18n.Message("PUK must be exactly 8 characters long and may contain letters, digits, and symbols.")

// validatePIN rejects input that cannot be a PIV user PIN. It is used to check
// entered PINs before they are sent to the smart card, so that a typo does not
// consume an attempt.
func validatePIN(pin string) error {
	if !validPIN(pin) {
		return errInvalidPIN
	}
	return nil
}

// validatePUK rejects input that cannot be a PIV PUK.
func validatePUK(puk string) error {
	if !validPUK(puk) {
		return errInvalidPUK
	}
	return nil
}

// validPIN reports whether pin can be a PIV user PIN. A PIN is 6 to 8
// characters long and may contain digits, uppercase and lowercase letters, and
// non-alphanumeric symbols. A space is rejected because the masked dialog
// cannot show it, which would leave the PIN impossible to type later on.
func validPIN(pin string) bool {
	return validSecret(pin, 6, 8)
}

// validPUK reports whether puk can be a PIV PIN unlocking key: the PIV
// specification fixes the PUK at exactly 8 characters, which may be digits,
// uppercase and lowercase letters, and non-alphanumeric symbols.
func validPUK(puk string) bool {
	return validSecret(puk, 8, 8)
}

// validSecret reports whether secret consists of minLen to maxLen printable
// ASCII characters other than a space.
func validSecret(secret string, minLen, maxLen int) bool {
	if len(secret) < minLen || len(secret) > maxLen {
		return false
	}
	for i := 0; i < len(secret); i++ {
		if secret[i] < '!' || secret[i] > '~' {
			return false
		}
	}
	return true
}

// allSlots is every valid PIV slot in key-reference order. Callers must treat
// it as read-only.
var allSlots = []Slot{
	SlotAuthentication,
	SlotCardManagement,
	SlotSignature,
	SlotKeyManagement,
	SlotCardAuthentication,
	SlotRetiredKeyManagement1,
	SlotRetiredKeyManagement2,
	SlotRetiredKeyManagement3,
	SlotRetiredKeyManagement4,
	SlotRetiredKeyManagement5,
	SlotRetiredKeyManagement6,
	SlotRetiredKeyManagement7,
	SlotRetiredKeyManagement8,
	SlotRetiredKeyManagement9,
	SlotRetiredKeyManagement10,
	SlotRetiredKeyManagement11,
	SlotRetiredKeyManagement12,
	SlotRetiredKeyManagement13,
	SlotRetiredKeyManagement14,
	SlotRetiredKeyManagement15,
	SlotRetiredKeyManagement16,
	SlotRetiredKeyManagement17,
	SlotRetiredKeyManagement18,
	SlotRetiredKeyManagement19,
	SlotRetiredKeyManagement20,
	SlotAttestation,
}

// GetSlot returns a Slot. Defaults to 9c.
func GetSlot(slot string) Slot {
	for _, s := range allSlots {
		if string(s) == slot {
			return s
		}
	}
	return SlotSignature
}

// String returns the string representation of a Slot.
func (s Slot) String() string {
	return string(s)
}

// Description returns a human-readable description of the slot.
func (s Slot) Description() string {
	switch s {
	case SlotAuthentication:
		return i18n.Sprintf("Authentication")
	case SlotCardManagement:
		return i18n.Sprintf("Card Management")
	case SlotSignature:
		return i18n.Sprintf("Digital Signature")
	case SlotKeyManagement:
		return i18n.Sprintf("Key Management")
	case SlotCardAuthentication:
		return i18n.Sprintf("Card Authentication")
	case SlotAttestation:
		return i18n.Sprintf("Attestation")
	}

	// Retired key-management slots use key references 82-95.
	if n, err := strconv.ParseUint(string(s), 16, 8); err == nil && n >= 0x82 && n <= 0x95 {
		return i18n.Sprintf("Retired Key Management %d", n-0x81)
	}

	return string(s)
}
