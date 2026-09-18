package pivzavr

import (
	"crypto/sha3"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// CertHexFingerprint returns checksum of a certificate's raw bytes
func CertHexFingerprint(certificate *x509.Certificate) string {
	fpr := sha3.Sum256(certificate.Raw)
	return strings.ToUpper(hex.EncodeToString(fpr[:16]))
}

// GetPin prompts the user for a PIN.
//
// The PIN is entered through the pinentry program, which is launched directly
// and spoken to over the Assuan protocol. The reader argument is retained for
// backwards compatibility and is no longer used.
func GetPin(_ io.Reader) (string, error) {
	path, err := resolvePinentryPath()
	if err != nil {
		return "", err
	}

	client, err := newPinentryClient(path)
	if err != nil {
		return "", errors.Wrap(err, "Create pinentry client")
	}
	defer func() { _ = client.close() }()

	if err := client.configure(pinentryTTY()); err != nil {
		return "", errors.Wrap(err, "Configure pinentry")
	}

	pin, err := client.getPIN()
	if err != nil {
		if isCancelled(err) {
			return "", errors.New("PIN entry cancelled.")
		}
		return "", errors.Wrap(err, "Get PIN from pinentry")
	}

	if !validPIN(pin) {
		return "", errors.New("PIN must be 6-8 digits long.")
	}

	return pin, nil
}

// validPIN reports whether pin is a valid PIV user PIN: 6 to 8 numeric digits.
func validPIN(pin string) bool {
	if len(pin) < 6 || len(pin) > 8 {
		return false
	}
	for i := 0; i < len(pin); i++ {
		if pin[i] < '0' || pin[i] > '9' {
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
		return "Authentication"
	case SlotCardManagement:
		return "Card Management"
	case SlotSignature:
		return "Digital Signature"
	case SlotKeyManagement:
		return "Key Management"
	case SlotCardAuthentication:
		return "Card Authentication"
	case SlotAttestation:
		return "Attestation"
	}

	// Retired key-management slots use key references 82-95.
	if n, err := strconv.ParseUint(string(s), 16, 8); err == nil && n >= 0x82 && n <= 0x95 {
		return fmt.Sprintf("Retired Key Management %d", n-0x81)
	}

	return string(s)
}
