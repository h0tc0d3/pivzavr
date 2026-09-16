package pivzavr

import (
	"crypto"
	"crypto/x509"
	"io"
)

// Slot identifies a key/certificate pair on a PKCS#11 token.
//
// The string value is the PIV key reference (lowercase hex) for the four
// standard slots, the retired key-management slots (82-95) and the
// card-management (9b) and attestation (f9) slots.
type Slot string

const (
	// SlotAuthentication is the PIV Authentication slot (key reference 9a).
	SlotAuthentication Slot = "9a"
	// SlotCardManagement is the card management slot (key reference 9b).
	SlotCardManagement Slot = "9b"
	// SlotSignature is the Digital Signature slot (key reference 9c).
	SlotSignature Slot = "9c"
	// SlotKeyManagement is the Key Management slot (key reference 9d).
	SlotKeyManagement Slot = "9d"
	// SlotCardAuthentication is the Card Authentication slot (key reference 9e).
	SlotCardAuthentication Slot = "9e"
	// SlotAttestation is the PIV Attestation slot (key reference f9).
	SlotAttestation Slot = "f9"

	// Retired key-management slots (key references 82-95).
	SlotRetiredKeyManagement1  Slot = "82"
	SlotRetiredKeyManagement2  Slot = "83"
	SlotRetiredKeyManagement3  Slot = "84"
	SlotRetiredKeyManagement4  Slot = "85"
	SlotRetiredKeyManagement5  Slot = "86"
	SlotRetiredKeyManagement6  Slot = "87"
	SlotRetiredKeyManagement7  Slot = "88"
	SlotRetiredKeyManagement8  Slot = "89"
	SlotRetiredKeyManagement9  Slot = "8a"
	SlotRetiredKeyManagement10 Slot = "8b"
	SlotRetiredKeyManagement11 Slot = "8c"
	SlotRetiredKeyManagement12 Slot = "8d"
	SlotRetiredKeyManagement13 Slot = "8e"
	SlotRetiredKeyManagement14 Slot = "8f"
	SlotRetiredKeyManagement15 Slot = "90"
	SlotRetiredKeyManagement16 Slot = "91"
	SlotRetiredKeyManagement17 Slot = "92"
	SlotRetiredKeyManagement18 Slot = "93"
	SlotRetiredKeyManagement19 Slot = "94"
	SlotRetiredKeyManagement20 Slot = "95"
)

// Pivzavr is the minimal set of operations the pivzavr commands require from a
// PKCS#11 token.
type Pivzavr interface {
	// Close releases any resources held by the token.
	Close() error

	// Certificate returns the x509 certificate stored in slot.
	Certificate(slot Slot) (*x509.Certificate, error)

	// Slots returns the PIV slots that currently hold a certificate.
	Slots() ([]Slot, error)

	// Signer returns a crypto.Signer backed by the private key in slot.
	// prompt is used to obtain the PIN when the token requires a login.
	Signer(slot Slot, prompt io.Reader) (crypto.Signer, error)

	// Reset resets the token to factory state and initializes the default PIN.
	Reset() error

	// SetPIN changes the user PIN from oldPIN to newPIN.
	SetPIN(oldPIN, newPIN string) error
}

// TokenHandle returns a handle to the connected token.
// It errors unless there is exactly one token connected.
func TokenHandle() (Pivzavr, error) {
	return TokenHandleWithSerial("")
}
