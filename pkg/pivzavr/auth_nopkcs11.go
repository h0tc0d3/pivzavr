//go:build !darwin && !freebsd && !linux && !netbsd && !windows

package pivzavr

// This file holds the stand-ins for the PKCS#11 status codes that the PIN and
// PUK handling of auth.go reasons about. A build for a system the PKCS#11
// binding does not cover never loads a module, so it never sees an error that
// carries such a code: every PIN or PUK failure reaches the user as the error
// the smart card returned. See auth_pkcs11.go for the systems the binding
// covers.

const (
	// pkcs11PINIncorrect is the status code reported for a wrong PIN or PUK.
	pkcs11PINIncorrect uint = 0
	// pkcs11PINLocked is the status code of a PIN or PUK that has no attempts
	// left. A locked PIN is unlocked with the PUK, a locked PUK only with a
	// reset of the card.
	pkcs11PINLocked uint = 0
)

// pkcs11ErrorCode always reports that err carries no PKCS#11 status code.
func pkcs11ErrorCode(error) (uint, bool) {
	return 0, false
}
