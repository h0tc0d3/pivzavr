//go:build darwin || freebsd || linux || netbsd || windows

package pivzavr

import (
	"github.com/h0tc0d3/pivzavr/pkg/pkcs11"
	"github.com/pkg/errors"
)

// This file holds the PKCS#11 status codes the PIN and PUK handling of auth.go
// reasons about. The codes come from the local pkg/pkcs11 binding, which covers
// the systems whose dynamic loader purego can use; auth_nopkcs11.go provides the
// same names to a build for any other system.

const (
	// pkcs11PINIncorrect is the status code reported for a wrong PIN or PUK.
	pkcs11PINIncorrect = uint(pkcs11.CKR_PIN_INCORRECT)
	// pkcs11PINLocked is the status code of a PIN or PUK that has no attempts
	// left. A locked PIN is unlocked with the PUK, a locked PUK only with a
	// reset of the card.
	pkcs11PINLocked = uint(pkcs11.CKR_PIN_LOCKED)
)

// pkcs11ErrorCode returns the PKCS#11 status code carried by err and reports
// whether err is a PKCS#11 error at all.
func pkcs11ErrorCode(err error) (uint, bool) {
	var pkcs11Err pkcs11.Error
	if !errors.As(err, &pkcs11Err) {
		return 0, false
	}
	return uint(pkcs11Err), true
}
