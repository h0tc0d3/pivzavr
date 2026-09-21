//go:build darwin || freebsd || linux || netbsd || windows

package pivzavr

import (
	"testing"

	"github.com/h0tc0d3/pivzavr/pkg/pkcs11"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

// This file tests the PIN and PUK handling that reasons about PKCS#11 status
// codes, which exists on the systems the local pkg/pkcs11 binding covers.
// auth_test.go covers the part of classifySecret that every build has.

func TestClassifySecretPKCS11(t *testing.T) {
	t.Run("incorrect", func(t *testing.T) {
		err := classifySecret(pkcs11.Error(pkcs11.CKR_PIN_INCORRECT), errSecretIncorrect, errPINBlocked, "Login to token")
		assert.Equal(t, errSecretIncorrect, err)
	})

	t.Run("blocked", func(t *testing.T) {
		err := classifySecret(pkcs11.Error(pkcs11.CKR_PIN_LOCKED), errSecretIncorrect, errPINBlocked, "Login to token")
		assert.Equal(t, errPINBlocked, err)
	})

	t.Run("wrapped incorrect", func(t *testing.T) {
		err := classifySecret(
			errors.Wrap(pkcs11.Error(pkcs11.CKR_PIN_INCORRECT), "Login"),
			errSecretIncorrect,
			errPINBlocked,
			"Login to token",
		)
		assert.Equal(t, errSecretIncorrect, err)
	})
}

func TestIsPKCS11Error(t *testing.T) {
	assert.True(t, isPKCS11Error(pkcs11.Error(pkcs11.CKR_PIN_INCORRECT), pkcs11PINIncorrect))
	assert.True(t, isPKCS11Error(errors.Wrap(pkcs11.Error(pkcs11.CKR_PIN_LOCKED), "wrap"), pkcs11PINLocked))
	assert.False(t, isPKCS11Error(pkcs11.Error(pkcs11.CKR_PIN_LOCKED), pkcs11PINIncorrect))
	assert.False(t, isPKCS11Error(errors.New("boom"), pkcs11PINIncorrect))
	assert.False(t, isPKCS11Error(nil, pkcs11PINIncorrect))
}
