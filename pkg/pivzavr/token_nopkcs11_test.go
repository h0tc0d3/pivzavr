//go:build !darwin && !freebsd && !linux && !netbsd && !windows

package pivzavr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file tests the PKCS#11 entry points of a build for a system the PKCS#11
// binding does not cover, which cannot load a module and therefore has to report
// that a token cannot be used. The tests that exercise a real module live in
// token_pkcs11_test.go.

func TestTokenHandleWithSerialWithoutPKCS11(t *testing.T) {
	tok, err := TokenHandleWithSerial("00000000")

	assert.Nil(t, tok)
	require.ErrorIs(t, err, errNoPKCS11)
	assert.ErrorContains(t, err, "not supported on this system")
}

func TestDeviceInfosWithoutPKCS11(t *testing.T) {
	infos, err := DeviceInfos()

	assert.Nil(t, infos)
	require.ErrorIs(t, err, errNoPKCS11)
}
