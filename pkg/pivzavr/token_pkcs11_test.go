//go:build darwin || freebsd || linux || netbsd || windows

package pivzavr

import (
	"crypto/ecdsa"
	"testing"

	"github.com/stretchr/testify/assert"
)

// This file tests the PKCS#11 token implementation, which exists on the systems
// the local pkg/pkcs11 binding covers. The tests that need no PKCS#11 module
// live in token_test.go and token_helpers_test.go.

func TestPkcs11SignerPublic(t *testing.T) {
	pub := &ecdsa.PublicKey{}
	signer := &pkcs11Signer{pub: pub}

	assert.Same(t, pub, signer.Public())
}
