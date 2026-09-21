//go:build darwin || freebsd || linux || netbsd

package pcsc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLibraryLoads checks that the PC/SC library of the system is found under
// one of the names this package tries and that the entry points it uses are
// resolved in it. The library is loaded at run time, so this is the part of the
// implementation that a build cannot check. Neither a smart card reader nor a
// running smart card service is needed, which is why a system that does not have
// the library skips the test instead of failing it: the service is what pivzavr
// needs to talk to a card, not to build or to test the package.
func TestLibraryLoads(t *testing.T) {
	lib, err := library()
	if err != nil {
		t.Skipf("the PC/SC library is not available: %v", err)
	}
	require.NotNil(t, lib)
	assert.NotZero(t, lib.handle)

	// The library is loaded once, so every later caller gets the same one.
	again, err := library()
	require.NoError(t, err)
	assert.Same(t, lib, again)
}
