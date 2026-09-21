//go:build !windows

package pcsc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The Unix systems report a reader name as a byte string, so the names of the
// reader list are split as they are.
func TestReaderNames(t *testing.T) {
	assert.Equal(t, []string{"reader one", "reader two"}, readerNames([]byte("reader one\x00reader two\x00\x00")))
	assert.Nil(t, readerNames([]byte{0x00}))
}
