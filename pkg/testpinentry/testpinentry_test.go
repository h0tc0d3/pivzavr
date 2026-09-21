package testpinentry

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsTestRun(t *testing.T) {
	assert.False(t, IsTestRun([]string{"/tmp/pivzavr.test"}))
	assert.False(t, IsTestRun([]string{"/tmp/pivzavr.test", "-v"}))
	assert.True(t, IsTestRun([]string{"/tmp/pivzavr.test", "-test.timeout=10m0s"}))
	assert.True(t, IsTestRun([]string{"/tmp/pivzavr.test", "-test.run=TestIsTestRun", "-test.v"}))
}
