package pivzavr

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePinentryEnv, when set, makes the test binary behave as a pinentry
// process speaking the Assuan protocol. This lets the Assuan client be tested
// against a real subprocess without needing pinentry to be installed.
const fakePinentryEnv = "PIVZAVR_TEST_PINENTRY"

func TestMain(m *testing.M) {
	if mode := os.Getenv(fakePinentryEnv); mode != "" {
		os.Exit(runFakePinentry(mode))
	}
	os.Exit(m.Run())
}

// runFakePinentry implements the subset of the Assuan protocol that
// pinentryClient uses. mode is returned as the PIN, or "cancel" to simulate
// the user cancelling the dialog.
func runFakePinentry(mode string) int {
	fmt.Println("OK Pleased to meet you")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "GETPIN"):
			if mode == "cancel" {
				fmt.Println("ERR 83886179 cancelled")
				continue
			}
			fmt.Println("D " + mode)
			fmt.Println("OK")
		case strings.HasPrefix(line, "BYE"):
			fmt.Println("OK closing connection")
			return 0
		default:
			fmt.Println("OK")
		}
	}
	return 0
}

func TestAssuanEscapeUnescape(t *testing.T) {
	testCases := []struct {
		name      string
		unescaped string
		escaped   string
	}{
		{"plain", "PIN:", "PIN:"},
		{"newline", "a\nb", "a%0Ab"},
		{"carriage return", "a\rb", "a%0Db"},
		{"percent", "100%", "100%25"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.escaped, assuanEscape(testCase.unescaped))
			assert.Equal(t, testCase.unescaped, assuanUnescape(testCase.escaped))
		})
	}
}

func TestAssuanUnescapeInvalidSequences(t *testing.T) {
	// Lowercase hex digits and truncated escapes are interpreted literally.
	assert.Equal(t, "a%0ab", assuanUnescape("a%0ab"))
	assert.Equal(t, "a%", assuanUnescape("a%"))
	assert.Equal(t, "a%2", assuanUnescape("a%2"))
}

func TestNewAssuanError(t *testing.T) {
	err := newAssuanError("ERR 83886179 cancelled")
	assert.Equal(t, "cancelled", err.Error())
	assert.True(t, isCancelled(err))

	assert.False(t, isCancelled(newAssuanError("ERR 12345 other")))
	assert.False(t, isCancelled(fmt.Errorf("plain error")))

	// A malformed code is reported as an unexpected response.
	var unexpected *unexpectedResponseError
	require.ErrorAs(t, newAssuanError("ERR notacode nope"), &unexpected)
}

func TestPinentryClientGetPIN(t *testing.T) {
	t.Setenv(fakePinentryEnv, "123456")

	client, err := newPinentryClient(os.Args[0])
	require.NoError(t, err)
	defer func() { _ = client.close() }()

	require.NoError(t, client.configure(""))
	pin, err := client.getPIN()
	require.NoError(t, err)
	assert.Equal(t, "123456", pin)
}

func TestPinentryClientGetPINCancelled(t *testing.T) {
	t.Setenv(fakePinentryEnv, "cancel")

	client, err := newPinentryClient(os.Args[0])
	require.NoError(t, err)
	defer func() { _ = client.close() }()

	require.NoError(t, client.configure(""))
	_, err = client.getPIN()
	require.Error(t, err)
	assert.True(t, isCancelled(err))
}

func TestPinentryClientStartError(t *testing.T) {
	_, err := newPinentryClient(filepath.Join(t.TempDir(), "does-not-exist"))
	assert.Error(t, err)
}

func TestGetPin(t *testing.T) {
	t.Setenv(fakePinentryEnv, "123456")
	t.Setenv(pinentryEnv, os.Args[0])

	pin, err := GetPin(os.Stdin)
	require.NoError(t, err)
	assert.Equal(t, "123456", pin)
}

func TestGetPinInvalid(t *testing.T) {
	t.Setenv(fakePinentryEnv, "1234")
	t.Setenv(pinentryEnv, os.Args[0])

	_, err := GetPin(os.Stdin)
	assert.Error(t, err)
}

func TestGetPinCancelled(t *testing.T) {
	t.Setenv(fakePinentryEnv, "cancel")
	t.Setenv(pinentryEnv, os.Args[0])

	_, err := GetPin(os.Stdin)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cancelled")
}
