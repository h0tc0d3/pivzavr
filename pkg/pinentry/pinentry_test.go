package pinentry

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/h0tc0d3/pivzavr/pkg/testpinentry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain turns the test binary into a fake pinentry process when the tests
// start it as one.
func TestMain(m *testing.M) {
	testpinentry.Main(m)
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

func TestCommands(t *testing.T) {
	// A plain prompt names the title, the input field and its label.
	assert.Equal(t, []string{
		"SETTITLE pivzavr",
		"SETDESC Enter smart card PIN",
		"SETPROMPT PIN:",
	}, commands("", Prompt{Description: "Enter smart card PIN", Prompt: "PIN:"}))

	// A retry message is shown in the dialog as an explanation.
	prompt := Prompt{
		Description: "Enter smart card PIN. 2 attempts left.",
		Prompt:      "PIN:",
		Message:     "PIN incorrect.",
	}
	assert.Equal(t, []string{
		"OPTION ttyname=/dev/tty",
		"SETTITLE pivzavr",
		"SETDESC Enter smart card PIN. 2 attempts left.",
		"SETPROMPT PIN:",
		"SETERROR PIN incorrect.",
	}, commands("/dev/tty", prompt))

	// Newlines are escaped so that they cannot break the Assuan command.
	prompt.Message = "line1\nline2"
	out := commands("", prompt)
	assert.Equal(t, "SETERROR line1%0Aline2", out[len(out)-1])
}

func TestAsk(t *testing.T) {
	t.Setenv(testpinentry.Env, "123456")

	secret, err := Ask(os.Args[0], Prompt{Description: "Enter smart card PIN", Prompt: "PIN:"})
	require.NoError(t, err)
	assert.Equal(t, "123456", secret)
}

func TestAskCancelled(t *testing.T) {
	t.Setenv(testpinentry.Env, "cancel")

	_, err := Ask(os.Args[0], Prompt{Description: "Enter smart card PIN", Prompt: "PIN:"})
	assert.ErrorIs(t, err, ErrCancelled)
}

func TestClientGetPIN(t *testing.T) {
	t.Setenv(testpinentry.Env, "123456")

	c, err := newClient(os.Args[0])
	require.NoError(t, err)
	defer func() { _ = c.close() }()

	require.NoError(t, c.configure("", Prompt{Description: "Enter smart card PIN", Prompt: "PIN:"}))
	pin, err := c.getPIN()
	require.NoError(t, err)
	assert.Equal(t, "123456", pin)
}

func TestClientGetPINCancelled(t *testing.T) {
	t.Setenv(testpinentry.Env, "cancel")

	c, err := newClient(os.Args[0])
	require.NoError(t, err)
	defer func() { _ = c.close() }()

	require.NoError(t, c.configure("", Prompt{Description: "Enter smart card PIN", Prompt: "PIN:"}))
	_, err = c.getPIN()
	require.Error(t, err)
	assert.True(t, isCancelled(err))
}

func TestClientStartError(t *testing.T) {
	_, err := newClient(filepath.Join(t.TempDir(), "does-not-exist"))
	assert.Error(t, err)
}
