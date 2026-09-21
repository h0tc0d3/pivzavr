package pivzavr

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/h0tc0d3/pivzavr/pkg/config"
	"github.com/h0tc0d3/pivzavr/pkg/testpinentry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain turns the test binary into a fake pinentry process when the tests
// start it as one.
func TestMain(m *testing.M) {
	testpinentry.Main(m)
}

// The tests start the test binary itself as the pinentry program. These names
// keep the tests that set the environment variables of the harness short.
const (
	fakePinentryEnv    = testpinentry.Env
	fakePinentrySeqEnv = testpinentry.SeqEnv
	// pinentryEnv is the environment variable that selects the pinentry
	// program; the tests point it at the test binary.
	pinentryEnv = config.PinentryEnv
)

func TestDialogDescription(t *testing.T) {
	prompt := pinPrompt{Description: "Enter smart card PIN", Attempts: RetriesUnknown}
	assert.Equal(t, "Enter smart card PIN", prompt.dialogDescription())

	prompt.Attempts = 1
	assert.Equal(t, "Enter smart card PIN. 1 attempt left.", prompt.dialogDescription())

	// Pinentry sizes its dialog to fit the text, so the longer description of
	// the PUK prompt makes for a dialog that is larger than the PIN dialog.
	puk := pinPrompt{Description: "Enter smart card PUK to unlock the PIN", Attempts: 1}
	assert.Equal(t, "Enter smart card PUK to unlock the PIN. 1 attempt left.", puk.dialogDescription())
	assert.Greater(t, len(puk.dialogDescription()), len(prompt.dialogDescription()))
}

func TestGetSecret(t *testing.T) {
	t.Setenv(fakePinentryEnv, "123456")
	t.Setenv(pinentryEnv, os.Args[0])

	secret, err := getSecret(pinPrompt{Description: "Enter smart card PIN", Prompt: "PIN:"})
	require.NoError(t, err)
	assert.Equal(t, "123456", secret)
}

func TestGetSecretCancelled(t *testing.T) {
	t.Setenv(fakePinentryEnv, "cancel")
	t.Setenv(pinentryEnv, os.Args[0])

	_, err := getSecret(pinPrompt{Description: "Enter smart card PIN", Prompt: "PIN:"})
	require.Error(t, err)
	assert.Equal(t, errCancelled, err)
}

// TestGetSecret_pinentryDies makes sure that a pinentry process that is gone
// before it answers is replaced instead of failing the prompt. macOS runners
// started such processes occasionally, which made the unlock tests fail with a
// broken pipe.
func TestGetSecret_pinentryDies(t *testing.T) {
	t.Setenv(fakePinentryEnv, "die,123456")
	t.Setenv(fakePinentrySeqEnv, filepath.Join(t.TempDir(), "pinentry-state"))
	t.Setenv(pinentryEnv, os.Args[0])

	secret, err := getSecret(pinPrompt{Description: "Enter smart card PIN", Prompt: "PIN:"})
	require.NoError(t, err)
	assert.Equal(t, "123456", secret)
}
