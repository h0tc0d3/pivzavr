package pivzavr

import (
	"os"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubAsk answers prompts with secrets in order and records every prompt it was
// given. Running out of secrets returns errCancelled, which ends a prompt loop
// instead of letting a test hang.
type stubAsk struct {
	secrets []string
	prompts []pinPrompt
}

func (s *stubAsk) ask(prompt pinPrompt) (string, error) {
	s.prompts = append(s.prompts, prompt)
	if len(s.secrets) == 0 {
		return "", errCancelled
	}
	secret := s.secrets[0]
	s.secrets = s.secrets[1:]
	return secret, nil
}

// messages returns the retry messages of the prompts that followed a rejected
// or invalid secret.
func (s *stubAsk) messages() []string {
	var messages []string
	for _, prompt := range s.prompts {
		if prompt.Message != "" {
			messages = append(messages, prompt.Message)
		}
	}
	return messages
}

func TestRetryMessage(t *testing.T) {
	assert.Equal(t, "PIN incorrect.", retryMessage("PIN"))
	assert.Equal(t, "PUK incorrect.", retryMessage("PUK"))
}

func TestAttemptsMessage(t *testing.T) {
	testCases := []struct {
		attempts int
		want     string
	}{
		{3, "3 attempts left."},
		{2, "2 attempts left."},
		{1, "1 attempt left."},
		{0, ""},
		{RetriesUnknown, ""},
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.want, attemptsMessage(tc.attempts), "attempts %d", tc.attempts)
	}
}

// pinPromptForPIN returns a prompt for the user PIN that verifies secrets with
// verify and reads the remaining attempts with attempts.
func pinPromptForPIN(ask func(pinPrompt) (string, error), verify func(string) error, attempts func() int) secretPrompt {
	return secretPrompt{
		Name:     "PIN",
		Prompt:   pinPrompt{Description: "Enter smart card PIN", Prompt: "PIN:"},
		Ask:      ask,
		Validate: validatePIN,
		Verify:   verify,
		Attempts: attempts,
		Blocked:  errPINBlocked,
	}
}

func TestSecretPromptAskDefaultPinentry(t *testing.T) {
	// Without an Ask function the prompt falls back to pinentry, which is
	// replaced by the test binary here.
	t.Setenv(fakePinentryEnv, DefaultPIN)
	t.Setenv(pinentryEnv, os.Args[0])

	var verified []string
	prompt := pinPromptForPIN(nil, func(secret string) error {
		verified = append(verified, secret)
		return nil
	}, func() int { return RetriesUnknown })

	secret, err := prompt.ask()
	require.NoError(t, err)
	assert.Equal(t, DefaultPIN, secret)
	assert.Equal(t, []string{DefaultPIN}, verified)
}

func TestSecretPromptAsk(t *testing.T) {
	t.Run("accepts the secret on the first attempt", func(t *testing.T) {
		ask := &stubAsk{secrets: []string{DefaultPIN}}
		var verified []string

		secret, err := pinPromptForPIN(ask.ask, func(secret string) error {
			verified = append(verified, secret)
			return nil
		}, func() int { return RetriesUnknown }).ask()

		require.NoError(t, err)
		assert.Equal(t, DefaultPIN, secret)
		assert.Equal(t, []string{DefaultPIN}, verified)
		require.Len(t, ask.prompts, 1)
		assert.Empty(t, ask.prompts[0].Message)
	})

	t.Run("prompts again while the card rejects the secret", func(t *testing.T) {
		ask := &stubAsk{secrets: []string{"111111", "111111", DefaultPIN}}
		var verified []string

		secret, err := pinPromptForPIN(ask.ask, func(secret string) error {
			verified = append(verified, secret)
			if secret == DefaultPIN {
				return nil
			}
			return errSecretIncorrect
		}, func() int { return 1 }).ask()

		require.NoError(t, err)
		assert.Equal(t, DefaultPIN, secret)
		assert.Len(t, verified, 3)
		assert.Equal(t, []string{
			"PIN incorrect.",
			"PIN incorrect.",
		}, ask.messages())
	})

	t.Run("shows the attempts that are left before the secret is entered", func(t *testing.T) {
		ask := &stubAsk{secrets: []string{"111111", DefaultPIN}}
		left := fakeAttempts

		secret, err := pinPromptForPIN(ask.ask, func(secret string) error {
			if secret == DefaultPIN {
				return nil
			}
			// A rejected secret uses up an attempt.
			left--
			return errSecretIncorrect
		}, func() int { return left }).ask()

		require.NoError(t, err)
		assert.Equal(t, DefaultPIN, secret)
		require.Len(t, ask.prompts, 2)
		assert.Equal(t, fakeAttempts, ask.prompts[0].Attempts)
		assert.Equal(t, fakeAttempts-1, ask.prompts[1].Attempts)
		assert.Empty(t, ask.prompts[0].Message)
		assert.Equal(t, "PIN incorrect.", ask.prompts[1].Message)
	})

	t.Run("reports a blocked secret", func(t *testing.T) {
		ask := &stubAsk{secrets: []string{"111111"}}

		_, err := pinPromptForPIN(ask.ask, func(string) error {
			return errSecretIncorrect
		}, func() int { return 0 }).ask()

		assert.Equal(t, errPINBlocked, err)
		assert.Len(t, ask.prompts, 1)
	})

	t.Run("keeps prompting while the count is unknown", func(t *testing.T) {
		ask := &stubAsk{secrets: []string{"111111"}}

		_, err := pinPromptForPIN(ask.ask, func(string) error {
			return errSecretIncorrect
		}, func() int { return RetriesUnknown }).ask()

		assert.Equal(t, errCancelled, err)
		require.Len(t, ask.prompts, 2)
		assert.Equal(t, []string{"PIN incorrect."}, ask.messages())
	})

	t.Run("propagates a card that refuses further attempts", func(t *testing.T) {
		ask := &stubAsk{secrets: []string{"111111"}}

		_, err := pinPromptForPIN(ask.ask, func(string) error {
			return errPINBlocked
		}, func() int { return RetriesUnknown }).ask()

		assert.Equal(t, errPINBlocked, err)
		assert.Len(t, ask.prompts, 1)
	})

	t.Run("rejects input that cannot be a PIN without asking the card", func(t *testing.T) {
		ask := &stubAsk{secrets: []string{"1234", DefaultPIN}}
		var verified []string

		secret, err := pinPromptForPIN(ask.ask, func(secret string) error {
			verified = append(verified, secret)
			return nil
		}, func() int { return RetriesUnknown }).ask()

		require.NoError(t, err)
		assert.Equal(t, DefaultPIN, secret)
		assert.Equal(t, []string{DefaultPIN}, verified)
		assert.Equal(t, []string{errInvalidPIN.Error()}, ask.messages())
	})

	t.Run("propagates an unexpected verification error", func(t *testing.T) {
		ask := &stubAsk{secrets: []string{DefaultPIN}}
		boom := errors.New("boom")

		_, err := pinPromptForPIN(ask.ask, func(string) error {
			return boom
		}, func() int { return RetriesUnknown }).ask()

		assert.Equal(t, boom, err)
		assert.Len(t, ask.prompts, 1)
	})

	t.Run("propagates a cancelled dialog", func(t *testing.T) {
		ask := &stubAsk{}
		verified := 0

		_, err := pinPromptForPIN(ask.ask, func(string) error {
			verified++
			return nil
		}, func() int { return RetriesUnknown }).ask()

		assert.Equal(t, errCancelled, err)
		assert.Equal(t, 0, verified)
	})
}

func TestSecretPromptAskWithoutVerify(t *testing.T) {
	// A prompt without a Verify accepts input that only passes Validate, which
	// is how the new PIN of an unlock is asked for.
	ask := &stubAsk{secrets: []string{"1234", DefaultPIN}}

	secret, err := (secretPrompt{
		Name:     "PIN",
		Prompt:   pinPrompt{Description: "Enter the new smart card PIN", Prompt: "PIN:"},
		Ask:      ask.ask,
		Validate: validatePIN,
	}).ask()

	require.NoError(t, err)
	assert.Equal(t, DefaultPIN, secret)
	assert.Equal(t, []string{errInvalidPIN.Error()}, ask.messages())
}

func TestClassifySecret(t *testing.T) {
	t.Run("accepted", func(t *testing.T) {
		assert.NoError(t, classifySecret(nil, errSecretIncorrect, errPINBlocked, "Login to token"))
	})

	t.Run("other error carries the operation", func(t *testing.T) {
		err := classifySecret(errors.New("boom"), errSecretIncorrect, errPINBlocked, "Login to token")
		assert.ErrorContains(t, err, "Login to token")
		assert.ErrorContains(t, err, "boom")
	})
}
