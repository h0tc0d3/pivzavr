package pivzavr

// pinPrompt describes the pinentry dialog used to ask the user for a secret
// such as a PIN or a PUK.
type pinPrompt struct {
	// Description is the text displayed above the input field.
	Description string
	// Prompt labels the input field.
	Prompt string
	// Attempts is the number of attempts the card has left for the secret, or
	// RetriesUnknown when the count cannot be read. A known count is shown
	// below the description, so that the user knows how many attempts are
	// left before the secret is entered as well.
	Attempts int
	// Message explains why the secret is requested again, for example that
	// the previous attempt was rejected. It is empty for a first prompt.
	Message string
}

// dialogDescription returns the text displayed above the input field: the
// description of the prompt followed by the attempts the card has left for the
// secret. Pinentry sizes its dialog to fit the text it is given, so a longer
// description makes for a larger dialog.
func (p pinPrompt) dialogDescription() string {
	left := attemptsMessage(p.Attempts)
	if left == "" {
		return p.Description
	}
	return p.Description + ". " + left
}
