package pivzavr

import (
	"github.com/pkg/errors"
)

type ResetOpts struct {
	// Pin new PIN to set for performing certain operations on the smart card
	Pin string
}

// ResetToken resets the token and sets a new PIN.
func ResetToken(tok Pivzavr, opts *ResetOpts) error {
	if !validPIN(opts.Pin) {
		return errors.New("PIN must be 6-8 digits long.")
	}

	if err := tok.Reset(); err != nil {
		return errors.Wrap(err, "Reset token")
	}

	if err := tok.SetPIN(DefaultPIN, opts.Pin); err != nil {
		return errors.Wrap(err, "Failed to change pin")
	}

	return nil
}
