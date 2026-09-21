package pivzavr

import "github.com/h0tc0d3/pivzavr/pkg/i18n"

// ResetToken restores the factory state of the token: the keys and certificates
// stored in the PIV slots are erased, and the PIN, the PUK and the card
// management key are the factory defaults. The PIN and the PUK retry counters
// are full again as well.
//
// The reset needs neither the PIN, the PUK nor the management key of the token,
// because a PIV card resets itself once its PIN and its PUK are blocked. This
// cannot be undone: keys and certificates that are stored on the token are
// erased and cannot be recovered.
func ResetToken(tok Pivzavr) error {
	if err := tok.Reset(); err != nil {
		return i18n.Wrap(err, "Reset token")
	}
	return nil
}
