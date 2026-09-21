package pivzavr

import "github.com/h0tc0d3/pivzavr/pkg/i18n"

// Tags of the YubiKey PIV management data object (5F FF 00) and of the object
// that holds the card management key protected by the PIN (5F C1 09).
const (
	tagPivmanData      = 0x80
	tagPivmanFlags     = 0x81
	tagPivmanSalt      = 0x82
	tagPivmanPINTime   = 0x83
	tagPivmanProtected = 0x88
	tagPivmanKey       = 0x89
)

const (
	// pivmanMgmKeyProtected is the flag that reports that the card management
	// key is stored on the smart card, protected by the PIN.
	pivmanMgmKeyProtected = 0x02
)

// pivmanData is the YubiKey PIV management data: the flags that report how the
// card management key is kept, the salt of a management key that older YubiKey
// firmware derives from the PIN, and the time the PIN was last set. A derived
// key is no longer used, but the salt is kept so that the field survives a round
// trip. A field that the smart card does not hold is nil.
type pivmanData struct {
	flags   []byte
	salt    []byte
	pinTime []byte
}

// parsePivmanData parses the PIV management data object of a smart card. An
// empty object reports no data, which is what a card that does not hold the
// object answers with.
func parsePivmanData(raw []byte) (pivmanData, error) {
	if len(raw) == 0 {
		return pivmanData{}, nil
	}

	value, ok := tlvValue(raw, tagPivmanData)
	if !ok {
		return pivmanData{}, i18n.New("Malformed PIV management data.")
	}

	data := pivmanData{}
	if flags, ok := tlvValue(value, tagPivmanFlags); ok {
		if len(flags) != 1 {
			return pivmanData{}, i18n.New("Malformed PIV management data.")
		}
		data.flags = flags
	}
	data.salt, _ = tlvValue(value, tagPivmanSalt)
	data.pinTime, _ = tlvValue(value, tagPivmanPINTime)
	return data, nil
}

// mgmKeyProtected reports whether the smart card stores its card management key
// protected by the PIN.
func (d pivmanData) mgmKeyProtected() bool {
	return len(d.flags) == 1 && d.flags[0]&pivmanMgmKeyProtected != 0
}

// setMgmKeyProtected reports whether the card management key is stored on the
// smart card protected by the PIN. The flag is only written when the smart card
// holds a flags field or the key is stored, so that an empty data object stays
// empty.
func (d *pivmanData) setMgmKeyProtected(protected bool) {
	if len(d.flags) != 1 && !protected {
		return
	}

	var flags byte
	if len(d.flags) == 1 {
		flags = d.flags[0]
	}
	if protected {
		flags |= pivmanMgmKeyProtected
	} else {
		flags &^= pivmanMgmKeyProtected
	}
	d.flags = []byte{flags}
}

// bytes returns the PIV management data object, or nil when it holds no field
// and the smart card does not have to be written to.
func (d pivmanData) bytes() []byte {
	var value []byte
	if len(d.flags) == 1 {
		value = append(value, encodeTLV(tagPivmanFlags, d.flags)...)
	}
	if d.salt != nil {
		value = append(value, encodeTLV(tagPivmanSalt, d.salt)...)
	}
	if d.pinTime != nil {
		value = append(value, encodeTLV(tagPivmanPINTime, d.pinTime)...)
	}
	if len(value) == 0 {
		return nil
	}
	return encodeTLV(tagPivmanData, value)
}

// pivmanProtectedData is the data object that holds the card management key
// protected by the PIN.
type pivmanProtectedData struct {
	key []byte
}

// parsePivmanProtectedData parses the object that holds the card management key
// protected by the PIN. An empty object reports no key, which is what a card
// holds once a stored key was removed.
func parsePivmanProtectedData(raw []byte) (pivmanProtectedData, error) {
	if len(raw) == 0 {
		return pivmanProtectedData{}, nil
	}

	value, ok := tlvValue(raw, tagPivmanProtected)
	if !ok {
		return pivmanProtectedData{}, i18n.New("Malformed protected PIV management data.")
	}
	key, _ := tlvValue(value, tagPivmanKey)
	return pivmanProtectedData{key: key}, nil
}

// bytes returns the object that holds the card management key. A data object
// without a key is written as an empty object, which is how a stored key is
// removed from the smart card.
func (d pivmanProtectedData) bytes() []byte {
	if d.key == nil {
		return nil
	}
	return encodeTLV(tagPivmanProtected, encodeTLV(tagPivmanKey, d.key))
}
