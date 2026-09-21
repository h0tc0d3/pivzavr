package pivzavr

import (
	"bytes"
	"encoding/hex"
	"strings"

	"github.com/h0tc0d3/pivzavr/pkg/i18n"
	"github.com/h0tc0d3/pivzavr/pkg/pcsc"
)

// pivAID is the PIV application identifier defined by NIST SP 800-73-4. It is
// an array so its length is a compile-time constant.
var pivAID = [...]byte{0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01}

// PIV data objects that are not exposed through PKCS#11. The identifiers are
// the object identifiers defined by NIST SP 800-73-4, together with the two
// YubiKey objects that keep the card management key.
var (
	// oidCHUID is the Card Holder Unique Identifier.
	oidCHUID = []byte{0x5F, 0xC1, 0x02}
	// oidCCC is the Card Capability Container.
	oidCCC = []byte{0x5F, 0xC1, 0x07}
	// oidPivmanProtected holds the card management key protected by the PIN.
	// It is the object a PIV card keeps the printed information in as well.
	oidPivmanProtected = []byte{0x5F, 0xC1, 0x09}
	// oidPivman holds the YubiKey PIV management data: the flags that report
	// how the card management key is kept and, on older firmware, the salt of
	// a management key that is derived from the PIN.
	oidPivman = []byte{0x5F, 0xFF, 0x00}
)

// PIV command bytes and response status words.
const (
	insSelect           = 0xA4
	insVerify           = 0x20
	insChangeReference  = 0x24
	insResetRetry       = 0x2C
	insAuthenticate     = 0x87
	insGetData          = 0xCB
	insPutData          = 0xDB
	insGetMetadata      = 0xF7
	insReset            = 0xFB
	insSetManagementKey = 0xFF

	tagObjectData       = 0x53
	tagObjectIdentifier = 0x5C
	tagRetries          = 0x06
	tagMetadataAlgo     = 0x01
	tagDynamicAuth      = 0x7C
	tagAuthWitness      = 0x80
	tagAuthChallenge    = 0x81
	tagAuthResponse     = 0x82

	pinRef = 0x80
	pukRef = 0x81
	// slotCardManagement is the PIV key reference of the card management
	// key (9B), which is not a slot that holds a key pair.
	slotCardManagement = 0x9B
	// slotCardAuthentication is the PIV key reference of the card
	// authentication key (9E), which is the one PIV key that can be used
	// without the user PIN.
	slotCardAuthentication = 0x9E

	// pinLength is the length of the PIN and PUK field of a PIV command. A
	// shorter secret is filled up with 0xFF.
	pinLength = 8

	swNoError            = 0x9000
	swAuthMethodBlocked  = 0x6983
	swFileNotFound       = 0x6A82
	swInvalidInstruction = 0x6D00
)

// errObjectNotFound is returned when a smart card does not hold a PIV data
// object.
var errObjectNotFound = i18n.Message("PIV data object not found.")

// RetriesUnknown is the value stored in DeviceInfo.PinRetries and
// DeviceInfo.PukRetries when the retry count could not be read.
const RetriesUnknown = -1

// readPIVRetries returns the remaining PIN and PUK retry counts for the PIV
// card whose Card Holder Unique Identifier is chuid (hex-encoded). The CHUID is
// used to select the right card when several are present; when chuid is empty
// and exactly one PIV card is connected, that card is used. An unavailable
// count is reported as RetriesUnknown.
func readPIVRetries(chuid string) (int, int) {
	ctx, err := pcsc.EstablishContext()
	if err != nil {
		return RetriesUnknown, RetriesUnknown
	}
	defer func() { _ = ctx.Close() }()

	readers, err := ctx.Readers()
	if err != nil {
		return RetriesUnknown, RetriesUnknown
	}

	pin, puk := RetriesUnknown, RetriesUnknown
	matched := 0
	for _, reader := range readers {
		card, err := ctx.Connect(reader, pcsc.ShareShared, pcsc.ProtocolAny)
		if err != nil {
			continue
		}
		p, k, ok := cardRetries(card, chuid)
		_ = card.Disconnect(pcsc.LeaveCard)
		if !ok {
			continue
		}
		matched++
		pin, puk = p, k
		if chuid != "" {
			// The CHUID identifies a single card, so its retries are final.
			return pin, puk
		}
	}

	// Without a CHUID to match on, only trust the result when a single card
	// was found.
	if chuid == "" && matched == 1 {
		return pin, puk
	}
	return RetriesUnknown, RetriesUnknown
}

// cardRetries selects the PIV application on card, verifies its CHUID when
// chuid is non-empty and reads the PIN and PUK retry counts.
func cardRetries(card *pcsc.Card, chuid string) (int, int, bool) {
	if !cardMatchesPIV(card, chuid) {
		return RetriesUnknown, RetriesUnknown, false
	}

	pin, okPIN := queryRetries(card, pinRef)
	puk, okPUK := queryRetries(card, pukRef)
	return coalesceRetries(pin, okPIN, puk, okPUK)
}

// cardMatchesPIV reports whether card runs the PIV application and, when chuid
// is non-empty, whether its Card Holder Unique Identifier matches it.
func cardMatchesPIV(card cardCommander, chuid string) bool {
	if !selectPIV(card) {
		return false
	}
	if chuid == "" {
		return true
	}
	got, err := chuidHex(card)
	return err == nil && strings.EqualFold(got, chuid)
}

// resetPIV restores the PIV application of the card identified by chuid to its
// factory state: the keys and certificates stored in its slots are erased, and
// the PIN, the PUK and the card management key are the factory defaults.
//
// The CHUID identifies the card to reset; when it is empty any PIV card
// matches, which is only accepted when exactly one is connected. This is the
// behavior of readPIVRetries, and it keeps a reset from hitting the wrong card.
func resetPIV(chuid string) error {
	ctx, err := pcsc.EstablishContext()
	if err != nil {
		return i18n.Wrap(err, "Establish PC/SC context")
	}
	defer func() { _ = ctx.Close() }()

	// Look for the card before touching it, so that the wrong card is not left
	// blocked by a failed reset.
	reader, err := findPIVReader(ctx, chuid, i18n.Sprintf("reset"))
	if err != nil {
		return err
	}

	card, err := ctx.Connect(reader, pcsc.ShareShared, pcsc.ProtocolAny)
	if err != nil {
		return i18n.Wrap(err, "Connect to smart card")
	}
	defer func() { _ = card.Disconnect(pcsc.LeaveCard) }()

	return cardReset(card)
}

// cardReset restores the factory state of the PIV application on card, which
// discards the keys and certificates stored in its slots and resets the PIN,
// the PUK and the card management key to their factory defaults.
//
// A PIV card only accepts the RESET command once its PIN and its PUK are
// blocked, so both references are blocked first.
func cardReset(card cardCommander) error {
	if !selectPIV(card) {
		return i18n.New("The smart card does not run the PIV application.")
	}

	// A card does not check a reference that it considers verified, so the PIN
	// verification state is cleared before the PIN is blocked. The command is a
	// YubiKey extension; a card that does not know it is not a failure.
	deauthenticatePIN(card)

	if err := blockPIN(card); err != nil {
		return i18n.Wrap(err, "Block PIN")
	}
	if err := blockPUK(card); err != nil {
		return i18n.Wrap(err, "Block PUK")
	}

	_, sw, err := transmit(card, []byte{0x00, insReset, 0x00, 0x00})
	if err != nil {
		return i18n.Wrap(err, "Reset smart card")
	}
	if sw != swNoError {
		return i18n.Errorf("RESET failed with status 0x%04X.", sw)
	}
	return nil
}

// deauthenticatePIN clears the PIN verification state of card. A YubiKey keeps
// a verified PIN until it is deselected, and a card does not verify a PIN that
// it considers verified already, which would keep the PIN from being blocked.
// The command is best effort: cards that do not support it reject it.
func deauthenticatePIN(card cardCommander) {
	_, _, _ = transmit(card, []byte{0x00, insVerify, 0xFF, pinRef})
}

// blockPIN uses up the remaining PIN attempts of card, which makes the card
// block the PIN.
func blockPIN(card cardCommander) error {
	return blockReference(card, insVerify, pinRef, wrongPINField(), "PIN")
}

// blockPUK uses up the remaining PUK attempts of card, which makes the card
// block the PUK. A PIV card verifies the PUK with the RESET RETRY COUNTER
// command, which carries the PUK and the new PIN in its data field.
func blockPUK(card cardCommander) error {
	data := append(wrongPINField(), wrongPINField()...)
	return blockReference(card, insResetRetry, pinRef, data, "PUK")
}

// wrongPINField returns a PIN field that a smart card rejects. A PIV card
// expects a field of eight bytes, so a secret that cannot be a PIN of the card
// is used to use up an attempt.
func wrongPINField() []byte {
	return pinField("")
}

// pinField returns the PIN or PUK field of a PIV command: the secret padded to
// eight bytes with 0xFF, which is how a PIV card expects a secret.
func pinField(secret string) []byte {
	field := bytes.Repeat([]byte{0xFF}, pinLength)
	copy(field, secret)
	return field
}

// blockReference sends ins for the reference ref with a secret that the card
// rejects until the card reports that the reference is blocked. A rejected
// secret uses up an attempt and the card reports the attempts that are left
// with 63Cx; the count has to go down for the loop to make progress, and a
// blocked reference is reported with 6983.
func blockReference(card cardCommander, ins, ref byte, data []byte, name string) error {
	apdu := []byte{0x00, ins, 0x00, ref, byte(len(data))} // #nosec G115 -- data is a short fixed-size field.
	apdu = append(apdu, data...)

	left := -1
	for {
		_, sw, err := transmit(card, apdu)
		if err != nil {
			return err
		}

		attempts, ok := parseVerifyRetries(sw)
		if !ok {
			if sw == swNoError {
				// The card accepts the reference without checking it.
				return i18n.Errorf("The smart card does not check its %s, so it cannot use it up (status 0x%04X).", name, sw)
			}
			return i18n.Errorf("The smart card did not reject the %s (status 0x%04X).", name, sw)
		}
		if attempts == 0 {
			return nil
		}
		if left != -1 && attempts >= left {
			return i18n.Errorf("The smart card did not use up its %s attempts (status 0x%04X).", name, sw)
		}
		left = attempts
	}
}

// coalesceRetries merges the optional PIN and PUK retry counts read from a
// card. A count that could not be read is reported as RetriesUnknown so that it
// is not mistaken for an exhausted PIN or PUK. The boolean result is false only
// when neither count could be read, in which case the card does not match.
func coalesceRetries(pin int, okPIN bool, puk int, okPUK bool) (int, int, bool) {
	if !okPIN {
		pin = RetriesUnknown
	}
	if !okPUK {
		puk = RetriesUnknown
	}
	return pin, puk, okPIN || okPUK
}

// queryRetries reads the number of remaining attempts for the PIN (pinRef) or
// PUK (pukRef). YubiKeys report the count directly through the GET METADATA
// command; for other cards the count is derived from the status word returned
// by a VERIFY command sent without a PIN.
func queryRetries(card cardCommander, ref byte) (int, bool) {
	if retries, ok := metadataRetries(card, ref); ok {
		return retries, true
	}
	return verifyRetries(card, ref)
}

// selectPIV selects the PIV application on card.
func selectPIV(card cardCommander) bool {
	apdu := []byte{0x00, insSelect, 0x04, 0x00, byte(len(pivAID))} // #nosec G115 -- pivAID is a short fixed-size array.
	apdu = append(apdu, pivAID[:]...)
	_, sw, err := transmit(card, apdu)
	return err == nil && sw == swNoError
}

// chuidHex reads the Card Holder Unique Identifier from card and returns it as
// an upper-case hex string, matching the representation produced by PKCS#11.
func chuidHex(card cardCommander) (string, error) {
	value, err := cardGetObject(card, oidCHUID)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(value)), nil
}

// metadataRetries reads the remaining attempts for the given reference using
// the YubiKey GET METADATA command.
func metadataRetries(card cardCommander, ref byte) (int, bool) {
	data, sw, err := transmit(card, []byte{0x00, insGetMetadata, 0x00, ref})
	if err != nil || sw != swNoError {
		return 0, false
	}
	return tlvRetries(data)
}

// verifyRetries derives the remaining attempts for the given reference from a
// PIV VERIFY command sent without a PIN. A card that reports the count answers
// with 63Cx; a card that considers the reference verified answers with success
// instead, in which case the count stays unknown. This is a fallback for cards
// that do not answer the GET METADATA command.
func verifyRetries(card cardCommander, ref byte) (int, bool) {
	_, sw, err := transmit(card, []byte{0x00, insVerify, 0x00, ref, 0x00})
	if err != nil {
		return 0, false
	}
	return parseVerifyRetries(sw)
}

// cardCommander transmits APDUs to a smart card. *pcsc.Card is used outside
// of tests; the interface lets the PIV command sequences that change the state
// of a card be tested without hardware.
type cardCommander interface {
	Transmit(apdu []byte) ([]byte, error)
}

// transmit sends apdu to card and returns the response data and status word.
func transmit(card cardCommander, apdu []byte) ([]byte, int, error) {
	response, err := card.Transmit(apdu)
	if err != nil {
		return nil, 0, err
	}
	if len(response) < 2 {
		return nil, 0, i18n.New("Short APDU response.")
	}
	data := response[:len(response)-2]
	sw := int(response[len(response)-2])<<8 | int(response[len(response)-1])
	return data, sw, nil
}

// dataObjectValue unwraps the 53 TLV that PIV cards use to return a data
// object, yielding the object's value.
func dataObjectValue(data []byte) ([]byte, bool) {
	return tlvValue(data, tagObjectData)
}

// tlvRetries extracts the remaining attempt count from a GET METADATA response.
// The response contains a tag 06 value holding the total and remaining
// attempts, in that order.
func tlvRetries(data []byte) (int, bool) {
	for i := 0; i+2 <= len(data); {
		tag := data[i]
		length := int(data[i+1])
		i += 2
		if i+length > len(data) {
			return 0, false
		}
		if tag == tagRetries && length == 2 {
			return int(data[i+1]), true
		}
		i += length
	}
	return 0, false
}

// parseVerifyRetries derives the remaining attempt count from the status word
// of a PIV VERIFY command.
func parseVerifyRetries(sw int) (int, bool) {
	switch {
	case sw == swAuthMethodBlocked:
		return 0, true
	case sw&0xFFF0 == 0x63C0:
		return sw & 0x0F, true
	case sw&0xFF00 == 0x6300:
		return sw & 0xFF, true
	}
	return 0, false
}
