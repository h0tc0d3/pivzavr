package pivzavr

import (
	"encoding/hex"
	"strings"

	"github.com/ebfe/scard"
	"github.com/pkg/errors"
)

// pivAID is the PIV application identifier defined by NIST SP 800-73-4. It is
// an array so its length is a compile-time constant.
var pivAID = [...]byte{0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01}

// chuidOID is the BER-encoded PIV object identifier of the Card Holder Unique
// Identifier: the 5C tag carrying the 5FC102 object identifier.
var chuidOID = [...]byte{0x5C, 0x03, 0x5F, 0xC1, 0x02}

// PIV command bytes and response status words.
const (
	insSelect      = 0xA4
	insVerify      = 0x20
	insGetData     = 0xCB
	insGetMetadata = 0xF7

	tagGetDataObject = 0x53
	tagRetries       = 0x06

	pinRef = 0x80
	pukRef = 0x81

	swNoError           = 0x9000
	swAuthMethodBlocked = 0x6983
)

// RetriesUnknown is the value stored in DeviceInfo.PinRetries and
// DeviceInfo.PukRetries when the retry count could not be read.
const RetriesUnknown = -1

// readPIVRetries returns the remaining PIN and PUK retry counts for the PIV
// card whose Card Holder Unique Identifier is chuid (hex-encoded). The CHUID is
// used to select the right card when several are present; when chuid is empty
// and exactly one PIV card is connected, that card is used. An unavailable
// count is reported as RetriesUnknown.
func readPIVRetries(chuid string) (int, int) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return RetriesUnknown, RetriesUnknown
	}
	defer func() { _ = ctx.Release() }()

	readers, err := ctx.ListReaders()
	if err != nil {
		return RetriesUnknown, RetriesUnknown
	}

	pin, puk := RetriesUnknown, RetriesUnknown
	matched := 0
	for _, reader := range readers {
		card, err := ctx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
		if err != nil {
			continue
		}
		p, k, ok := cardRetries(card, chuid)
		_ = card.Disconnect(scard.LeaveCard)
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
func cardRetries(card *scard.Card, chuid string) (int, int, bool) {
	if !selectPIV(card) {
		return RetriesUnknown, RetriesUnknown, false
	}

	if chuid != "" {
		got, err := chuidHex(card)
		if err != nil || !strings.EqualFold(got, chuid) {
			return RetriesUnknown, RetriesUnknown, false
		}
	}

	pin, okPIN := queryRetries(card, pinRef)
	puk, okPUK := queryRetries(card, pukRef)
	return coalesceRetries(pin, okPIN, puk, okPUK)
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
func queryRetries(card *scard.Card, ref byte) (int, bool) {
	if retries, ok := metadataRetries(card, ref); ok {
		return retries, true
	}
	return verifyRetries(card, ref)
}

// selectPIV selects the PIV application on card.
func selectPIV(card *scard.Card) bool {
	apdu := []byte{0x00, insSelect, 0x04, 0x00, byte(len(pivAID))} // #nosec G115 -- pivAID is a short fixed-size array.
	apdu = append(apdu, pivAID[:]...)
	_, sw, err := transmit(card, apdu)
	return err == nil && sw == swNoError
}

// chuidHex reads the Card Holder Unique Identifier from card and returns it as
// an upper-case hex string, matching the representation produced by PKCS#11.
func chuidHex(card *scard.Card) (string, error) {
	apdu := []byte{0x00, insGetData, 0x3F, 0xFF, byte(len(chuidOID))} // #nosec G115 -- chuidOID is a short fixed-size array.
	apdu = append(apdu, chuidOID[:]...)
	apdu = append(apdu, 0x00) // Le

	data, sw, err := transmit(card, apdu)
	if err != nil {
		return "", err
	}
	if sw != swNoError {
		return "", errors.Errorf("GET DATA failed with status 0x%04X.", sw)
	}

	value, ok := dataObjectValue(data)
	if !ok {
		return "", errors.New("Unexpected CHUID data object.")
	}
	return strings.ToUpper(hex.EncodeToString(value)), nil
}

// metadataRetries reads the remaining attempts for the given reference using
// the YubiKey GET METADATA command.
func metadataRetries(card *scard.Card, ref byte) (int, bool) {
	data, sw, err := transmit(card, []byte{0x00, insGetMetadata, 0x00, ref})
	if err != nil || sw != swNoError {
		return 0, false
	}
	return tlvRetries(data)
}

// verifyRetries derives the remaining attempts for the given reference from a
// PIV VERIFY command sent without a PIN. The card returns 63Cx carrying the
// remaining count without consuming an attempt.
func verifyRetries(card *scard.Card, ref byte) (int, bool) {
	_, sw, err := transmit(card, []byte{0x00, insVerify, 0x00, ref, 0x00})
	if err != nil {
		return 0, false
	}
	return parseVerifyRetries(sw)
}

// transmit sends apdu to card and returns the response data and status word.
func transmit(card *scard.Card, apdu []byte) ([]byte, int, error) {
	response, err := card.Transmit(apdu)
	if err != nil {
		return nil, 0, err
	}
	if len(response) < 2 {
		return nil, 0, errors.New("Short APDU response.")
	}
	data := response[:len(response)-2]
	sw := int(response[len(response)-2])<<8 | int(response[len(response)-1])
	return data, sw, nil
}

// dataObjectValue unwraps the 53 TLV that PIV cards use to return a data
// object, yielding the object's value.
func dataObjectValue(data []byte) ([]byte, bool) {
	if len(data) < 2 || data[0] != tagGetDataObject {
		return nil, false
	}

	length := int(data[1])
	offset := 2
	if length&0x80 != 0 {
		// Long-form BER length.
		n := length & 0x7F
		if n == 0 || n > 3 || len(data) < 2+n {
			return nil, false
		}
		length = 0
		for i := 0; i < n; i++ {
			length = length<<8 | int(data[2+i])
		}
		offset = 2 + n
	}
	if len(data) < offset+length {
		return nil, false
	}
	return data[offset : offset+length], true
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
