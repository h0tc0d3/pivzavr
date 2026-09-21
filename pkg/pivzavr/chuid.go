package pivzavr

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/h0tc0d3/pivzavr/pkg/i18n"
)

// Tags of a Card Holder Unique Identifier (NIST SP 800-73-4).
const (
	// tagFascN holds the Federal Agency Smart Credential Number.
	tagFascN = 0x30
	// tagGUID holds the globally unique identifier of the card.
	tagGUID = 0x34
	// tagExpiration holds the date the card expires, as YYYYMMDD.
	tagExpiration = 0x35
	// tagAsymmetricSignature holds the signature of the issuer over the
	// card holder unique identifier; it is empty for a card that is not
	// signed by an issuer.
	tagAsymmetricSignature = 0x3E
	// tagLRC holds the longitudinal redundancy check of the data object.
	tagLRC = 0xFE
)

// Tags of a Card Capability Container (NIST SP 800-73-4).
const (
	tagCCCCardIdentifier      = 0xF0
	tagCCCVersion             = 0xF1
	tagCCCGrammar             = 0xF2
	tagCCCCardURL             = 0xF3
	tagCCCPKCS15              = 0xF4
	tagCCCRegisteredDataModel = 0xF5
	tagCCCAccessControl       = 0xF6
	tagCCCFingerprints        = 0xF7
	tagCCCSecurityObject      = 0xFA
	tagCCCFacialImage         = 0xFB
	tagCCCSignatureImage      = 0xFC
	tagCCCPrintedInformation  = 0xFD
)

const (
	// chuidGUIDLength is the length of the globally unique identifier of a
	// card, and cccRandomLength the length of the random part of the card
	// identifier of a Card Capability Container.
	chuidGUIDLength = 16
	cccRandomLength = 14

	// chuidExpirationYears is the number of years a generated Card Holder
	// Unique Identifier stays valid.
	chuidExpirationYears = 10
)

// The bit patterns that separate the fields of a FASC-N: the start sentinel,
// the field separator and the end sentinel.
const (
	fascNStartSentinel  = "11010"
	fascNFieldSeparator = "10110"
	fascNEndSentinel    = "11111"

	// fascNFieldCount is the number of fields a FASC-N consists of, and
	// fascNBits is the length of a FASC-N encoding: five bits per digit,
	// the sentinels and a five-bit longitudinal redundancy check.
	fascNFieldCount = 9
	fascNBits       = 200
)

// fascNFieldDigits is the number of decimal digits of every FASC-N field, in
// the order the fields are encoded.
var fascNFieldDigits = [fascNFieldCount]int{4, 4, 6, 1, 1, 10, 1, 4, 1}

// fascN is a Federal Agency Smart Credential Number: the nine numeric fields
// that identify the holder of a card, in the encoding defined by the Smart
// Card Alliance.
type fascN struct {
	agencyCode                      int
	systemCode                      int
	credentialNumber                int
	credentialSeries                int
	individualCredentialIssue       int
	personIdentifier                int
	organizationalCategory          int
	organizationalIdentifier        int
	organizationAssociationCategory int
}

// nonFederalFascN is the FASC-N of a card that is not issued by a federal
// agency: the agency and system codes are the reserved non-federal values, and
// the person identifier is empty.
var nonFederalFascN = fascN{
	agencyCode:                      9999,
	systemCode:                      9999,
	credentialNumber:                999999,
	individualCredentialIssue:       1,
	organizationalCategory:          3,
	organizationAssociationCategory: 1,
}

// fields returns the field values of the FASC-N in the order they are encoded.
func (f fascN) fields() [fascNFieldCount]int {
	return [fascNFieldCount]int{
		f.agencyCode,
		f.systemCode,
		f.credentialNumber,
		f.credentialSeries,
		f.individualCredentialIssue,
		f.personIdentifier,
		f.organizationalCategory,
		f.organizationalIdentifier,
		f.organizationAssociationCategory,
	}
}

// bytes returns the 25-byte FASC-N encoding of the fields: every digit is
// encoded as a nibble with an odd parity bit, the fields are separated by the
// start, field and end sentinels, and the encoding is closed by a longitudinal
// redundancy check over the sentinels and the digits.
func (f fascN) bytes() []byte {
	fields := f.fields()

	var encoded strings.Builder
	encoded.WriteString(fascNStartSentinel)
	for i, value := range fields {
		// The first five fields are followed by a field separator; the last
		// four are the person identifier and the organization codes.
		if i > 0 && i <= 5 {
			encoded.WriteString(fascNFieldSeparator)
		}
		encoded.WriteString(bcdGroup(value, fascNFieldDigits[i]))
	}
	encoded.WriteString(fascNEndSentinel)

	// The longitudinal redundancy check is the exclusive or of the five-bit
	// groups the encoding consists of, and it is appended to it.
	bits := encoded.String()
	check := 0
	for i := 0; i+5 <= len(bits); i += 5 {
		check ^= binaryValue(bits[i : i+5])
	}

	value, ok := new(big.Int).SetString(bits+fmt.Sprintf("%05b", check), 2)
	if !ok {
		return nil
	}
	return value.FillBytes(make([]byte, fascNBits/8))
}

// bcdGroup returns the BCD encoding of a FASC-N field: every decimal digit is
// encoded as its four bits, least significant bit first, followed by an odd
// parity bit. The digits are encoded from the least significant one, so the
// most significant digit ends up first.
func bcdGroup(value, digits int) string {
	groups := make([]string, 0, digits)
	for i := 0; i < digits; i++ {
		// The bits of the digit are encoded least significant bit first.
		bits := reverse(fmt.Sprintf("%04b", value%10))
		// The parity bit makes the number of set bits of the group odd.
		parity := (strings.Count(bits, "1") + 1) % 2
		groups = append(groups, bits+strconv.Itoa(parity))
		value /= 10
	}
	slices.Reverse(groups)
	return strings.Join(groups, "")
}

// reverse returns s with its characters in the opposite order.
func reverse(s string) string {
	runes := []rune(s)
	slices.Reverse(runes)
	return string(runes)
}

// binaryValue returns the value of a string of binary digits.
func binaryValue(bits string) int {
	value := 0
	for _, bit := range bits {
		value = value<<1 | int(bit-'0')
	}
	return value
}

// chuidExpirationDate returns the date the generated Card Holder Unique
// Identifiers expire: ten years from today, in the YYYYMMDD form the expiration
// field of a CHUID uses.
func chuidExpirationDate() string {
	return time.Now().AddDate(chuidExpirationYears, 0, 0).Format("20060102")
}

// chuidValue returns the encoding of a Card Holder Unique Identifier for the
// FASC-N and the globally unique identifier: the two values, the expiration
// date and the empty asymmetric signature, closed by the longitudinal
// redundancy check.
func chuidValue(fascN fascN, guid []byte) []byte {
	value := encodeTLV(tagFascN, fascN.bytes())
	value = append(value, encodeTLV(tagGUID, guid)...)
	value = append(value, encodeTLV(tagExpiration, []byte(chuidExpirationDate()))...)
	value = append(value, encodeTLV(tagAsymmetricSignature, nil)...)
	return append(value, encodeTLV(tagLRC, nil)...)
}

// generateCHUID returns a Card Holder Unique Identifier for a card that is not
// issued by a federal agency, with a random identifier.
func generateCHUID() ([]byte, error) {
	guid := make([]byte, chuidGUIDLength)
	if _, err := io.ReadFull(rand.Reader, guid); err != nil {
		return nil, i18n.Wrap(err, "Generate card identifier")
	}
	return chuidValue(nonFederalFascN, guid), nil
}

// cccValue returns the encoding of a Card Capability Container whose card
// identifier ends with random: the identifier, the version and capability data
// of the PIV application, and the empty fields the container reserves for the
// other applications of the card.
func cccValue(random []byte) []byte {
	cardIdentifier := append([]byte{0xA0, 0x00, 0x00, 0x01, 0x16, 0xFF, 0x02}, random...)

	value := encodeTLV(tagCCCCardIdentifier, cardIdentifier)
	value = append(value, encodeTLV(tagCCCVersion, []byte{0x21})...)
	value = append(value, encodeTLV(tagCCCGrammar, []byte{0x21})...)
	value = append(value, encodeTLV(tagCCCCardURL, nil)...)
	value = append(value, encodeTLV(tagCCCPKCS15, []byte{0x00})...)
	value = append(value, encodeTLV(tagCCCRegisteredDataModel, []byte{0x10})...)
	value = append(value, encodeTLV(tagCCCAccessControl, nil)...)
	value = append(value, encodeTLV(tagCCCFingerprints, nil)...)
	value = append(value, encodeTLV(tagCCCSecurityObject, nil)...)
	value = append(value, encodeTLV(tagCCCFacialImage, nil)...)
	value = append(value, encodeTLV(tagCCCSignatureImage, nil)...)
	value = append(value, encodeTLV(tagCCCPrintedInformation, nil)...)
	return append(value, encodeTLV(tagLRC, nil)...)
}

// generateCCC returns a Card Capability Container for a PIV card, with a random
// card identifier.
func generateCCC() ([]byte, error) {
	random := make([]byte, cccRandomLength)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return nil, i18n.Wrap(err, "Generate card identifier")
	}
	return cccValue(random), nil
}
