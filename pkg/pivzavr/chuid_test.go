package pivzavr

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The reference data objects are the encodings that the generators have to
// produce: the FASC-N of a card that is not issued by a federal agency, a Card
// Holder Unique Identifier and a Card Capability Container whose random parts
// are zero.
const (
	referenceFascN = "d4e739da739ced39ce739d836858210842108421c84210c3eb"
	// referenceCHUIDPrefix is a reference CHUID up to the expiration date,
	// which referenceCHUID appends.
	referenceCHUIDPrefix = "3019d4e739da739ced39ce739d836858210842108421c84210c3eb" +
		"3410000102030405060708090a0b0c0d0e0f"
	// referenceCHUIDSuffix is the reference CHUID from the empty asymmetric
	// signature on, which referenceCHUID appends.
	referenceCHUIDSuffix = "3e00" + "fe00"
	referenceCCC         = "f015a000000116ff020000000000000000000000000000" +
		"f10121f20121f300f40100f50110f600f700fa00fb00fc00fd00fe00"
)

// referenceCHUID is the Card Holder Unique Identifier the generator has to
// produce: the reference FASC-N and identifier, the expiration date the
// generator computes and the empty asymmetric signature.
func referenceCHUID() string {
	date := hex.EncodeToString([]byte(chuidExpirationDate()))
	return referenceCHUIDPrefix + "3508" + date + referenceCHUIDSuffix
}

func TestFascNBytes(t *testing.T) {
	encoded := nonFederalFascN.bytes()
	assert.Len(t, encoded, 25)
	assert.Equal(t, referenceFascN, hex.EncodeToString(encoded))

	// The fields of the encoding can be read back from it: the start sentinel
	// is followed by the agency code.
	assert.Equal(t, binaryValue(fascNStartSentinel), int(encoded[0])>>3)
}

func TestBcdGroup(t *testing.T) {
	// A digit is encoded as its four bits, least significant bit first, and an
	// odd parity bit.
	assert.Equal(t, "00001", bcdGroup(0, 1))
	assert.Equal(t, "10000", bcdGroup(1, 1))
	assert.Equal(t, "10101", bcdGroup(5, 1))
	assert.Equal(t, "10011", bcdGroup(9, 1))

	// The digits are encoded from the least significant one, so the most
	// significant digit ends up first.
	assert.Equal(t, "10011100111001110011", bcdGroup(9999, 4))
	assert.Equal(t, "10000"+"00001"+"10000"+"00001", bcdGroup(1010, 4))
}

func TestBinaryValue(t *testing.T) {
	assert.Equal(t, 0, binaryValue("00000"))
	assert.Equal(t, 26, binaryValue("11010"))
	assert.Equal(t, 31, binaryValue("11111"))
}

func TestReverse(t *testing.T) {
	assert.Equal(t, "cba", reverse("abc"))
	assert.Equal(t, "", reverse(""))
}

func TestChuidExpirationDate(t *testing.T) {
	expiration, err := time.Parse("20060102", chuidExpirationDate())
	require.NoError(t, err)
	assert.Equal(t, time.Now().AddDate(chuidExpirationYears, 0, 0).Format("20060102"), expiration.Format("20060102"))
}

func TestChuidValue(t *testing.T) {
	guid := mustHex(t, "000102030405060708090A0B0C0D0E0F")
	assert.Equal(t, referenceCHUID(), hex.EncodeToString(chuidValue(nonFederalFascN, guid)))
}

func TestGenerateCHUID(t *testing.T) {
	first, err := generateCHUID()
	require.NoError(t, err)
	second, err := generateCHUID()
	require.NoError(t, err)

	// The data object has the size of the reference object, and the FASC-N and
	// the expiration date are the same in both.
	require.Len(t, first, len(referenceCHUID())/2)
	assert.Equal(t, hex.EncodeToString(first[:27]), hex.EncodeToString(second[:27]))
	assert.Equal(t, hex.EncodeToString(first[45:]), hex.EncodeToString(second[45:]))
	assert.Equal(t, referenceFascN, hex.EncodeToString(first[2:27]))
	assert.Equal(t, "3508"+hex.EncodeToString([]byte(chuidExpirationDate()))+"3e00fe00", hex.EncodeToString(first[45:]))

	// The card identifier is random.
	assert.NotEqual(t, hex.EncodeToString(first), hex.EncodeToString(second))
	assert.NotEqual(t, hex.EncodeToString(first[27:45]), hex.EncodeToString(second[27:45]))
}

func TestCccValue(t *testing.T) {
	assert.Equal(t, referenceCCC, hex.EncodeToString(cccValue(make([]byte, cccRandomLength))))
}

func TestGenerateCCC(t *testing.T) {
	first, err := generateCCC()
	require.NoError(t, err)
	second, err := generateCCC()
	require.NoError(t, err)

	require.Len(t, first, len(referenceCCC)/2)
	assert.Equal(t, "f015a000000116ff02", hex.EncodeToString(first[:9]))
	assert.Equal(t, hex.EncodeToString(first[23:]), hex.EncodeToString(second[23:]))
	assert.NotEqual(t, hex.EncodeToString(first), hex.EncodeToString(second))
}
