package pivzavr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSlotID(t *testing.T) {
	testCases := []struct {
		name    string
		slot    Slot
		want    []byte
		wantErr bool
	}{
		{"authentication", SlotAuthentication, []byte{0x01}, false},
		{"card management", SlotCardManagement, nil, true},
		{"signature", SlotSignature, []byte{0x02}, false},
		{"key management", SlotKeyManagement, []byte{0x03}, false},
		{"card authentication", SlotCardAuthentication, []byte{0x04}, false},
		{"attestation", SlotAttestation, []byte{0x19}, false},
		{"retired 1", SlotRetiredKeyManagement1, []byte{0x05}, false},
		{"retired 2", SlotRetiredKeyManagement2, []byte{0x06}, false},
		{"retired 3", SlotRetiredKeyManagement3, []byte{0x07}, false},
		{"retired 4", SlotRetiredKeyManagement4, []byte{0x08}, false},
		{"retired 5", SlotRetiredKeyManagement5, []byte{0x09}, false},
		{"retired 6", SlotRetiredKeyManagement6, []byte{0x0a}, false},
		{"retired 7", SlotRetiredKeyManagement7, []byte{0x0b}, false},
		{"retired 8", SlotRetiredKeyManagement8, []byte{0x0c}, false},
		{"retired 9", SlotRetiredKeyManagement9, []byte{0x0d}, false},
		{"retired 10", SlotRetiredKeyManagement10, []byte{0x0e}, false},
		{"retired 11", SlotRetiredKeyManagement11, []byte{0x0f}, false},
		{"retired 12", SlotRetiredKeyManagement12, []byte{0x10}, false},
		{"retired 13", SlotRetiredKeyManagement13, []byte{0x11}, false},
		{"retired 14", SlotRetiredKeyManagement14, []byte{0x12}, false},
		{"retired 15", SlotRetiredKeyManagement15, []byte{0x13}, false},
		{"retired 16", SlotRetiredKeyManagement16, []byte{0x14}, false},
		{"retired 17", SlotRetiredKeyManagement17, []byte{0x15}, false},
		{"retired 18", SlotRetiredKeyManagement18, []byte{0x16}, false},
		{"retired 19", SlotRetiredKeyManagement19, []byte{0x17}, false},
		{"retired 20", SlotRetiredKeyManagement20, []byte{0x18}, false},
		{"invalid", Slot("zz"), nil, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := tc.slot.id()
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, id)
		})
	}
}

func TestSlots(t *testing.T) {
	tok, err := testToken()
	if err != nil {
		t.Fatal(err)
	}

	slots, err := tok.Slots()
	assert.NoError(t, err)
	assert.Empty(t, slots)

	if _, err := generateKeyAndCertificate(tok, SlotSignature); err != nil {
		t.Fatal(err)
	}
	if _, err := generateKeyAndCertificate(tok, SlotRetiredKeyManagement1); err != nil {
		t.Fatal(err)
	}

	slots, err = tok.Slots()
	assert.NoError(t, err)
	assert.Equal(t, []Slot{SlotSignature, SlotRetiredKeyManagement1}, slots)
}

func TestInfo(t *testing.T) {
	tok, err := testToken()
	if err != nil {
		t.Fatal(err)
	}

	cert, err := generateKeyAndCertificate(tok, SlotSignature)
	if err != nil {
		t.Fatal(err)
	}

	tok.chuid = "CHUID"
	tok.ccc = "CCC"
	tok.pinRetries = 3
	tok.pukRetries = 2

	info, err := tok.Info()
	assert.NoError(t, err)
	assert.Equal(t, "pivzavr test", info.Name)
	assert.Equal(t, "1.0", info.FirmwareVersion)
	assert.Equal(t, "00000000", info.SerialNumber)
	assert.Equal(t, "CHUID", info.CHUID)
	assert.Equal(t, "CCC", info.CCC)
	assert.Equal(t, 3, info.PinRetries)
	assert.Equal(t, 2, info.PukRetries)
	assert.Equal(t, []SlotInfo{{Slot: SlotSignature, Certificate: cert}}, info.Slots)
}

func TestLabelMatches(t *testing.T) {
	labels := []string{"Card Holder Unique Identifier", "CHUID"}

	assert.True(t, labelMatches("Card Holder Unique Identifier", labels))
	assert.True(t, labelMatches("chuid", labels))
	assert.False(t, labelMatches("Card Capability Container", labels))
}

func TestFormatFirmwareVersion(t *testing.T) {
	testCases := []struct {
		name   string
		major  byte
		minor  byte
		ykcs11 bool
		want   string
	}{
		{name: "ykcs11 5.7.4", major: 5, minor: 74, ykcs11: true, want: "5.7.4"},
		{name: "ykcs11 5.4.3", major: 5, minor: 43, ykcs11: true, want: "5.4.3"},
		{name: "ykcs11 5.2.0", major: 5, minor: 20, ykcs11: true, want: "5.2.0"},
		{name: "other module", major: 5, minor: 74, ykcs11: false, want: "5.74"},
		{name: "other module plain", major: 1, minor: 2, ykcs11: false, want: "1.2"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, formatFirmwareVersion(tc.major, tc.minor, tc.ykcs11))
		})
	}
}
