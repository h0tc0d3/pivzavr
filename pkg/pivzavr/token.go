package pivzavr

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"

	"github.com/h0tc0d3/pivzavr/pkg/i18n"
)

// This file holds the parts of the package that do not need a PKCS#11 module:
// the mapping of a PIV slot to its CKA_ID and the encodings a PKCS#11 module
// expects from a signature. It is compiled into every build.

const (
	// DefaultPIN is the PIV default user PIN.
	DefaultPIN = "123456"
	// DefaultPUK is the PIV default PIN unlocking key. It is used to
	// unlock (recover) the user PIN.
	DefaultPUK = "12345678"
	// DefaultManagementKey is the PIV default card management key in
	// hexadecimal. It authenticates writes to the PIV slots and, on a PIV
	// card, it is the PKCS#11 security officer (SO) PIN. A reset restores it.
	DefaultManagementKey = "010203040506070801020304050607080102030405060708"
)

// id returns the CKA_ID value associated with a slot.
//
// The YubiKey PKCS#11 module (ykcs11) assigns sequential CKA_ID values to the
// PIV keys in key-reference order: the four standard keys use 0x01-0x04, the
// retired key-management slots (82-95) use 0x05-0x18 (key reference 0x82 maps
// to 0x05, 0x83 to 0x06, and so on), and the attestation slot (f9) uses 0x19.
// The card-management slot (9b) is not exposed as a PKCS#11 object.
//
// Note that OpenSC's PIV emulation uses a different CKA_ID scheme for the
// retired slots (it interprets "10"-"24" as hexadecimal), so retired slots are
// only addressable when the YubiKey PKCS#11 module is in use.
//
// The token's certificate, public-key and private-key objects all share the
// same CKA_ID so they can be correlated.
func (s Slot) id() ([]byte, error) {
	switch s {
	case SlotAuthentication:
		return []byte{0x01}, nil
	case SlotSignature:
		return []byte{0x02}, nil
	case SlotKeyManagement:
		return []byte{0x03}, nil
	case SlotCardAuthentication:
		return []byte{0x04}, nil
	case SlotAttestation:
		return []byte{0x19}, nil
	case SlotCardManagement:
		return nil, i18n.New("Card management slot (9b) is not exposed as a PKCS#11 object.")
	case SlotRetiredKeyManagement1:
		return []byte{0x05}, nil
	case SlotRetiredKeyManagement2:
		return []byte{0x06}, nil
	case SlotRetiredKeyManagement3:
		return []byte{0x07}, nil
	case SlotRetiredKeyManagement4:
		return []byte{0x08}, nil
	case SlotRetiredKeyManagement5:
		return []byte{0x09}, nil
	case SlotRetiredKeyManagement6:
		return []byte{0x0a}, nil
	case SlotRetiredKeyManagement7:
		return []byte{0x0b}, nil
	case SlotRetiredKeyManagement8:
		return []byte{0x0c}, nil
	case SlotRetiredKeyManagement9:
		return []byte{0x0d}, nil
	case SlotRetiredKeyManagement10:
		return []byte{0x0e}, nil
	case SlotRetiredKeyManagement11:
		return []byte{0x0f}, nil
	case SlotRetiredKeyManagement12:
		return []byte{0x10}, nil
	case SlotRetiredKeyManagement13:
		return []byte{0x11}, nil
	case SlotRetiredKeyManagement14:
		return []byte{0x12}, nil
	case SlotRetiredKeyManagement15:
		return []byte{0x13}, nil
	case SlotRetiredKeyManagement16:
		return []byte{0x14}, nil
	case SlotRetiredKeyManagement17:
		return []byte{0x15}, nil
	case SlotRetiredKeyManagement18:
		return []byte{0x16}, nil
	case SlotRetiredKeyManagement19:
		return []byte{0x17}, nil
	case SlotRetiredKeyManagement20:
		return []byte{0x18}, nil
	default:
		return nil, i18n.Errorf("Invalid slot %q.", s)
	}
}

// labelMatches reports whether label equals any of candidates, ignoring case
// and surrounding whitespace.
func labelMatches(label string, candidates []string) bool {
	for _, candidate := range candidates {
		if strings.EqualFold(label, candidate) {
			return true
		}
	}
	return false
}

// encodeECDSASignature converts a fixed-width r||s ECDSA signature into the
// ASN.1 DER-encoded ECDSA-Sig-Value that crypto.Signer is expected to return.
//
// The PKCS#11 specification describes CKM_ECDSA as returning the raw, padded
// r||s concatenation, but several modules (notably the YubiKey PKCS#11 module)
// return the signature already DER encoded. Re-encoding such a signature would
// wrap each half of the SEQUENCE inside a fresh INTEGER, producing an invalid
// signature that no verifier accepts. Detect that case and pass the signature
// through unchanged.
func encodeECDSASignature(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, i18n.New("Invalid ECDSA signature length.")
	}

	type ecdsaSignature struct {
		R, S *big.Int
	}

	var sig ecdsaSignature
	if rest, err := asn1.Unmarshal(raw, &sig); err == nil && len(rest) == 0 {
		return raw, nil
	}

	if len(raw)%2 != 0 {
		return nil, i18n.New("Invalid ECDSA signature length.")
	}
	half := len(raw) / 2
	sig.R = new(big.Int).SetBytes(raw[:half])
	sig.S = new(big.Int).SetBytes(raw[half:])
	return asn1.Marshal(sig)
}

// pkcs1DigestInfo builds the DigestInfo structure consumed by CKM_RSA_PKCS.
func pkcs1DigestInfo(hash crypto.Hash, digest []byte) ([]byte, error) {
	var oid asn1.ObjectIdentifier
	switch hash {
	case crypto.SHA1:
		oid = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	case crypto.SHA224:
		oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	case crypto.SHA256:
		oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	case crypto.SHA384:
		oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	case crypto.SHA512:
		oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	default:
		return nil, i18n.Errorf("Unsupported hash algorithm %v.", hash)
	}

	info := struct {
		Algorithm pkix.AlgorithmIdentifier
		Digest    []byte
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.NullRawValue,
		},
		Digest: digest,
	}
	return asn1.Marshal(info)
}

// pkcs1v15Pad pads info with the PKCS #1 v1.5 signature padding that a PIV card
// expects: the type 1 padding block 0x00, 0x01, 0xFF ... 0xFF, 0x00 followed by
// info, so that the result is keySize bytes long.
//
// A PIV card signs the raw message representative of an RSA key, so the padding
// that CKM_RSA_PKCS performs for a PKCS#11 module has to be done before the
// DigestInfo is sent to the card.
func pkcs1v15Pad(info []byte, keySize int) ([]byte, error) {
	// The padding block needs at least eight 0xFF bytes between the 0x00 0x01
	// prefix and the 0x00 separator.
	if len(info)+11 > keySize {
		return nil, i18n.Errorf(
			"A DigestInfo of %d bytes does not fit into a %d byte RSA signature.", len(info), keySize)
	}

	padded := make([]byte, keySize)
	padded[0] = 0x00
	padded[1] = 0x01
	separator := keySize - len(info) - 1
	for i := 2; i < separator; i++ {
		padded[i] = 0xFF
	}
	// padded[separator] stays 0x00, the separator of the padding block.
	copy(padded[separator+1:], info)
	return padded, nil
}

// formatFirmwareVersion renders the firmware version reported by a PKCS#11
// module in its CK_VERSION form.
//
// ykcs11 packs the YubiKey firmware version major.minor.patch into CK_VERSION as
// major = major and minor = minor*10 + patch, so firmware 5.7.4 is reported as
// major 5, minor 74. For that module the minor byte is split back into its two
// components; other modules report the version components directly.
func formatFirmwareVersion(major, minor byte, ykcs11 bool) string {
	if ykcs11 {
		return fmt.Sprintf("%d.%d.%d", major, minor/10, minor%10)
	}
	return fmt.Sprintf("%d.%d", major, minor)
}
