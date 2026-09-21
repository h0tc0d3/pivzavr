package pivzavr

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseManagementKeyAlgorithm(t *testing.T) {
	testCases := []struct {
		name string
		want ManagementKeyAlgorithm
	}{
		{name: "AES128", want: ManagementKeyAES128},
		{name: "aes192", want: ManagementKeyAES192},
		{name: " AES256 ", want: ManagementKeyAES256},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseManagementKeyAlgorithm(tc.name)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	// Triple-DES is not set as a new key any more: it is only recognised as
	// the algorithm of a key that a smart card still holds.
	for _, name := range []string{"TDES", "tdes", "3DES", "AES64"} {
		_, err := ParseManagementKeyAlgorithm(name)
		assert.ErrorContains(t, err, "Unknown management key algorithm", name)
	}
}

func TestManagementKeyAlgorithmProperties(t *testing.T) {
	testCases := []struct {
		algorithm ManagementKeyAlgorithm
		name      string
		keyLen    int
	}{
		{algorithm: ManagementKeyTDES, name: "TDES", keyLen: 24},
		{algorithm: ManagementKeyAES128, name: "AES128", keyLen: 16},
		{algorithm: ManagementKeyAES192, name: "AES192", keyLen: 24},
		{algorithm: ManagementKeyAES256, name: "AES256", keyLen: 32},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.name, tc.algorithm.String())
			assert.Equal(t, tc.keyLen, tc.algorithm.keyLen())
		})
	}

	assert.Equal(t, 8, ManagementKeyTDES.challengeLen())
	assert.Equal(t, 16, ManagementKeyAES256.challengeLen())
	assert.Equal(t, "0x42", ManagementKeyAlgorithm(0x42).String())
}

func TestManagementKeyCipher(t *testing.T) {
	block, err := managementKeyCipher(fakeManagementKey, ManagementKeyTDES)
	require.NoError(t, err)
	assert.Equal(t, des.BlockSize, block.BlockSize())

	block, err = managementKeyCipher(bytes.Repeat([]byte{0x01}, 32), ManagementKeyAES256)
	require.NoError(t, err)
	assert.Equal(t, aes.BlockSize, block.BlockSize())

	_, err = managementKeyCipher(fakeManagementKey, ManagementKeyAES256)
	assert.ErrorContains(t, err, "AES256 management key is 32 bytes long")
}

// managementKeyAPDU returns the APDU of the AUTHENTICATE command step that
// carries value in its dynamic authentication template.
func managementKeyAPDU(algorithm ManagementKeyAlgorithm, value []byte) []byte {
	return pivAPDU(insAuthenticate, byte(algorithm), slotCardManagement, encodeTLV(tagDynamicAuth, value))
}

// encryptBlock encrypts one block with the management key of the algorithm.
func encryptBlock(t *testing.T, key []byte, algorithm ManagementKeyAlgorithm, value []byte) []byte {
	t.Helper()
	block, err := managementKeyCipher(key, algorithm)
	require.NoError(t, err)
	out := make([]byte, block.BlockSize())
	block.Encrypt(out, value)
	return out
}

// witnessResponse returns the response of a smart card to the first step of the
// management key exchange: the witness it encrypted with the management key.
func witnessResponse(t *testing.T, key []byte, algorithm ManagementKeyAlgorithm, witness []byte) []byte {
	t.Helper()
	value := encodeTLV(tagAuthWitness, encryptBlock(t, key, algorithm, witness))
	return append(encodeTLV(tagDynamicAuth, value), 0x90, 0x00)
}

func TestCardAuthenticate(t *testing.T) {
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28}
	witness := []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
	challenge := []byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48}

	card := &fakeCard{responses: [][]byte{
		witnessResponse(t, key, ManagementKeyTDES, witness),
		append(encodeTLV(tagDynamicAuth, encodeTLV(tagAuthResponse, encryptBlock(t, key, ManagementKeyTDES, challenge))), 0x90, 0x00),
	}}

	require.NoError(t, cardAuthenticateWith(card, key, ManagementKeyTDES, bytes.NewReader(challenge)))

	// The card is asked for a witness, and the witness is sent back in plain
	// text together with a challenge.
	expected := managementKeyAPDU(ManagementKeyTDES, encodeTLV(tagAuthWitness, nil))
	second := managementKeyAPDU(ManagementKeyTDES, append(
		encodeTLV(tagAuthWitness, witness),
		encodeTLV(tagAuthChallenge, challenge)...,
	))
	assert.Equal(t, [][]byte{expected, second}, card.apdus)
}

func TestCardAuthenticate_aes(t *testing.T) {
	key := bytes.Repeat([]byte{0xA5}, 32)
	witness := bytes.Repeat([]byte{0x5A}, aes.BlockSize)
	challenge := bytes.Repeat([]byte{0xC3}, aes.BlockSize)

	card := &fakeCard{responses: [][]byte{
		witnessResponse(t, key, ManagementKeyAES256, witness),
		append(encodeTLV(tagDynamicAuth, encodeTLV(tagAuthResponse, encryptBlock(t, key, ManagementKeyAES256, challenge))), 0x90, 0x00),
	}}

	require.NoError(t, cardAuthenticateWith(card, key, ManagementKeyAES256, bytes.NewReader(challenge)))
	assert.Equal(t, byte(ManagementKeyAES256), card.apdus[0][2])
	assert.Len(t, card.apdus[1], 5+2+2+aes.BlockSize+2+aes.BlockSize)
}

func TestCardAuthenticate_wrongKey(t *testing.T) {
	key := fakeManagementKey
	witness := []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
	challenge := []byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48}

	// The card encrypts the challenge with the key it holds, which is not the
	// key that was used.
	card := &fakeCard{responses: [][]byte{
		witnessResponse(t, key, ManagementKeyTDES, witness),
		append(encodeTLV(tagDynamicAuth, encodeTLV(tagAuthResponse, bytes.Repeat([]byte{0x00}, 8))), 0x90, 0x00),
	}}

	assert.Equal(t, errSecretIncorrect, cardAuthenticateWith(card, key, ManagementKeyTDES, bytes.NewReader(challenge)))
}

func TestCardAuthenticate_failures(t *testing.T) {
	key := fakeManagementKey
	challenge := []byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48}

	t.Run("reports a transmit error", func(t *testing.T) {
		card := &fakeCard{err: errors.New("no card")}

		assert.ErrorContains(t, cardAuthenticateWith(card, key, ManagementKeyTDES, bytes.NewReader(challenge)), "no card")
	})

	t.Run("reports a rejected first step", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x6A, 0x80}}}

		assert.ErrorContains(t, cardAuthenticateWith(card, key, ManagementKeyTDES, bytes.NewReader(challenge)),
			"Authenticating with a TDES management key failed with status 0x6A80")
	})

	t.Run("reports a response without a witness", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x7C, 0x00, 0x90, 0x00}}}

		assert.ErrorContains(t, cardAuthenticateWith(card, key, ManagementKeyTDES, bytes.NewReader(challenge)),
			"Unexpected AUTHENTICATE response")
	})

	t.Run("reports a witness of the wrong length", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{
			append(encodeTLV(tagDynamicAuth, encodeTLV(tagAuthWitness, []byte{0x01})), 0x90, 0x00),
		}}

		assert.ErrorContains(t, cardAuthenticateWith(card, key, ManagementKeyTDES, bytes.NewReader(challenge)),
			"Unexpected AUTHENTICATE response")
	})

	t.Run("reports a rejected second step", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{
			witnessResponse(t, key, ManagementKeyTDES, bytes.Repeat([]byte{0x01}, 8)),
			{0x69, 0x82},
		}}

		assert.Equal(t, errSecretIncorrect, cardAuthenticateWith(card, key, ManagementKeyTDES, bytes.NewReader(challenge)))
	})

	t.Run("reports a response without an answer", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{
			witnessResponse(t, key, ManagementKeyTDES, bytes.Repeat([]byte{0x01}, 8)),
			{0x90, 0x00},
		}}

		assert.ErrorContains(t, cardAuthenticateWith(card, key, ManagementKeyTDES, bytes.NewReader(challenge)),
			"Unexpected AUTHENTICATE response")
	})
}

func TestPinField(t *testing.T) {
	// A secret that is shorter than the field is filled up with 0xFF.
	assert.Equal(t, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, pinField(""))
	assert.Equal(t, []byte("123456\xFF\xFF"), pinField(DefaultPIN))
	assert.Equal(t, []byte(DefaultPUK), pinField(DefaultPUK))
	assert.Equal(t, pinField(""), wrongPINField())
}

func TestReferenceName(t *testing.T) {
	assert.Equal(t, "PIN", referenceName(pinRef))
	assert.Equal(t, "PUK", referenceName(pukRef))
}

func TestCardChangeReference(t *testing.T) {
	t.Run("reports a changed reference", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x90, 0x00}}}

		require.NoError(t, cardChangeReference(card, pinRef, DefaultPIN, "654321", errPINBlocked))
		assert.Equal(t, [][]byte{pivAPDU(insChangeReference, 0x00, pinRef, append(pinField(DefaultPIN), pinField("654321")...))}, card.apdus)
	})

	t.Run("reports a rejected current secret", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x63, 0xC2}}}

		assert.Equal(t, errSecretIncorrect, cardChangeReference(card, pinRef, "654321", "87654321", errPINBlocked))
	})

	t.Run("reports a blocked reference", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x63, 0xC0}}}
		assert.Equal(t, errPINBlocked, cardChangeReference(card, pinRef, "654321", "87654321", errPINBlocked))

		card = &fakeCard{responses: [][]byte{{0x69, 0x83}}}
		assert.Equal(t, errPINBlocked, cardChangeReference(card, pinRef, "654321", "87654321", errPINBlocked))
	})

	t.Run("reports a card that does not change the PUK", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x6D, 0x00}}}

		err := cardChangeReference(card, pukRef, DefaultPUK, "87654321", errPUKBlocked)
		assert.ErrorContains(t, err, "does not support changing its PUK")
	})

	t.Run("reports an unexpected status", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x6A, 0x80}}}

		assert.ErrorContains(t, cardChangeReference(card, pinRef, DefaultPIN, "87654321", errPINBlocked),
			"CHANGE REFERENCE failed with status 0x6A80")
	})

	t.Run("reports a transmit error", func(t *testing.T) {
		card := &fakeCard{err: errors.New("no card")}

		assert.ErrorContains(t, cardChangeReference(card, pinRef, DefaultPIN, "87654321", errPINBlocked), "no card")
	})
}

func TestCardVerifyReference(t *testing.T) {
	t.Run("reports a verified reference", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x90, 0x00}}}

		require.NoError(t, cardVerifyReference(card, pinRef, DefaultPIN, errPINBlocked))
		assert.Equal(t, [][]byte{pivAPDU(insVerify, 0x00, pinRef, pinField(DefaultPIN))}, card.apdus)
	})

	t.Run("reports a rejected secret", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x63, 0xC2}}}

		assert.Equal(t, errSecretIncorrect, cardVerifyReference(card, pinRef, "654321", errPINBlocked))
	})

	t.Run("reports a blocked reference", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x63, 0xC0}}}

		assert.Equal(t, errPINBlocked, cardVerifyReference(card, pinRef, "654321", errPINBlocked))
	})

	t.Run("reports an unexpected status", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x6A, 0x80}}}

		assert.ErrorContains(t, cardVerifyReference(card, pinRef, DefaultPIN, errPINBlocked),
			"VERIFY failed with status 0x6A80")
	})

	t.Run("reports a transmit error", func(t *testing.T) {
		card := &fakeCard{err: errors.New("no card")}

		assert.ErrorContains(t, cardVerifyReference(card, pinRef, DefaultPIN, errPINBlocked), "no card")
	})
}

func TestCardSetManagementKey(t *testing.T) {
	t.Run("reports a set key", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x90, 0x00}}}
		key := bytes.Repeat([]byte{0xA5}, 32)

		require.NoError(t, cardSetManagementKey(card, ManagementKeyAES256, key))

		// The command carries the algorithm and the key in the card
		// management slot.
		expected := pivAPDU(insSetManagementKey, 0xFF, 0xFF, append([]byte{0x0C}, encodeTLV(slotCardManagement, key)...))
		assert.Equal(t, [][]byte{expected}, card.apdus)
	})

	t.Run("rejects a key of the wrong length", func(t *testing.T) {
		card := &fakeCard{}

		assert.ErrorContains(t, cardSetManagementKey(card, ManagementKeyAES256, fakeManagementKey), "AES256 management key is 32 bytes long")
		assert.Empty(t, card.apdus)
	})

	t.Run("reports a failed command", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x6A, 0x80}}}

		assert.ErrorContains(t, cardSetManagementKey(card, ManagementKeyAES192, fakeManagementKey),
			"SET MANAGEMENT KEY failed with status 0x6A80")
	})
}

func TestCardManagementKeyAlgorithm(t *testing.T) {
	t.Run("reads the algorithm from the metadata", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x01, 0x01, 0x0A, 0x05, 0x01, 0x00, 0x90, 0x00}}}

		got, err := cardManagementKeyAlgorithm(card)
		require.NoError(t, err)
		assert.Equal(t, ManagementKeyAES192, got)
		assert.Equal(t, [][]byte{{0x00, insGetMetadata, 0x00, slotCardManagement}}, card.apdus)
	})

	t.Run("keeps the default of a card without metadata", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x6D, 0x00}}}

		got, err := cardManagementKeyAlgorithm(card)
		require.NoError(t, err)
		assert.Equal(t, ManagementKeyTDES, got)
	})

	t.Run("keeps the default when the algorithm is missing", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x05, 0x01, 0x00, 0x90, 0x00}}}

		got, err := cardManagementKeyAlgorithm(card)
		require.NoError(t, err)
		assert.Equal(t, ManagementKeyTDES, got)
	})

	t.Run("reports an unsupported algorithm", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x01, 0x01, 0x42, 0x90, 0x00}}}

		_, err := cardManagementKeyAlgorithm(card)
		assert.ErrorContains(t, err, "Unsupported management key algorithm 0x42")
	})

	t.Run("reports a transmit error", func(t *testing.T) {
		card := &fakeCard{err: errors.New("no card")}

		_, err := cardManagementKeyAlgorithm(card)
		assert.ErrorContains(t, err, "no card")
	})
}

func TestCardGetObject(t *testing.T) {
	value := []byte{0x01, 0x02, 0x03}

	t.Run("returns the value of an object", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{append(encodeTLV(tagObjectData, value), 0x90, 0x00)}}

		got, err := cardGetObject(card, oidCCC)
		require.NoError(t, err)
		assert.Equal(t, value, got)

		// The command carries the object identifier and asks for the value.
		expected := append(pivAPDU(insGetData, 0x3F, 0xFF, encodeTLV(tagObjectIdentifier, oidCCC)), 0x00)
		assert.Equal(t, [][]byte{expected}, card.apdus)
	})

	t.Run("reports an object the card does not hold", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x6A, 0x82}}}

		_, err := cardGetObject(card, oidPivman)
		assert.Equal(t, errObjectNotFound, err)
	})

	t.Run("reports a failed command", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x69, 0x82}}}

		_, err := cardGetObject(card, oidPivman)
		assert.ErrorContains(t, err, "GET DATA failed with status 0x6982")
	})

	t.Run("reports a response without the object", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x70, 0x00, 0x90, 0x00}}}

		_, err := cardGetObject(card, oidPivman)
		assert.ErrorContains(t, err, "Unexpected data object response")
	})
}

func TestCardPutObject(t *testing.T) {
	value := []byte{0x5A, 0x5B}

	t.Run("writes an object", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x90, 0x00}}}

		require.NoError(t, cardPutObject(card, oidCHUID, value))

		body := append(encodeTLV(tagObjectIdentifier, oidCHUID), encodeTLV(tagObjectData, value)...)
		assert.Equal(t, [][]byte{pivAPDU(insPutData, 0x3F, 0xFF, body)}, card.apdus)
	})

	t.Run("rejects an object that is too large for a short APDU", func(t *testing.T) {
		card := &fakeCard{}

		err := cardPutObject(card, oidCHUID, bytes.Repeat([]byte{0x01}, 256))
		assert.ErrorContains(t, err, "too large")
		assert.Empty(t, card.apdus)
	})

	t.Run("reports a failed command", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x6A, 0x80}}}

		assert.ErrorContains(t, cardPutObject(card, oidCHUID, value), "PUT DATA failed with status 0x6A80")
	})

	t.Run("reports a transmit error", func(t *testing.T) {
		card := &fakeCard{err: errors.New("no card")}

		assert.ErrorContains(t, cardPutObject(card, oidCHUID, value), "no card")
	})
}

func TestCardRetryCounts(t *testing.T) {
	// The count of both references is read through the YubiKey metadata
	// command.
	card := &fakeCard{responses: [][]byte{
		{0x06, 0x02, 0x03, 0x02, 0x90, 0x00},
		{0x06, 0x02, 0x03, 0x00, 0x90, 0x00},
	}}

	pin, puk := cardRetryCounts(card)
	assert.Equal(t, 2, pin)
	assert.Equal(t, 0, puk)
}

// generalAuthResponse returns the APDU response (the data field and the status
// word) of a GENERAL AUTHENTICATE command that carries signature in its dynamic
// authentication template.
func generalAuthResponse(signature []byte) []byte {
	response := encodeTLV(tagDynamicAuth, encodeTLV(tagAuthResponse, signature))
	return append(response, 0x90, 0x00)
}

func TestCardSignCardAuthenticationECDSA(t *testing.T) {
	r := bytes.Repeat([]byte{0x01}, 32)
	s := bytes.Repeat([]byte{0x02}, 32)
	digest := bytes.Repeat([]byte{0xAB}, 32)
	key := &ecdsa.PublicKey{Curve: elliptic.P256()}

	card := &fakeCard{responses: [][]byte{generalAuthResponse(append(append([]byte{}, r...), s...))}}
	sig, err := cardSignCardAuthentication(card, key, digest, crypto.SHA256)
	require.NoError(t, err)

	var parsed struct{ R, S *big.Int }
	_, err = asn1.Unmarshal(sig, &parsed)
	require.NoError(t, err)
	assert.Equal(t, new(big.Int).SetBytes(r), parsed.R)
	assert.Equal(t, new(big.Int).SetBytes(s), parsed.S)

	require.Len(t, card.apdus, 1)
	apdu := card.apdus[0]
	assert.Equal(t, byte(0x00), apdu[0])
	assert.Equal(t, byte(insAuthenticate), apdu[1])
	assert.Equal(t, byte(algoECCP256), apdu[2])
	assert.Equal(t, byte(slotCardAuthentication), apdu[3])
	assert.Len(t, apdu, 5+38+1)

	// The data field is the dynamic authentication template 7C { 82 00, 81
	// digest } that GENERAL AUTHENTICATE carries the digest in, followed by Le.
	expected := []byte{tagDynamicAuth, 0x24, tagAuthResponse, 0x00, tagAuthChallenge, 0x20}
	expected = append(expected, digest...)
	assert.Equal(t, expected, apdu[5:len(apdu)-1])
	assert.Equal(t, byte(0x00), apdu[len(apdu)-1])
}

func TestCardSignCardAuthenticationECDSAKeyLength(t *testing.T) {
	// A P-384 key signs a 32 byte digest as a 48 byte message representative,
	// left-padded with zero bytes.
	digest := bytes.Repeat([]byte{0xAB}, 32)
	key := &ecdsa.PublicKey{Curve: elliptic.P384()}

	card := &fakeCard{responses: [][]byte{generalAuthResponse(bytes.Repeat([]byte{0x5A}, 96))}}
	_, err := cardSignCardAuthentication(card, key, digest, crypto.SHA256)
	require.NoError(t, err)

	require.Len(t, card.apdus, 1)
	apdu := card.apdus[0]
	assert.Equal(t, byte(algoECCP384), apdu[2])

	representative := apdu[len(apdu)-1-48 : len(apdu)-1]
	assert.Equal(t, append(bytes.Repeat([]byte{0x00}, 16), digest...), representative)
}

func TestPivMessageRepresentative(t *testing.T) {
	assert.Equal(t, []byte{0x01, 0x02}, pivMessageRepresentative([]byte{0x01, 0x02}, 2))
	assert.Equal(t, []byte{0x01, 0x02}, pivMessageRepresentative([]byte{0x01, 0x02, 0x03}, 2))
	assert.Equal(t, []byte{0x00, 0x00, 0x01, 0x02}, pivMessageRepresentative([]byte{0x01, 0x02}, 4))
}

func TestCardSignCardAuthenticationUnsupportedKey(t *testing.T) {
	digest := bytes.Repeat([]byte{0x01}, 32)

	_, err := cardSignCardAuthentication(&fakeCard{}, ed25519.PublicKey{}, digest, crypto.SHA256)
	assert.ErrorContains(t, err, "Unsupported key type")

	_, err = cardSignCardAuthentication(&fakeCard{}, &ecdsa.PublicKey{Curve: elliptic.P521()}, digest, crypto.SHA256)
	assert.ErrorContains(t, err, "Unsupported curve P-521")

	_, err = cardSignCardAuthentication(&fakeCard{}, &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 511)}, digest, crypto.SHA256)
	assert.ErrorContains(t, err, "Unsupported RSA key size of 512 bits")
}

func TestCardSignCardAuthenticationRSA(t *testing.T) {
	digest := bytes.Repeat([]byte{0xCD}, 32)
	signature := bytes.Repeat([]byte{0x5A}, 256)
	// 2^2047 is a 2048 bit number, the key size of a PIV RSA-2048 key.
	key := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047)}

	// The payload of an RSA signature does not fit into a short APDU, so the
	// card acknowledges the first block before it returns the signature.
	card := &fakeCard{responses: [][]byte{{0x90, 0x00}, generalAuthResponse(signature)}}
	sig, err := cardSignCardAuthentication(card, key, digest, crypto.SHA256)
	require.NoError(t, err)
	assert.Equal(t, signature, sig)

	// The DigestInfo of the SHA-256 digest is padded with the PKCS #1 v1.5
	// type 1 block: 0x00, 0x01, 202 bytes of 0xFF, 0x00 and the DigestInfo.
	padded := []byte{0x00, 0x01}
	padded = append(padded, bytes.Repeat([]byte{0xFF}, 256-51-3)...)
	padded = append(padded, 0x00)
	padded = append(padded, []byte{
		0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
	}...)
	padded = append(padded, digest...)
	require.Len(t, padded, 256)

	expected := []byte{
		tagDynamicAuth, 0x82, 0x01, 0x06,
		tagAuthResponse, 0x00,
		tagAuthChallenge, 0x82, 0x01, 0x00,
	}
	expected = append(expected, padded...)

	require.Len(t, card.apdus, 2)
	first, last := card.apdus[0], card.apdus[1]

	// The first block of a chained command marks the chain with the command
	// chaining bit of the class byte and carries the full 255 byte payload.
	assert.Equal(t, byte(0x10), first[0])
	assert.Equal(t, byte(insAuthenticate), first[1])
	assert.Equal(t, byte(algoRSA2048), first[2])
	assert.Equal(t, byte(slotCardAuthentication), first[3])
	assert.Equal(t, byte(0xFF), first[4])
	assert.Len(t, first, 5+0xFF+1)
	assert.Equal(t, byte(0x00), first[len(first)-1])

	assert.Equal(t, byte(0x00), last[0])
	assert.Equal(t, byte(insAuthenticate), last[1])
	assert.Equal(t, byte(algoRSA2048), last[2])
	assert.Equal(t, byte(slotCardAuthentication), last[3])
	assert.Len(t, last, 5+11+1)
	assert.Equal(t, byte(0x00), last[len(last)-1])

	reassembled := append(append([]byte{}, first[5:len(first)-1]...), last[5:len(last)-1]...)
	assert.Equal(t, expected, reassembled)
}

func TestCardSignCardAuthenticationCardErrors(t *testing.T) {
	key := &ecdsa.PublicKey{Curve: elliptic.P256()}
	digest := bytes.Repeat([]byte{0x01}, 32)

	t.Run("transport error", func(t *testing.T) {
		card := &fakeCard{err: errors.New("no card")}
		_, err := cardSignCardAuthentication(card, key, digest, crypto.SHA256)
		assert.ErrorContains(t, err, "Sign with the card authentication key")
	})

	t.Run("card rejects the command", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x6A, 0x80}}}
		_, err := cardSignCardAuthentication(card, key, digest, crypto.SHA256)
		assert.ErrorContains(t, err, "GENERAL AUTHENTICATE failed with status 0x6A80")
	})

	t.Run("unexpected response", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{{0x90, 0x00}}}
		_, err := cardSignCardAuthentication(card, key, digest, crypto.SHA256)
		assert.ErrorContains(t, err, "Unexpected GENERAL AUTHENTICATE response")
	})

	t.Run("empty signature", func(t *testing.T) {
		card := &fakeCard{responses: [][]byte{generalAuthResponse(nil)}}
		_, err := cardSignCardAuthentication(card, key, digest, crypto.SHA256)
		assert.ErrorContains(t, err, "Unexpected GENERAL AUTHENTICATE response")
	})
}

// TestTransmitChainedShortCommand checks that a command whose data field fits
// into a short APDU is sent as a single command without the command chaining
// bit, and that the status word and the data of the response are returned.
func TestTransmitChainedShortCommand(t *testing.T) {
	card := &fakeCard{responses: [][]byte{{0xAB, 0x90, 0x00}}}
	data, sw, err := transmitChained(card, 0x00, insAuthenticate, 0x11, slotCardAuthentication, []byte{0x01, 0x02})
	require.NoError(t, err)
	assert.Equal(t, 0x9000, sw)
	assert.Equal(t, []byte{0xAB}, data)

	require.Len(t, card.apdus, 1)
	assert.Equal(t, []byte{0x00, insAuthenticate, 0x11, slotCardAuthentication, 0x02, 0x01, 0x02, 0x00}, card.apdus[0])
}

// TestTransmitChainedAccumulatesResponses checks that the data of every block
// that the card answers with is collected, which is what the reference smart
// card library does for a chained command.
func TestTransmitChainedAccumulatesResponses(t *testing.T) {
	card := &fakeCard{responses: [][]byte{{0x01, 0x90, 0x00}, {0x02, 0x90, 0x00}}}
	data, sw, err := transmitChained(card, 0x00, insAuthenticate, 0x07, slotCardAuthentication, bytes.Repeat([]byte{0xAA}, 256))
	require.NoError(t, err)
	assert.Equal(t, 0x9000, sw)
	assert.Equal(t, []byte{0x01, 0x02}, data)

	require.Len(t, card.apdus, 2)
	assert.Len(t, card.apdus[0], 5+0xFF+1)
	assert.Len(t, card.apdus[1], 5+1+1)
}

// TestTransmitChainedFailure checks that a block the card rejects is reported
// with its status word instead of a signature.
func TestTransmitChainedFailure(t *testing.T) {
	card := &fakeCard{responses: [][]byte{{0x6A, 0x80}}}
	data, sw, err := transmitChained(card, 0x00, insAuthenticate, 0x07, slotCardAuthentication, bytes.Repeat([]byte{0x01}, 512))
	require.NoError(t, err)
	assert.Equal(t, 0x6A80, sw)
	assert.Empty(t, data)
	assert.Len(t, card.apdus, 1)
}
