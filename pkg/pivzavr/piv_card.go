package pivzavr

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" // #nosec G502 -- Triple-DES is the algorithm of the PIV default management key.
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/h0tc0d3/pivzavr/pkg/i18n"
	"github.com/h0tc0d3/pivzavr/pkg/pcsc"
)

// PIV algorithm identifiers, as defined by NIST SP 800-78. They are the P1 of a
// GENERAL AUTHENTICATE command that uses a PIV key, and they select the key type
// and, for RSA, the key size of the signing operation.
const (
	algoRSA1024 = 0x06
	algoRSA2048 = 0x07
	algoRSA3072 = 0x05
	algoRSA4096 = 0x16
	// The PIV algorithm identifiers of the two elliptic curves that
	// NIST SP 800-78 defines for PIV.
	algoECCP256 = 0x11
	algoECCP384 = 0x14
)

// ManagementKeyAlgorithm identifies the algorithm of the PIV card management
// key, which authenticates the commands that write to the smart card. The values
// are the ones defined by NIST SP 800-78.
type ManagementKeyAlgorithm byte

const (
	// ManagementKeyTDES is Triple-DES, the algorithm of the factory default
	// management key. It is read and verified to authenticate the key that a
	// smart card still holds, so that a card with its factory default key can
	// be moved to AES; it is not set as a new key.
	ManagementKeyTDES ManagementKeyAlgorithm = 0x03
	// ManagementKeyAES128 is an AES-128 key, which YubiKeys support from
	// firmware 5.4.0 on.
	ManagementKeyAES128 ManagementKeyAlgorithm = 0x08
	// ManagementKeyAES192 is an AES-192 key, which YubiKeys support from
	// firmware 5.4.0 on.
	ManagementKeyAES192 ManagementKeyAlgorithm = 0x0A
	// ManagementKeyAES256 is an AES-256 key, which YubiKeys support from
	// firmware 5.4.0 on.
	ManagementKeyAES256 ManagementKeyAlgorithm = 0x0C
)

// String returns the name of the algorithm, in the form that
// ParseManagementKeyAlgorithm accepts.
func (a ManagementKeyAlgorithm) String() string {
	switch a {
	case ManagementKeyTDES:
		return "TDES"
	case ManagementKeyAES128:
		return "AES128"
	case ManagementKeyAES192:
		return "AES192"
	case ManagementKeyAES256:
		return "AES256"
	}
	return fmt.Sprintf("0x%02X", byte(a))
}

// keyLen returns the length of a management key of the algorithm.
func (a ManagementKeyAlgorithm) keyLen() int {
	switch a {
	case ManagementKeyTDES:
		return 24
	case ManagementKeyAES128:
		return 16
	case ManagementKeyAES192:
		return 24
	case ManagementKeyAES256:
		return 32
	}
	return 0
}

// challengeLen returns the length of the witness the smart card encrypts while
// the management key is verified, which is the block size of the algorithm.
func (a ManagementKeyAlgorithm) challengeLen() int {
	if a == ManagementKeyTDES {
		return des.BlockSize
	}
	return aes.BlockSize
}

// ParseManagementKeyAlgorithm parses the name of a management key algorithm:
// the name of the algorithm, ignoring case.
func ParseManagementKeyAlgorithm(name string) (ManagementKeyAlgorithm, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "AES128":
		return ManagementKeyAES128, nil
	case "AES192":
		return ManagementKeyAES192, nil
	case "AES256":
		return ManagementKeyAES256, nil
	}
	return 0, i18n.Errorf("Unknown management key algorithm %q, use AES128, AES192 or AES256.", name)
}

// PIVCard is a session with the PIV application of a smart card. It offers the
// commands that the PKCS#11 interface of a token does not, so that the PIN, the
// PUK, the PIV data objects and the card management key of a card can be
// changed.
type PIVCard interface {
	// Close ends the session with the smart card.
	Close() error

	// Authenticate verifies the card management key, which the commands that
	// write to the smart card require.
	Authenticate(key []byte, algorithm ManagementKeyAlgorithm) error

	// ManagementKeyAlgorithm returns the algorithm of the management key the
	// smart card currently uses.
	ManagementKeyAlgorithm() (ManagementKeyAlgorithm, error)

	// SetManagementKey replaces the card management key.
	SetManagementKey(algorithm ManagementKeyAlgorithm, key []byte) error

	// ChangePIN replaces the user PIN, and ChangePUK the PUK.
	ChangePIN(oldPIN, newPIN string) error
	ChangePUK(oldPUK, newPUK string) error

	// VerifyPIN verifies the user PIN, which the smart card asks for before
	// it hands out the object that holds a protected management key.
	VerifyPIN(pin string) error

	// RetryCounts returns the number of PIN and PUK attempts that are left,
	// or RetriesUnknown for a count that cannot be read.
	RetryCounts() (int, int)

	// GetObject returns the value of the PIV data object oid, and PutObject
	// writes it.
	GetObject(oid []byte) ([]byte, error)
	PutObject(oid []byte, value []byte) error
}

// cardSession implements PIVCard over a PC/SC connection to a smart card.
type cardSession struct {
	ctx  *pcsc.Context
	card *pcsc.Card
}

// openPIVCard opens the PIV application of the smart card whose Card Holder
// Unique Identifier is chuid (hex-encoded). When chuid is empty and exactly one
// PIV card is connected, that card is used.
func openPIVCard(chuid string) (PIVCard, error) {
	return openCardSession(chuid)
}

// openCardSession opens the PIV application of the smart card whose Card Holder
// Unique Identifier is chuid (hex-encoded) like openPIVCard, and returns the
// session itself. The commands that are implemented as package level functions,
// such as the signature with the card authentication key, use the connection of
// the session directly.
func openCardSession(chuid string) (*cardSession, error) {
	ctx, err := pcsc.EstablishContext()
	if err != nil {
		return nil, i18n.Wrap(err, "Establish PC/SC context")
	}

	reader, err := findPIVReader(ctx, chuid, i18n.Sprintf("change"))
	if err != nil {
		_ = ctx.Close()
		return nil, err
	}

	card, err := ctx.Connect(reader, pcsc.ShareShared, pcsc.ProtocolAny)
	if err != nil {
		_ = ctx.Close()
		return nil, i18n.Wrap(err, "Connect to smart card")
	}
	return &cardSession{ctx: ctx, card: card}, nil
}

// signCardAuthentication signs digest with the card authentication key (slot
// 9E) of the smart card whose Card Holder Unique Identifier is chuid
// (hex-encoded). When chuid is empty and exactly one PIV card is connected,
// that card is used.
//
// The card authentication key is the one PIV key that the PIV applet uses
// without the user PIN, and a PKCS#11 module does not expose its private key
// object before a login. The signature is therefore produced over PC/SC with
// the GENERAL AUTHENTICATE command, which asks for no PIN.
func signCardAuthentication(chuid string, pub crypto.PublicKey, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	session, err := openCardSession(chuid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = session.Close() }()

	return cardSignCardAuthentication(session.card, pub, digest, opts)
}

// findPIVReader returns the reader of the PIV smart card identified by chuid.
// The card is selected and, when chuid is non-empty, compared to the identifier
// before it is used, so that a command does not reach the wrong card. operation
// names the command that is about to run, so that the error reports what the
// card was needed for.
func findPIVReader(ctx *pcsc.Context, chuid, operation string) (string, error) {
	readers, err := ctx.Readers()
	if err != nil {
		return "", i18n.Wrap(err, "List smart card readers")
	}

	selected := ""
	matches := 0
	for _, reader := range readers {
		card, err := ctx.Connect(reader, pcsc.ShareShared, pcsc.ProtocolAny)
		if err != nil {
			continue
		}
		matched := cardMatchesPIV(card, chuid)
		_ = card.Disconnect(pcsc.LeaveCard)
		if !matched {
			continue
		}
		matches++
		selected = reader
		if chuid != "" {
			// The CHUID identifies a single card, so its match is final.
			break
		}
	}

	switch {
	case matches == 0:
		return "", i18n.Errorf("No PIV smart card found to %s.", operation)
	case matches > 1:
		return "", i18n.New("Multiple PIV smart cards found but no CHUID to tell them apart.")
	}
	return selected, nil
}

// Close ends the session with the smart card and releases the PC/SC context.
func (s *cardSession) Close() error {
	var err error
	if s.card != nil {
		err = s.card.Disconnect(pcsc.LeaveCard)
	}
	if s.ctx != nil {
		_ = s.ctx.Close()
	}
	return err
}

// Authenticate verifies the card management key of the smart card.
func (s *cardSession) Authenticate(key []byte, algorithm ManagementKeyAlgorithm) error {
	return cardAuthenticate(s.card, key, algorithm)
}

// ManagementKeyAlgorithm returns the algorithm of the management key of the
// smart card.
func (s *cardSession) ManagementKeyAlgorithm() (ManagementKeyAlgorithm, error) {
	return cardManagementKeyAlgorithm(s.card)
}

// SetManagementKey replaces the card management key of the smart card.
func (s *cardSession) SetManagementKey(algorithm ManagementKeyAlgorithm, key []byte) error {
	return cardSetManagementKey(s.card, algorithm, key)
}

// ChangePIN replaces the user PIN of the smart card.
func (s *cardSession) ChangePIN(oldPIN, newPIN string) error {
	return cardChangeReference(s.card, pinRef, oldPIN, newPIN, errPINBlocked)
}

// ChangePUK replaces the PUK of the smart card.
func (s *cardSession) ChangePUK(oldPUK, newPUK string) error {
	return cardChangeReference(s.card, pukRef, oldPUK, newPUK, errPUKBlocked)
}

// VerifyPIN verifies the user PIN on the smart card.
func (s *cardSession) VerifyPIN(pin string) error {
	return cardVerifyReference(s.card, pinRef, pin, errPINBlocked)
}

// RetryCounts returns the number of PIN and PUK attempts the smart card has
// left.
func (s *cardSession) RetryCounts() (int, int) {
	return cardRetryCounts(s.card)
}

// GetObject returns the value of the PIV data object oid.
func (s *cardSession) GetObject(oid []byte) ([]byte, error) {
	return cardGetObject(s.card, oid)
}

// PutObject writes the PIV data object oid.
func (s *cardSession) PutObject(oid []byte, value []byte) error {
	return cardPutObject(s.card, oid, value)
}

var _ PIVCard = (*cardSession)(nil)

// pivAPDU returns the APDU of the PIV command that carries value as its data
// field. PIV commands are short APDUs, so a value of a variable length has to
// be checked by the caller before it is passed in.
func pivAPDU(ins, p1, p2 byte, value []byte) []byte {
	apdu := []byte{0x00, ins, p1, p2, byte(len(value))} // #nosec G115 -- PIV commands carry values of at most 255 bytes.
	return append(apdu, value...)
}

// referenceName returns the name of the reference that holds a secret.
func referenceName(ref byte) string {
	if ref == pukRef {
		return "PUK"
	}
	return "PIN"
}

// dynamicAuthValue returns the value of the dynamic authentication template of
// the response to an AUTHENTICATE command, which wraps the witness, the
// challenge or the response of the management key exchange.
func dynamicAuthValue(data []byte) []byte {
	value, _ := tlvValue(data, tagDynamicAuth)
	return value
}

// cardAuthenticate verifies the card management key on card, which the commands
// that write to the PIV application require.
//
// The smart card sends a witness that it encrypts with the management key, and
// it expects the witness back in plain text together with a challenge that it
// encrypts in turn. The exchange proves that both sides hold the same key.
func cardAuthenticate(card cardCommander, key []byte, algorithm ManagementKeyAlgorithm) error {
	return cardAuthenticateWith(card, key, algorithm, rand.Reader)
}

// cardAuthenticateWith authenticates like cardAuthenticate, drawing the
// challenge from random, so that the exchange can be tested without a smart
// card.
func cardAuthenticateWith(card cardCommander, key []byte, algorithm ManagementKeyAlgorithm, random io.Reader) error {
	block, err := managementKeyCipher(key, algorithm)
	if err != nil {
		return err
	}

	// The smart card answers the first command with a witness that is
	// encrypted with the management key.
	value := encodeTLV(tagDynamicAuth, encodeTLV(tagAuthWitness, nil))
	data, sw, err := transmit(card, pivAPDU(insAuthenticate, byte(algorithm), slotCardManagement, value))
	if err != nil {
		return i18n.Wrap(err, "Authenticate with the management key")
	}
	if sw != swNoError {
		return i18n.Errorf("Authenticating with a %s management key failed with status 0x%04X.", algorithm, sw)
	}
	witness, ok := tlvValue(dynamicAuthValue(data), tagAuthWitness)
	if !ok || len(witness) != block.BlockSize() {
		return i18n.New("Unexpected AUTHENTICATE response.")
	}

	// The witness is decrypted with the management key and sent back with a
	// challenge, which the card encrypts in return.
	decrypted := make([]byte, block.BlockSize())
	block.Decrypt(decrypted, witness) // #nosec G602 -- the witness is one block, which is checked above.

	challenge := make([]byte, algorithm.challengeLen())
	if _, err := io.ReadFull(random, challenge); err != nil {
		return i18n.Wrap(err, "Generate authentication challenge")
	}

	value = encodeTLV(tagDynamicAuth, append(encodeTLV(tagAuthWitness, decrypted), encodeTLV(tagAuthChallenge, challenge)...))
	data, sw, err = transmit(card, pivAPDU(insAuthenticate, byte(algorithm), slotCardManagement, value))
	if err != nil {
		return i18n.Wrap(err, "Authenticate with the management key")
	}
	if sw != swNoError {
		// A card that rejects the witness rejects the management key as
		// well, so the key can be entered again.
		return errSecretIncorrect
	}
	encrypted, ok := tlvValue(dynamicAuthValue(data), tagAuthResponse)
	if !ok {
		return i18n.New("Unexpected AUTHENTICATE response.")
	}

	expected := make([]byte, block.BlockSize())
	block.Encrypt(expected, challenge)
	if subtle.ConstantTimeCompare(expected, encrypted) != 1 {
		return errSecretIncorrect
	}
	return nil
}

// managementKeyCipher returns the block cipher a management key is encrypted
// with.
func managementKeyCipher(key []byte, algorithm ManagementKeyAlgorithm) (cipher.Block, error) {
	if len(key) != algorithm.keyLen() {
		return nil, i18n.Errorf(
			"A %s management key is %d bytes long, but %d bytes were given.", algorithm, algorithm.keyLen(), len(key))
	}
	if algorithm == ManagementKeyTDES {
		// #nosec G405 -- the PIV card management key is a Triple-DES key
		// unless the card was moved to AES.
		return des.NewTripleDESCipher(key)
	}
	return aes.NewCipher(key)
}

// cardSignCardAuthentication signs digest with the card authentication key
// (slot 9E) of card, which is the one PIV key that the PIV applet uses without
// the user PIN. pub is the public key stored in the slot, which selects the
// algorithm of the signature.
//
// PIV cards sign the raw message representative: an ECDSA signature is returned
// as the fixed-width r||s pair of crypto.Signer's ASN.1 encoding, and an RSA
// signature is returned over the PKCS #1 v1.5 padded DigestInfo.
func cardSignCardAuthentication(card cardCommander, pub crypto.PublicKey, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		algorithm, keyLen, err := pivECDSAParameters(key)
		if err != nil {
			return nil, err
		}
		raw, err := cardGeneralAuthenticate(card, algorithm, pivMessageRepresentative(digest, keyLen))
		if err != nil {
			return nil, err
		}
		return encodeECDSASignature(raw)
	case *rsa.PublicKey:
		algorithm, keyLen, err := pivRSAParameters(key)
		if err != nil {
			return nil, err
		}
		info, err := pkcs1DigestInfo(opts.HashFunc(), digest)
		if err != nil {
			return nil, err
		}
		padded, err := pkcs1v15Pad(info, keyLen)
		if err != nil {
			return nil, err
		}
		return cardGeneralAuthenticate(card, algorithm, padded)
	default:
		return nil, i18n.Errorf("Unsupported key type %T.", pub)
	}
}

// pivECDSAParameters returns the PIV algorithm identifier and the length of the
// message representative of an ECDSA key. The curves that NIST SP 800-78 defines
// for PIV are P-256 and P-384.
func pivECDSAParameters(key *ecdsa.PublicKey) (byte, int, error) {
	switch key.Curve.Params().Name {
	case "P-256":
		return algoECCP256, 32, nil
	case "P-384":
		return algoECCP384, 48, nil
	}
	return 0, 0, i18n.Errorf("Unsupported curve %s of the card authentication key.", key.Curve.Params().Name)
}

// pivRSAParameters returns the PIV algorithm identifier and the length of the
// message representative of an RSA key. The key sizes are the ones of the PIV
// algorithm identifiers of NIST SP 800-78.
func pivRSAParameters(key *rsa.PublicKey) (byte, int, error) {
	switch key.Size() {
	case 128:
		return algoRSA1024, 128, nil
	case 256:
		return algoRSA2048, 256, nil
	case 384:
		return algoRSA3072, 384, nil
	case 512:
		return algoRSA4096, 512, nil
	}
	return 0, 0, i18n.Errorf("Unsupported RSA key size of %s bits.", strconv.Itoa(key.N.BitLen()))
}

// pivMessageRepresentative returns the message representative of an ECDSA
// signature over digest, which is the digest truncated to its leftmost bytes or
// left-padded with zero bytes to the length of the curve (NIST SP 800-73-4).
func pivMessageRepresentative(digest []byte, keyLen int) []byte {
	switch {
	case len(digest) == keyLen:
		return digest
	case len(digest) > keyLen:
		return digest[:keyLen]
	}
	representative := make([]byte, keyLen)
	copy(representative[keyLen-len(digest):], digest)
	return representative
}

// cardGeneralAuthenticate sends the GENERAL AUTHENTICATE command that uses the
// card authentication key of card. value is the message representative to sign,
// which the command carries in its dynamic authentication template, and the
// signature is returned from the response template.
func cardGeneralAuthenticate(card cardCommander, algorithm byte, value []byte) ([]byte, error) {
	template := encodeTLV(tagDynamicAuth,
		append([]byte{tagAuthResponse, 0x00}, encodeTLV(tagAuthChallenge, value)...))

	data, sw, err := transmitChained(card, 0x00, insAuthenticate, algorithm, slotCardAuthentication, template)
	if err != nil {
		return nil, i18n.Wrap(err, "Sign with the card authentication key")
	}
	if sw != swNoError {
		return nil, i18n.Errorf("GENERAL AUTHENTICATE failed with status 0x%04X.", sw)
	}

	signature, ok := tlvValue(dynamicAuthValue(data), tagAuthResponse)
	if !ok || len(signature) == 0 {
		return nil, i18n.New("Unexpected GENERAL AUTHENTICATE response.")
	}
	return signature, nil
}

// transmitChained sends the PIV command with data field value to card, splitting
// a value that does not fit into a short APDU over several commands that the
// card joins again. The blocks of a chained command are marked with the command
// chaining bit of the class byte, which every block but the last one has set.
//
// The data of the responses is accumulated, as the reference smart card library
// does, so that a card that answers a block as well is read in full. The status
// word of a block that the card does not accept ends the chain, and the caller
// reports the failure of the command.
func transmitChained(card cardCommander, cla, ins, p1, p2 byte, value []byte) ([]byte, int, error) {
	var response []byte
	for {
		block := value
		if len(block) > 0xFF {
			block = block[:0xFF]
		}
		value = value[len(block):]

		apdu := []byte{cla, ins, p1, p2, byte(len(block))} // #nosec G115 -- a block holds at most 255 bytes.
		apdu = append(apdu, block...)
		apdu = append(apdu, 0x00) // Le
		if len(value) > 0 {
			apdu[0] |= 0x10 // command chaining
		}

		data, sw, err := transmit(card, apdu)
		if err != nil {
			return nil, 0, err
		}
		response = append(response, data...)
		if len(value) == 0 || sw != swNoError {
			return response, sw, nil
		}
	}
}

// cardChangeReference replaces the PIN or the PUK of card: the current secret
// and the new one are sent to the card, which checks the current secret and
// installs the new one. blocked is returned once the card has no attempt left
// for the secret.
func cardChangeReference(card cardCommander, ref byte, current, newSecret string, blocked error) error {
	value := append(pinField(current), pinField(newSecret)...)
	_, sw, err := transmit(card, pivAPDU(insChangeReference, 0x00, ref, value))
	if err != nil {
		return i18n.Wrap(err, "Change "+referenceName(ref))
	}

	switch sw {
	case swNoError:
		return nil
	case swInvalidInstruction:
		return i18n.Errorf("The smart card does not support changing its %s.", referenceName(ref))
	}
	if attempts, ok := parseVerifyRetries(sw); ok {
		if attempts == 0 {
			return blocked
		}
		return errSecretIncorrect
	}
	return i18n.Errorf("CHANGE REFERENCE failed with status 0x%04X.", sw)
}

// cardVerifyReference verifies a secret on card. blocked is returned once the
// card has no attempt left for the secret, which is reported by the status word
// as well.
func cardVerifyReference(card cardCommander, ref byte, secret string, blocked error) error {
	_, sw, err := transmit(card, pivAPDU(insVerify, 0x00, ref, pinField(secret)))
	if err != nil {
		return i18n.Wrap(err, "Verify "+referenceName(ref))
	}
	if sw == swNoError {
		return nil
	}
	if attempts, ok := parseVerifyRetries(sw); ok {
		if attempts == 0 {
			return blocked
		}
		return errSecretIncorrect
	}
	return i18n.Errorf("VERIFY failed with status 0x%04X.", sw)
}

// cardSetManagementKey replaces the card management key of card. The command
// carries the algorithm of the new key, and the key itself in the card
// management slot.
func cardSetManagementKey(card cardCommander, algorithm ManagementKeyAlgorithm, key []byte) error {
	if len(key) != algorithm.keyLen() {
		return i18n.Errorf("A %s management key is %d bytes long.", algorithm, algorithm.keyLen())
	}

	value := append([]byte{byte(algorithm)}, encodeTLV(slotCardManagement, key)...)
	_, sw, err := transmit(card, pivAPDU(insSetManagementKey, 0xFF, 0xFF, value))
	if err != nil {
		return i18n.Wrap(err, "Set management key")
	}
	if sw != swNoError {
		return i18n.Errorf("SET MANAGEMENT KEY failed with status 0x%04X.", sw)
	}
	return nil
}

// cardManagementKeyAlgorithm returns the algorithm of the management key that
// is set on card. A card that does not answer the metadata command keeps the
// PIV default, which is a Triple-DES key.
func cardManagementKeyAlgorithm(card cardCommander) (ManagementKeyAlgorithm, error) {
	data, sw, err := transmit(card, []byte{0x00, insGetMetadata, 0x00, slotCardManagement})
	if err != nil {
		return 0, i18n.Wrap(err, "Get management key metadata")
	}
	if sw != swNoError {
		return ManagementKeyTDES, nil
	}

	value, ok := tlvValue(data, tagMetadataAlgo)
	if !ok || len(value) != 1 {
		return ManagementKeyTDES, nil
	}
	algorithm := ManagementKeyAlgorithm(value[0])
	if algorithm.keyLen() == 0 {
		return 0, i18n.Errorf("Unsupported management key algorithm 0x%02X.", value[0])
	}
	return algorithm, nil
}

// cardGetObject returns the value of the PIV data object oid of card. An object
// that the card does not hold is reported as errObjectNotFound.
func cardGetObject(card cardCommander, oid []byte) ([]byte, error) {
	value := encodeTLV(tagObjectIdentifier, oid)
	apdu := []byte{0x00, insGetData, 0x3F, 0xFF, byte(len(value))} // #nosec G115 -- an object identifier is a short fixed-size value.
	apdu = append(apdu, value...)
	apdu = append(apdu, 0x00) // Le

	data, sw, err := transmit(card, apdu)
	if err != nil {
		return nil, i18n.Wrap(err, "Read data object")
	}
	if sw == swFileNotFound {
		return nil, errObjectNotFound
	}
	if sw != swNoError {
		return nil, i18n.Errorf("GET DATA failed with status 0x%04X.", sw)
	}

	value, ok := dataObjectValue(data)
	if !ok {
		return nil, i18n.New("Unexpected data object response.")
	}
	return value, nil
}

// cardPutObject writes the PIV data object oid on card, which requires the card
// management key to be verified.
func cardPutObject(card cardCommander, oid []byte, value []byte) error {
	body := append(encodeTLV(tagObjectIdentifier, oid), encodeTLV(tagObjectData, value)...)
	if len(body) > 0xFF {
		return i18n.Errorf("A PIV data object of %s bytes is too large.", strconv.Itoa(len(value)))
	}

	_, sw, err := transmit(card, pivAPDU(insPutData, 0x3F, 0xFF, body))
	if err != nil {
		return i18n.Wrap(err, "Write data object")
	}
	if sw != swNoError {
		return i18n.Errorf("PUT DATA failed with status 0x%04X.", sw)
	}
	return nil
}

// cardRetryCounts returns the number of PIN and PUK attempts that are left on
// card, or RetriesUnknown for a count the card does not report.
func cardRetryCounts(card cardCommander) (int, int) {
	pin, okPIN := queryRetries(card, pinRef)
	puk, okPUK := queryRetries(card, pukRef)
	retriesPIN, retriesPUK, _ := coalesceRetries(pin, okPIN, puk, okPUK)
	return retriesPIN, retriesPUK
}
