package pivzavr

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"

	"github.com/h0tc0d3/pivzavr/pkg/i18n"
)

type slotContent struct {
	privateKey crypto.Signer
	cert       *x509.Certificate
}

type fakeToken struct {
	pin             string
	puk             string
	name            string
	firmwareVersion string
	serialNumber    string
	chuid           string
	ccc             string
	pinRetries      int
	pukRetries      int
	slots           map[Slot]*slotContent
	card            *fakePIVCard
}

func testToken() (*fakeToken, error) {
	return &fakeToken{
		pin:             DefaultPIN,
		puk:             DefaultPUK,
		name:            "pivzavr test",
		firmwareVersion: "1.0",
		serialNumber:    "00000000",
		pinRetries:      RetriesUnknown,
		pukRetries:      RetriesUnknown,
		slots:           make(map[Slot]*slotContent),
		card:            newFakePIVCard(),
	}, nil
}

func (f *fakeToken) Close() error {
	return nil
}

func (f *fakeToken) Certificate(slot Slot) (*x509.Certificate, error) {
	c, ok := f.slots[slot]
	if !ok || c.cert == nil {
		return nil, i18n.New("Key not found.")
	}
	return c.cert, nil
}

func (f *fakeToken) Slots() ([]Slot, error) {
	var slots []Slot
	for _, slot := range allSlots {
		if c, ok := f.slots[slot]; ok && c.cert != nil {
			slots = append(slots, slot)
		}
	}
	return slots, nil
}

func (f *fakeToken) Info() (*DeviceInfo, error) {
	info := &DeviceInfo{
		Name:            f.name,
		FirmwareVersion: f.firmwareVersion,
		SerialNumber:    f.serialNumber,
		CHUID:           f.chuid,
		CCC:             f.ccc,
		PinRetries:      f.pinRetries,
		PukRetries:      f.pukRetries,
	}
	slots, err := f.Slots()
	if err != nil {
		return nil, err
	}
	for _, slot := range slots {
		cert, err := f.Certificate(slot)
		if err != nil {
			return nil, err
		}
		info.Slots = append(info.Slots, SlotInfo{Slot: slot, Certificate: cert})
	}
	return info, nil
}

func (f *fakeToken) Signer(slot Slot) (crypto.Signer, error) {
	c, ok := f.slots[slot]
	if !ok || c.privateKey == nil {
		return nil, i18n.New("Key not found.")
	}
	return c.privateKey, nil
}

// RetryCounts returns the number of attempts the fake smart card has left for
// its PIN and PUK.
func (f *fakeToken) RetryCounts() (int, int) {
	return f.pinRetries, f.pukRetries
}

// Reset restores the fake smart card to its factory state: it discards the
// stored keys and certificates, restores the default PIN and PUK, and fills the
// PIN and PUK retry counters again. The PIV application of the card is restored
// as well, which drops a changed PIN and management key.
func (f *fakeToken) Reset() error {
	f.pin = DefaultPIN
	f.puk = DefaultPUK
	f.pinRetries = fakeAttempts
	f.pukRetries = fakeAttempts
	f.slots = make(map[Slot]*slotContent)
	f.card = newFakePIVCard()
	return nil
}

// Card returns the emulated PIV application of the fake smart card, which the
// commands that change the PIN, the PUK, the PIV data objects and the card
// management key use.
func (f *fakeToken) Card() (PIVCard, error) {
	if f.card == nil {
		f.card = newFakePIVCard()
	}
	return f.card, nil
}

// Unlock unlocks the fake smart card PIN with puk and sets it to newPIN. Like
// a smart card it tracks the attempts left for the PUK: a card without attempts
// left rejects the PUK, and a successful unlock restores the full number of
// attempts. A fake token configured with RetriesUnknown attempts never runs
// out, which mirrors a card whose count cannot be read.
func (f *fakeToken) Unlock(puk, newPIN string) error {
	if f.pukRetries == 0 {
		return errPUKBlocked
	}
	if f.puk != puk {
		if f.pukRetries > 0 {
			f.pukRetries--
		}
		return errSecretIncorrect
	}
	f.pin = newPIN
	f.pukRetries = fakeAttempts
	if f.card != nil {
		f.card.pin = newPIN
	}
	return nil
}

// fakePIVCard emulates the PIV application of a smart card in memory. Unlike
// fakeToken, which emulates the PKCS#11 interface, it holds the PIN, the PUK,
// the card management key and the PIV data objects, and it refuses the commands
// a smart card refuses: writing a data object needs the management key, and the
// object that holds a protected management key needs the PIN as well.
type fakePIVCard struct {
	pin           string
	puk           string
	mgmKey        []byte
	mgmAlgorithm  ManagementKeyAlgorithm
	objects       map[string][]byte
	pinRetries    int
	pukRetries    int
	authenticated bool
	pinVerified   bool
}

// fakeManagementKey is the factory default card management key, which is a
// Triple-DES key.
var fakeManagementKey = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
}

// newFakePIVCard returns a PIV card in its factory state.
func newFakePIVCard() *fakePIVCard {
	return &fakePIVCard{
		pin:          DefaultPIN,
		puk:          DefaultPUK,
		mgmKey:       append([]byte(nil), fakeManagementKey...),
		mgmAlgorithm: ManagementKeyTDES,
		objects:      make(map[string][]byte),
		pinRetries:   fakeAttempts,
		pukRetries:   fakeAttempts,
	}
}

// Close ends the session with the fake card, which forgets that the PIN and the
// management key were verified, as a smart card does when it is deselected.
func (f *fakePIVCard) Close() error {
	f.authenticated = false
	f.pinVerified = false
	return nil
}

// Authenticate verifies the card management key of the fake card.
func (f *fakePIVCard) Authenticate(key []byte, algorithm ManagementKeyAlgorithm) error {
	if algorithm != f.mgmAlgorithm {
		return i18n.Errorf("The smart card holds a %s management key.", f.mgmAlgorithm)
	}
	if !bytes.Equal(key, f.mgmKey) {
		return errSecretIncorrect
	}
	f.authenticated = true
	return nil
}

// ManagementKeyAlgorithm returns the algorithm of the management key of the fake
// card.
func (f *fakePIVCard) ManagementKeyAlgorithm() (ManagementKeyAlgorithm, error) {
	return f.mgmAlgorithm, nil
}

// SetManagementKey replaces the card management key of the fake card.
func (f *fakePIVCard) SetManagementKey(algorithm ManagementKeyAlgorithm, key []byte) error {
	if !f.authenticated {
		return i18n.New("The card management key is not verified.")
	}
	if len(key) != algorithm.keyLen() {
		return i18n.Errorf("A %s management key is %d bytes long.", algorithm, algorithm.keyLen())
	}
	f.mgmAlgorithm = algorithm
	f.mgmKey = append([]byte(nil), key...)
	return nil
}

// ChangePIN replaces the user PIN of the fake card.
func (f *fakePIVCard) ChangePIN(oldPIN, newPIN string) error {
	return f.changeReference(&f.pin, oldPIN, newPIN, &f.pinRetries, errPINBlocked)
}

// ChangePUK replaces the PUK of the fake card.
func (f *fakePIVCard) ChangePUK(oldPUK, newPUK string) error {
	return f.changeReference(&f.puk, oldPUK, newPUK, &f.pukRetries, errPUKBlocked)
}

// changeReference replaces a secret the way a smart card does: the current
// secret is checked, a wrong secret uses up an attempt, and a reference without
// attempts left is reported as blocked.
func (f *fakePIVCard) changeReference(secret *string, current, newSecret string, retries *int, blocked error) error {
	if *retries == 0 {
		return blocked
	}
	if *secret != current {
		*retries--
		if *retries == 0 {
			return blocked
		}
		return errSecretIncorrect
	}
	*secret = newSecret
	*retries = fakeAttempts
	return nil
}

// VerifyPIN verifies the user PIN of the fake card.
func (f *fakePIVCard) VerifyPIN(pin string) error {
	if f.pinRetries == 0 {
		return errPINBlocked
	}
	if pin != f.pin {
		f.pinRetries--
		if f.pinRetries == 0 {
			return errPINBlocked
		}
		return errSecretIncorrect
	}
	f.pinVerified = true
	f.pinRetries = fakeAttempts
	return nil
}

// RetryCounts returns the number of PIN and PUK attempts that are left on the
// fake card.
func (f *fakePIVCard) RetryCounts() (int, int) {
	return f.pinRetries, f.pukRetries
}

// GetObject returns the value of a PIV data object of the fake card. The object
// that holds the protected management key is only handed out to a verified PIN.
func (f *fakePIVCard) GetObject(oid []byte) ([]byte, error) {
	if bytes.Equal(oid, oidPivmanProtected) && !f.pinVerified {
		return nil, i18n.New("The user PIN is not verified.")
	}
	value, ok := f.objects[string(oid)]
	if !ok {
		return nil, errObjectNotFound
	}
	return append([]byte(nil), value...), nil
}

// PutObject writes a PIV data object of the fake card.
func (f *fakePIVCard) PutObject(oid []byte, value []byte) error {
	if !f.authenticated {
		return i18n.New("The card management key is not verified.")
	}
	if bytes.Equal(oid, oidPivmanProtected) && !f.pinVerified {
		return i18n.New("The user PIN is not verified.")
	}
	f.objects[string(oid)] = append([]byte(nil), value...)
	return nil
}

var _ PIVCard = (*fakePIVCard)(nil)

// fakeAttempts is the number of attempts the fake smart card offers for the
// PIN and the PUK, matching the PIV default.
const fakeAttempts = 3

var _ Pivzavr = (*fakeToken)(nil)

func generateKeyAndCertificate(f *fakeToken, slot Slot) (*x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "pivzavr test",
		},
		DNSNames:    []string{},
		IPAddresses: []net.IP{},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(0, 0, 1),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	f.slots[slot] = &slotContent{
		privateKey: key,
		cert:       cert,
	}
	return cert, nil
}

func randomSerial() (*big.Int, error) {
	maxSerial := new(big.Int)
	maxSerial.Exp(big.NewInt(2), big.NewInt(160), nil).Sub(maxSerial, big.NewInt(1))
	return rand.Int(rand.Reader, maxSerial)
}
