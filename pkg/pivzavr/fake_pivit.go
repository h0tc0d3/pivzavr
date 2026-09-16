package pivzavr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/pkg/errors"
)

type slotContent struct {
	privateKey crypto.Signer
	cert       *x509.Certificate
}

type fakeToken struct {
	pin   string
	slots map[Slot]*slotContent
}

func testToken() (*fakeToken, error) {
	return &fakeToken{
		pin:   DefaultPIN,
		slots: make(map[Slot]*slotContent),
	}, nil
}

func (f *fakeToken) Close() error {
	return nil
}

func (f *fakeToken) Certificate(slot Slot) (*x509.Certificate, error) {
	c, ok := f.slots[slot]
	if !ok || c.cert == nil {
		return nil, errors.New("Key not found.")
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

func (f *fakeToken) Signer(slot Slot, _ io.Reader) (crypto.Signer, error) {
	c, ok := f.slots[slot]
	if !ok || c.privateKey == nil {
		return nil, errors.New("Key not found.")
	}
	return c.privateKey, nil
}

func (f *fakeToken) Reset() error {
	f.pin = DefaultPIN
	f.slots = make(map[Slot]*slotContent)
	return nil
}

func (f *fakeToken) SetPIN(oldPIN, newPIN string) error {
	if f.pin != oldPIN {
		return errors.New("Wrong PIN.")
	}
	f.pin = newPIN
	return nil
}

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
