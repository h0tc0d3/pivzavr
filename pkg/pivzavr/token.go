package pivzavr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"
	"strings"

	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

const (
	// DefaultPIN is the PIV default user PIN.
	DefaultPIN = "123456"
	// defaultSO is the PIV default security officer PIN.
	defaultSO = "12345678"
	// defaultLabel is the label assigned to the token when it is initialized.
	defaultLabel = "pivzavr"
	// pkcs11ModuleEnv is the environment variable used to select the PKCS#11
	// module to load.
	pkcs11ModuleEnv = "PIVZAVR_PKCS11_MODULE"
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
		return nil, errors.New("Card management slot (9b) is not exposed as a PKCS#11 object.")
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
		return nil, errors.Errorf("Invalid slot %q.", s)
	}
}

// pkcs11Token implements Pivzavr on top of a PKCS#11 module.
type pkcs11Token struct {
	ctx    *pkcs11.Ctx
	slotID uint
}

// findModulePath returns the first PIV PKCS#11 module found in the conventional
// system locations for the current operating system.
func findModulePath() (string, error) {
	for _, path := range candidateModulePaths(runtime.GOOS, runtime.GOARCH) {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, nil
		}
	}

	return "", fmt.Errorf(
		"PKCS#11 module not found for %s/%s (set %s to override)",
		runtime.GOOS, runtime.GOARCH, pkcs11ModuleEnv,
	)
}

// candidateModulePaths returns the conventional PIV PKCS#11 module paths for
// the given operating system and architecture, ordered by likelihood.
//
// The YubiKey PKCS#11 module (ykcs11) is preferred over OpenSC. OpenSC only
// discovers retired key-management slots from the card's key-history object,
// which YubiKeys do not implement, so retired slots are only addressable
// through ykcs11.
func candidateModulePaths(goos, goarch string) []string {
	paths := make([]string, 0, 16)
	add := func(p string) { paths = append(paths, p) }

	switch goos {
	case "linux":
		archDir := map[string]string{
			"amd64": "x86_64-linux-gnu",
			"386":   "i386-linux-gnu",
			"arm64": "aarch64-linux-gnu",
			"arm":   "arm-linux-gnueabihf",
		}[goarch]
		if archDir != "" {
			add("/usr/lib/" + archDir + "/libykcs11.so")     // Debian/Ubuntu
			add("/usr/lib/" + archDir + "/opensc-pkcs11.so") // Debian/Ubuntu
		}
		add("/usr/lib64/libykcs11.so") // RHEL/CentOS/Fedora
		add("/usr/lib64/opensc-pkcs11.so")
		add("/usr/lib/libykcs11.so") // Arch Linux / generic
		add("/usr/lib/opensc-pkcs11.so")
		add("/usr/local/lib/libykcs11.so")
		add("/usr/local/lib/opensc-pkcs11.so")
	case "darwin":
		// Apple Silicon and Intel Homebrew prefixes, plus the official
		// OpenSC installer location.
		add("/opt/homebrew/lib/libykcs11.dylib")
		add("/usr/local/lib/libykcs11.dylib")
		add("/opt/homebrew/lib/opensc-pkcs11.so")
		add("/opt/homebrew/lib/opensc-pkcs11.dylib")
		add("/usr/local/lib/opensc-pkcs11.so")
		add("/usr/local/lib/opensc-pkcs11.dylib")
		add("/Library/OpenSC/lib/opensc-pkcs11.so")
		add("/Library/OpenSC/lib/opensc-pkcs11.dylib")
	case "freebsd", "openbsd", "netbsd", "dragonfly":
		add("/usr/local/lib/libykcs11.so")
		add("/usr/local/lib/opensc-pkcs11.so") // pkg/ports
		add("/usr/lib/opensc-pkcs11.so")
	default:
		// Let the dynamic linker resolve the module by its soname.
		add("libykcs11.so")
		add("opensc-pkcs11.so")
	}

	return paths
}

// TokenHandleWithSerial returns a handle to the token in the slot matching
// serial. If serial is empty, the token is returned only if exactly one token
// is present.
func TokenHandleWithSerial(serial string) (Pivzavr, error) {
	var err error
	module := os.Getenv(pkcs11ModuleEnv)
	if module == "" {
		module, err = findModulePath()
	}

	if err != nil {
		return nil, err
	}

	ctx := pkcs11.New(module)
	if ctx == nil {
		return nil, errors.Errorf("Failed to load PKCS#11 module %q.", module)
	}

	// Ensure the module is released on every error path. On success, ownership
	// transfers to the returned token, which releases it in Close.
	owned := true
	defer func() {
		if owned {
			ctx.Destroy()
		}
	}()

	if err = ctx.Initialize(); err != nil {
		return nil, errors.Wrapf(err, "Initialize PKCS#11 module %q", module)
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, errors.Wrap(err, "Enumerate smart cards")
	}
	if len(slots) == 0 {
		return nil, errors.New("No smart card found.")
	}

	if serial == "" {
		if len(slots) > 1 {
			return nil, errors.New("Multiple smart cards found but no serial specified.")
		}
		owned = false
		return &pkcs11Token{ctx: ctx, slotID: slots[0]}, nil
	}

	for _, slot := range slots {
		info, err := ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if strings.TrimSpace(info.SerialNumber) == serial {
			owned = false
			return &pkcs11Token{ctx: ctx, slotID: slot}, nil
		}
	}

	return nil, errors.Errorf("No smart card found with serial number %s.", serial)
}

// Close releases the PKCS#11 module.
func (t *pkcs11Token) Close() error {
	if t.ctx == nil {
		return nil
	}
	t.ctx.Destroy()
	t.ctx = nil
	return nil
}

// openSession opens a serial read/write session with the token.
func (t *pkcs11Token) openSession() (pkcs11.SessionHandle, error) {
	sh, err := t.ctx.OpenSession(t.slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return 0, errors.Wrap(err, "Open PKCS#11 session")
	}
	return sh, nil
}

// Certificate returns the certificate stored in slot.
func (t *pkcs11Token) Certificate(slot Slot) (*x509.Certificate, error) {
	sh, err := t.openSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.ctx.CloseSession(sh) }()

	obj, err := t.findObject(sh, pkcs11.CKO_CERTIFICATE, slot)
	if err != nil {
		return nil, err
	}

	attrs, err := t.ctx.GetAttributeValue(sh, obj, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return nil, errors.Wrap(err, "Read certificate")
	}
	if len(attrs) != 1 || len(attrs[0].Value) == 0 {
		return nil, errors.New("Certificate value not found.")
	}

	cert, err := x509.ParseCertificate(attrs[0].Value)
	if err != nil {
		return nil, errors.Wrap(err, "Parse certificate")
	}
	return cert, nil
}

// Slots returns the PIV slots that currently hold a certificate, in
// key-reference order.
func (t *pkcs11Token) Slots() ([]Slot, error) {
	sh, err := t.openSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.ctx.CloseSession(sh) }()

	// Collect the CKA_IDs of every certificate object on the token.
	ids := make(map[string]bool)
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	}
	if err := t.ctx.FindObjectsInit(sh, template); err != nil {
		return nil, errors.Wrap(err, "Start object search")
	}
	defer func() { _ = t.ctx.FindObjectsFinal(sh) }()

	for {
		objs, _, err := t.ctx.FindObjects(sh, 100)
		if err != nil {
			return nil, errors.Wrap(err, "Search objects")
		}
		if len(objs) == 0 {
			break
		}
		for _, obj := range objs {
			attrs, err := t.ctx.GetAttributeValue(sh, obj, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			})
			if err != nil {
				return nil, errors.Wrap(err, "Read object ID")
			}
			if len(attrs) == 1 && len(attrs[0].Value) > 0 {
				ids[string(attrs[0].Value)] = true
			}
		}
	}

	// Map the collected CKA_IDs back to slots in key-reference order.
	var slots []Slot
	for _, slot := range allSlots {
		id, err := slot.id()
		if err != nil {
			continue
		}
		if ids[string(id)] {
			slots = append(slots, slot)
		}
	}
	return slots, nil
}

// Signer returns a crypto.Signer backed by the private key in slot.
func (t *pkcs11Token) Signer(slot Slot, prompt io.Reader) (crypto.Signer, error) {
	cert, err := t.Certificate(slot)
	if err != nil {
		return nil, err
	}
	return &pkcs11Signer{
		token:  t,
		slot:   slot,
		prompt: prompt,
		pub:    cert.PublicKey,
	}, nil
}

// findObject locates the first object of the given class whose CKA_ID matches
// slot.
func (t *pkcs11Token) findObject(sh pkcs11.SessionHandle, class uint, slot Slot) (pkcs11.ObjectHandle, error) {
	id, err := slot.id()
	if err != nil {
		return 0, err
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	if err := t.ctx.FindObjectsInit(sh, template); err != nil {
		return 0, errors.Wrap(err, "Start object search")
	}
	defer func() { _ = t.ctx.FindObjectsFinal(sh) }()

	objs, _, err := t.ctx.FindObjects(sh, 1)
	if err != nil {
		return 0, errors.Wrap(err, "Search objects")
	}
	if len(objs) == 0 {
		return 0, errors.Errorf("Object not found for slot %s.", slot)
	}
	return objs[0], nil
}

// Reset reinitializes the token and sets the default user PIN.
func (t *pkcs11Token) Reset() error {
	if err := t.ctx.InitToken(t.slotID, defaultSO, defaultLabel); err != nil {
		return errors.Wrap(err, "Reset token")
	}

	sh, err := t.openSession()
	if err != nil {
		return err
	}
	defer func() { _ = t.ctx.CloseSession(sh) }()

	if err := t.ctx.InitPIN(sh, DefaultPIN); err != nil {
		return errors.Wrap(err, "Set initial PIN")
	}
	return nil
}

// SetPIN changes the user PIN.
func (t *pkcs11Token) SetPIN(oldPIN, newPIN string) error {
	sh, err := t.openSession()
	if err != nil {
		return err
	}
	defer func() { _ = t.ctx.CloseSession(sh) }()

	if err := t.ctx.SetPIN(sh, oldPIN, newPIN); err != nil {
		return errors.Wrap(err, "Set PIN")
	}
	return nil
}

// pkcs11Signer implements crypto.Signer using a PKCS#11 private key object.
type pkcs11Signer struct {
	token  *pkcs11Token
	slot   Slot
	prompt io.Reader
	pub    crypto.PublicKey
}

func (s *pkcs11Signer) Public() crypto.PublicKey {
	return s.pub
}

func (s *pkcs11Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sh, err := s.token.openSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.token.ctx.CloseSession(sh) }()

	// Private key objects are only visible after a user login, so obtain the
	// PIN (via pinentry) and authenticate before attempting to locate the key.
	pin, err := GetPin(s.prompt)
	if err != nil {
		return nil, errors.Wrap(err, "Get pin")
	}
	if err := s.token.ctx.Login(sh, pkcs11.CKU_USER, pin); err != nil {
		return nil, errors.Wrap(err, "Login to token")
	}

	key, err := s.token.findObject(sh, pkcs11.CKO_PRIVATE_KEY, s.slot)
	if err != nil {
		return nil, err
	}

	return s.sign(sh, key, digest, opts)
}

func (s *pkcs11Signer) sign(sh pkcs11.SessionHandle, key pkcs11.ObjectHandle, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch s.pub.(type) {
	case *ecdsa.PublicKey:
		mech := pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
		if err := s.token.ctx.SignInit(sh, []*pkcs11.Mechanism{mech}, key); err != nil {
			return nil, errors.Wrap(err, "Initialize signature")
		}
		raw, err := s.token.ctx.Sign(sh, digest)
		if err != nil {
			return nil, errors.Wrap(err, "Sign")
		}
		return encodeECDSASignature(raw)
	case *rsa.PublicKey:
		hash := opts.HashFunc()
		info, err := pkcs1DigestInfo(hash, digest)
		if err != nil {
			return nil, err
		}
		mech := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
		if err := s.token.ctx.SignInit(sh, []*pkcs11.Mechanism{mech}, key); err != nil {
			return nil, errors.Wrap(err, "Initialize signature")
		}
		return s.token.ctx.Sign(sh, info)
	default:
		return nil, errors.Errorf("Unsupported key type %T.", s.pub)
	}
}

// encodeECDSASignature converts the PKCS#11 fixed-width r||s encoding into an
// ASN.1 DER-encoded ECDSA-Sig-Value as expected by crypto.Signer.
func encodeECDSASignature(raw []byte) ([]byte, error) {
	if len(raw)%2 != 0 || len(raw) == 0 {
		return nil, errors.New("Invalid ECDSA signature length.")
	}
	half := len(raw) / 2
	r := new(big.Int).SetBytes(raw[:half])
	s := new(big.Int).SetBytes(raw[half:])

	type ecdsaSignature struct {
		R, S *big.Int
	}
	return asn1.Marshal(ecdsaSignature{R: r, S: s})
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
		return nil, errors.Errorf("Unsupported hash algorithm %v.", hash)
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

var _ crypto.Signer = (*pkcs11Signer)(nil)
var _ Pivzavr = (*pkcs11Token)(nil)
