//go:build darwin || freebsd || linux || netbsd || windows

package pivzavr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"io"
	"strings"

	"github.com/h0tc0d3/pivzavr/pkg/config"
	"github.com/h0tc0d3/pivzavr/pkg/i18n"
	"github.com/h0tc0d3/pivzavr/pkg/pkcs11"
)

// This file holds the PKCS#11 implementation of Pivzavr: loading a PKCS#11
// module and driving the token through it. The module is used through the local
// pkg/pkcs11 binding, which calls into the C API of the module with purego and
// therefore needs no cgo and no C toolchain. The binding covers the systems
// whose dynamic loader purego can use; token_nopkcs11.go serves a build for any
// other system and reports that no PKCS#11 token can be used.
//
// The rest of the package stays available to every build: module discovery
// (module.go), the mapping of PIV slots to PKCS#11 objects (token.go) and the
// PIV applet access over PC/SC (piv_card.go).

// pkcs11Token implements Pivzavr on top of a PKCS#11 module.
type pkcs11Token struct {
	ctx    *pkcs11.Ctx
	slotID uint
	// ykcs11 reports whether the loaded module is the YubiKey PKCS#11 module,
	// which packs the firmware version differently from other modules.
	ykcs11 bool
	// module is the path of the PKCS#11 module the token was opened through,
	// which is what tells the module of a card from the one of another vendor.
	module string
}

// openModule is a PKCS#11 module that is loaded and initialized, together with
// the path it was loaded from. owned reports whether the module was handed to a
// token, which releases it in Close, rather than being released by this file.
type openModule struct {
	ctx   *pkcs11.Ctx
	path  string
	owned bool
}

// openModules loads and initializes every PKCS#11 module that the configuration
// names, in the order they are to be used. A module that cannot be loaded is
// skipped, because the smart cards that another module serves are still
// reachable; only a run in which no module at all could be loaded fails.
func openModules() ([]*openModule, error) {
	paths, err := config.PKCS11ModulePaths()
	if err != nil {
		return nil, err
	}

	modules := make([]*openModule, 0, len(paths))
	for _, path := range paths {
		ctx, err := pkcs11.New(path)
		if err != nil {
			continue
		}
		if err := ctx.Initialize(); err != nil {
			ctx.Destroy()
			continue
		}
		modules = append(modules, &openModule{ctx: ctx, path: path})
	}
	if len(modules) == 0 {
		return nil, i18n.Errorf("No PKCS#11 module could be loaded (tried %s).", strings.Join(paths, ", "))
	}
	return modules, nil
}

// release destroys every module that was not handed to a token.
func release(modules []*openModule) {
	for _, module := range modules {
		if !module.owned {
			module.ctx.Destroy()
		}
	}
}

// tokenLocation is a smart card that a loaded module exposes in a slot.
type tokenLocation struct {
	module *openModule
	slotID uint
	ykcs11 bool
	serial string
}

// tokenLocations returns the smart cards that the modules expose, in the order
// of the modules. A card that more than one module sees is reported once, for
// the first module that saw it; the conventional module locations list the
// vendor module of a card before OpenSC, so the vendor module is the one that
// is used and a card is not addressed through a module that knows less of it.
//
// A card is told apart by its Card Holder Unique Identifier, which every module
// reports the same way, rather than by the token serial number: the module of a
// card's vendor and OpenSC report different serial numbers for the same card
// (the YubiKey module reports the device serial in decimal, OpenSC a GUID
// fragment in hex), so a card would be reported twice when both modules are
// loaded. The serial number is only used for a card whose CHUID is not exposed
// through PKCS#11.
func tokenLocations(modules []*openModule) []tokenLocation {
	var locations []tokenLocation
	seen := make(map[string]bool)

	for _, module := range modules {
		slots, err := module.ctx.GetSlotList(true)
		if err != nil {
			continue
		}
		for _, slotID := range slots {
			info, err := module.ctx.GetTokenInfo(slotID)
			if err != nil {
				continue
			}
			serial := strings.TrimSpace(info.SerialNumber)

			value, ok := tokenDataObject(module.ctx, slotID, "Card Holder Unique Identifier", "CHUID")
			key := tokenKey(value, ok, serial)
			if key != "" {
				if seen[key] {
					continue
				}
				seen[key] = true
			}

			locations = append(locations, tokenLocation{
				module: module,
				slotID: slotID,
				ykcs11: config.IsYkcs11Module(module.path),
				serial: serial,
			})
		}
	}
	return locations
}

// token returns a handle to the card that the location names. From here on the
// module belongs to the token, which releases it in Close.
func (l tokenLocation) token() Pivzavr {
	l.module.owned = true
	return &pkcs11Token{
		ctx:    l.module.ctx,
		slotID: l.slotID,
		ykcs11: l.ykcs11,
		module: l.module.path,
	}
}

// TokenHandleWithSerial returns a handle to the token in the slot matching
// serial. If serial is empty, the token is returned only if exactly one token
// is present. A card that several modules expose counts as one token.
func TokenHandleWithSerial(serial string) (Pivzavr, error) {
	modules, err := openModules()
	if err != nil {
		return nil, err
	}
	defer release(modules)

	locations := tokenLocations(modules)
	if len(locations) == 0 {
		return nil, i18n.New("No smart card found.")
	}

	if serial == "" {
		if len(locations) > 1 {
			return nil, i18n.New("Multiple smart cards found but no serial specified.")
		}
		return locations[0].token(), nil
	}

	for _, location := range locations {
		if location.serial == serial {
			return location.token(), nil
		}
	}

	return nil, i18n.Errorf("No smart card found with serial number %s.", serial)
}

// DeviceInfos returns identification data for every smart card currently
// present, in the order the PKCS#11 modules report them. The cards of every
// module are listed, so that a YubiKey, a Rutoken and a JaCarta that need
// different modules are all reported, and a card that more than one module
// exposes is reported once.
func DeviceInfos() ([]*DeviceInfo, error) {
	modules, err := openModules()
	if err != nil {
		return nil, err
	}
	defer release(modules)

	locations := tokenLocations(modules)
	if len(locations) == 0 {
		return nil, i18n.New("No smart card found.")
	}

	infos := make([]*DeviceInfo, 0, len(locations))
	for _, location := range locations {
		tok := &pkcs11Token{
			ctx:    location.module.ctx,
			slotID: location.slotID,
			ykcs11: location.ykcs11,
			module: location.module.path,
		}
		info, err := tok.Info()
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}
	return infos, nil
}

// Info returns identification data for the token together with the
// certificates stored in its active slots.
func (t *pkcs11Token) Info() (*DeviceInfo, error) {
	ti, err := t.ctx.GetTokenInfo(t.slotID)
	if err != nil {
		return nil, i18n.Wrap(err, "Get token info")
	}

	info := &DeviceInfo{
		Name:            strings.TrimSpace(ti.Label),
		Module:          t.module,
		FirmwareVersion: formatFirmwareVersion(ti.FirmwareVersion.Major, ti.FirmwareVersion.Minor, t.ykcs11),
		SerialNumber:    strings.TrimSpace(ti.SerialNumber),
	}
	if value, ok := t.dataObject("Card Holder Unique Identifier", "CHUID"); ok {
		info.CHUID = strings.ToUpper(hex.EncodeToString(value))
	}
	if value, ok := t.dataObject("Card Capability Container", "CCC"); ok {
		info.CCC = strings.ToUpper(hex.EncodeToString(value))
	}

	// PIN/PUK retry counts are not exposed through PKCS#11, so they are read
	// from the PIV applet directly.
	info.PinRetries, info.PukRetries = t.RetryCounts()

	slots, err := t.Slots()
	if err != nil {
		return nil, err
	}
	for _, slot := range slots {
		cert, err := t.Certificate(slot)
		if err != nil {
			return nil, err
		}
		info.Slots = append(info.Slots, SlotInfo{Slot: slot, Certificate: cert})
	}
	return info, nil
}

// RetryCounts returns the number of remaining attempts the smart card offers
// for its PIN and PUK. A count that could not be read is reported as
// RetriesUnknown.
//
// The counts are not exposed through PKCS#11, so they are read from the PIV
// applet directly. The Card Holder Unique Identifier selects the right card
// when several are connected.
func (t *pkcs11Token) RetryCounts() (int, int) {
	chuid, _ := t.dataObject("Card Holder Unique Identifier", "CHUID")
	return readPIVRetries(strings.ToUpper(hex.EncodeToString(chuid)))
}

// dataObject returns the value of the first PKCS#11 data object whose CKA_LABEL
// matches one of labels, compared case-insensitively. The boolean result
// reports whether a matching object was found. Tokens that do not expose PIV
// data objects (such as some PKCS#11 modules) yield false.
func (t *pkcs11Token) dataObject(labels ...string) ([]byte, bool) {
	return tokenDataObject(t.ctx, t.slotID, labels...)
}

// tokenDataObject returns the value of the first PKCS#11 data object that the
// token of slotID exposes and whose CKA_LABEL matches one of labels, compared
// case-insensitively. The boolean result reports whether a matching object was
// found. Tokens that do not expose PIV data objects (such as some PKCS#11
// modules) yield false.
//
// It is a free function rather than a method so that a card can be identified by
// its data objects before a token handle for it exists, which is what lets the
// cards that the modules expose be deduplicated by CHUID.
func tokenDataObject(ctx *pkcs11.Ctx, slotID uint, labels ...string) ([]byte, bool) {
	sh, err := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, false
	}
	defer func() { _ = ctx.CloseSession(sh) }()

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
	}
	if err := ctx.FindObjectsInit(sh, template); err != nil {
		return nil, false
	}
	defer func() { _ = ctx.FindObjectsFinal(sh) }()

	for {
		objs, err := ctx.FindObjects(sh, 32)
		if err != nil || len(objs) == 0 {
			return nil, false
		}
		for _, obj := range objs {
			attrs, err := ctx.GetAttributeValue(sh, obj, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
				pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
			})
			if err != nil || len(attrs) != 2 {
				continue
			}
			if !labelMatches(strings.TrimSpace(string(attrs[0].Value)), labels) {
				continue
			}
			if len(attrs[1].Value) == 0 {
				continue
			}
			return attrs[1].Value, true
		}
	}
}

// normalizeCHUID returns the value of a CHUID data object as a PKCS#11 module
// reports it, with the wrapping 53 TLV removed when the module includes it. The
// YubiKey module returns the raw value while OpenSC returns the value wrapped in
// the TLV that a PIV card uses to return a data object, so the wrapper is
// removed when it is present to give the identifier that is the same whichever
// module reports it.
func normalizeCHUID(value []byte) []byte {
	if unwrapped, ok := dataObjectValue(value); ok {
		return unwrapped
	}
	return value
}

// tokenKey returns the key that identifies a card across the modules that
// expose it. The normalized CHUID is used whenever the module exposes one, so a
// card that the module of its vendor and OpenSC both see yields one key even
// though the two modules report different serial numbers for it. The serial
// number is the fallback for a card whose CHUID is not exposed through PKCS#11.
// An empty key means the card can be identified by neither.
func tokenKey(chuid []byte, chuidOK bool, serial string) string {
	if chuidOK {
		return "chuid:" + strings.ToUpper(hex.EncodeToString(normalizeCHUID(chuid)))
	}
	if serial != "" {
		return "serial:" + serial
	}
	return ""
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
		return 0, i18n.Wrap(err, "Open PKCS#11 session")
	}
	return sh, nil
}

// login authenticates sh with the user PIN.
//
// The PIN is obtained from the user and verified against the smart card,
// prompting again while the card reports it as incorrect. Once the card has no
// attempts left errPINBlocked is returned, which tells the user to unlock the
// PIN with the PUK.
func (t *pkcs11Token) login(sh pkcs11.SessionHandle) error {
	_, err := (secretPrompt{
		Name:     "PIN",
		Prompt:   pinPrompt{Description: i18n.Sprintf("Enter smart card PIN"), Prompt: "PIN:"},
		Validate: validatePIN,
		Verify: func(pin string) error {
			err := t.ctx.Login(sh, pkcs11.CKU_USER, pin)

			// A token that is already unlocked needs no PIN, so the session
			// can be used for signing as it is.
			if isPKCS11Error(err, uint(pkcs11.CKR_USER_ALREADY_LOGGED_IN)) {
				return nil
			}
			return classifySecret(err, errSecretIncorrect, errPINBlocked, "Login to token")
		},
		Attempts: func() int {
			pin, _ := t.RetryCounts()
			return pin
		},
		Blocked: errPINBlocked,
	}).ask()
	return err
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
		return nil, i18n.Wrap(err, "Read certificate")
	}
	if len(attrs) != 1 || len(attrs[0].Value) == 0 {
		return nil, i18n.New("Certificate value not found.")
	}

	cert, err := x509.ParseCertificate(attrs[0].Value)
	if err != nil {
		return nil, i18n.Wrap(err, "Parse certificate")
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
		return nil, i18n.Wrap(err, "Start object search")
	}
	defer func() { _ = t.ctx.FindObjectsFinal(sh) }()

	for {
		objs, err := t.ctx.FindObjects(sh, 100)
		if err != nil {
			return nil, i18n.Wrap(err, "Search objects")
		}
		if len(objs) == 0 {
			break
		}
		for _, obj := range objs {
			attrs, err := t.ctx.GetAttributeValue(sh, obj, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			})
			if err != nil {
				return nil, i18n.Wrap(err, "Read object ID")
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
func (t *pkcs11Token) Signer(slot Slot) (crypto.Signer, error) {
	cert, err := t.Certificate(slot)
	if err != nil {
		return nil, err
	}
	return &pkcs11Signer{
		token: t,
		slot:  slot,
		pub:   cert.PublicKey,
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
		return 0, i18n.Wrap(err, "Start object search")
	}
	defer func() { _ = t.ctx.FindObjectsFinal(sh) }()

	objs, err := t.ctx.FindObjects(sh, 1)
	if err != nil {
		return 0, i18n.Wrap(err, "Search objects")
	}
	if len(objs) == 0 {
		return 0, i18n.Errorf("Object not found for slot %s.", slot)
	}
	return objs[0], nil
}

// Reset restores the factory state of the token: the keys and certificates
// stored in the PIV slots are erased, and the PIN, the PUK and the card
// management key are the factory defaults.
//
// A PIV card only accepts the RESET command once its PIN and PUK are blocked,
// so both are blocked first. The reset needs neither the PIN, the PUK nor the
// management key of the card.
//
// The command is not exposed through PKCS#11, so the card is reset over PC/SC.
// C_InitToken cannot be used instead: it authenticates with the management key
// it is given before it resets the applet, so it fails on a card whose
// management key is no longer the factory default.
func (t *pkcs11Token) Reset() error {
	chuid, _ := t.dataObject("Card Holder Unique Identifier", "CHUID")
	if err := resetPIV(strings.ToUpper(hex.EncodeToString(chuid))); err != nil {
		return i18n.Wrap(err, "Reset smart card")
	}
	return nil
}

// Card returns a session with the PIV application of the token, which offers the
// commands that PKCS#11 does not expose.
//
// The commands run over PC/SC, and the Card Holder Unique Identifier selects the
// right smart card when several are connected.
func (t *pkcs11Token) Card() (PIVCard, error) {
	chuid, _ := t.dataObject("Card Holder Unique Identifier", "CHUID")
	return openPIVCard(strings.ToUpper(hex.EncodeToString(chuid)))
}

// Unlock unlocks the user PIN with the PUK and sets it to newPIN, which resets
// the PIN and PUK retry counters of the card.
//
// A PIV card unlocks a blocked PIN with the RESET RETRY COUNTER command, which
// is only accepted once the PUK has been verified. The YubiKey PKCS#11 module
// performs both steps when C_SetPIN is called with the PUK and the new PIN
// tagged with the "puk:" and "pin:" prefixes, which is how a PIV card is
// unlocked over PKCS#11. Modules that do not know this convention cannot
// unlock a PIN.
func (t *pkcs11Token) Unlock(puk, newPIN string) error {
	if !t.ykcs11 {
		return i18n.New("Unlocking a PIN requires the YubiKey PKCS#11 module.")
	}

	sh, err := t.openSession()
	if err != nil {
		return err
	}
	defer func() { _ = t.ctx.CloseSession(sh) }()

	return classifySecret(
		t.ctx.SetPIN(sh, "puk:"+puk, "pin:"+newPIN),
		errSecretIncorrect,
		errPUKBlocked,
		"Unlock PIN",
	)
}

// pkcs11Signer implements crypto.Signer using a PKCS#11 private key object.
type pkcs11Signer struct {
	token *pkcs11Token
	slot  Slot
	pub   crypto.PublicKey
}

func (s *pkcs11Signer) Public() crypto.PublicKey {
	return s.pub
}

func (s *pkcs11Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// The card authentication key (9E) is used without the user PIN, and a
	// PKCS#11 module does not make a private key object visible before a login.
	// Signing the slot over PC/SC therefore avoids a PIN prompt that the PIV
	// applet does not ask for; the other slots keep using the module.
	if s.slot == SlotCardAuthentication {
		return s.token.cardAuthenticationSign(s.pub, digest, opts)
	}

	sh, err := s.token.openSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.token.ctx.CloseSession(sh) }()

	// Private key objects are only visible after a user login, so authenticate
	// (which asks the user for the PIN through pinentry) before attempting to
	// locate the key.
	if err := s.token.login(sh); err != nil {
		return nil, err
	}

	key, err := s.token.findObject(sh, pkcs11.CKO_PRIVATE_KEY, s.slot)
	if err != nil {
		return nil, err
	}

	return s.sign(sh, key, digest, opts)
}

// cardAuthenticationSign signs digest with the card authentication key of the
// token over PC/SC, which does not require the user PIN.
//
// The Card Holder Unique Identifier selects the right smart card when several
// are connected, like it does for the other commands that run outside the
// PKCS#11 module.
func (t *pkcs11Token) cardAuthenticationSign(pub crypto.PublicKey, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	chuid, _ := t.dataObject("Card Holder Unique Identifier", "CHUID")
	return signCardAuthentication(strings.ToUpper(hex.EncodeToString(chuid)), pub, digest, opts)
}

func (s *pkcs11Signer) sign(sh pkcs11.SessionHandle, key pkcs11.ObjectHandle, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch s.pub.(type) {
	case *ecdsa.PublicKey:
		if err := s.token.ctx.SignInit(sh, pkcs11.NewMechanism(pkcs11.CKM_ECDSA), key); err != nil {
			return nil, i18n.Wrap(err, "Initialize signature")
		}
		raw, err := s.token.ctx.Sign(sh, digest)
		if err != nil {
			return nil, i18n.Wrap(err, "Sign")
		}
		return encodeECDSASignature(raw)
	case *rsa.PublicKey:
		hash := opts.HashFunc()
		info, err := pkcs1DigestInfo(hash, digest)
		if err != nil {
			return nil, err
		}
		if err := s.token.ctx.SignInit(sh, pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS), key); err != nil {
			return nil, i18n.Wrap(err, "Initialize signature")
		}
		return s.token.ctx.Sign(sh, info)
	default:
		return nil, i18n.Errorf("Unsupported key type %T.", s.pub)
	}
}

var _ crypto.Signer = (*pkcs11Signer)(nil)

var _ Pivzavr = (*pkcs11Token)(nil)
