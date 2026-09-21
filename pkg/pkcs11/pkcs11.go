//go:build darwin || freebsd || linux || netbsd || windows

// Package pkcs11 is a small, self-contained binding to the PKCS#11 (Cryptoki)
// API. It loads a PKCS#11 module at run time and calls the entry points that
// the module publishes through C_GetFunctionList, so neither a build nor a run
// of a program that uses the package needs a C toolchain or the development
// headers of the module.
//
// The API is deliberately narrow: it covers the operations pivzavr needs to
// drive a smart card token, which are the enumeration of the tokens that are
// present, sessions with a token, a login, searches for objects and attributes
// and signatures. The parts of the API that a general-purpose binding exposes
// but pivzavr does not use are left out.
//
// The names of the specification are kept as they are (Attribute, CKA_VALUE,
// CKR_PIN_INCORRECT, ...). CK_ULONG is the one type of the specification whose
// width differs between the platforms; see ckULong.
package pkcs11

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/ebitengine/purego"
)

// Object classes (CK_OBJECT_CLASS) of the objects this package looks for.
const (
	CKO_DATA        = 0x00000000
	CKO_CERTIFICATE = 0x00000001
	CKO_PRIVATE_KEY = 0x00000003
)

// Attributes (CK_ATTRIBUTE_TYPE) of the objects this package reads.
const (
	CKA_CLASS = 0x00000000
	CKA_LABEL = 0x00000003
	CKA_VALUE = 0x00000011
	CKA_ID    = 0x00000102
)

// Flags (CK_FLAGS) that a session is opened with. A serial session is what the
// specification asks for when the application may be multi-threaded, and a
// read/write session is what signing through the token needs.
const (
	CKF_RW_SESSION     = 0x00000002
	CKF_SERIAL_SESSION = 0x00000004
)

// ckfOSLockingOK tells a module that it may use its own locking of the
// operating system, which an application that may use the module from several
// threads reports instead of providing the locking functions itself.
const ckfOSLockingOK = 0x00000002

// User types (CK_USER_TYPE) of a login. The user PIN of a PIV card is the one
// pivzavr logs in with.
const (
	CKU_USER = 0x00000001
)

// Mechanisms (CK_MECHANISM_TYPE) that this package signs with.
const (
	CKM_RSA_PKCS = 0x00000001
	CKM_ECDSA    = 0x00001041

	// The signature mechanisms of GOST R 34.10-2012, which a Rutoken ECP or a
	// JaCarta uses for a key on a GOST curve. A 256-bit key is signed with
	// CKM_GOSTR3410_2012_256 and a 512-bit key with CKM_GOSTR3410_2012_512.
	CKM_GOSTR3410_2012_256 = 0x00001205
	CKM_GOSTR3410_2012_512 = 0x00001206

	// The digest mechanisms of GOST R 34.11-2012. They are listed for
	// completeness: pivzavr computes the digest itself and only the signature
	// is performed by the module.
	CKM_GOSTR3411_2012_256 = 0x00001213
	CKM_GOSTR3411_2012_512 = 0x00001214
)

// unavailableInformation is CK_UNAVAILABLE_INFORMATION, the value a module
// reports as the size of an attribute that it cannot read, because the
// attribute is sensitive or does not exist on the object.
const unavailableInformation = ^ckULong(0)

// Error is a status code (CK_RV) returned by a PKCS#11 module. The codes of the
// specification that a caller can tell apart are named below; the string form
// of an Error reports the name of the code, which is what a failure can be
// looked up under in the specification.
type Error ckULong

// Status codes (CK_RV) of the PKCS#11 specification.
const (
	CKR_OK                        Error = 0x00000000
	CKR_HOST_MEMORY               Error = 0x00000002
	CKR_SLOT_ID_INVALID           Error = 0x00000003
	CKR_GENERAL_ERROR             Error = 0x00000005
	CKR_FUNCTION_FAILED           Error = 0x00000006
	CKR_ARGUMENTS_BAD             Error = 0x00000007
	CKR_ATTRIBUTE_TYPE_INVALID    Error = 0x00000012
	CKR_ATTRIBUTE_VALUE_INVALID   Error = 0x00000013
	CKR_DATA_LEN_RANGE            Error = 0x00000021
	CKR_DEVICE_ERROR              Error = 0x00000030
	CKR_FUNCTION_NOT_SUPPORTED    Error = 0x00000054
	CKR_KEY_HANDLE_INVALID        Error = 0x00000060
	CKR_MECHANISM_INVALID         Error = 0x00000070
	CKR_OBJECT_HANDLE_INVALID     Error = 0x00000082
	CKR_OPERATION_NOT_INITIALIZED Error = 0x00000091
	CKR_PIN_INCORRECT             Error = 0x000000A0
	CKR_PIN_INVALID               Error = 0x000000A1
	CKR_PIN_LEN_RANGE             Error = 0x000000A2
	CKR_PIN_EXPIRED               Error = 0x000000A3
	CKR_PIN_LOCKED                Error = 0x000000A4
	CKR_SESSION_COUNT             Error = 0x000000B1
	CKR_SESSION_HANDLE_INVALID    Error = 0x000000B3
	CKR_TEMPLATE_INCOMPLETE       Error = 0x000000D0
	CKR_TOKEN_NOT_PRESENT         Error = 0x000000E0
	CKR_USER_ALREADY_LOGGED_IN    Error = 0x00000100
	CKR_USER_NOT_LOGGED_IN        Error = 0x00000101
	CKR_BUFFER_TOO_SMALL          Error = 0x00000150
	CKR_CRYPTOKI_NOT_INITIALIZED  Error = 0x00000190
)

// errorNames maps a status code to its name in the specification, which is what
// the string form of an Error reports.
//
// #nosec G101 -- the names are the status codes of the specification, so
// CKR_TOKEN_NOT_PRESENT is the name of a code and not a credential.
var errorNames = map[Error]string{
	CKR_OK:                        "CKR_OK",
	CKR_HOST_MEMORY:               "CKR_HOST_MEMORY",
	CKR_SLOT_ID_INVALID:           "CKR_SLOT_ID_INVALID",
	CKR_GENERAL_ERROR:             "CKR_GENERAL_ERROR",
	CKR_FUNCTION_FAILED:           "CKR_FUNCTION_FAILED",
	CKR_ARGUMENTS_BAD:             "CKR_ARGUMENTS_BAD",
	CKR_ATTRIBUTE_TYPE_INVALID:    "CKR_ATTRIBUTE_TYPE_INVALID",
	CKR_ATTRIBUTE_VALUE_INVALID:   "CKR_ATTRIBUTE_VALUE_INVALID",
	CKR_DATA_LEN_RANGE:            "CKR_DATA_LEN_RANGE",
	CKR_DEVICE_ERROR:              "CKR_DEVICE_ERROR",
	CKR_FUNCTION_NOT_SUPPORTED:    "CKR_FUNCTION_NOT_SUPPORTED",
	CKR_KEY_HANDLE_INVALID:        "CKR_KEY_HANDLE_INVALID",
	CKR_MECHANISM_INVALID:         "CKR_MECHANISM_INVALID",
	CKR_OBJECT_HANDLE_INVALID:     "CKR_OBJECT_HANDLE_INVALID",
	CKR_OPERATION_NOT_INITIALIZED: "CKR_OPERATION_NOT_INITIALIZED",
	CKR_PIN_INCORRECT:             "CKR_PIN_INCORRECT",
	CKR_PIN_INVALID:               "CKR_PIN_INVALID",
	CKR_PIN_LEN_RANGE:             "CKR_PIN_LEN_RANGE",
	CKR_PIN_EXPIRED:               "CKR_PIN_EXPIRED",
	CKR_PIN_LOCKED:                "CKR_PIN_LOCKED",
	CKR_SESSION_COUNT:             "CKR_SESSION_COUNT",
	CKR_SESSION_HANDLE_INVALID:    "CKR_SESSION_HANDLE_INVALID",
	CKR_TEMPLATE_INCOMPLETE:       "CKR_TEMPLATE_INCOMPLETE",
	CKR_TOKEN_NOT_PRESENT:         "CKR_TOKEN_NOT_PRESENT",
	CKR_USER_ALREADY_LOGGED_IN:    "CKR_USER_ALREADY_LOGGED_IN",
	CKR_USER_NOT_LOGGED_IN:        "CKR_USER_NOT_LOGGED_IN",
	CKR_BUFFER_TOO_SMALL:          "CKR_BUFFER_TOO_SMALL",
	CKR_CRYPTOKI_NOT_INITIALIZED:  "CKR_CRYPTOKI_NOT_INITIALIZED",
}

// Name returns the name of the status code in the specification, or an empty
// string when the code is not one that this package knows.
func (e Error) Name() string {
	return errorNames[e]
}

// Error implements error. The message names the status code, so that a failure
// can be looked up in the specification.
func (e Error) Error() string {
	if name := errorNames[e]; name != "" {
		return fmt.Sprintf("pkcs11: 0x%X: %s", ckULong(e), name)
	}
	return fmt.Sprintf("pkcs11: unknown error 0x%X", ckULong(e))
}

// toError converts the status code that a call returned into an error. A call
// that succeeded reports CKR_OK, which is not an error, so a caller can return
// the result unchanged.
func toError(rv ckULong) error {
	if rv == ckULong(CKR_OK) {
		return nil
	}
	return Error(rv)
}

// SessionHandle is the value a module uses to identify a session with a token.
type SessionHandle uint

// ObjectHandle is the value a module uses to identify an object on a token.
type ObjectHandle uint

// Version is a CK_VERSION: the major and the minor part of a version number.
type Version struct {
	Major byte
	Minor byte
}

// TokenInfo is the CK_TOKEN_INFO that a module reports for the token in a slot.
// The character fields of the specification are padded with spaces at their
// end, which is why the trailing spaces are removed here.
type TokenInfo struct {
	Label              string // 32 bytes.
	ManufacturerID     string // 32 bytes.
	Model              string // 16 bytes.
	SerialNumber       string // 16 bytes.
	Flags              uint
	MaxSessionCount    uint
	SessionCount       uint
	MaxRwSessionCount  uint
	RwSessionCount     uint
	MaxPinLen          uint
	MinPinLen          uint
	TotalPublicMemory  uint
	FreePublicMemory   uint
	TotalPrivateMemory uint
	FreePrivateMemory  uint
	HardwareVersion    Version
	FirmwareVersion    Version
	UTCTime            string // 16 bytes.
}

// Attribute is a CK_ATTRIBUTE as the Go API sees it: the type of an attribute
// together with its value. NewAttribute builds one for a search, and the
// attributes that a module reported carry the value the module returned.
type Attribute struct {
	Type  uint
	Value []byte
}

// NewAttribute returns an attribute of the given type. A nil value asks a
// module for the size of the attribute instead of its content, which is what
// GetAttributeValue does. A value is a byte slice, a string, a bool or an
// integer; an integer is encoded as the CK_ULONG that the specification uses
// for an attribute that holds a number.
func NewAttribute(typ uint, value any) *Attribute {
	attribute := &Attribute{Type: typ}
	switch v := value.(type) {
	case nil:
	case bool:
		attribute.Value = []byte{0}
		if v {
			attribute.Value = []byte{1}
		}
	case []byte:
		attribute.Value = v
	case string:
		attribute.Value = []byte(v)
	case int:
		attribute.Value = signedUlongBytes(int64(v))
	case int8:
		attribute.Value = signedUlongBytes(int64(v))
	case int16:
		attribute.Value = signedUlongBytes(int64(v))
	case int32:
		attribute.Value = signedUlongBytes(int64(v))
	case int64:
		attribute.Value = signedUlongBytes(v)
	case uint:
		attribute.Value = ulongBytes(uint64(v))
	case uint8:
		attribute.Value = ulongBytes(uint64(v))
	case uint16:
		attribute.Value = ulongBytes(uint64(v))
	case uint32:
		attribute.Value = ulongBytes(uint64(v))
	case uint64:
		attribute.Value = ulongBytes(v)
	default:
		panic(fmt.Sprintf("pkcs11: unsupported attribute value type %T", value))
	}
	return attribute
}

// Mechanism is a CK_MECHANISM: the mechanism of a cryptographic operation. The
// mechanisms this package signs with take no parameter, so a mechanism is only
// its type.
type Mechanism struct {
	Mechanism uint
}

// NewMechanism returns a mechanism of the given type. None of the mechanisms
// this package signs with takes a parameter, which is why there is no way to set
// one.
func NewMechanism(mechanism uint) *Mechanism {
	return &Mechanism{Mechanism: mechanism}
}

// ulongBytes returns x as the bytes of a CK_ULONG, which is the form a module
// expects an attribute that holds a number in. The bytes are in the byte order
// of the platform, because a module reads an attribute value in that order.
func ulongBytes(x uint64) []byte {
	buf := make([]byte, unsafe.Sizeof(ckULong(0)))
	if len(buf) == 4 {
		binary.NativeEndian.PutUint32(buf, uint32(x)) // #nosec G115 -- a CK_ULONG of four bytes holds the low four bytes of x.
	} else {
		binary.NativeEndian.PutUint64(buf, x)
	}
	return buf
}

// signedUlongBytes returns x as the bytes of a CK_ULONG. An attribute that
// holds a number is a class or a count of a token, so its value is never
// negative; the conversion of a signed value is done here once instead of in
// every case of NewAttribute.
func signedUlongBytes(x int64) []byte {
	return ulongBytes(uint64(x)) // #nosec G115 -- the low bytes of the value are the CK_ULONG.
}

// The structures below are the ones the C API of PKCS#11 defines. They are
// unexported because they are an implementation detail: a caller works with the
// Go types above. Each of them has the same layout as its C counterpart, which
// is what lets a module read and write them.

// ckAttribute is CK_ATTRIBUTE: the type of an attribute, a pointer to the value
// of the attribute and the length of that value.
type ckAttribute struct {
	typ      ckULong
	value    unsafe.Pointer
	valueLen ckULong
}

// ckMechanism is CK_MECHANISM: the mechanism of an operation, a pointer to the
// parameter of the mechanism and the length of that parameter.
type ckMechanism struct {
	mechanism    ckULong
	parameter    unsafe.Pointer
	parameterLen ckULong
}

// ckTokenInfo is CK_TOKEN_INFO: the character fields of the specification, which
// are all padded with spaces, the counters of the token and two versions of two
// bytes.
type ckTokenInfo struct {
	label              [32]byte
	manufacturerID     [32]byte
	model              [16]byte
	serialNumber       [16]byte
	flags              ckULong
	maxSessionCount    ckULong
	sessionCount       ckULong
	maxRwSessionCount  ckULong
	rwSessionCount     ckULong
	maxPinLen          ckULong
	minPinLen          ckULong
	totalPublicMemory  ckULong
	freePublicMemory   ckULong
	totalPrivateMemory ckULong
	freePrivateMemory  ckULong
	hardwareVersion    [2]byte
	firmwareVersion    [2]byte
	utcTime            [16]byte
}

// ckInitializeArgs is CK_C_INITIALIZE_ARGS. The four locking functions are left
// null together with CKF_OS_LOCKING_OK, which tells the module that it may lock
// with the operating system itself instead of calling back into the application.
type ckInitializeArgs struct {
	createMutex  uintptr
	destroyMutex uintptr
	lockMutex    uintptr
	unlockMutex  uintptr
	flags        ckULong
	reserved     unsafe.Pointer
}

// functionList is the CK_FUNCTION_LIST that a module publishes: the version of
// the module followed by its entry points in the order the specification defines
// them. Only the entry points up to C_Sign are declared, because the package uses
// no other one; the fields of a structure are laid out in the order they are
// declared, so leaving out a later entry point does not move the ones that are
// declared before it.
type functionList struct {
	version           [2]byte
	initialize        uintptr
	finalize          uintptr
	getInfo           uintptr
	getFunctionList   uintptr
	getSlotList       uintptr
	getSlotInfo       uintptr
	getTokenInfo      uintptr
	getMechanismList  uintptr
	getMechanismInfo  uintptr
	initToken         uintptr
	initPIN           uintptr
	setPIN            uintptr
	openSession       uintptr
	closeSession      uintptr
	closeAllSessions  uintptr
	getSessionInfo    uintptr
	getOperationState uintptr
	setOperationState uintptr
	login             uintptr
	logout            uintptr
	createObject      uintptr
	copyObject        uintptr
	destroyObject     uintptr
	getObjectSize     uintptr
	getAttributeValue uintptr
	setAttributeValue uintptr
	findObjectsInit   uintptr
	findObjects       uintptr
	findObjectsFinal  uintptr
	encryptInit       uintptr
	encrypt           uintptr
	encryptUpdate     uintptr
	encryptFinal      uintptr
	decryptInit       uintptr
	decrypt           uintptr
	decryptUpdate     uintptr
	decryptFinal      uintptr
	digestInit        uintptr
	digest            uintptr
	digestUpdate      uintptr
	digestKey         uintptr
	digestFinal       uintptr
	signInit          uintptr
	sign              uintptr
}

// functions are the entry points of a module as functions that can be called
// from Go. Their signatures are the ones of the specification, with the types of
// this package in place of the C ones: a status code is returned and every other
// result travels in a pointer argument.
type functions struct {
	initialize        func(args *ckInitializeArgs) ckULong
	finalize          func(reserved unsafe.Pointer) ckULong
	getSlotList       func(tokenPresent byte, slots *ckULong, count *ckULong) ckULong
	getTokenInfo      func(slotID ckULong, info *ckTokenInfo) ckULong
	setPIN            func(sh ckULong, oldPin *byte, oldLen ckULong, newPin *byte, newLen ckULong) ckULong
	openSession       func(slotID ckULong, flags ckULong, application unsafe.Pointer, notify uintptr, sh *ckULong) ckULong
	closeSession      func(sh ckULong) ckULong
	login             func(sh ckULong, userType ckULong, pin *byte, pinLen ckULong) ckULong
	getAttributeValue func(sh ckULong, object ckULong, template *ckAttribute, count ckULong) ckULong
	findObjectsInit   func(sh ckULong, template *ckAttribute, count ckULong) ckULong
	findObjects       func(sh ckULong, objects *ckULong, count ckULong, found *ckULong) ckULong
	findObjectsFinal  func(sh ckULong) ckULong
	signInit          func(sh ckULong, mechanism *ckMechanism, key ckULong) ckULong
	sign              func(sh ckULong, data *byte, dataLen ckULong, signature *byte, signatureLen *ckULong) ckULong
}

// register turns the entry points of list into the callable functions of f. Every
// entry point this package uses has to be present, because a module that does not
// offer one cannot serve the operations of this package.
func (f *functions) register(list *functionList) error {
	entryPoints := []struct {
		name  string
		entry uintptr
		into  any
	}{
		{"C_Initialize", list.initialize, &f.initialize},
		{"C_Finalize", list.finalize, &f.finalize},
		{"C_GetSlotList", list.getSlotList, &f.getSlotList},
		{"C_GetTokenInfo", list.getTokenInfo, &f.getTokenInfo},
		{"C_SetPIN", list.setPIN, &f.setPIN},
		{"C_OpenSession", list.openSession, &f.openSession},
		{"C_CloseSession", list.closeSession, &f.closeSession},
		{"C_Login", list.login, &f.login},
		{"C_GetAttributeValue", list.getAttributeValue, &f.getAttributeValue},
		{"C_FindObjectsInit", list.findObjectsInit, &f.findObjectsInit},
		{"C_FindObjects", list.findObjects, &f.findObjects},
		{"C_FindObjectsFinal", list.findObjectsFinal, &f.findObjectsFinal},
		{"C_SignInit", list.signInit, &f.signInit},
		{"C_Sign", list.sign, &f.sign},
	}
	for _, entryPoint := range entryPoints {
		if entryPoint.entry == 0 {
			return fmt.Errorf("pkcs11: the module does not offer %s", entryPoint.name)
		}
		purego.RegisterFunc(entryPoint.into, entryPoint.entry)
	}
	return nil
}

// Ctx is a PKCS#11 module that was loaded into the process. A context is created
// with New, initialized with Initialize and released with Destroy.
type Ctx struct {
	handle      uintptr
	functions   functions
	initialized bool
}

// New loads the PKCS#11 module at path and resolves the entry points this
// package uses. The module is not initialized yet, which Initialize does. The
// caller owns the returned context and has to release it with Destroy.
func New(path string) (*Ctx, error) {
	handle, err := loadLibrary(path)
	if err != nil {
		return nil, fmt.Errorf("load PKCS#11 module %q: %w", path, err)
	}

	list, err := functionListOf(handle)
	if err == nil {
		ctx := &Ctx{handle: handle}
		err = ctx.functions.register(list)
		if err == nil {
			return ctx, nil
		}
	}
	_ = unloadLibrary(handle)
	return nil, fmt.Errorf("load PKCS#11 module %q: %w", path, err)
}

// functionListOf asks the module of handle for its function list, which is how a
// PKCS#11 library publishes its entry points: the library exports
// C_GetFunctionList, and the pointer that call reports points at the whole list.
func functionListOf(handle uintptr) (*functionList, error) {
	address, err := loadSymbol(handle, "C_GetFunctionList")
	if err != nil {
		return nil, fmt.Errorf("find C_GetFunctionList: %w", err)
	}

	var getFunctionList func(list *unsafe.Pointer) ckULong
	purego.RegisterFunc(&getFunctionList, address)

	var list unsafe.Pointer
	if err := toError(getFunctionList(&list)); err != nil {
		return nil, err
	}
	if list == nil {
		return nil, errors.New("the module reported no function list")
	}
	return (*functionList)(list), nil
}

// Destroy finalizes the module and unloads it. A context that was never
// initialized is unloaded without a finalize call, and a context that was
// destroyed already is left alone, so that Destroy can be deferred safely.
func (c *Ctx) Destroy() {
	if c == nil || c.handle == 0 {
		return
	}
	if c.initialized {
		_ = c.functions.finalize(nil)
		c.initialized = false
	}
	_ = unloadLibrary(c.handle)
	c.handle = 0
}

// Initialize initializes the module. It has to be called before any other
// operation of the context, and initializing a context that was initialized
// already is not an error. The module is told that it may lock with the
// operating system itself, which is what an application that may use the module
// from several threads reports.
func (c *Ctx) Initialize() error {
	if c == nil || c.handle == 0 {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if c.initialized {
		return nil
	}
	args := ckInitializeArgs{flags: ckfOSLockingOK}
	if err := toError(c.functions.initialize(&args)); err != nil {
		return err
	}
	c.initialized = true
	return nil
}

// GetSlotList returns the IDs of the slots that are present. tokenPresent asks
// for the slots that hold a token, which is what a caller that looks for a smart
// card wants.
func (c *Ctx) GetSlotList(tokenPresent bool) ([]uint, error) {
	if c == nil || c.handle == 0 {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// The first call asks the module for the number of slots, the second one
	// fills a list of that size.
	present := ckULong(0)
	if tokenPresent {
		present = 1
	}

	var count ckULong
	if err := toError(c.functions.getSlotList(byte(present), nil, &count)); err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}

	slots := make([]ckULong, count)
	if err := toError(c.functions.getSlotList(byte(present), &slots[0], &count)); err != nil {
		return nil, err
	}
	if int(count) < len(slots) {
		// A module may report fewer slots the second time, for example when a
		// token was removed in between.
		slots = slots[:count]
	}

	ids := make([]uint, len(slots))
	for i, slot := range slots {
		ids[i] = uint(slot)
	}
	return ids, nil
}

// GetTokenInfo returns the information that the token in slot reports about
// itself.
func (c *Ctx) GetTokenInfo(slotID uint) (TokenInfo, error) {
	if c == nil || c.handle == 0 {
		return TokenInfo{}, CKR_CRYPTOKI_NOT_INITIALIZED
	}
	var info ckTokenInfo
	if err := toError(c.functions.getTokenInfo(ckULong(slotID), &info)); err != nil {
		return TokenInfo{}, err
	}
	return TokenInfo{
		Label:              paddedString(info.label[:]),
		ManufacturerID:     paddedString(info.manufacturerID[:]),
		Model:              paddedString(info.model[:]),
		SerialNumber:       paddedString(info.serialNumber[:]),
		Flags:              uint(info.flags),
		MaxSessionCount:    uint(info.maxSessionCount),
		SessionCount:       uint(info.sessionCount),
		MaxRwSessionCount:  uint(info.maxRwSessionCount),
		RwSessionCount:     uint(info.rwSessionCount),
		MaxPinLen:          uint(info.maxPinLen),
		MinPinLen:          uint(info.minPinLen),
		TotalPublicMemory:  uint(info.totalPublicMemory),
		FreePublicMemory:   uint(info.freePublicMemory),
		TotalPrivateMemory: uint(info.totalPrivateMemory),
		FreePrivateMemory:  uint(info.freePrivateMemory),
		HardwareVersion:    Version{Major: info.hardwareVersion[0], Minor: info.hardwareVersion[1]},
		FirmwareVersion:    Version{Major: info.firmwareVersion[0], Minor: info.firmwareVersion[1]},
		UTCTime:            paddedString(info.utcTime[:]),
	}, nil
}

// paddedString converts a character field of a structure of the specification,
// which is padded with spaces at its end, into a string.
func paddedString(field []byte) string {
	return strings.TrimRight(string(field), " ")
}

// OpenSession opens a session with the token in slot. The flags are the CKF_
// flags of the specification; a caller that signs through the token asks for a
// serial read/write session, which is CKF_SERIAL_SESSION|CKF_RW_SESSION.
func (c *Ctx) OpenSession(slotID uint, flags uint) (SessionHandle, error) {
	if c == nil || c.handle == 0 {
		return 0, CKR_CRYPTOKI_NOT_INITIALIZED
	}
	var session ckULong
	// The application pointer and the notification callback are left null,
	// which is what an application that does not want to be called back uses.
	if err := toError(c.functions.openSession(ckULong(slotID), ckULong(flags), nil, 0, &session)); err != nil {
		return 0, err
	}
	return SessionHandle(session), nil
}

// CloseSession ends a session.
func (c *Ctx) CloseSession(sh SessionHandle) error {
	if c == nil || c.handle == 0 {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	return toError(c.functions.closeSession(ckULong(sh)))
}

// Login logs the session in as userType with pin, which is what a PIV card
// requires before its private keys can be used. CKU_USER is the user PIN; the
// card management key is the security officer PIN, which is not CKU_USER.
func (c *Ctx) Login(sh SessionHandle, userType uint, pin string) error {
	if c == nil || c.handle == 0 {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	return toError(c.functions.login(ckULong(sh), ckULong(userType), stringPointer(pin), ckULong(len(pin))))
}

// SetPIN changes the PIN of the token in the session from oldPIN to newPIN.
func (c *Ctx) SetPIN(sh SessionHandle, oldPIN, newPIN string) error {
	if c == nil || c.handle == 0 {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	return toError(c.functions.setPIN(ckULong(sh), stringPointer(oldPIN), ckULong(len(oldPIN)), stringPointer(newPIN), ckULong(len(newPIN))))
}

// FindObjectsInit starts a search for the objects that match template. The
// search has to be finished with FindObjectsFinal, also when it found nothing.
// An empty template matches every object of the token.
func (c *Ctx) FindObjectsInit(sh SessionHandle, template []*Attribute) error {
	if c == nil || c.handle == 0 {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	attributes := attributeList(template)

	var list *ckAttribute
	if len(attributes) > 0 {
		list = &attributes[0]
	}
	return toError(c.functions.findObjectsInit(ckULong(sh), list, ckULong(len(attributes))))
}

// FindObjects returns the next objects that the search started with
// FindObjectsInit matches, at most limit of them. An empty result means that
// the search is done, and calling the method again returns the following
// objects.
func (c *Ctx) FindObjects(sh SessionHandle, limit int) ([]ObjectHandle, error) {
	if c == nil || c.handle == 0 {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if limit <= 0 {
		return nil, nil
	}

	objects := make([]ckULong, limit)
	var found ckULong
	if err := toError(c.functions.findObjects(ckULong(sh), &objects[0], ckULong(limit), &found)); err != nil {
		return nil, err
	}
	if int(found) < len(objects) {
		objects = objects[:found]
	}

	handles := make([]ObjectHandle, len(objects))
	for i, object := range objects {
		handles[i] = ObjectHandle(object)
	}
	return handles, nil
}

// FindObjectsFinal ends the search that FindObjectsInit started.
func (c *Ctx) FindObjectsFinal(sh SessionHandle) error {
	if c == nil || c.handle == 0 {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	return toError(c.functions.findObjectsFinal(ckULong(sh)))
}

// GetAttributeValue returns the value of every attribute of template, in the
// order of the template. The type of an attribute of the template selects the
// attribute to read; its value is not used, and a module reports an empty value
// for an attribute it cannot read.
func (c *Ctx) GetAttributeValue(sh SessionHandle, object ObjectHandle, template []*Attribute) ([]*Attribute, error) {
	if c == nil || c.handle == 0 {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if len(template) == 0 {
		return nil, nil
	}

	// The first call asks the module for the size of every value, the second
	// one fills the buffers that were allocated for them.
	attributes := make([]ckAttribute, len(template))
	for i, attribute := range template {
		attributes[i].typ = ckULong(attribute.Type)
	}
	if err := toError(c.functions.getAttributeValue(ckULong(sh), ckULong(object), &attributes[0], ckULong(len(attributes)))); err != nil {
		return nil, err
	}

	values := make([][]byte, len(attributes))
	for i := range attributes {
		if attributes[i].valueLen == unavailableInformation {
			// The module cannot read this attribute, which is how it
			// reports an attribute that is sensitive or absent.
			continue
		}
		values[i] = make([]byte, attributes[i].valueLen)
		// #nosec G103 -- the buffer is passed to C_GetAttributeValue, which only writes into it for the duration of the call.
		attributes[i].value = unsafe.Pointer(unsafe.SliceData(values[i]))
	}
	if err := toError(c.functions.getAttributeValue(ckULong(sh), ckULong(object), &attributes[0], ckULong(len(attributes)))); err != nil {
		return nil, err
	}

	result := make([]*Attribute, len(attributes))
	for i := range attributes {
		attribute := &Attribute{Type: uint(attributes[i].typ)}
		if value := values[i]; value != nil {
			// The module reports the length of what it wrote, which can be
			// shorter than the buffer that was allocated for it.
			if length := int(attributes[i].valueLen); length < len(value) { // #nosec G115 -- the length fits the buffer that was allocated for it.
				value = value[:length]
			}
			attribute.Value = value
		}
		result[i] = attribute
	}
	return result, nil
}

// SignInit starts a signature operation in the session with the private key of
// key. The mechanism selects the kind of signature: a PIV card signs an ECDSA
// key with CKM_ECDSA and an RSA key with CKM_RSA_PKCS.
func (c *Ctx) SignInit(sh SessionHandle, mechanism *Mechanism, key ObjectHandle) error {
	if c == nil || c.handle == 0 {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if mechanism == nil {
		return errors.New("pkcs11: no signature mechanism")
	}

	ck := ckMechanism{mechanism: ckULong(mechanism.Mechanism)}
	return toError(c.functions.signInit(ckULong(sh), &ck, ckULong(key)))
}

// Sign signs message in the operation that SignInit started. The module signs
// the message as one part: an ECDSA key is given the digest, an RSA key the
// DigestInfo of the digest. The signature is returned in the raw form of the
// specification, which for an ECDSA key is the concatenation of r and s, each
// padded to the size of the key.
func (c *Ctx) Sign(sh SessionHandle, message []byte) ([]byte, error) {
	if c == nil || c.handle == 0 {
		return nil, CKR_CRYPTOKI_NOT_INITIALIZED
	}

	// The first call asks the module for the size of the signature, the second
	// one writes it into a buffer of that size.
	var length ckULong
	// #nosec G103 -- the message is passed to C_Sign for the duration of the call.
	if err := toError(c.functions.sign(ckULong(sh), unsafe.SliceData(message), ckULong(len(message)), nil, &length)); err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}

	signature := make([]byte, length)
	// #nosec G103 -- the message is passed to C_Sign for the duration of the call.
	if err := toError(c.functions.sign(ckULong(sh), unsafe.SliceData(message), ckULong(len(message)), &signature[0], &length)); err != nil {
		return nil, err
	}
	if int(length) < len(signature) {
		signature = signature[:length]
	}
	return signature, nil
}

// attributeList converts the attributes of the Go API into the array of
// CK_ATTRIBUTE that a module reads. The values of the list are the ones the
// caller passed, which have to stay unchanged for the duration of the call the
// list is used for.
func attributeList(attributes []*Attribute) []ckAttribute {
	if len(attributes) == 0 {
		return nil
	}
	list := make([]ckAttribute, len(attributes))
	for i, attribute := range attributes {
		list[i].typ = ckULong(attribute.Type)
		if value := attribute.Value; len(value) > 0 {
			// #nosec G103 -- the value is passed to the module for the duration of the call that uses the list.
			list[i].value = unsafe.Pointer(unsafe.SliceData(value))
			list[i].valueLen = ckULong(len(value))
		}
	}
	return list
}

// stringPointer returns a pointer to the bytes of s, or nil when s is empty,
// which is how a module is told that no PIN was given. The length of the string
// travels in an argument of its own, so the pointer does not have to point at a
// NUL-terminated string.
func stringPointer(s string) *byte {
	if len(s) == 0 {
		return nil
	}
	// #nosec G103 -- the module reads the bytes of the string for the duration of the call.
	return unsafe.StringData(s)
}
