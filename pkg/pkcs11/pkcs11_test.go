package pkcs11

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFunctionListOffsets pins the order of the entry points of a function list.
// A PKCS#11 module publishes its entry points as one structure, so the order is
// part of the ABI: an entry point in the wrong place would call a different
// function of the module. The positions below are the ones the specification
// defines, which the C header of the API confirms.
func TestFunctionListOffsets(t *testing.T) {
	var list functionList

	// The version of the module is two bytes long, and the first entry point
	// follows after the padding of a pointer-sized field.
	pointer := unsafe.Sizeof(uintptr(0))
	assert.Equal(t, uintptr(0), unsafe.Offsetof(list.version))

	tests := []struct {
		name  string
		entry uintptr
		index uintptr
	}{
		{"C_Initialize", unsafe.Offsetof(list.initialize), 0},
		{"C_Finalize", unsafe.Offsetof(list.finalize), 1},
		{"C_GetSlotList", unsafe.Offsetof(list.getSlotList), 4},
		{"C_GetTokenInfo", unsafe.Offsetof(list.getTokenInfo), 6},
		{"C_SetPIN", unsafe.Offsetof(list.setPIN), 11},
		{"C_OpenSession", unsafe.Offsetof(list.openSession), 12},
		{"C_CloseSession", unsafe.Offsetof(list.closeSession), 13},
		{"C_Login", unsafe.Offsetof(list.login), 18},
		{"C_GetAttributeValue", unsafe.Offsetof(list.getAttributeValue), 24},
		{"C_FindObjectsInit", unsafe.Offsetof(list.findObjectsInit), 26},
		{"C_FindObjects", unsafe.Offsetof(list.findObjects), 27},
		{"C_FindObjectsFinal", unsafe.Offsetof(list.findObjectsFinal), 28},
		{"C_SignInit", unsafe.Offsetof(list.signInit), 42},
		{"C_Sign", unsafe.Offsetof(list.sign), 43},
	}
	for _, tt := range tests {
		assert.Equal(t, pointer+tt.index*pointer, tt.entry, tt.name)
	}
}

// TestStructLayout pins the layout of the structures that a module reads and
// writes. The sizes and offsets are the ones the C API has on a system where
// CK_ULONG and a pointer are the same size, which every system this package is
// built for except Windows is; on Windows only the width of CK_ULONG differs,
// which ckULong carries.
func TestStructLayout(t *testing.T) {
	if unsafe.Sizeof(ckULong(0)) != unsafe.Sizeof(uintptr(0)) {
		t.Skip("the width of CK_ULONG differs from the width of a pointer")
	}

	assert.Equal(t, uintptr(0), unsafe.Offsetof(ckAttribute{}.typ))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(ckAttribute{}.value))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(ckAttribute{}.valueLen))
	assert.Equal(t, uintptr(24), unsafe.Sizeof(ckAttribute{}))

	assert.Equal(t, uintptr(0), unsafe.Offsetof(ckMechanism{}.mechanism))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(ckMechanism{}.parameter))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(ckMechanism{}.parameterLen))
	assert.Equal(t, uintptr(24), unsafe.Sizeof(ckMechanism{}))

	// The character fields of a token info are 32, 32, 16 and 16 bytes long, so
	// the flags start at byte 96; ten counters and the two versions follow.
	assert.Equal(t, uintptr(96), unsafe.Offsetof(ckTokenInfo{}.flags))
	assert.Equal(t, uintptr(104), unsafe.Offsetof(ckTokenInfo{}.maxSessionCount))
	assert.Equal(t, uintptr(184), unsafe.Offsetof(ckTokenInfo{}.hardwareVersion))
	assert.Equal(t, uintptr(186), unsafe.Offsetof(ckTokenInfo{}.firmwareVersion))
	assert.Equal(t, uintptr(188), unsafe.Offsetof(ckTokenInfo{}.utcTime))
	assert.Equal(t, uintptr(208), unsafe.Sizeof(ckTokenInfo{}))

	// The four locking functions of the initialization arguments are left null
	// and are part of the layout all the same.
	assert.Equal(t, uintptr(0), unsafe.Offsetof(ckInitializeArgs{}.createMutex))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(ckInitializeArgs{}.destroyMutex))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(ckInitializeArgs{}.lockMutex))
	assert.Equal(t, uintptr(24), unsafe.Offsetof(ckInitializeArgs{}.unlockMutex))
	assert.Equal(t, uintptr(32), unsafe.Offsetof(ckInitializeArgs{}.flags))
	assert.Equal(t, uintptr(40), unsafe.Offsetof(ckInitializeArgs{}.reserved))
	assert.Equal(t, uintptr(48), unsafe.Sizeof(ckInitializeArgs{}))
}

func TestNewAttribute(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  []byte
	}{
		{name: "nil asks for the size of the value", value: nil, want: nil},
		{name: "true", value: true, want: []byte{1}},
		{name: "false", value: false, want: []byte{0}},
		{name: "bytes", value: []byte{0x01, 0x02}, want: []byte{0x01, 0x02}},
		{name: "string", value: "label", want: []byte("label")},
		{name: "empty bytes", value: []byte{}, want: []byte{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attribute := NewAttribute(CKA_VALUE, tt.value)
			assert.Equal(t, uint(CKA_VALUE), attribute.Type)
			assert.Equal(t, tt.want, attribute.Value)
		})
	}

	// A number is encoded as a CK_ULONG in the byte order of the platform,
	// which is how a module reads an attribute that holds a class or an ID.
	attribute := NewAttribute(CKA_CLASS, uint(0x1234))
	want := make([]byte, unsafe.Sizeof(ckULong(0)))
	if len(want) == 8 {
		binary.NativeEndian.PutUint64(want, 0x1234)
	} else {
		binary.NativeEndian.PutUint32(want, 0x1234)
	}
	assert.Equal(t, want, attribute.Value)

	// A value of a type that an attribute cannot hold is a programming error.
	assert.Panics(t, func() { NewAttribute(CKA_CLASS, 1.5) })
}

func TestErrorName(t *testing.T) {
	assert.Equal(t, "CKR_PIN_INCORRECT", CKR_PIN_INCORRECT.Name())
	assert.Equal(t, "CKR_PIN_LOCKED", CKR_PIN_LOCKED.Name())
	assert.Equal(t, "CKR_USER_ALREADY_LOGGED_IN", CKR_USER_ALREADY_LOGGED_IN.Name())
	assert.Empty(t, Error(0x0BADF00D).Name())
}

func TestErrorString(t *testing.T) {
	assert.Equal(t, "pkcs11: 0xA0: CKR_PIN_INCORRECT", CKR_PIN_INCORRECT.Error())
	assert.Equal(t, "pkcs11: unknown error 0xBADF00D", Error(0x0BADF00D).Error())
}

func TestToError(t *testing.T) {
	assert.NoError(t, toError(0))
	require.ErrorIs(t, toError(ckULong(CKR_PIN_INCORRECT)), CKR_PIN_INCORRECT)
	require.ErrorIs(t, toError(ckULong(CKR_PIN_LOCKED)), CKR_PIN_LOCKED)
}

// TestNewRejectsAMissingModule checks that a module that cannot be loaded is
// reported with the error of the loader.
func TestNewRejectsAMissingModule(t *testing.T) {
	ctx, err := New("pivzavr-no-such-pkcs11-module.so")

	assert.Nil(t, ctx)
	require.Error(t, err)
	assert.ErrorContains(t, err, "load PKCS#11 module")
}

// TestContextRejectsUseWithoutAModule checks that a context that was never
// created reports that the module is not initialized, which keeps a caller that
// got no context from a crash.
func TestContextRejectsUseWithoutAModule(t *testing.T) {
	var ctx *Ctx

	_, err := ctx.GetSlotList(true)
	require.ErrorIs(t, err, CKR_CRYPTOKI_NOT_INITIALIZED)

	_, err = ctx.GetTokenInfo(0)
	require.ErrorIs(t, err, CKR_CRYPTOKI_NOT_INITIALIZED)

	_, err = ctx.OpenSession(0, CKF_SERIAL_SESSION)
	require.ErrorIs(t, err, CKR_CRYPTOKI_NOT_INITIALIZED)

	_, err = ctx.FindObjects(0, 1)
	require.ErrorIs(t, err, CKR_CRYPTOKI_NOT_INITIALIZED)

	_, err = ctx.GetAttributeValue(0, 0, []*Attribute{NewAttribute(CKA_VALUE, nil)})
	require.ErrorIs(t, err, CKR_CRYPTOKI_NOT_INITIALIZED)

	_, err = ctx.Sign(0, []byte{1})
	require.ErrorIs(t, err, CKR_CRYPTOKI_NOT_INITIALIZED)

	require.ErrorIs(t, ctx.Initialize(), CKR_CRYPTOKI_NOT_INITIALIZED)
	require.ErrorIs(t, ctx.CloseSession(0), CKR_CRYPTOKI_NOT_INITIALIZED)
	require.ErrorIs(t, ctx.Login(0, CKU_USER, "1234"), CKR_CRYPTOKI_NOT_INITIALIZED)
	require.ErrorIs(t, ctx.SetPIN(0, "old", "new"), CKR_CRYPTOKI_NOT_INITIALIZED)
	require.ErrorIs(t, ctx.FindObjectsInit(0, nil), CKR_CRYPTOKI_NOT_INITIALIZED)
	require.ErrorIs(t, ctx.FindObjectsFinal(0), CKR_CRYPTOKI_NOT_INITIALIZED)
	require.ErrorIs(t, ctx.SignInit(0, NewMechanism(CKM_ECDSA), 0), CKR_CRYPTOKI_NOT_INITIALIZED)

	// Destroying a context that was never created is not a crash, which keeps
	// a deferred Destroy safe.
	ctx.Destroy()
}
