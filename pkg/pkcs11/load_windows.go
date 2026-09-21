//go:build windows

package pkcs11

import "syscall"

// Windows loads a module with LoadLibrary and resolves its symbols with
// GetProcAddress, which the syscall package offers; the entry points of the
// function list are then turned into callable functions by purego. Only
// C_GetFunctionList is looked up as a symbol, because that is the one entry
// point a PKCS#11 module has to export.

// loadLibrary loads the module at path.
func loadLibrary(path string) (uintptr, error) {
	handle, err := syscall.LoadLibrary(path)
	if err != nil {
		return 0, err
	}
	return uintptr(handle), nil
}

// loadSymbol resolves the symbol name in the module of handle.
func loadSymbol(handle uintptr, name string) (uintptr, error) {
	return syscall.GetProcAddress(syscall.Handle(handle), name)
}

// unloadLibrary releases the module of handle.
func unloadLibrary(handle uintptr) error {
	return syscall.FreeLibrary(syscall.Handle(handle))
}
