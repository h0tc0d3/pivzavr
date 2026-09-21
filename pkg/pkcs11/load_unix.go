//go:build darwin || freebsd || linux || netbsd

package pkcs11

import "github.com/ebitengine/purego"

// The Unix systems load a module with the dynamic loader of the C library,
// which purego makes available through Dlopen, Dlsym and Dlclose.

// loadLibrary loads the shared library at path.
func loadLibrary(path string) (uintptr, error) {
	return purego.Dlopen(path, purego.RTLD_LAZY)
}

// loadSymbol resolves the symbol name in the library of handle.
func loadSymbol(handle uintptr, name string) (uintptr, error) {
	return purego.Dlsym(handle, name)
}

// unloadLibrary releases the library of handle.
func unloadLibrary(handle uintptr) error {
	return purego.Dlclose(handle)
}
