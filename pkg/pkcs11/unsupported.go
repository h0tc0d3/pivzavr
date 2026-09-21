//go:build !darwin && !freebsd && !linux && !netbsd && !windows

// Package pkcs11 has no binding for this system. The package loads a PKCS#11
// module with the dynamic loader of the platform, which is only available on
// the systems listed in the build constraints of the files that make up the
// binding. This file keeps a build for any other system working; it provides
// nothing to import, so a program that needs a PKCS#11 module has to leave the
// platform out as well.
package pkcs11
