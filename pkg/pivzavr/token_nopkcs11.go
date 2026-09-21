//go:build !darwin && !freebsd && !linux && !netbsd && !windows

package pivzavr

import "github.com/h0tc0d3/pivzavr/pkg/i18n"

// This file provides the PKCS#11 entry points of a build for a system that the
// local pkg/pkcs11 binding does not cover. Such a system may well have a
// PKCS#11 module, but loading it needs a binding of the dynamic loader of that
// system, which pivzavr does not have. The entry points still exist so that the
// package and the pivzavr command build and their other parts can be used.

// errNoPKCS11 is reported by every PKCS#11 operation of this build.
var errNoPKCS11 = i18n.Message("pivzavr: loading a PKCS#11 module is not supported on this system")

// TokenHandleWithSerial returns a handle to the token in the slot matching
// serial on the systems the PKCS#11 binding covers. Any other system reports
// errNoPKCS11.
func TokenHandleWithSerial(serial string) (Pivzavr, error) {
	return nil, errNoPKCS11
}

// DeviceInfos returns identification data for every smart card currently present
// on the systems the PKCS#11 binding covers. Any other system reports
// errNoPKCS11.
func DeviceInfos() ([]*DeviceInfo, error) {
	return nil, errNoPKCS11
}
