//go:build !darwin && !freebsd && !linux && !netbsd && !windows

package pcsc

import "errors"

// This file provides the PC/SC entry points of a build for a system whose
// PC/SC service this package does not bind to. Such a system has a smart card
// service of its own, but talking to it would need cgo and a binding of its
// API, neither of which pivzavr wants to depend on. The entry points still
// exist so that the package and everything that uses it build and their other
// parts keep working.

// errUnsupported is reported by every operation of this build.
var errUnsupported = errors.New("pcsc: the PC/SC service of this system is not supported")

// scardEstablishContext always fails in a build for an unsupported system.
func scardEstablishContext() (uintptr, error) { return 0, errUnsupported }

// scardReleaseContext always fails in a build for an unsupported system.
func scardReleaseContext(uintptr) error { return errUnsupported }

// scardListReaders always fails in a build for an unsupported system.
func scardListReaders(uintptr, []byte) (uint32, error) { return 0, errUnsupported }

// scardConnect always fails in a build for an unsupported system.
func scardConnect(uintptr, string, ShareMode, Protocol) (uintptr, Protocol, error) {
	return 0, 0, errUnsupported
}

// scardDisconnect always fails in a build for an unsupported system.
func scardDisconnect(uintptr, Disposition) error { return errUnsupported }

// scardTransmit always fails in a build for an unsupported system.
func scardTransmit(uintptr, Protocol, []byte, []byte) (uint32, error) {
	return 0, errUnsupported
}
