// Package config resolves the settings and the system paths that pivzavr uses.
//
// It reads the pivzavr configuration file, locates the pinentry program and the
// PKCS#11 module, and keeps the trust store that signatures are verified against
// in the pivzavr configuration directory. The trust store holds the CA
// certificates and the public keys that a signature is checked against.
//
// A setting that has an environment variable of its own can be overridden with
// it (PKCS11ModuleEnv, PinentryEnv and SerialEnv): the environment takes
// precedence over the configuration file, which in turn takes precedence over
// the conventional locations of the operating system.
//
// The language setting of the configuration file names the language that the
// messages of pivzavr are translated into. The i18n package resolves it, so
// that a message which is reported before a setting that names a path is read
// is translated as well.
package config
