package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/h0tc0d3/pivzavr/pkg/i18n"
)

const (
	// PKCS11ModuleEnv is the environment variable used to select the PKCS#11
	// module to load.
	PKCS11ModuleEnv = "PIVZAVR_PKCS11_MODULE"
	// PinentryEnv is the environment variable used to select the pinentry
	// program to launch.
	PinentryEnv = "PIVZAVR_PINENTRY"
	// SerialEnv is the environment variable used to select the smart card to
	// use when more than one is connected.
	SerialEnv = "PIVZAVR_SERIAL"
	// ConfigDirEnv overrides the base directory that holds the pivzavr
	// configuration file, following the XDG Base Directory specification.
	ConfigDirEnv = "XDG_CONFIG_HOME"

	// configDirName is the application directory under the base config
	// directory (e.g. ~/.config/pivzavr).
	configDirName = "pivzavr"
	// configFileName is the pivzavr configuration file name
	// (e.g. ~/.config/pivzavr/config).
	configFileName = "config"

	// configPinentryKey selects the pinentry program.
	configPinentryKey = "pinentry"
	// configPKCS11ModuleKey selects the PKCS#11 module.
	configPKCS11ModuleKey = "pkcs11-module"
	// configSerialKey selects the smart card by serial number.
	configSerialKey = "serial"
	// configCaCertificateKey adds a CA certificate source that the trust
	// store is assembled from. The setting may be repeated.
	configCaCertificateKey = "ca-certificate"
	// configOCSPServerKey adds an OCSP responder that a certificate is asked
	// about, in addition to the responders it names itself. The setting may
	// be repeated.
	configOCSPServerKey = "ocsp-server"
	// configPublicKeyKey adds a public key source that a signature is
	// verified against when its certificate cannot be verified with the CA
	// certificates of the trust store. The setting may be repeated.
	configPublicKeyKey = "public-key"
	// configRequireOCSPKey requires a positive OCSP response when a signature
	// is verified.
	configRequireOCSPKey = "require-ocsp"
	// configLanguageKey selects the language that messages are translated
	// into.
	configLanguageKey = "language"
)

// config holds the settings read from the configuration file.
type config struct {
	pinentry       string
	pkcs11Module   string
	serial         string
	language       string
	caCertificates []string
	ocspServers    []string
	publicKeys     []string
	requireOCSP    string
}

// configDir returns the pivzavr configuration directory:
// $XDG_CONFIG_HOME/pivzavr, or ~/.config/pivzavr when XDG_CONFIG_HOME is not
// set.
func configDir() (string, error) {
	base := os.Getenv(ConfigDirEnv)
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", i18n.Wrap(err, "Locate home directory")
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, configDirName), nil
}

// configPath returns the path to the pivzavr configuration file:
// $XDG_CONFIG_HOME/pivzavr/config, or ~/.config/pivzavr/config when
// XDG_CONFIG_HOME is not set.
func configPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, configFileName), nil
}

// readConfig reads the pivzavr configuration file. A missing file is not an
// error and yields an empty configuration.
func readConfig() (*config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}

	file, err := os.Open(path) // #nosec G304 -- path is derived from the user configuration directory.
	if err != nil {
		if os.IsNotExist(err) {
			return &config{}, nil
		}
		return nil, i18n.Wrapf(err, "Open configuration file %q", path)
	}
	defer func() { _ = file.Close() }()

	cfg := &config{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value := parseConfigLine(scanner.Text())
		switch key {
		case configPinentryKey:
			cfg.pinentry = value
		case configPKCS11ModuleKey:
			cfg.pkcs11Module = value
		case configSerialKey:
			cfg.serial = value
		case configLanguageKey:
			cfg.language = value
		case configCaCertificateKey:
			if value != "" {
				cfg.caCertificates = append(cfg.caCertificates, value)
			}
		case configOCSPServerKey:
			if value != "" {
				cfg.ocspServers = append(cfg.ocspServers, value)
			}
		case configPublicKeyKey:
			if value != "" {
				cfg.publicKeys = append(cfg.publicKeys, value)
			}
		case configRequireOCSPKey:
			cfg.requireOCSP = value
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, i18n.Wrapf(err, "Read configuration file %q", path)
	}
	return cfg, nil
}

// parseConfigLine parses a single configuration line. Blank lines and lines
// starting with '#' are ignored. A setting is written as "key value" or
// "key = value"; the value may itself contain spaces.
func parseConfigLine(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", ""
	}

	if idx := strings.IndexByte(line, '='); idx >= 0 {
		return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:])
	}

	idx := strings.IndexFunc(line, unicode.IsSpace)
	if idx < 0 {
		return line, ""
	}
	return line[:idx], strings.TrimSpace(line[idx:])
}

// expandHome expands a leading "~" or "~/" in path to the user's home
// directory.
func expandHome(path string) string {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~/"))
}

// PinentryPath returns the pinentry program to launch. The PIVZAVR_PINENTRY
// environment variable takes precedence over the "pinentry" setting in the
// configuration file, which in turn takes precedence over the default pinentry
// locations for the current operating system.
func PinentryPath() (string, error) {
	if path := strings.TrimSpace(os.Getenv(PinentryEnv)); path != "" {
		return path, nil
	}
	cfg, err := readConfig()
	if err != nil {
		return "", err
	}
	if cfg.pinentry != "" {
		return expandHome(cfg.pinentry), nil
	}
	return findPinentryPath()
}

// PKCS11ModulePath returns the PKCS#11 module to load. The
// PIVZAVR_PKCS11_MODULE environment variable takes precedence over the
// "pkcs11-module" setting in the configuration file, which in turn takes
// precedence over the default PKCS#11 locations for the current operating
// system.
func PKCS11ModulePath() (string, error) {
	if module := strings.TrimSpace(os.Getenv(PKCS11ModuleEnv)); module != "" {
		return module, nil
	}
	cfg, err := readConfig()
	if err != nil {
		return "", err
	}
	if cfg.pkcs11Module != "" {
		return expandHome(cfg.pkcs11Module), nil
	}
	return findModulePath()
}

// Serial returns the serial number of the smart card to use. The
// PIVZAVR_SERIAL environment variable takes precedence over the "serial"
// setting in the configuration file. An empty return value means the token is
// used only when exactly one smart card is present.
func Serial() (string, error) {
	if serial := strings.TrimSpace(os.Getenv(SerialEnv)); serial != "" {
		return serial, nil
	}
	cfg, err := readConfig()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(cfg.serial), nil
}

// Language returns the language from the "language" setting of the
// configuration file. The setting is a language name such as "en" or "ru", or a
// locale such as "ru_RU.UTF-8". An empty return value means no language was
// configured and the language of the system locale is to be used.
func Language() (string, error) {
	cfg, err := readConfig()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(cfg.language), nil
}

// CACertificates returns the CA certificate sources from the "ca-certificate"
// settings of the configuration file, in the order they were written. A source
// is the http(s) URL of a certificate bundle, or the path of a PEM or DER
// encoded certificate file, in which case a leading "~" is expanded to the home
// directory.
func CACertificates() ([]string, error) {
	cfg, err := readConfig()
	if err != nil {
		return nil, err
	}
	return cfg.caCertificates, nil
}

// OCSPServers returns the OCSP responder URLs from the "ocsp-server" settings
// of the configuration file, in the order they were written. A responder is
// asked after the responders that a certificate names itself, so a certificate
// whose own responder cannot be reached can still be checked.
func OCSPServers() ([]string, error) {
	cfg, err := readConfig()
	if err != nil {
		return nil, err
	}
	return cfg.ocspServers, nil
}

// PublicKeys returns the public key sources from the "public-key" settings of
// the configuration file, in the order they were written. A source is the
// http(s) URL of a public key file, or the path of a PEM or DER encoded public
// key file, in which case a leading "~" is expanded to the home directory.
func PublicKeys() ([]string, error) {
	cfg, err := readConfig()
	if err != nil {
		return nil, err
	}
	return cfg.publicKeys, nil
}

// RequireOCSP reports whether signature verification requires a positive OCSP
// response. It is disabled by default: a signature whose revocation status
// cannot be checked is verified with a warning on stderr.
func RequireOCSP() (bool, error) {
	cfg, err := readConfig()
	if err != nil {
		return false, err
	}
	return parseRequireOCSP(cfg.requireOCSP)
}

// parseRequireOCSP parses the value of the "require-ocsp" setting. An unset
// setting is disabled, and a value that is not a boolean is rejected rather
// than silently disabling the setting.
func parseRequireOCSP(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return false, nil
	case "0", "false", "no", "off":
		return false, nil
	case "1", "true", "yes", "on":
		return true, nil
	default:
		return false, i18n.Errorf("Invalid require-ocsp value %q.", value)
	}
}
