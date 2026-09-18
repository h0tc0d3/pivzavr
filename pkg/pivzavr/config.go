package pivzavr

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/pkg/errors"
)

const (
	// pkcs11ModuleEnv is the environment variable used to select the PKCS#11
	// module to load.
	pkcs11ModuleEnv = "PIVZAVR_PKCS11_MODULE"
	// pinentryEnv is the environment variable used to select the pinentry
	// program to launch.
	pinentryEnv = "PIVZAVR_PINENTRY"
	// serialEnv is the environment variable used to select the smart card to
	// use when more than one is connected.
	serialEnv = "PIVZAVR_SERIAL"
	// configDirEnv overrides the base directory that holds the pivzavr
	// configuration file, following the XDG Base Directory specification.
	configDirEnv = "XDG_CONFIG_HOME"

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
)

// config holds the settings read from the configuration file.
type config struct {
	pinentry     string
	pkcs11Module string
	serial       string
}

// configPath returns the path to the pivzavr configuration file:
// $XDG_CONFIG_HOME/pivzavr/config, or ~/.config/pivzavr/config when
// XDG_CONFIG_HOME is not set.
func configPath() (string, error) {
	base := os.Getenv(configDirEnv)
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", errors.Wrap(err, "Locate home directory")
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, configDirName, configFileName), nil
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
		return nil, errors.Wrapf(err, "Open configuration file %q", path)
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
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.Wrapf(err, "Read configuration file %q", path)
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

// resolvePinentryPath returns the pinentry program to launch. The PIVZAVR_PINENTRY
// environment variable takes precedence over the "pinentry" setting in the
// configuration file, which in turn takes precedence over the default pinentry
// locations for the current operating system.
func resolvePinentryPath() (string, error) {
	if path := strings.TrimSpace(os.Getenv(pinentryEnv)); path != "" {
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

// resolvePKCS11Module returns the PKCS#11 module to load. The
// PIVZAVR_PKCS11_MODULE environment variable takes precedence over the
// "pkcs11-module" setting in the configuration file, which in turn takes
// precedence over the default PKCS#11 locations for the current operating
// system.
func resolvePKCS11Module() (string, error) {
	if module := strings.TrimSpace(os.Getenv(pkcs11ModuleEnv)); module != "" {
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
	if serial := strings.TrimSpace(os.Getenv(serialEnv)); serial != "" {
		return serial, nil
	}
	cfg, err := readConfig()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(cfg.serial), nil
}
