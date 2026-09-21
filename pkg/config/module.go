package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/h0tc0d3/pivzavr/pkg/i18n"
)

// This file locates the PKCS#11 module that is loaded and checks whether a
// YubiKey is attached, which decides whether the YubiKey module is considered.
// Nothing here needs cgo, so the code is available to every build.

// yubicoVendorID is Yubico's USB vendor ID, which is how a YubiKey is told
// apart from the other USB devices the system has.
const yubicoVendorID = "1050"

// findModulePath returns the first PIV PKCS#11 module found in the conventional
// system locations for the current operating system. The YubiKey PKCS#11 module
// is only considered when a YubiKey device is present.
func findModulePath() (string, error) {
	path, ok := firstExistingModule(candidateModulePaths(runtime.GOOS, runtime.GOARCH), yubiKeyPresent())
	if !ok {
		return "", i18n.Errorf(
			"PKCS#11 module not found for %s/%s (set %s to override)",
			runtime.GOOS, runtime.GOARCH, PKCS11ModuleEnv,
		)
	}
	return path, nil
}

// firstExistingModule returns the first path in candidates that exists as a
// regular file. YubiKey module paths are skipped when yubiKeyPresent is false.
func firstExistingModule(candidates []string, yubiKeyPresent bool) (string, bool) {
	for _, path := range candidates {
		if !yubiKeyPresent && IsYkcs11Module(path) {
			continue
		}
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, true
		}
	}
	return "", false
}

// IsYkcs11Module reports whether path refers to the YubiKey PKCS#11 module.
func IsYkcs11Module(path string) bool {
	base := filepath.Base(path)
	return strings.HasPrefix(base, "libykcs11") || strings.HasPrefix(base, "ykcs11")
}

// IsRtPKCS11Module reports whether path refers to the Rutoken ECP PKCS#11
// module.
func IsRtPKCS11Module(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return strings.HasPrefix(base, "librtpkcs11") || strings.HasPrefix(base, "rtpkcs11")
}

// IsJcPKCS11Module reports whether path refers to the JaCarta PKCS#11 module.
func IsJcPKCS11Module(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return strings.HasPrefix(base, "libjcpkcs11") || strings.HasPrefix(base, "jcpkcs11")
}

// yubiKeyPresent reports whether a YubiKey device is currently attached to the
// system. YubiKeys identify themselves with Yubico's USB vendor ID (0x1050).
func yubiKeyPresent() bool {
	switch runtime.GOOS {
	case "linux":
		return sysfsVendorPresent("/sys", "bus/usb/devices", yubicoVendorID)
	case "darwin":
		return darwinYubiKeyPresent()
	default:
		return false
	}
}

// sysfsVendorPresent reports whether any device directory under root/relDir
// exposes the given USB vendor ID in its idVendor attribute. File access is
// scoped to root using os.Root, which also resolves the device symlinks used
// by sysfs.
func sysfsVendorPresent(rootPath, relDir, vendorID string) bool {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return false
	}
	defer func() { _ = root.Close() }()

	dir, err := root.Open(relDir)
	if err != nil {
		return false
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		return false
	}

	for _, entry := range entries {
		data, err := root.ReadFile(filepath.Join(relDir, entry.Name(), "idVendor"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(data)) == vendorID {
			return true
		}
	}
	return false
}

// darwinYubiKeyPresent reports whether a YubiKey is attached by querying the
// I/O Registry with ioreg.
func darwinYubiKeyPresent() bool {
	out, err := exec.Command("ioreg", "-p", "IOUSB", "-l", "-w", "0").Output()
	if err != nil {
		return false
	}
	// ioreg prints USB vendor IDs in decimal by default.
	return strings.Contains(string(out), `"idVendor" = 1050`) ||
		strings.Contains(string(out), `"idVendor" = 0x1050`)
}

// candidateModulePaths returns the conventional PIV PKCS#11 module paths for
// the given operating system and architecture, ordered by likelihood.
//
// Within a directory the module of a card's vendor is listed before OpenSC, so
// that a card which both modules serve is used through the module of its vendor,
// which knows more of it. The YubiKey PKCS#11 module (ykcs11) comes before the
// modules of the other vendors: OpenSC only discovers retired key-management
// slots from the card's key-history object, which YubiKeys do not implement, so
// retired slots are only addressable through ykcs11.
func candidateModulePaths(goos, goarch string) []string {
	paths := make([]string, 0, 24)
	add := func(p string) { paths = append(paths, p) }

	switch goos {
	case "linux":
		archDir := map[string]string{
			"amd64": "x86_64-linux-gnu",
			"386":   "i386-linux-gnu",
			"arm64": "aarch64-linux-gnu",
			"arm":   "arm-linux-gnueabihf",
		}[goarch]

		// Debian and Ubuntu keep the modules of the distribution in a
		// directory that is named after the architecture.
		if archDir != "" {
			dir := "/usr/lib/" + archDir + "/"
			add(dir + "libykcs11.so")
			for _, name := range vendorModuleNames {
				add(dir + name)
			}
			add(dir + "opensc-pkcs11.so")
		}

		// RHEL, CentOS and Fedora, then Arch Linux and the other
		// distributions that use a plain library directory.
		for _, dir := range []string{"/usr/lib64/", "/usr/lib/", "/usr/local/lib/"} {
			add(dir + "libykcs11.so")
			for _, name := range vendorModuleNames {
				add(dir + name)
			}
			add(dir + "opensc-pkcs11.so")
		}
	case "darwin":
		// Apple Silicon and Intel Homebrew prefixes, plus the official
		// OpenSC installer location.
		for _, dir := range []string{"/opt/homebrew/lib/", "/usr/local/lib/", "/Library/OpenSC/lib/"} {
			add(dir + "libykcs11.dylib")
			for _, name := range vendorModuleNamesDarwin {
				add(dir + name)
			}
			add(dir + "opensc-pkcs11.so")
			add(dir + "opensc-pkcs11.dylib")
		}
	case "freebsd", "openbsd", "netbsd", "dragonfly":
		for _, dir := range []string{"/usr/local/lib/", "/usr/lib/"} {
			add(dir + "libykcs11.so")
			for _, name := range vendorModuleNames {
				add(dir + name)
			}
			add(dir + "opensc-pkcs11.so") // pkg/ports
		}
	default:
		// Let the dynamic linker resolve the module by its soname.
		add("libykcs11.so")
		add("opensc-pkcs11.so")
		for _, name := range vendorModuleNames {
			add(name)
		}
	}

	return paths
}

// findModulePaths returns every PKCS#11 module in the conventional system
// locations for the current operating system, in the order of preference. A
// module that is not present is left out, so that a caller can load all the
// modules that are installed and reach the smart card that each of them serves,
// which is what makes a YubiKey, a Rutoken and a JaCarta usable at the same
// time. The YubiKey module is only considered when a YubiKey is present.
func findModulePaths() []string {
	yubiKey := yubiKeyPresent()
	seen := make(map[string]bool)

	paths := make([]string, 0, 8)
	for _, path := range candidateModulePaths(runtime.GOOS, runtime.GOARCH) {
		if seen[path] || (!yubiKey && IsYkcs11Module(path)) {
			continue
		}
		seen[path] = true
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			paths = append(paths, path)
		}
	}
	return paths
}

// vendorModuleNames are the file names under which the PKCS#11 module of a
// Rutoken ECP or a JaCarta appears on Linux, in the order they are tried. The
// spelling of the names differs between the distributions that package them.
var vendorModuleNames = []string{
	"librtpkcs11ecp.so",
	"librtPKCS11ECP.so",
	"rtPKCS11ECP.so",
	"librtPKCS11.so",
	"libjcPKCS11-2.so",
	"libjcPKCS11.so",
	"jcPKCS11.so",
}

// vendorModuleNamesDarwin are the names of the same modules on macOS.
var vendorModuleNamesDarwin = []string{
	"librtpkcs11ecp.dylib",
	"librtPKCS11ECP.dylib",
	"librtPKCS11ECP.so",
	"libjcPKCS11.dylib",
	"libjcPKCS11.so",
}

// PKCS11ModulePaths returns the PKCS#11 modules to load, in the order they are
// tried. The PIVZAVR_PKCS11_MODULE environment variable takes precedence over
// the "pkcs11-module" setting of the configuration file, which in turn takes
// precedence over the modules found in the conventional locations for the
// current operating system.
//
// A value may name more than one module, separated by the path list separator
// of the system (":" on Unix, ";" on Windows). Loading every installed module
// is what lets pivzavr talk to a YubiKey, a Rutoken and a JaCarta at the same
// time, because a card is only visible to the module that knows it.
func PKCS11ModulePaths() ([]string, error) {
	if paths := moduleList(os.Getenv(PKCS11ModuleEnv)); len(paths) > 0 {
		return paths, nil
	}

	cfg, err := readConfig()
	if err != nil {
		return nil, err
	}
	if paths := moduleList(cfg.pkcs11Module); len(paths) > 0 {
		expanded := make([]string, 0, len(paths))
		for _, path := range paths {
			expanded = append(expanded, expandHome(path))
		}
		return expanded, nil
	}

	paths := findModulePaths()
	if len(paths) == 0 {
		return nil, i18n.Errorf(
			"PKCS#11 module not found for %s/%s (set %s to override)",
			runtime.GOOS, runtime.GOARCH, PKCS11ModuleEnv,
		)
	}
	return paths, nil
}

// moduleList splits a PKCS#11 module setting into the module paths it names,
// dropping the empty entries of a value that lists no module at all.
func moduleList(value string) []string {
	var paths []string
	for _, path := range filepath.SplitList(value) {
		if path = strings.TrimSpace(path); path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}
