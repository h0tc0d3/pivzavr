package pivzavr

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// pinentryNames lists the pinentry programs in order of preference across all
// supported operating systems.
var pinentryNames = []string{
	"pinentry-qt",
	"pinentry-gtk",
	"pinentry-gtk-2",
	"pinentry-curses",
	"pinentry-tty",
}

// findPinentryPath returns the first pinentry program found in the conventional
// locations for the current operating system.
func findPinentryPath() (string, error) {
	path, ok := firstExistingProgram(candidatePinentryPaths(runtime.GOOS))
	if !ok {
		return "", fmt.Errorf(
			"pinentry not found for %s (set %s to override)",
			runtime.GOOS, pinentryEnv,
		)
	}
	return path, nil
}

// firstExistingProgram returns the first candidate that names an executable.
// Candidates containing a path separator are checked directly; bare names are
// resolved through PATH.
func firstExistingProgram(candidates []string) (string, bool) {
	for _, candidate := range candidates {
		if !strings.ContainsRune(candidate, os.PathSeparator) {
			if path, err := exec.LookPath(candidate); err == nil {
				return path, true
			}
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, true
		}
	}
	return "", false
}

// candidatePinentryPaths returns the conventional pinentry program paths for
// the given operating system. Programs are ordered pinentry-qt, pinentry-gtk,
// pinentry-curses, pinentry-tty, with each directory searched before the next.
func candidatePinentryPaths(goos string) []string {
	names := make([]string, 0, len(pinentryNames)+2)
	names = append(names, pinentryNames...)
	if goos == "darwin" {
		// pinentry-mac is the native macOS dialog.
		names = append(names, "pinentry-mac")
	}
	names = append(names, "pinentry")

	dirs := candidatePinentryDirs(goos)
	paths := make([]string, 0, len(dirs)*len(names)+len(names))
	for _, dir := range dirs {
		for _, name := range names {
			paths = append(paths, filepath.Join(dir, name))
		}
	}
	// Fall back to resolving the program names through PATH.
	return append(paths, names...)
}

// candidatePinentryDirs returns the directories that commonly hold pinentry
// programs for the given operating system, ordered by likelihood.
func candidatePinentryDirs(goos string) []string {
	switch goos {
	case "linux":
		return []string{"/usr/bin", "/usr/local/bin"}
	case "darwin":
		return []string{"/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"}
	case "windows":
		return []string{
			`C:\Program Files\GnuPG\bin`,
			`C:\Program Files (x86)\GnuPG\bin`,
		}
	case "freebsd", "openbsd", "netbsd", "dragonfly":
		return []string{"/usr/local/bin", "/usr/bin"}
	default:
		return []string{"/usr/bin", "/usr/local/bin"}
	}
}
