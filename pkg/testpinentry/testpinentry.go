// Package testpinentry lets the tests of a package act as a pinentry process.
//
// The tests start the test binary itself as the pinentry program by pointing the
// PIVZAVR_PINENTRY environment variable at os.Args[0] and setting Env to the
// response the dialog should give. A test package that uses this calls Main
// from its TestMain, which turns the process into a fake pinentry when Env is
// set and otherwise runs the tests. This lets the Assuan client be tested
// against a real subprocess without needing pinentry to be installed.
package testpinentry

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

const (
	// Env makes the test binary behave as a pinentry process when it is set,
	// speaking the Assuan protocol that returns the value as the secret. The
	// special value "cancel" cancels the dialog, and "die" ends the process
	// right after the handshake, before it reads a command.
	Env = "PIVZAVR_TEST_PINENTRY"
	// SeqEnv names a state file that turns Env into a comma-separated list of
	// responses instead of a single response. Each pinentry process consumes
	// the next entry, so a test can script a retry.
	SeqEnv = "PIVZAVR_TEST_PINENTRY_STATE"
)

// Main runs the tests, or acts as a fake pinentry process when Env is set. It
// is meant to be called from the TestMain of a test package:
//
//	func TestMain(m *testing.M) { testpinentry.Main(m) }
func Main(m *testing.M) {
	mode := os.Getenv(Env)
	if mode != "" {
		// The pinentry processes started by the tests are run without
		// arguments, while the go tool starts the test binary with "-test."
		// flags. A mode that is left in the environment of a test run is
		// ignored, so that it cannot turn the whole run into a single
		// pinentry process that runs no tests at all.
		if IsTestRun(os.Args) {
			fmt.Fprintf(os.Stderr,
				"pivzavr tests: ignoring %s=%q, it is only meant for the pinentry processes the tests start\n",
				Env, mode)
		} else {
			os.Exit(runFakePinentry(mode))
		}
	}
	os.Exit(m.Run())
}

// IsTestRun reports whether args are those of a test binary started by the go
// tool, which passes at least one flag that starts with "-test.". The fake
// pinentry processes are started with no arguments at all.
func IsTestRun(args []string) bool {
	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "-test.") {
			return true
		}
	}
	return false
}

// responses splits mode into the responses that were scripted for it. Without a
// sequence the mode is the only response, and the returned state path is empty.
func responses(mode string) (list []string, statePath string) {
	statePath = os.Getenv(SeqEnv)
	if statePath == "" {
		return []string{mode}, ""
	}
	return strings.Split(mode, ","), statePath
}

// consumed returns the number of responses that pinentry processes have used so
// far, as recorded in the state file.
func consumed(statePath string) int {
	// #nosec G304 G703 -- the state file was named by the test that set the
	// environment variable.
	data, err := os.ReadFile(statePath)
	if err != nil {
		return 0
	}
	index, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return index
}

// peek returns the response that the next call to next would use, without
// consuming it.
func peek(mode string) string {
	list, statePath := responses(mode)
	index := 0
	if statePath != "" {
		index = consumed(statePath)
	}
	if index >= len(list) {
		index = len(list) - 1
	}
	return list[index]
}

// next returns the response this pinentry process should give for mode. It is
// mode itself unless SeqEnv names a state file, in which case mode is a
// comma-separated list and each call uses the next entry.
func next(mode string) string {
	list, statePath := responses(mode)
	if statePath == "" {
		return list[0]
	}

	index := consumed(statePath)
	if index >= len(list) {
		index = len(list) - 1
	}
	// #nosec G304 G703 -- the state file was named by the test that set the
	// environment variable.
	if err := os.WriteFile(statePath, []byte(strconv.Itoa(index+1)), 0o600); err != nil {
		return "cancel"
	}
	return list[index]
}

// runFakePinentry implements the subset of the Assuan protocol that the
// pinentry client uses. mode is returned as the secret, or "cancel" to simulate
// the user cancelling the dialog. The scripted response is taken when the
// secret is requested rather than when the process starts, so that a process
// that dies before it is asked does not use up an entry of the sequence.
//
// The response "die" makes the process exit right after the handshake, before
// it reads a command. That is how the tests stand in for the pinentry process
// that is gone by the time it is asked for a secret.
func runFakePinentry(mode string) int {
	fmt.Println("OK Pleased to meet you")

	if peek(mode) == "die" {
		// The process dies before it answers, so the caller retries with a
		// fresh process. The marker is consumed here, so that the retry
		// receives the response that follows it.
		next(mode)
		return 1
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		switch line := scanner.Text(); {
		case strings.HasPrefix(line, "GETPIN"):
			response := next(mode)
			if response == "cancel" {
				fmt.Println("ERR 83886179 cancelled")
				continue
			}
			fmt.Println("D " + response)
			fmt.Println("OK")
		case strings.HasPrefix(line, "BYE"):
			fmt.Println("OK closing connection")
			return 0
		default:
			fmt.Println("OK")
		}
	}
	return 0
}
