// Package pinentry asks the user for a secret, such as a smart card PIN, with a
// pinentry dialog.
//
// Pinentry is the dialog program of GnuPG. It is started as a child process and
// driven over its standard input and output with the Assuan protocol, so that
// the secret never passes through a command line or an environment variable.
package pinentry

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// ErrCancelled is returned by Ask when the user cancelled the dialog. It marks
// the outcome rather than wording a message: the caller renders the error it
// shows, as pivzavr does with its "Entry cancelled.".
var ErrCancelled = errors.New("entry cancelled")

// dialogTitle is shown in the title bar of the dialog.
const dialogTitle = "pivzavr"

// Prompt describes the dialog that asks the user for a secret such as a PIN or
// a PUK. How many attempts the card has left for the secret, if that is known,
// is part of Description: the dialog sizes itself to fit the text it is given.
type Prompt struct {
	// Description is the text displayed above the input field.
	Description string
	// Prompt labels the input field.
	Prompt string
	// Message explains why the secret is requested again, for example that
	// the previous attempt was rejected. It is empty for a first prompt.
	Message string
}

// Ask runs the pinentry program at binary and returns the secret the user
// entered. A dialog the user cancelled is reported as ErrCancelled.
func Ask(binary string, prompt Prompt) (string, error) {
	client, err := newClient(binary)
	if err != nil {
		return "", fmt.Errorf("create pinentry client: %w", err)
	}
	defer func() { _ = client.close() }()

	if err := client.configure(tty(), prompt); err != nil {
		return "", fmt.Errorf("configure pinentry: %w", err)
	}

	secret, err := client.getPIN()
	if err != nil {
		if isCancelled(err) {
			return "", ErrCancelled
		}
		return "", err
	}
	return secret, nil
}

// assuanErrorCancelled is the Assuan error code that pinentry returns when the
// user cancels the dialog.
const assuanErrorCancelled = 83886179

// assuanError is an error returned by pinentry over the Assuan protocol.
type assuanError struct {
	code        int
	description string
}

func (e *assuanError) Error() string {
	return e.description
}

// unexpectedResponseError is returned when pinentry sends a response that is
// not valid for the command that was issued.
type unexpectedResponseError struct {
	line string
}

func (e *unexpectedResponseError) Error() string {
	return fmt.Sprintf("pinentry: unexpected response %q", e.line)
}

func unexpectedResponse(line string) error {
	return &unexpectedResponseError{line: line}
}

// client speaks the Assuan protocol to a pinentry process over its standard
// input and output.
type client struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
}

// newClient starts the pinentry program at binary and performs the Assuan
// handshake.
func newClient(binary string) (*client, error) {
	// #nosec G204 -- binary is selected by the user through configuration.
	cmd := exec.Command(binary)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("create pinentry stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("create pinentry stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("start pinentry %q: %w", binary, err)
	}

	c := &client{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReader(stdout),
	}
	line, err := c.readLine()
	if err != nil {
		_ = c.close()
		return nil, fmt.Errorf("pinentry handshake: %w", err)
	}
	if !isOK(line) {
		_ = c.close()
		return nil, unexpectedResponse(line)
	}
	return c, nil
}

// commands returns the Assuan commands that configure a dialog asking for the
// secret described by prompt. tty is the terminal text-mode pinentry frontends
// should use for the dialog; it may be empty.
func commands(tty string, prompt Prompt) []string {
	out := make([]string, 0, 5)
	if tty != "" {
		out = append(out, "OPTION ttyname="+assuanEscape(tty))
	}
	out = append(out,
		"SETTITLE "+assuanEscape(dialogTitle),
		"SETDESC "+assuanEscape(prompt.Description),
		"SETPROMPT "+assuanEscape(prompt.Prompt),
	)
	if prompt.Message != "" {
		out = append(out, "SETERROR "+assuanEscape(prompt.Message))
	}
	return out
}

// configure sends the dialog options used to ask for the secret described by
// prompt. tty is the terminal pinentry should use for text-mode dialogs; it may
// be empty.
func (c *client) configure(tty string, prompt Prompt) error {
	for _, command := range commands(tty, prompt) {
		if err := c.writeCommand(command); err != nil {
			return err
		}
	}
	return nil
}

// getPIN asks pinentry for a PIN. If the user cancels the dialog, the returned
// error can be tested with isCancelled.
func (c *client) getPIN() (string, error) {
	if err := c.writeLine("GETPIN"); err != nil {
		return "", err
	}

	var pin string
	for {
		line, err := c.readLine()
		if err != nil {
			return "", err
		}
		switch {
		case isOK(line):
			return pin, nil
		case isData(line):
			pin = assuanUnescape(line[2:])
		case isStatus(line):
			// Informational status lines (e.g. S PIN_REPEATED) are ignored.
		case isInquire(line):
			// We do not provide password quality information.
			if err := c.writeLine("CAN"); err != nil {
				return "", err
			}
		default:
			return "", unexpectedResponse(line)
		}
	}
}

// writeCommand writes an Assuan command and expects an OK response.
func (c *client) writeCommand(command string) error {
	if err := c.writeLine(command); err != nil {
		return err
	}
	return c.readOK()
}

// writeLine writes a single Assuan line to pinentry.
func (c *client) writeLine(line string) error {
	if _, err := io.WriteString(c.stdin, line+"\n"); err != nil {
		return fmt.Errorf("write to pinentry: %w", err)
	}
	return nil
}

// readOK reads a response and requires it to be OK.
func (c *client) readOK() error {
	line, err := c.readLine()
	if err != nil {
		return err
	}
	if !isOK(line) {
		return unexpectedResponse(line)
	}
	return nil
}

// readLine reads a single non-empty, non-comment line and converts ERR
// responses into errors.
func (c *client) readLine() (string, error) {
	for {
		line, err := c.stdout.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("read from pinentry: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if isError(line) {
			return "", newAssuanError(line)
		}
		return line, nil
	}
}

// close terminates the pinentry process. It is best effort and safe to call
// more than once.
func (c *client) close() error {
	if c.stdin == nil {
		return nil
	}

	var err error
	if writeErr := c.writeLine("BYE"); writeErr != nil {
		err = writeErr
	} else {
		_ = c.readOK()
	}
	_ = c.stdin.Close()
	c.stdin = nil
	_ = c.cmd.Wait()
	return err
}

func isOK(line string) bool      { return strings.HasPrefix(line, "OK") }
func isData(line string) bool    { return strings.HasPrefix(line, "D ") }
func isStatus(line string) bool  { return strings.HasPrefix(line, "S ") }
func isError(line string) bool   { return strings.HasPrefix(line, "ERR ") }
func isInquire(line string) bool { return strings.HasPrefix(line, "INQUIRE") }

// newAssuanError parses an "ERR <code> <description>" response.
func newAssuanError(line string) error {
	code, description, _ := strings.Cut(strings.TrimPrefix(line, "ERR "), " ")
	n, err := strconv.Atoi(code)
	if err != nil {
		return unexpectedResponse(line)
	}
	return &assuanError{code: n, description: description}
}

// isCancelled reports whether err is the Assuan error returned when the user
// cancels the pinentry dialog.
func isCancelled(err error) bool {
	var assuanErr *assuanError
	return errors.As(err, &assuanErr) && assuanErr.code == assuanErrorCancelled
}

// assuanEscape percent-escapes the characters that are not allowed verbatim in
// an Assuan command argument.
func assuanEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\n':
			b.WriteString("%0A")
		case '\r':
			b.WriteString("%0D")
		case '%':
			b.WriteString("%25")
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// assuanUnescape reverses assuanEscape. Invalid escape sequences are
// interpreted literally.
func assuanUnescape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if i+2 < len(s) && s[i] == '%' && isUpperHexDigit(s[i+1]) && isUpperHexDigit(s[i+2]) {
			b.WriteByte(hexDigitValue(s[i+1])<<4 | hexDigitValue(s[i+2]))
			i += 3
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func isUpperHexDigit(c byte) bool {
	return ('0' <= c && c <= '9') || ('A' <= c && c <= 'F')
}

func hexDigitValue(c byte) byte {
	if '0' <= c && c <= '9' {
		return c - '0'
	}
	return c - 'A' + 0xA
}

// tty returns the terminal that pinentry should use for text-mode dialogs. It
// returns an empty string when no terminal can be determined.
func tty() string {
	if tty := os.Getenv("GPG_TTY"); tty != "" {
		return tty
	}
	if runtime.GOOS == "windows" {
		return ""
	}
	// On Linux the controlling terminal is exposed through /proc. Otherwise
	// fall back to /dev/tty, which pinentry opens itself when needed.
	if tty, err := os.Readlink("/proc/self/fd/0"); err == nil && strings.HasPrefix(tty, "/dev/") {
		return tty
	}
	return "/dev/tty"
}
