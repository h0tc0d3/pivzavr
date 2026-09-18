package pivzavr

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

const (
	// assuanErrorCancelled is the Assuan error code that pinentry returns when
	// the user cancels the dialog.
	assuanErrorCancelled = 83886179
)

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

// pinentryClient speaks the Assuan protocol to a pinentry process over its
// standard input and output.
type pinentryClient struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
}

// newPinentryClient starts the pinentry program at binary and performs the
// Assuan handshake.
func newPinentryClient(binary string) (*pinentryClient, error) {
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

	client := &pinentryClient{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReader(stdout),
	}
	line, err := client.readLine()
	if err != nil {
		_ = client.close()
		return nil, fmt.Errorf("pinentry handshake: %w", err)
	}
	if !isOK(line) {
		_ = client.close()
		return nil, unexpectedResponse(line)
	}
	return client, nil
}

// configure sends the dialog options used for a PIN prompt. tty is the
// terminal pinentry should use for text-mode dialogs; it may be empty.
func (c *pinentryClient) configure(tty string) error {
	commands := make([]string, 0, 5)
	if tty != "" {
		commands = append(commands, "OPTION ttyname="+assuanEscape(tty))
	}
	commands = append(commands,
		"SETTITLE "+assuanEscape("pivzavr"),
		"SETDESC "+assuanEscape("Enter smart card PIN"),
		"SETPROMPT "+assuanEscape("PIN:"),
	)
	for _, command := range commands {
		if err := c.writeCommand(command); err != nil {
			return err
		}
	}
	return nil
}

// getPIN asks pinentry for a PIN. If the user cancels the dialog, the returned
// error can be tested with isCancelled.
func (c *pinentryClient) getPIN() (string, error) {
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
func (c *pinentryClient) writeCommand(command string) error {
	if err := c.writeLine(command); err != nil {
		return err
	}
	return c.readOK()
}

// writeLine writes a single Assuan line to pinentry.
func (c *pinentryClient) writeLine(line string) error {
	if _, err := io.WriteString(c.stdin, line+"\n"); err != nil {
		return fmt.Errorf("write to pinentry: %w", err)
	}
	return nil
}

// readOK reads a response and requires it to be OK.
func (c *pinentryClient) readOK() error {
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
func (c *pinentryClient) readLine() (string, error) {
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
func (c *pinentryClient) close() error {
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

// pinentryTTY returns the terminal that pinentry should use for text-mode
// dialogs. It returns an empty string when no terminal can be determined.
func pinentryTTY() string {
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
