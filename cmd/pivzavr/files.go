package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/h0tc0d3/pivzavr/pkg/embed"
	"github.com/h0tc0d3/pivzavr/pkg/i18n"
	"github.com/h0tc0d3/pivzavr/pkg/pivzavr"
)

// detachedSignatureOpts holds the options of the standalone --detach-sign
// command and of the --sign form that writes a signature file.
type detachedSignatureOpts struct {
	// input is the file the signature is made over.
	input string
	// output is the file the signature is written to. It is empty when the
	// signature file is named after the input file.
	output string
	// extension is the extension of the signature file, without the dot.
	extension string
	// armor requests a text based signature.
	armor bool
	// statusFd is the file descriptor the status protocol is written to.
	statusFd int
	// timestampAuthority is the URL of an RFC 3161 timestamp authority.
	timestampAuthority string
	// userID identifies the certificate that signs.
	userID string
	// slot is the smart card slot that holds the key.
	slot pivzavr.Slot
}

// embeddableSignature reports whether a signing invocation embeds the signature
// in the file rather than writing a signature file of its own. That is the case
// for a single file whose format carries an embedded signature, when the
// invocation neither asks for a detached signature nor names a signature file
// as its output.
func embeddableSignature(fileArgs []string, sign, detach bool, output, extension string) (embed.Format, bool) {
	if !sign || detach || extension != "" || len(fileArgs) != 1 {
		return embed.Unknown, false
	}
	if output != "" && isSignatureFileOutput(output) {
		return embed.Unknown, false
	}
	format := embed.Detect(fileArgs[0])
	if !format.Embeddable() {
		return embed.Unknown, false
	}
	return format, true
}

// isSignatureFileOutput reports whether a file name ends in a recognized
// signature extension, in which case it holds a signature rather than a signed
// document.
func isSignatureFileOutput(name string) bool {
	if name == "" || name == "-" {
		return false
	}
	_, err := pivzavr.ParseSignatureExtension(filepath.Ext(name))
	return err == nil
}

// embeddedSignatureName returns the file a signed document is written to: the
// name of the document with ".signed" before its extension, so that the signed
// file keeps the extension that identifies its format.
func embeddedSignatureName(name string) string {
	extension := filepath.Ext(name)
	return strings.TrimSuffix(name, extension) + ".signed" + extension
}

// writeDetachedSignature writes a detached signature of a file to the file its
// extension selects.
func writeDetachedSignature(tok pivzavr.Pivzavr, opts detachedSignatureOpts) error {
	output, format, err := pivzavr.DetachedOutputName(opts.input, opts.output, opts.extension, opts.armor)
	if err != nil {
		return err
	}

	message, err := os.Open(opts.input)
	if err != nil {
		return err
	}
	defer func() {
		_ = message.Close()
	}()

	signature, err := pivzavr.Sign(tok, &pivzavr.SignOpts{
		StatusFd:           opts.statusFd,
		Detach:             !format.Attached,
		Armor:              format.Armor,
		UserID:             opts.userID,
		TimestampAuthority: opts.timestampAuthority,
		Message:            message,
		Slot:               opts.slot,
	})
	if err != nil {
		return err
	}
	return writeSignatureOutput(signature, output)
}

// writeEmbeddedSignature embeds a signature in a container file and writes the
// signed file next to it, or to the file that was named.
func writeEmbeddedSignature(tok pivzavr.Pivzavr, output, input string, format embed.Format, statusFd int, userID string, slot pivzavr.Slot) error {
	message, err := os.Open(input) // #nosec G304 -- the file is named on the command line.
	if err != nil {
		return err
	}
	defer func() {
		_ = message.Close()
	}()

	if output == "" {
		output = embeddedSignatureName(input)
	}
	// The signed file is as readable as the file it was made from.
	mode := fileMode(input, 0o644)
	signed, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode) // #nosec G304 -- the file is named on the command line.
	if err != nil {
		return i18n.Wrapf(err, "Write signed file %s", output)
	}
	defer func() {
		_ = signed.Close()
	}()

	err = pivzavr.SignEmbedded(tok, &pivzavr.EmbeddedSignOpts{
		StatusFd: statusFd,
		UserID:   userID,
		Format:   format,
		Message:  message,
		Output:   signed,
		Slot:     slot,
	})
	if err != nil {
		return err
	}
	_, err = i18n.Fprintf(os.Stdout, "Signature embedded in the file, signed file written to %s\n", output)
	return err
}

// writeSignatureOutput writes a signature to a file, or to the standard output
// when no file was named.
func writeSignatureOutput(signature []byte, output string) error {
	if output == "" {
		_, err := os.Stdout.Write(signature)
		return err
	}
	if err := os.WriteFile(output, signature, fileMode(output, 0o644)); err != nil { // #nosec G306 G304 -- the file is named on the command line and a signature is meant to be read.
		return i18n.Wrapf(err, "Write signature file %s", output)
	}
	_, err := i18n.Fprintf(os.Stdout, "Signature written to %s\n", output)
	return err
}

// fileMode returns the permission of a file, or fallback when the file does not
// exist yet.
func fileMode(name string, fallback os.FileMode) os.FileMode {
	if info, err := os.Stat(name); err == nil { // #nosec G304 -- the file is named on the command line.
		return info.Mode().Perm()
	}
	return fallback
}

// verifyEmbeddedFile verifies the signature that is embedded in a file.
func verifyEmbeddedFile(tok pivzavr.Pivzavr, slot pivzavr.Slot, format embed.Format, name string) error {
	message, err := os.Open(name) // #nosec G304 -- the file is named on the command line.
	if err != nil {
		return err
	}
	defer func() {
		_ = message.Close()
	}()

	return pivzavr.VerifyEmbedded(tok, &pivzavr.EmbeddedVerifyOpts{
		Format:  format,
		Message: message,
		Slot:    slot,
	})
}

// verifyDetachedFile verifies the detached signature of a file.
func verifyDetachedFile(tok pivzavr.Pivzavr, slot pivzavr.Slot, signatureName, messageName string) error {
	signature, err := os.Open(signatureName) // #nosec G304 -- the file is named on the command line.
	if err != nil {
		return i18n.Wrap(err, "Read signature file")
	}
	defer func() {
		_ = signature.Close()
	}()

	message, err := os.Open(messageName) // #nosec G304 -- the file is named on the command line.
	if err != nil {
		return i18n.Wrapf(err, "Read message file %s", messageName)
	}
	defer func() {
		_ = message.Close()
	}()

	return pivzavr.VerifySignature(tok, &pivzavr.VerifyOpts{
		Signature: signature,
		Message:   message,
		Slot:      slot,
	})
}
