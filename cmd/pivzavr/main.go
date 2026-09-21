// Command pivzavr manages the X.509 certificates of a PIV smart card and signs
// and verifies data with them. It is compatible with the way git invokes an
// external program to sign and verify commits and tags.
package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"github.com/h0tc0d3/pivzavr/pkg/config"
	"github.com/h0tc0d3/pivzavr/pkg/embed"
	"github.com/h0tc0d3/pivzavr/pkg/i18n"
	"github.com/h0tc0d3/pivzavr/pkg/pivzavr"
	"github.com/pborman/getopt/v2"
)

func main() {
	if err := runCommand(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// version is the version of the program. A release build stamps the version
// into the binary with the linker, as in
//
//	go build -ldflags "-X main.version=v1.5.0" ./cmd/pivzavr
//
// which the Makefile does, and a build that does not set it reports that it is a
// development build.
var version = "development"

// helpWidth is the width, in characters, that the description of a command
// line option is wrapped at.
const helpWidth = 60

// optionHelp translates the description of a command line option and wraps it
// at helpWidth characters. getopt wraps the help text at a number of bytes,
// which would break a translated description after fewer characters than the
// English one, so the descriptions are wrapped here and getopt is left to
// print them unchanged.
func optionHelp(description string) string {
	return wrap(i18n.Sprintf(description), helpWidth)
}

func runCommand() error {
	// The language is resolved before the options are registered, so that the
	// help text of the options is translated as well. A configuration file
	// that cannot be read is not reported here: the commands that need a
	// setting from it report it, and a translated message is more useful than
	// one that could not be translated yet.
	language, _ := config.Language()
	i18n.SetLanguage(i18n.ResolveLanguage(language))

	helpFlag := getopt.BoolLong("help", 'h', optionHelp("print this help message"))
	versionFlag := getopt.BoolLong("version", 'V', optionHelp("print the version of pivzavr and exit"))
	signFlag := getopt.BoolLong("sign", 's', optionHelp("make a signature"))
	verifyFlag := getopt.BoolLong("verify", 0, optionHelp("verify a signature"))
	resetFlag := getopt.BoolLong("reset", 0, optionHelp("restore the factory state of the smart card by erasing the PIV keys and certificates"))
	unlockFlag := getopt.BoolLong("unlock", 0, optionHelp("unlock the smart card PIN with the PUK, resetting the PIN and PUK retry counters"))
	setPINFlag := getopt.BoolLong("set-pin", 0, optionHelp("replace the smart card PIN"))
	setPUKFlag := getopt.BoolLong("set-puk", 0, optionHelp("replace the smart card PUK"))
	setCHUIDFlag := getopt.BoolLong("set-chuid", 0, optionHelp("write a new Card Holder Unique Identifier (CHUID) to the smart card"))
	setCCCFlag := getopt.BoolLong("set-ccc", 0, optionHelp("write a new Card Capability Container (CCC) to the smart card"))
	setManagementKeyOpt := getopt.StringLong("set-management-key", 0, "", optionHelp("replace the card management key with a key of ALGO (AES128, AES192 or AES256; default AES256)"), "ALGO")
	getopt.Lookup("set-management-key").SetOptional()
	protectOpt := getopt.StringLong("protect", 0, "", optionHelp("store the new card management key on the smart card, protected by the PIN (0 or 1)"), "0|1")
	randomFlag := getopt.BoolLong("random", 0, optionHelp("generate the new card management key instead of asking for it"))
	slot := getopt.StringLong("slot", 'w', "9c", optionHelp("choose a PIV slot by key reference (9a-9e, 82-95, f9), defaults to PIV slot 9c"), "slot")
	printFlag := getopt.BoolLong("print", 'p', optionHelp("prints the certificate with it's fingerprint and details"))
	infoFlag := getopt.BoolLong("info", 'i', optionHelp("print device information and active PIV slots"))
	updateTrustFlag := getopt.BoolLong("update-trust", 0, optionHelp("rebuild the trust store from the Mozilla store, the smart card sources and the configured CA certificates and public keys"))

	localUserOpt := getopt.StringLong("local-user", 'u', "", optionHelp("use USER-ID to sign: a key fingerprint or an email address in the certificate Subject DN"), "USER-ID")
	detachSignFlag := getopt.BoolLong("detach-sign", 'b', optionHelp("make a detached signature: on its own it writes a signature file, with --sign it keeps the content out of the signature"))
	armorFlag := getopt.BoolLong("armor", 'a', optionHelp("create ascii armored output"))
	clearsignFlag := getopt.BoolLong("clearsign", 0, optionHelp("make a clear text signature of a text file or message"))
	outputOpt := getopt.StringLong("output", 'o', "", optionHelp("write the signature to FILE instead of the standard output"), "FILE")
	extOpt := getopt.StringLong("ext", 0, "", optionHelp("extension of the signature file (sig, sign, sgn, p7s, p7m, asc or pem, without the dot)"), "EXT")
	statusFdOpt := getopt.IntLong("status-fd", 0, -1, optionHelp("write special status strings to the file descriptor n."), "n")
	tsaOpt := getopt.StringLong("timestamp-authority", 't', "", optionHelp("URL of RFC3161 timestamp authority to use for timestamping"), "url")

	// getopt aligns the option names in a column that is at most
	// HelpColumn-3 characters wide and puts the help text of a longer option
	// on its own line. The help text itself is wrapped by optionHelp, so
	// getopt is asked not to wrap it: it wraps at a number of bytes, which
	// breaks a translated description after fewer characters than an English
	// one.
	getopt.HelpColumn = 40
	getopt.DisplayWidth = math.MaxInt
	getopt.SetParameters("[files]")
	getopt.SetUsage(func() {
		printUsage(os.Stderr)
	})
	getopt.Parse()
	fileArgs := getopt.Args()
	// The algorithm of the new management key is optional, so the command is
	// recognised by the option itself rather than by a value.
	setManagementKey := getopt.IsSet("set-management-key")

	if *helpFlag {
		printUsage(os.Stderr)
		return nil
	}
	if *versionFlag {
		_, _ = fmt.Fprintf(os.Stdout, "pivzavr %s\n", version)
		return nil
	}

	// Validate the command before opening the smart card so invalid invocations
	// report a usage error instead of requiring hardware to be present.
	commandFlags := 0
	if *infoFlag {
		commandFlags++
	}
	if *updateTrustFlag {
		commandFlags++
	}
	if *signFlag {
		commandFlags++
	}
	if *verifyFlag {
		commandFlags++
	}
	if *clearsignFlag {
		commandFlags++
	}
	if *resetFlag {
		commandFlags++
	}
	if *unlockFlag {
		commandFlags++
	}
	if *setPINFlag {
		commandFlags++
	}
	if *setPUKFlag {
		commandFlags++
	}
	if *setCHUIDFlag {
		commandFlags++
	}
	if *setCCCFlag {
		commandFlags++
	}
	if setManagementKey {
		commandFlags++
	}
	if *printFlag {
		commandFlags++
	}
	// Without --sign, --detach-sign is a command of its own that writes a
	// detached signature file. It is one only when it is the only command, so
	// that a combination with another command is named by the check of that
	// command rather than as a second command.
	detachSignCommand := *detachSignFlag && !*signFlag && commandFlags == 0
	if detachSignCommand {
		commandFlags++
	}
	if err := commandError(commandFlags); err != nil {
		return err
	}

	// The options that adjust how the management key is replaced belong to
	// --set-management-key, so a plain invocation does not carry them.
	if !setManagementKey {
		if *randomFlag {
			return i18n.New("Random requires --set-management-key.")
		}
		if *protectOpt != "" {
			return i18n.New("Protect requires --set-management-key.")
		}
	}
	algorithm, fileArgs, err := managementKeyArgument(setManagementKey, *setManagementKeyOpt, fileArgs)
	if err != nil {
		return err
	}
	protect, err := parseProtect(*protectOpt)
	if err != nil {
		return err
	}

	// Validate command-specific arguments before accessing the smart card.
	// The options that only --verify rejects are checked first, so that a
	// combination such as --detach-sign with --verify names the option instead
	// of asking for a user to sign with.
	if *verifyFlag {
		switch {
		case len(*localUserOpt) > 0:
			return i18n.New("Local-user cannot be specified for verification.")
		case *detachSignFlag:
			return i18n.New("Detach-sign cannot be specified for verification.")
		case *armorFlag:
			return i18n.New("Armor cannot be specified for verification.")
		}
	}
	if (*signFlag || detachSignCommand || *clearsignFlag) && len(*localUserOpt) == 0 {
		return i18n.New("Specify a USER-ID to sign with.")
	}
	// The options that change how the signature is written belong to the
	// signing commands.
	if !*signFlag && !detachSignCommand && !*clearsignFlag {
		if *outputOpt != "" {
			return i18n.New("Output requires --sign, --clearsign or --detach-sign.")
		}
		if *extOpt != "" {
			return i18n.New("Ext requires --sign or --detach-sign.")
		}
	}
	if *clearsignFlag {
		if err := clearsignOptionError(*extOpt, *detachSignFlag); err != nil {
			return err
		}
	}
	// The signature of a container file is embedded in the file itself, unless
	// the invocation asks for a signature file.
	embeddedFormat, embedded := embeddableSignature(fileArgs, *signFlag, *detachSignFlag, *outputOpt, *extOpt)

	// The info command reports every connected device, so it runs before a
	// single token is selected.
	if *infoFlag {
		devices, err := pivzavr.DeviceInfos()
		if err != nil {
			return err
		}
		for _, device := range devices {
			if _, err := fmt.Fprint(os.Stdout, pivzavr.FormatDeviceInfo(device)); err != nil {
				return err
			}
		}
		return nil
	}

	// Updating the trust store only writes to the configuration directory, so
	// it runs before a token is selected as well.
	if *updateTrustFlag {
		path, err := config.UpdateTrust()
		if err != nil {
			return err
		}
		_, err = i18n.Fprintf(os.Stdout, "Trust store updated: %s\n", path)
		return err
	}

	serial, err := config.Serial()
	if err != nil {
		return err
	}

	tok, err := pivzavr.TokenHandleWithSerial(serial)
	if err != nil {
		return i18n.Wrap(err, "Failed to open smart card")
	}
	defer func() {
		_ = tok.Close()
	}()

	if detachSignCommand {
		if len(fileArgs) != 1 {
			return i18n.Errorf("expected exactly one file argument but got: %v", fileArgs)
		}
		return writeDetachedSignature(tok, detachedSignatureOpts{
			input:              fileArgs[0],
			output:             *outputOpt,
			extension:          *extOpt,
			armor:              *armorFlag,
			statusFd:           *statusFdOpt,
			timestampAuthority: *tsaOpt,
			userID:             *localUserOpt,
			slot:               pivzavr.GetSlot(*slot),
		})
	}

	if *clearsignFlag {
		var message io.ReadCloser
		var err error
		switch len(fileArgs) {
		case 0:
			message = os.Stdin
		case 1:
			if message, err = os.Open(fileArgs[0]); err != nil {
				return err
			}
			defer func() {
				_ = message.Close()
			}()
		default:
			return i18n.Errorf("expected 0 or 1 file arguments but got: %v", fileArgs)
		}

		signature, err := pivzavr.Sign(tok, &pivzavr.SignOpts{
			StatusFd:           *statusFdOpt,
			Clearsign:          true,
			UserID:             *localUserOpt,
			TimestampAuthority: *tsaOpt,
			Message:            message,
			Slot:               pivzavr.GetSlot(*slot),
		})
		if err != nil {
			return err
		}
		return writeSignatureOutput(signature, *outputOpt)
	}

	if *signFlag {
		if embedded {
			if len(fileArgs) != 1 {
				return i18n.Errorf("expected exactly one file argument but got: %v", fileArgs)
			}
			return writeEmbeddedSignature(tok, *outputOpt, fileArgs[0], embeddedFormat, *statusFdOpt, *localUserOpt, pivzavr.GetSlot(*slot))
		}

		// A detached signature that names an output file or an extension is
		// written to that file, like the standalone --detach-sign command.
		if *detachSignFlag && (*outputOpt != "" || *extOpt != "") {
			if len(fileArgs) != 1 {
				return i18n.Errorf("expected exactly one file argument but got: %v", fileArgs)
			}
			return writeDetachedSignature(tok, detachedSignatureOpts{
				input:              fileArgs[0],
				output:             *outputOpt,
				extension:          *extOpt,
				armor:              *armorFlag,
				statusFd:           *statusFdOpt,
				timestampAuthority: *tsaOpt,
				userID:             *localUserOpt,
				slot:               pivzavr.GetSlot(*slot),
			})
		}

		var message io.ReadCloser
		var err error
		switch len(fileArgs) {
		case 0:
			message = os.Stdin
		case 1:
			if message, err = os.Open(fileArgs[0]); err != nil {
				return err
			}
			defer func() {
				_ = message.Close()
			}()
		default:
			return i18n.Errorf("expected 0 or 1 file arguments but got: %v", fileArgs)
		}

		opts := &pivzavr.SignOpts{
			StatusFd:           *statusFdOpt,
			Detach:             *detachSignFlag,
			Armor:              *armorFlag,
			UserID:             *localUserOpt,
			TimestampAuthority: *tsaOpt,
			Message:            message,
			Slot:               pivzavr.GetSlot(*slot),
		}
		signature, err := pivzavr.Sign(tok, opts)
		if err != nil {
			return err
		}
		return writeSignatureOutput(signature, *outputOpt)
	}

	if *verifyFlag {
		var signature io.ReadCloser
		var message io.ReadCloser
		var err error
		message = nil
		switch len(fileArgs) {
		case 2:
			// verify detached signature
			signature, err = os.Open(fileArgs[0])
			if err != nil {
				return i18n.Wrap(err, "Read signature file")
			}
			defer func() {
				_ = signature.Close()
			}()

			if fileArgs[1] == "-" {
				message = os.Stdin
			} else {
				message, err = os.Open(fileArgs[1])
				if err != nil {
					return i18n.Wrap(err, "Read message file")
				}

				defer func() {
					_ = message.Close()
				}()
			}
		case 1:
			// A signature file that has the file it signs next to it is
			// verified as a detached signature, and a file whose format carries
			// an embedded signature is verified in itself.
			if fileArgs[0] != "-" {
				if format := embed.Detect(fileArgs[0]); !isSignatureFileOutput(fileArgs[0]) && format.Embeddable() {
					return verifyEmbeddedFile(tok, pivzavr.GetSlot(*slot), format, fileArgs[0])
				}
				if original, ok := pivzavr.OriginalFileName(fileArgs[0]); ok {
					if _, statErr := os.Stat(original); statErr == nil {
						return verifyDetachedFile(tok, pivzavr.GetSlot(*slot), fileArgs[0], original)
					}
				}
			}

			// verify attached signature
			signature, err = os.Open(fileArgs[0])
			if err != nil {
				return i18n.Wrap(err, "Read signature file")
			}
			defer func() {
				_ = signature.Close()
			}()
		case 0:
			// verify attached signature from stdin
			signature = os.Stdin
		default:
			return i18n.Errorf("expected either 0, 1, or 2 file arguments but got: %v", fileArgs)
		}

		opts := &pivzavr.VerifyOpts{
			Signature: signature,
			Message:   message,
			Slot:      pivzavr.GetSlot(*slot),
		}
		return pivzavr.VerifySignature(tok, opts)
	}

	if *unlockFlag {
		return pivzavr.UnlockToken(tok)
	}

	if *resetFlag {
		if err := pivzavr.ResetToken(tok); err != nil {
			return err
		}
		if _, err := fmt.Fprint(os.Stdout, resetMessage()); err != nil {
			return err
		}
		return nil
	}

	if *setPINFlag {
		if err := pivzavr.SetPIN(tok); err != nil {
			return err
		}
		_, err := i18n.Fprintf(os.Stdout, "New PIN set.\n")
		return err
	}

	if *setPUKFlag {
		if err := pivzavr.SetPUK(tok); err != nil {
			return err
		}
		_, err := i18n.Fprintf(os.Stdout, "New PUK set.\n")
		return err
	}

	if *setCHUIDFlag {
		value, err := pivzavr.SetCHUID(tok)
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(os.Stdout, objectMessage("CHUID", value))
		return err
	}

	if *setCCCFlag {
		value, err := pivzavr.SetCCC(tok)
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(os.Stdout, objectMessage("CCC", value))
		return err
	}

	if setManagementKey {
		generated, err := pivzavr.SetManagementKey(tok, algorithm, protect, *randomFlag)
		if err != nil {
			return err
		}
		if generated != nil {
			if _, err := i18n.Fprintf(os.Stdout, "Generated management key: %s\n", strings.ToUpper(hex.EncodeToString(generated))); err != nil {
				return err
			}
		}
		_, err = fmt.Fprint(os.Stdout, managementKeyMessage(protect))
		return err
	}

	if *printFlag {
		opts := &pivzavr.CertificateOpts{
			Slot: pivzavr.GetSlot(*slot),
		}
		certificateInfo, err := pivzavr.Certificate(tok, opts)
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(os.Stdout, pivzavr.FormatCertificate(certificateInfo))
		return err
	}

	return i18n.New(commandList)
}

// commandError reports the error of an invocation that does not name exactly one
// command. The commands are run one at a time, so a call that names none and a
// call that names several are both rejected, and each reports what is wrong with
// it. No error is returned for a single command.
func commandError(commandFlags int) error {
	switch {
	case commandFlags > 1:
		return i18n.New(multipleCommands)
	case commandFlags < 1:
		return i18n.New(commandList)
	}
	return nil
}

// commandList is the message reported when an invocation names no command.
const commandList = "No actions detected. Use \"--help\" or \"-h\" to view help on available commands."

// multipleCommands is the message reported when an invocation names more than
// one command, which is rejected because the commands replace the state of a
// smart card one at a time.
const multipleCommands = "More than one action detected. Run one action at a time. Use \"--help\" or \"-h\" to view help on available commands."

// clearsignOptionError reports the options that a clear text signature does not
// accept. A clear text signature is written to one text file, so it names no
// signature format of its own and an extension does not describe it. It keeps
// the content out of the signature and always armors it as well, so
// --detach-sign does not describe it either.
func clearsignOptionError(extension string, detachSign bool) error {
	if extension != "" {
		return i18n.New("Ext cannot be specified with --clearsign.")
	}
	if detachSign {
		return i18n.New("Detach-sign cannot be specified with --clearsign.")
	}
	return nil
}

// parseProtect parses the value of the --protect option, which reports whether
// the new management key is stored on the smart card. An option that was not
// given asks for the key not to be stored.
func parseProtect(value string) (bool, error) {
	switch strings.TrimSpace(value) {
	case "", "0":
		return false, nil
	case "1":
		return true, nil
	}
	return false, i18n.Errorf("Invalid --protect value %q, use 0 or 1.", value)
}

// managementKeyMessage reports the state of the card management key after it was
// replaced.
func managementKeyMessage(protect bool) string {
	if protect {
		return i18n.Sprintf("New management key set and stored on the smart card, protected by the PIN.\n")
	}
	return i18n.Sprintf("New management key set.\n")
}

// objectMessage reports a PIV data object that was written to a smart card,
// named name, as the value that the card stored, in the form the device
// information reports it.
func objectMessage(name string, value []byte) string {
	return i18n.Sprintf("New %s written to the smart card.\n%s: %s\n", name, name, strings.ToUpper(hex.EncodeToString(value)))
}

// managementKeyArgument returns the algorithm of --set-management-key and the
// arguments that are left for the rest of the command. set reports whether the
// option was given: the arguments of a command that does not replace the
// management key, such as the file that is signed, are returned unchanged.
// getopt only takes the value of an option with an optional parameter when it is
// attached with an equals sign, so an algorithm that is written behind the
// option is taken from the argument that follows it, which is the form the
// option accepted before the algorithm became optional.
func managementKeyArgument(set bool, algorithm string, args []string) (string, []string, error) {
	if !set {
		return algorithm, args, nil
	}
	if algorithm == "" && len(args) == 1 {
		return args[0], nil, nil
	}
	if len(args) != 0 {
		return "", nil, i18n.New("No files can be specified with --set-management-key.")
	}
	return algorithm, args, nil
}

// resetMessage reports the factory state the smart card is in after a reset.
func resetMessage() string {
	return i18n.Sprintf(
		"Reset complete. All PIV data has been cleared from the smart card.\n"+
			"The smart card now has the default PIN, PUK and management key:\n"+
			"\tPIN:\t%s\n"+
			"\tPUK:\t%s\n"+
			"\tManagement Key:\t%s\n",
		pivzavr.DefaultPIN, pivzavr.DefaultPUK, pivzavr.DefaultManagementKey)
}
