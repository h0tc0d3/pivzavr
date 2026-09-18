package main

import (
	"fmt"
	"io"
	"os"

	"github.com/h0tc0d3/pivzavr/pkg/pivzavr"
	"github.com/pborman/getopt/v2"
	"github.com/pkg/errors"
)

func main() {
	if err := runCommand(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runCommand() error {
	helpFlag := getopt.BoolLong("help", 'h', "print this help message")
	signFlag := getopt.BoolLong("sign", 's', "make a signature")
	verifyFlag := getopt.BoolLong("verify", 0, "verify a signature")
	resetFlag := getopt.BoolLong("reset", 'r', "resets the smart card PIV applet and sets new PIN, random PUK, and PIN derived management key")
	slot := getopt.StringLong("slot", 'w', "9c", "choose a PIV slot by key reference (9a-9e, 82-95, f9), defaults to PIV slot 9c", "slot")
	printFlag := getopt.BoolLong("print", 'p', "prints the certificate with its fingerprint and details")
	infoFlag := getopt.BoolLong("info", 'i', "print device information and active PIV slots")

	localUserOpt := getopt.StringLong("local-user", 'u', "", "use USER-ID to sign", "USER-ID")
	detachSignFlag := getopt.BoolLong("detach-sign", 'b', "make a detached signature")
	armorFlag := getopt.BoolLong("armor", 'a', "create ascii armored output")
	statusFdOpt := getopt.IntLong("status-fd", 0, -1, "write special status strings to the file descriptor n.", "n")
	tsaOpt := getopt.StringLong("timestamp-authority", 't', "", "URL of RFC3161 timestamp authority to use for timestamping", "url")

	getopt.HelpColumn = 40
	getopt.SetParameters("[files]")
	getopt.Parse()
	fileArgs := getopt.Args()

	if *helpFlag {
		getopt.Usage()
		return nil
	}

	// Validate the command before opening the smart card so invalid invocations
	// report a usage error instead of requiring hardware to be present.
	commandFlags := 0
	if *infoFlag {
		commandFlags++
	}
	if *signFlag {
		commandFlags++
	}
	if *verifyFlag {
		commandFlags++
	}
	if *resetFlag {
		commandFlags++
	}
	if *printFlag {
		commandFlags++
	}
	if commandFlags != 1 {
		return errors.New("Specify --help, --sign, --verify, --reset, --print or --info.")
	}

	// Validate command-specific arguments before accessing the smart card.
	if *signFlag && len(*localUserOpt) == 0 {
		return errors.New("Specify a USER-ID to sign with.")
	}
	if *verifyFlag {
		if len(*localUserOpt) > 0 {
			return errors.New("Local-user cannot be specified for verification.")
		} else if *detachSignFlag {
			return errors.New("Detach-sign cannot be specified for verification.")
		} else if *armorFlag {
			return errors.New("Armor cannot be specified for verification.")
		}
	}

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

	serial, err := pivzavr.Serial()
	if err != nil {
		return err
	}

	tok, err := pivzavr.TokenHandleWithSerial(serial)
	if err != nil {
		return errors.Wrap(err, "Failed to open smart card")
	}
	defer func() {
		_ = tok.Close()
	}()

	if *signFlag {
		var message io.ReadCloser
		var err error
		if len(fileArgs) == 0 {
			message = os.Stdin
		} else if len(fileArgs) == 1 {
			if message, err = os.Open(fileArgs[0]); err != nil {
				return err
			}
			defer func() {
				_ = message.Close()
			}()
		} else {
			return fmt.Errorf("expected 0 or 1 file arguments but got: %v", fileArgs)
		}

		opts := &pivzavr.SignOpts{
			StatusFd:           *statusFdOpt,
			Detach:             *detachSignFlag,
			Armor:              *armorFlag,
			UserId:             *localUserOpt,
			TimestampAuthority: *tsaOpt,
			Message:            message,
			Slot:               pivzavr.GetSlot(*slot),
			Prompt:             os.Stdin,
		}
		signature, err := pivzavr.Sign(tok, opts)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(signature)
		return err
	}

	if *verifyFlag {
		var signature io.ReadCloser
		var message io.ReadCloser
		var err error
		message = nil
		if len(fileArgs) == 2 {
			// verify detached signature
			signature, err = os.Open(fileArgs[0])
			if err != nil {
				return errors.Wrap(err, "Read signature file")
			}
			defer func() {
				_ = signature.Close()
			}()

			if fileArgs[1] == "-" {
				message = os.Stdin
			} else {
				message, err = os.Open(fileArgs[1])
				if err != nil {
					return errors.Wrap(err, "Read message file")
				}

				defer func() {
					_ = message.Close()
				}()
			}
		} else if len(fileArgs) == 1 {
			// verify attached signature
			signature, err = os.Open(fileArgs[0])
			if err != nil {
				return errors.Wrap(err, "Read signature file")
			}
			defer func() {
				_ = signature.Close()
			}()
		} else if len(fileArgs) == 0 {
			// verify attached signature from stdin
			signature = os.Stdin
		} else {
			return fmt.Errorf("expected either 0, 1, or 2 file arguments but got: %v", fileArgs)
		}

		opts := &pivzavr.VerifyOpts{
			Signature: signature,
			Message:   message,
			Slot:      pivzavr.GetSlot(*slot),
		}
		return pivzavr.VerifySignature(tok, opts)
	}

	if *resetFlag {
		pin, err := pivzavr.GetPin(os.Stdin)
		if err != nil {
			return err
		}
		opts := &pivzavr.ResetOpts{Pin: pin}
		return pivzavr.ResetToken(tok, opts)
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

	return errors.New("Specify --help, --sign, --verify, --reset, --print or --info.")
}
