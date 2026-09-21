package pivzavr

import (
	"path/filepath"
	"strings"

	"github.com/h0tc0d3/pivzavr/pkg/i18n"
)

// SignatureFormat describes how a signature is encoded in a file: the file
// extension it uses, whether it is PEM armored text, and whether the signed
// content is embedded in the signature.
type SignatureFormat struct {
	// Extension is the file extension without the leading dot, lowercase.
	Extension string
	// Armor reports whether the signature is PEM armored text rather than
	// binary DER.
	Armor bool
	// Attached reports whether the signed content is embedded in the
	// signature. An attached signature does not need the original file to be
	// verified.
	Attached bool
}

// signatureFormats are the recognized signature file extensions.
//
//   - .sig, .sign and .sgn are general-purpose detached signature extensions.
//   - .p7s is the detached form of PKCS#7/CMS while .p7m encapsulates the
//     signed content together with the signature.
//   - .asc and .pem hold a text-based (PEM/armor) signature.
var signatureFormats = []SignatureFormat{
	{Extension: "sig"},
	{Extension: "sign"},
	{Extension: "sgn"},
	{Extension: "p7s"},
	{Extension: "p7m", Attached: true},
	{Extension: "asc", Armor: true},
	{Extension: "pem", Armor: true},
}

// defaultBinaryExtension is the extension used for a binary detached signature
// when neither an output file nor an extension is given.
const defaultBinaryExtension = "sig"

// defaultArmorExtension is the extension used for an armored detached signature
// when neither an output file nor an extension is given.
const defaultArmorExtension = "asc"

// supportedSignatureExtensions renders the recognized extensions as a list for
// error messages.
func supportedSignatureExtensions() string {
	exts := make([]string, 0, len(signatureFormats))
	for _, format := range signatureFormats {
		exts = append(exts, "."+format.Extension)
	}
	return strings.Join(exts, ", ")
}

// ParseSignatureExtension returns the format described by ext, which may carry
// a leading dot. The lookup is case-insensitive.
func ParseSignatureExtension(ext string) (SignatureFormat, error) {
	name := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(ext), "."))
	for _, format := range signatureFormats {
		if format.Extension == name {
			return format, nil
		}
	}
	return SignatureFormat{}, i18n.Errorf("Unsupported signature extension %q, use one of %s.", ext, supportedSignatureExtensions())
}

// extensionOf returns the lowercase extension of a file name without its
// leading dot, or an empty string when the name has no extension.
func extensionOf(name string) string {
	return strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
}

// DetachedOutputName resolves the file a detached signature is written to and
// the format it is encoded in.
//
// An explicit output file wins and its extension determines the format.
// Otherwise an explicit signature extension is appended to the input file
// name. When neither is given the signature is written next to the input file
// with the default .sig extension, or with the .asc extension when armor was
// requested.
func DetachedOutputName(input, output, ext string, armor bool) (string, SignatureFormat, error) {
	switch {
	case output != "":
		if ext != "" {
			return "", SignatureFormat{}, i18n.New("Specify either an output file or a signature extension, not both.")
		}
		format, err := ParseSignatureExtension(extensionOf(output))
		if err != nil {
			return "", SignatureFormat{}, i18n.Errorf("Cannot infer the signature format of output file %q: %v", output, err)
		}
		if err := requireArmor(format, armor); err != nil {
			return "", SignatureFormat{}, err
		}
		return output, format, nil
	case ext != "":
		format, err := ParseSignatureExtension(ext)
		if err != nil {
			return "", SignatureFormat{}, err
		}
		if err := requireArmor(format, armor); err != nil {
			return "", SignatureFormat{}, err
		}
		return input + "." + format.Extension, format, nil
	case armor:
		return input + "." + defaultArmorExtension, SignatureFormat{Extension: defaultArmorExtension, Armor: true}, nil
	default:
		return input + "." + defaultBinaryExtension, SignatureFormat{Extension: defaultBinaryExtension}, nil
	}
}

// requireArmor rejects a text-based signature format that was requested without
// armor.
func requireArmor(format SignatureFormat, armor bool) error {
	if format.Armor && !armor {
		return i18n.Errorf("Signature extension \".%s\" requires -a or --armor.", format.Extension)
	}
	return nil
}

// OriginalFileName infers the file a detached signature was made from by
// removing a recognized detached-signature extension. It returns false when
// name does not end in such an extension.
func OriginalFileName(name string) (string, bool) {
	ext := extensionOf(name)
	if ext == "" {
		return "", false
	}
	format, err := ParseSignatureExtension(ext)
	if err != nil || format.Attached {
		return "", false
	}
	return strings.TrimSuffix(name, filepath.Ext(name)), true
}
