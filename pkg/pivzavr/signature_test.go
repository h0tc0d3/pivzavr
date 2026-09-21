package pivzavr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSignatureExtension(t *testing.T) {
	testCases := []struct {
		extension string
		armor     bool
		attached  bool
	}{
		{extension: "sig"},
		{extension: ".sig"},
		{extension: "SIG"},
		{extension: "sign"},
		{extension: "sgn"},
		{extension: "p7s"},
		{extension: "p7m", attached: true},
		{extension: "asc", armor: true},
		{extension: "pem", armor: true},
	}

	for _, test := range testCases {
		t.Run(test.extension, func(t *testing.T) {
			format, err := ParseSignatureExtension(test.extension)
			require.NoError(t, err)
			assert.Equal(t, test.armor, format.Armor)
			assert.Equal(t, test.attached, format.Attached)
		})
	}

	_, err := ParseSignatureExtension("docx")
	assert.ErrorContains(t, err, "Unsupported signature extension")
}

func TestDetachedOutputName(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		output    string
		extension string
		armor     bool
		wantName  string
		wantArmor bool
		wantAtt   bool
	}{
		{
			name:     "defaults to a binary signature next to the file",
			input:    "message.txt",
			wantName: "message.txt.sig",
		},
		{
			name:      "armor defaults to a text signature",
			input:     "message.txt",
			armor:     true,
			wantName:  "message.txt.asc",
			wantArmor: true,
		},
		{
			name:      "the extension names the signature file",
			input:     "message.txt",
			extension: "p7s",
			wantName:  "message.txt.p7s",
		},
		{
			name:      "an encapsulating extension attaches the content",
			input:     "message.txt",
			extension: ".p7m",
			wantName:  "message.txt.p7m",
			wantAtt:   true,
		},
		{
			name:      "a text extension needs armor",
			input:     "message.txt",
			extension: "asc",
			armor:     true,
			wantName:  "message.txt.asc",
			wantArmor: true,
		},
		{
			name:     "the output file decides the format",
			input:    "message.txt",
			output:   "signature.p7m",
			wantName: "signature.p7m",
			wantAtt:  true,
		},
		{
			name:      "the output file may be armored",
			input:     "message.txt",
			output:    "signature.asc",
			armor:     true,
			wantName:  "signature.asc",
			wantArmor: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			name, format, err := DetachedOutputName(test.input, test.output, test.extension, test.armor)
			require.NoError(t, err)
			assert.Equal(t, test.wantName, name)
			assert.Equal(t, test.wantArmor, format.Armor)
			assert.Equal(t, test.wantAtt, format.Attached)
		})
	}
}

func TestDetachedOutputNameErrors(t *testing.T) {
	_, _, err := DetachedOutputName("message.txt", "", "docx", false)
	assert.ErrorContains(t, err, "Unsupported signature extension")

	_, _, err = DetachedOutputName("message.txt", "", "asc", false)
	assert.ErrorContains(t, err, "requires -a or --armor")

	_, _, err = DetachedOutputName("message.txt", "signature", "", false)
	assert.ErrorContains(t, err, "Cannot infer the signature format")

	_, _, err = DetachedOutputName("message.txt", "signature.sig", "p7s", false)
	assert.ErrorContains(t, err, "not both")
}

func TestOriginalFileName(t *testing.T) {
	testCases := []struct {
		name string
		want string
		ok   bool
	}{
		{name: "message.txt.sig", want: "message.txt", ok: true},
		{name: "message.txt.p7s", want: "message.txt", ok: true},
		{name: "archive.tar.sign", want: "archive.tar", ok: true},
		{name: "message.txt.asc", want: "message.txt", ok: true},
		{name: "message.txt.p7m"},
		{name: "message.txt"},
		{name: "message"},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			got, ok := OriginalFileName(test.name)
			assert.Equal(t, test.ok, ok)
			if test.ok {
				assert.Equal(t, test.want, got)
			}
		})
	}
}
