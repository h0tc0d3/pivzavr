package main

import (
	"testing"

	"github.com/h0tc0d3/pivzavr/pkg/embed"
	"github.com/stretchr/testify/assert"
)

func TestEmbeddedSignatureName(t *testing.T) {
	assert.Equal(t, "report.signed.pdf", embeddedSignatureName("report.pdf"))
	assert.Equal(t, "/tmp/book.signed.xlsx", embeddedSignatureName("/tmp/book.xlsx"))
	assert.Equal(t, "invoice.signed.xml", embeddedSignatureName("invoice.xml"))
	assert.Equal(t, "archive.signed", embeddedSignatureName("archive"))
}

func TestIsSignatureFileOutput(t *testing.T) {
	assert.True(t, isSignatureFileOutput("message.txt.sig"))
	assert.True(t, isSignatureFileOutput("message.p7m"))
	assert.True(t, isSignatureFileOutput("message.asc"))
	assert.False(t, isSignatureFileOutput("report.pdf"))
	assert.False(t, isSignatureFileOutput("report"))
	assert.False(t, isSignatureFileOutput(""))
	assert.False(t, isSignatureFileOutput("-"))
}

func TestEmbeddableSignature(t *testing.T) {
	testCases := []struct {
		name      string
		fileArgs  []string
		sign      bool
		detach    bool
		output    string
		extension string
		want      embed.Format
		wantOK    bool
	}{
		{
			name:     "a PDF is signed in itself",
			fileArgs: []string{"report.pdf"},
			sign:     true,
			want:     embed.PDF,
			wantOK:   true,
		},
		{
			name:     "the output keeps the format of the document",
			fileArgs: []string{"report.pdf"},
			sign:     true,
			output:   "signed.pdf",
			want:     embed.PDF,
			wantOK:   true,
		},
		{
			name:     "a signature output file is not embedded",
			fileArgs: []string{"report.pdf"},
			sign:     true,
			output:   "report.pdf.sig",
			wantOK:   false,
		},
		{
			name:      "a guessed extension is not embedded",
			fileArgs:  []string{"report.pdf"},
			sign:      true,
			extension: "p7m",
			wantOK:    false,
		},
		{
			name:     "a detached signature is never embedded",
			fileArgs: []string{"report.pdf"},
			sign:     true,
			detach:   true,
			wantOK:   false,
		},
		{
			name:     "a plain text file has no embedded signature",
			fileArgs: []string{"notes.txt"},
			sign:     true,
			wantOK:   false,
		},
		{
			name:     "several files are never embedded",
			fileArgs: []string{"a.pdf", "b.pdf"},
			sign:     true,
			wantOK:   false,
		},
		{
			name:     "verification does not embed",
			fileArgs: []string{"report.pdf"},
			sign:     false,
			wantOK:   false,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			format, ok := embeddableSignature(test.fileArgs, test.sign, test.detach, test.output, test.extension)
			assert.Equal(t, test.wantOK, ok)
			if test.wantOK {
				assert.Equal(t, test.want, format)
			}
		})
	}
}
