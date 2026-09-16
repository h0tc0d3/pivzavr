package pivzavr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCertificate_errEmptyToken(t *testing.T) {
	tok, err := testToken()
	if err != nil {
		t.Fatal(err)
	}

	opts := &CertificateOpts{
		Slot: SlotCardAuthentication,
	}
	_, err = Certificate(tok, opts)
	assert.EqualError(t, err, "Get PIV certificate: Key not found.")
}

func TestPrintCertificate_success(t *testing.T) {
	tok, err := testToken()
	if err != nil {
		t.Fatal(err)
	}

	_, err = generateKeyAndCertificate(tok, SlotCardAuthentication)
	if err != nil {
		t.Fatal(err)
	}

	opts := &CertificateOpts{
		Slot: SlotCardAuthentication,
	}
	output, err := Certificate(tok, opts)
	assert.NoError(t, err)
	assert.NotEmpty(t, output.Fingerprint)
	assert.NotEmpty(t, output.CertificatePem)
	assert.Equal(t, SlotCardAuthentication, output.Slot)
	assert.NotNil(t, output.Certificate)
	assert.Equal(t, "pivzavr test", output.Certificate.Subject.CommonName)
}
