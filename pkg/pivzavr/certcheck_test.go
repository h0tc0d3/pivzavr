package pivzavr

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateSigningCertificate(t *testing.T) {
	testCases := []struct {
		name    string
		mutate  func(*x509.Certificate)
		wantErr string
	}{
		{
			name: "certificate without usage extensions",
		},
		{
			name:   "key usage permits digital signatures",
			mutate: func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature },
		},
		{
			name:   "key usage permits content commitment",
			mutate: func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageContentCommitment },
		},
		{
			name: "key usage permits signing and encryption",
			mutate: func(c *x509.Certificate) {
				c.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
			},
		},
		{
			name:   "extended key usage permits client authentication",
			mutate: func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} },
		},
		{
			name:   "extended key usage permits code signing",
			mutate: func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning} },
		},
		{
			name:   "extended key usage is unconstrained",
			mutate: func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} },
		},
		{
			name: "key usage does not permit signatures",
			mutate: func(c *x509.Certificate) {
				c.KeyUsage = x509.KeyUsageKeyEncipherment
			},
			wantErr: "does not permit digital signatures",
		},
		{
			name: "key usage is limited to certificate signing",
			mutate: func(c *x509.Certificate) {
				c.KeyUsage = x509.KeyUsageCertSign
			},
			wantErr: "does not permit digital signatures",
		},
		{
			name: "extended key usage is limited to server authentication",
			mutate: func(c *x509.Certificate) {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
			wantErr: "not valid for signing",
		},
		{
			name: "extended key usage is limited to OCSP signing",
			mutate: func(c *x509.Certificate) {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
			},
			wantErr: "not valid for signing",
		},
		{
			name: "certificate is a CA",
			mutate: func(c *x509.Certificate) {
				c.BasicConstraintsValid = true
				c.IsCA = true
				c.KeyUsage = x509.KeyUsageCertSign
			},
			wantErr: "is a CA certificate",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			tmpl := &x509.Certificate{}
			if testCase.mutate != nil {
				testCase.mutate(tmpl)
			}
			cert, _ := newCertificate(t, nil, nil, tmpl)

			err := validateSigningCertificate(cert)
			if testCase.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), testCase.wantErr)
		})
	}
}

func TestPermitsSigning(t *testing.T) {
	microsoftDocumentSigning := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 12}

	testCases := []struct {
		name string
		cert *x509.Certificate
		want bool
	}{
		{
			name: "no extended key usage extension",
			cert: &x509.Certificate{},
			want: true,
		},
		{
			name: "empty extended key usage extension",
			cert: &x509.Certificate{
				Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}}},
			},
			want: true,
		},
		{
			name: "constrained to client authentication",
			cert: &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
			want: true,
		},
		{
			name: "constrained to server authentication",
			cert: &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
			want: false,
		},
		{
			name: "constrained to server authentication and code signing",
			cert: &x509.Certificate{
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning},
			},
			want: true,
		},
		{
			name: "unconstrained purpose",
			cert: &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
			want: true,
		},
		{
			name: "unnamed document signing purpose",
			cert: &x509.Certificate{UnknownExtKeyUsage: []asn1.ObjectIdentifier{microsoftDocumentSigning}},
			want: true,
		},
		{
			name: "unnamed unconstrained purpose",
			cert: &x509.Certificate{
				UnknownExtKeyUsage: []asn1.ObjectIdentifier{{2, 5, 29, 37, 0}},
			},
			want: true,
		},
		{
			name: "unnamed unrelated purpose",
			cert: &x509.Certificate{
				UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 9}},
			},
			want: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.want, permitsSigning(testCase.cert))
		})
	}
}

func TestIsSelfSigned(t *testing.T) {
	selfSigned, _ := newCertificate(t, nil, nil, &x509.Certificate{})
	assert.True(t, isSelfSigned(selfSigned))

	issuer, issuerKey := newCertificate(t, nil, nil, &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	})
	leaf, _ := newCertificate(t, issuer, issuerKey, &x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature})
	assert.False(t, isSelfSigned(leaf))
}

func TestSamePublicKey(t *testing.T) {
	cert, _ := newCertificate(t, nil, nil, &x509.Certificate{})
	other, _ := newCertificate(t, nil, nil, &x509.Certificate{})

	assert.True(t, samePublicKey(cert, cert))
	assert.False(t, samePublicKey(cert, other))
	assert.False(t, samePublicKey(cert, nil))
	assert.False(t, samePublicKey(nil, cert))
}

func TestFormatKeyUsage(t *testing.T) {
	assert.Equal(t, "none", formatKeyUsage(0))
	assert.Equal(t, "digitalSignature", formatKeyUsage(x509.KeyUsageDigitalSignature))
	assert.Equal(t, "digitalSignature, keyCertSign",
		formatKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign))
	assert.Equal(t, "cRLSign", formatKeyUsage(x509.KeyUsageCRLSign))
}

func TestFormatExtKeyUsage(t *testing.T) {
	assert.Equal(t, "none", formatExtKeyUsage(&x509.Certificate{}))
	assert.Equal(t, "serverAuth, clientAuth", formatExtKeyUsage(&x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}))
	assert.Equal(t, "1.3.6.1.4.1.311.10.3.12", formatExtKeyUsage(&x509.Certificate{
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 311, 10, 3, 12}},
	}))
	assert.Equal(t, "timeStamping", formatExtKeyUsage(&x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}))
}
