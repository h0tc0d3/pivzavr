package pivzavr

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

// testLeaf returns a certificate issued by issuer that names responderURL as
// its OCSP responder.
func testLeaf(t *testing.T, issuer *x509.Certificate, issuerKey crypto.Signer, responderURL string) *x509.Certificate {
	t.Helper()

	leaf, _ := newCertificate(t, issuer, issuerKey, &x509.Certificate{
		Subject:    pkix.Name{CommonName: "pivzavr test leaf"},
		KeyUsage:   x509.KeyUsageDigitalSignature,
		OCSPServer: []string{responderURL},
	})
	return leaf
}

// ocspResponseServer starts an OCSP responder that answers every request with
// status, using the certificate of the request. It returns the URL the
// responder listens on.
func ocspResponseServer(t *testing.T, issuer *x509.Certificate, issuerKey crypto.Signer, status int) string {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		request, err := ocsp.ParseRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		now := time.Now().UTC()
		response, err := ocsp.CreateResponse(issuer, issuer, ocsp.Response{
			Status:       status,
			SerialNumber: request.SerialNumber,
			ThisUpdate:   now.Add(-time.Minute),
			NextUpdate:   now.Add(time.Hour),
			RevokedAt:    now.Add(-time.Hour),
		}, issuerKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(response)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func TestCheckRevocation(t *testing.T) {
	testCases := []struct {
		name   string
		status int
		want   revocationStatus
	}{
		{"good", ocsp.Good, revocationGood},
		{"revoked", ocsp.Revoked, revocationRevoked},
		{"unknown", ocsp.Unknown, revocationUnknown},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			issuer, issuerKey := testIssuer(t)
			leaf := testLeaf(t, issuer, issuerKey, ocspResponseServer(t, issuer, issuerKey, testCase.status))

			result := checkRevocation(leaf, issuer, nil)
			assert.Equal(t, testCase.want, result.Status)
			assert.NoError(t, result.Err)
			if testCase.want == revocationRevoked {
				assert.False(t, result.RevokedAt.IsZero())
			}
		})
	}
}

func TestCheckRevocationWithoutResponder(t *testing.T) {
	issuer, issuerKey := testIssuer(t)
	leaf, _ := newCertificate(t, issuer, issuerKey, &x509.Certificate{
		KeyUsage: x509.KeyUsageDigitalSignature,
	})

	// A certificate that names no responder is not checked at all.
	result := checkRevocation(leaf, issuer, nil)
	assert.Equal(t, revocationNotChecked, result.Status)
	assert.NoError(t, result.Err)
}

func TestCheckRevocationWithoutIssuer(t *testing.T) {
	issuer, issuerKey := testIssuer(t)
	leaf := testLeaf(t, issuer, issuerKey, "http://127.0.0.1:1/ocsp")

	result := checkRevocation(leaf, nil, nil)
	assert.Equal(t, revocationNotChecked, result.Status)
	assert.NoError(t, result.Err)
}

func TestCheckRevocationReportsUnavailableResponder(t *testing.T) {
	issuer, issuerKey := testIssuer(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	leaf := testLeaf(t, issuer, issuerKey, server.URL)

	result := checkRevocation(leaf, issuer, nil)
	assert.Equal(t, revocationUnknown, result.Status)
	require.Error(t, result.Err)
}

func TestCheckRevocationFallsBackToSecondResponder(t *testing.T) {
	issuer, issuerKey := testIssuer(t)
	unknownURL := ocspResponseServer(t, issuer, issuerKey, ocsp.Unknown)
	goodURL := ocspResponseServer(t, issuer, issuerKey, ocsp.Good)

	leaf, _ := newCertificate(t, issuer, issuerKey, &x509.Certificate{
		KeyUsage:   x509.KeyUsageDigitalSignature,
		OCSPServer: []string{unknownURL, goodURL},
	})

	// A responder that does not know the certificate is not an answer, so the
	// next one is asked.
	result := checkRevocation(leaf, issuer, nil)
	assert.Equal(t, revocationGood, result.Status)
	assert.NoError(t, result.Err)
}

func TestCheckRevocationIgnoresResponseForOtherCertificate(t *testing.T) {
	issuer, issuerKey := testIssuer(t)

	// The responder answers for a different serial number than the one that
	// was asked about.
	other, _ := newCertificate(t, issuer, issuerKey, &x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response, err := ocsp.CreateResponse(issuer, issuer, ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: other.SerialNumber,
			ThisUpdate:   time.Now().Add(-time.Minute).UTC(),
			NextUpdate:   time.Now().Add(time.Hour).UTC(),
		}, issuerKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(response)
	}))
	t.Cleanup(server.Close)

	leaf := testLeaf(t, issuer, issuerKey, server.URL)

	result := checkRevocation(leaf, issuer, nil)
	assert.Equal(t, revocationUnknown, result.Status)
	require.Error(t, result.Err)
}

func TestCheckRevocationUsesConfiguredResponder(t *testing.T) {
	issuer, issuerKey := testIssuer(t)

	// The certificate names no responder of its own, so the configured
	// responder is the only one that is asked.
	goodURL := ocspResponseServer(t, issuer, issuerKey, ocsp.Good)
	leaf, _ := newCertificate(t, issuer, issuerKey, &x509.Certificate{
		KeyUsage: x509.KeyUsageDigitalSignature,
	})

	result := checkRevocation(leaf, issuer, []string{goodURL})
	assert.Equal(t, revocationGood, result.Status)
	assert.NoError(t, result.Err)
}

func TestCheckRevocationFallsBackToConfiguredResponder(t *testing.T) {
	issuer, issuerKey := testIssuer(t)

	unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusInternalServerError)
	}))
	t.Cleanup(unavailable.Close)

	goodURL := ocspResponseServer(t, issuer, issuerKey, ocsp.Good)
	leaf := testLeaf(t, issuer, issuerKey, unavailable.URL)

	// The responder of the certificate is asked first, and the configured
	// responder afterwards.
	result := checkRevocation(leaf, issuer, []string{goodURL})
	assert.Equal(t, revocationGood, result.Status)
	assert.NoError(t, result.Err)
}

func TestCheckRevocationPrefersCertificateResponder(t *testing.T) {
	issuer, issuerKey := testIssuer(t)

	revokedURL := ocspResponseServer(t, issuer, issuerKey, ocsp.Revoked)
	goodURL := ocspResponseServer(t, issuer, issuerKey, ocsp.Good)
	leaf := testLeaf(t, issuer, issuerKey, revokedURL)

	// The certificate keeps the first word: a configured responder cannot
	// overturn the answer of the responder that the certificate names.
	result := checkRevocation(leaf, issuer, []string{goodURL})
	assert.Equal(t, revocationRevoked, result.Status)
}

func TestCheckRevocationWithoutIssuerSkipsConfiguredResponder(t *testing.T) {
	issuer, issuerKey := testIssuer(t)
	leaf := testLeaf(t, issuer, issuerKey, "http://127.0.0.1:1/ocsp")

	// Without an issuer there is nothing to check an OCSP answer against, so
	// not even a configured responder is asked.
	result := checkRevocation(leaf, nil, []string{"http://127.0.0.1:1/ocsp"})
	assert.Equal(t, revocationNotChecked, result.Status)
	assert.NoError(t, result.Err)
}

func TestOCSPResponders(t *testing.T) {
	cert := &x509.Certificate{OCSPServer: []string{"http://cert.example", "http://shared.example"}}

	// The responders of the certificate come first, and a configured responder
	// that the certificate names already is not repeated.
	assert.Equal(t, []string{"http://cert.example", "http://shared.example", "http://extra.example"},
		ocspResponders(cert, []string{"http://shared.example", "http://extra.example"}))

	// An empty URL is ignored.
	assert.Equal(t, []string{"http://cert.example", "http://shared.example"},
		ocspResponders(cert, []string{"", ""}))

	assert.Empty(t, ocspResponders(&x509.Certificate{}, nil))
}

func TestValidateOCSPResponse(t *testing.T) {
	t.Run("fresh response", func(t *testing.T) {
		response := &ocsp.Response{
			ThisUpdate: time.Now().Add(-time.Minute),
			NextUpdate: time.Now().Add(time.Hour),
		}
		assert.NoError(t, validateOCSPResponse(response))
	})

	t.Run("expired response", func(t *testing.T) {
		response := &ocsp.Response{
			ThisUpdate: time.Now().Add(-2 * time.Hour),
			NextUpdate: time.Now().Add(-time.Hour),
		}
		assert.Error(t, validateOCSPResponse(response))
	})

	t.Run("response without next update", func(t *testing.T) {
		response := &ocsp.Response{ThisUpdate: time.Now().Add(-ocspMaxAge - time.Hour)}
		assert.Error(t, validateOCSPResponse(response))
	})

	t.Run("response without updates", func(t *testing.T) {
		assert.NoError(t, validateOCSPResponse(&ocsp.Response{}))
	})
}

func TestApplyRevocationPolicy(t *testing.T) {
	testCases := []struct {
		name    string
		config  string
		result  *revocationResult
		wantErr string
	}{
		{
			name:   "certificate is not revoked",
			result: &revocationResult{Status: revocationGood},
		},
		{
			name: "revoked certificate",
			result: &revocationResult{
				Status:    revocationRevoked,
				RevokedAt: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
			},
			wantErr: "revoked at 2024-01-02 03:04:05 UTC",
		},
		{
			name:   "certificate without responder is not required",
			result: &revocationResult{Status: revocationNotChecked},
		},
		{
			name:    "certificate without responder is required",
			config:  "require-ocsp true\n",
			result:  &revocationResult{Status: revocationNotChecked},
			wantErr: "names no OCSP responder",
		},
		{
			name:   "unreachable responder is not required",
			result: &revocationResult{Status: revocationUnknown, Err: errors.New("no answer")},
		},
		{
			name:    "unreachable responder is required",
			config:  "require-ocsp true\n",
			result:  &revocationResult{Status: revocationUnknown, Err: errors.New("no answer")},
			wantErr: "could not be checked",
		},
		{
			name:    "unknown certificate is required",
			config:  "require-ocsp true\n",
			result:  &revocationResult{Status: revocationUnknown},
			wantErr: "did not know the signer certificate",
		},
		{
			name:    "invalid configuration",
			config:  "require-ocsp maybe\n",
			result:  &revocationResult{Status: revocationGood},
			wantErr: "Invalid require-ocsp value",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			useConfig(t, testCase.config)

			err := applyRevocationPolicy(testCase.result)
			if testCase.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), testCase.wantErr)
		})
	}
}

func TestChainIssuer(t *testing.T) {
	issuer, _ := testIssuer(t)
	leaf, _ := newCertificate(t, nil, nil, &x509.Certificate{})

	assert.Nil(t, chainIssuer(nil))
	assert.Nil(t, chainIssuer([]*x509.Certificate{leaf}))
	assert.Equal(t, issuer, chainIssuer([]*x509.Certificate{leaf, issuer}))
}

func TestCheckChainRevocationSkipsChainWithoutIssuer(t *testing.T) {
	cert, _ := newCertificate(t, nil, nil, &x509.Certificate{
		KeyUsage:   x509.KeyUsageDigitalSignature,
		OCSPServer: []string{"http://127.0.0.1:1/ocsp"},
	})
	useConfig(t, "require-ocsp true\n")

	// A certificate that is its own trust anchor has no issuer whose answer
	// could be checked, so its revocation status is not required.
	assert.NoError(t, checkChainRevocation(nil))
	assert.NoError(t, checkChainRevocation([]*x509.Certificate{cert}))
}

func TestCheckChainRevocationRequiresOCSP(t *testing.T) {
	issuer, issuerKey := testIssuer(t)
	leaf, _ := newCertificate(t, issuer, issuerKey, &x509.Certificate{
		KeyUsage: x509.KeyUsageDigitalSignature,
	})
	useConfig(t, "require-ocsp true\n")

	// The certificate names no responder, so it cannot be checked, which
	// require-ocsp turns into an error.
	require.Error(t, checkChainRevocation([]*x509.Certificate{leaf, issuer}))
}

func TestCheckChainRevocationUsesConfiguredServers(t *testing.T) {
	issuer, issuerKey := testIssuer(t)

	unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusInternalServerError)
	}))
	t.Cleanup(unavailable.Close)

	goodURL := ocspResponseServer(t, issuer, issuerKey, ocsp.Good)
	leaf, _ := newCertificate(t, issuer, issuerKey, &x509.Certificate{
		KeyUsage:   x509.KeyUsageDigitalSignature,
		OCSPServer: []string{unavailable.URL},
	})
	useConfig(t, "ocsp-server "+goodURL+"\n")

	// The configured responder answers for the certificate whose own responder
	// is unreachable.
	assert.NoError(t, checkChainRevocation([]*x509.Certificate{leaf, issuer}))
}

func TestCheckChainRevocationRejectsInvalidConfig(t *testing.T) {
	issuer, issuerKey := testIssuer(t)
	leaf, _ := newCertificate(t, issuer, issuerKey, &x509.Certificate{
		KeyUsage:   x509.KeyUsageDigitalSignature,
		OCSPServer: []string{"http://127.0.0.1:1/ocsp"},
	})
	useConfig(t, "ocsp-server https://ocsp.example.com\nrequire-ocsp maybe\n")

	// The invalid require-ocsp value is reported rather than ignored, so a
	// typo does not silently disable the check.
	assert.Error(t, checkChainRevocation([]*x509.Certificate{leaf, issuer}))
}
