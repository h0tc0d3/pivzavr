package pivzavr

import (
	"bytes"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/h0tc0d3/pivzavr/pkg/config"
	"github.com/h0tc0d3/pivzavr/pkg/i18n"
	"golang.org/x/crypto/ocsp"
)

const (
	// ocspTimeout is the longest a single OCSP request may take.
	ocspTimeout = 30 * time.Second
	// ocspMaxResponseSize is the largest OCSP response that is accepted.
	ocspMaxResponseSize = 1 << 20
	// ocspRequestContentType is the media type of an OCSP request.
	ocspRequestContentType = "application/ocsp-request"
	// ocspMaxAge is how old an OCSP response may be when the responder did not
	// say when it stops being valid.
	ocspMaxAge = 7 * 24 * time.Hour
)

// revocationStatus is the outcome of an OCSP revocation check.
type revocationStatus int

const (
	// revocationNotChecked means the certificate names no OCSP responder, so
	// there was nothing to ask.
	revocationNotChecked revocationStatus = iota
	// revocationGood means a responder confirmed that the certificate is not
	// revoked.
	revocationGood
	// revocationRevoked means a responder reported the certificate as revoked.
	revocationRevoked
	// revocationUnknown means no responder gave a definitive answer.
	revocationUnknown
)

// revocationResult describes the outcome of an OCSP revocation check.
type revocationResult struct {
	// Status is the answer the responders gave.
	Status revocationStatus
	// RevokedAt is the time the certificate was revoked, set when Status is
	// revocationRevoked.
	RevokedAt time.Time
	// Err describes why no definitive answer could be obtained, set when
	// Status is revocationUnknown.
	Err error
}

// checkRevocation asks the OCSP responders that cert names, followed by the
// configured responders in extra, whether the certificate is revoked. The
// request is not signed, and the responses are checked against issuer, which is
// how the revocation status of an end-entity certificate is checked.
//
// A configured responder is asked after the responders of the certificate
// itself, so it is a fallback for a responder that cannot be reached rather than
// a replacement for the responder the certificate names.
func checkRevocation(cert, issuer *x509.Certificate, extra []string) *revocationResult {
	if issuer == nil {
		return &revocationResult{Status: revocationNotChecked}
	}

	responders := ocspResponders(cert, extra)
	if len(responders) == 0 {
		return &revocationResult{Status: revocationNotChecked}
	}

	request, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return &revocationResult{
			Status: revocationUnknown,
			Err:    i18n.Wrap(err, "Create OCSP request"),
		}
	}

	var lastErr error
	for _, server := range responders {
		result := queryOCSPResponder(server, request, cert, issuer)
		if result.Status == revocationGood || result.Status == revocationRevoked {
			return result
		}
		if result.Err != nil {
			lastErr = result.Err
		}
	}
	return &revocationResult{Status: revocationUnknown, Err: lastErr}
}

// ocspResponders returns the responders a certificate is checked against: the
// responders it names itself, followed by the configured responders that it
// does not name already.
func ocspResponders(cert *x509.Certificate, extra []string) []string {
	responders := make([]string, 0, len(cert.OCSPServer)+len(extra))
	seen := make(map[string]bool, len(cert.OCSPServer)+len(extra))

	add := func(server string) {
		if server == "" || seen[server] {
			return
		}
		seen[server] = true
		responders = append(responders, server)
	}
	for _, server := range cert.OCSPServer {
		add(server)
	}
	for _, server := range extra {
		add(server)
	}
	return responders
}

// queryOCSPResponder sends a request to a single OCSP responder and interprets
// its response.
func queryOCSPResponder(url string, request []byte, cert, issuer *x509.Certificate) *revocationResult {
	response, err := postOCSPRequest(url, request)
	if err != nil {
		return &revocationResult{
			Status: revocationUnknown,
			Err:    i18n.Wrapf(err, "OCSP responder %q", url),
		}
	}

	// ParseResponseForCert verifies the signature of the response and that it
	// answers for cert.
	parsed, err := ocsp.ParseResponseForCert(response, cert, issuer)
	if err != nil {
		return &revocationResult{
			Status: revocationUnknown,
			Err:    i18n.Wrapf(err, "OCSP response from %q", url),
		}
	}
	if err := validateOCSPResponse(parsed); err != nil {
		return &revocationResult{
			Status: revocationUnknown,
			Err:    i18n.Wrapf(err, "OCSP response from %q", url),
		}
	}

	switch parsed.Status {
	case ocsp.Good:
		return &revocationResult{Status: revocationGood}
	case ocsp.Revoked:
		return &revocationResult{Status: revocationRevoked, RevokedAt: parsed.RevokedAt}
	default:
		// An "unknown" response is not an answer, so another responder is
		// asked before the check is given up on.
		return &revocationResult{Status: revocationUnknown}
	}
}

// postOCSPRequest sends a DER encoded OCSP request and returns the raw response.
func postOCSPRequest(url string, request []byte) ([]byte, error) {
	// #nosec G107 -- the URL is the OCSP responder named by the certificate.
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(request))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", ocspRequestContentType)

	client := &http.Client{
		Timeout: ocspTimeout,
		// Every request uses a connection of its own, matching the CA
		// downloader: a reused connection of some responders is answered not
		// at all.
		Transport: &http.Transport{
			Proxy:             http.ProxyFromEnvironment,
			DisableKeepAlives: true,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, i18n.Errorf("unexpected status %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, ocspMaxResponseSize))
}

// validateOCSPResponse rejects a response that the responder itself allowed to
// go stale.
func validateOCSPResponse(response *ocsp.Response) error {
	if response.ThisUpdate.IsZero() {
		return nil
	}

	now := time.Now()
	if !response.NextUpdate.IsZero() {
		if now.After(response.NextUpdate) {
			return i18n.New("response has expired")
		}
		return nil
	}
	if now.Sub(response.ThisUpdate) > ocspMaxAge {
		return i18n.New("response is too old")
	}
	return nil
}

// checkChainRevocation checks the leaf certificate of a verified chain for
// revocation and applies the "require-ocsp" configuration. The certificate is
// checked against the responders it names and against the responders of the
// "ocsp-server" settings.
//
// A chain without an issuer is a chain whose leaf is its own trust anchor, such
// as a self-signed smart card certificate that is trusted for that card, or a
// certificate that is trusted by a configured public key. No issuer is available
// to verify an OCSP answer against, so its revocation status is not checked, not
// even when require-ocsp is set.
func checkChainRevocation(chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return nil
	}

	issuer := chainIssuer(chain)
	if issuer == nil {
		return nil
	}

	servers, err := config.OCSPServers()
	if err != nil {
		return err
	}
	return applyRevocationPolicy(checkRevocation(chain[0], issuer, servers))
}

// chainIssuer returns the certificate that issued the leaf of a verified chain,
// or nil when the chain holds no issuer.
func chainIssuer(chain []*x509.Certificate) *x509.Certificate {
	if len(chain) < 2 {
		return nil
	}
	return chain[1]
}

// applyRevocationPolicy turns the outcome of a revocation check into an error
// according to the "require-ocsp" configuration. A revoked certificate always
// fails the verification; a check that could not be completed only warns unless
// require-ocsp is set, because a responder can be unreachable for reasons the
// signer cannot control.
func applyRevocationPolicy(result *revocationResult) error {
	require, err := config.RequireOCSP()
	if err != nil {
		return err
	}

	switch result.Status {
	case revocationRevoked:
		return i18n.Errorf("The signer certificate was revoked at %s.", formatTime(result.RevokedAt))
	case revocationGood:
		return nil
	case revocationNotChecked:
		if require {
			return i18n.New("The signer certificate names no OCSP responder, but require-ocsp is set.")
		}
		return nil
	default:
		if require {
			if result.Err != nil {
				return i18n.Wrap(result.Err, "The signer certificate revocation status could not be checked, but require-ocsp is set")
			}
			return i18n.New("The OCSP responder did not know the signer certificate, but require-ocsp is set.")
		}
		warnRevocationUnknown(result.Err)
		return nil
	}
}

// warnRevocationUnknown reports an inconclusive revocation check on stderr.
func warnRevocationUnknown(err error) {
	if err != nil {
		_, _ = i18n.Fprintf(os.Stderr, "WARNING: The signer certificate could not be checked for revocation: %v\n", err)
		return
	}
	_, _ = i18n.Fprintf(os.Stderr, "WARNING: The OCSP responder did not know the signer certificate, so it could not be checked for revocation.\n")
}
