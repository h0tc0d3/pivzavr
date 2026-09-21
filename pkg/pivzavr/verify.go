package pivzavr

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"time"

	"github.com/h0tc0d3/pivzavr/pkg/cms"
	"github.com/h0tc0d3/pivzavr/pkg/config"
	"github.com/h0tc0d3/pivzavr/pkg/i18n"
)

// VerifyOpts specifies the parameters required when verifying signatures
type VerifyOpts struct {
	// Signature to verify
	Signature io.Reader
	// Message associated with the signature.
	// This option is only used when verifying a detached signature
	Message io.Reader
	// Slot containing certificate to verify with
	Slot Slot
}

// VerifySignature verifies a digital signature.
//
// When the signature is detached, the signed message is read from
// VerifyOpts.Message.
//
// A clear text signature carries its message in front of the armored signature,
// so a signature that holds one is verified against the message that it carries
// and VerifyOpts.Message is left unused.
func VerifySignature(tok Pivzavr, opts *VerifyOpts) error {
	EmitNewSign()

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, opts.Signature); err != nil {
		return i18n.Wrap(err, "Read signature")
	}

	// A clear text signature carries its message in front of the armored
	// detached signature, so the message is read from the file when the caller
	// did not name one.
	message := opts.Message
	if message == nil {
		if clearText, ok := splitClearTextSignature(buf.Bytes()); ok {
			message = bytes.NewReader(clearText)
		}
	}

	var ber []byte
	if blk, _ := pem.Decode(buf.Bytes()); blk != nil {
		if !isSignaturePemHeader(blk.Type) {
			return i18n.Errorf("unexpected PEM header: %q", blk.Type)
		}
		ber = blk.Bytes
	} else {
		ber = buf.Bytes()
	}

	sd, err := cms.ParseSignedData(ber)
	if err != nil {
		return i18n.Wrap(err, "Parse signature")
	}

	details := signerDetails(sd)

	if sd.IsDetached() {
		if message == nil {
			return i18n.New("Expected detached signature, but message wasn't provided.")
		}
		return verifyDetached(tok, sd, message, opts.Slot, details)
	}

	// An attached signature already contains the signed data, so any message
	// reader that was passed in (for example when a caller always provides the
	// data file, regardless of whether the signature is attached or detached)
	// is ignored.
	return verifyAttached(tok, sd, opts.Slot, details)
}

// signerDetails returns the metadata of the first signature of sd. The metadata
// is reported best-effort: a signature that cannot be inspected is still
// verified, only its date and algorithm are left out of the report.
func signerDetails(sd *cms.SignedData) cms.SignerDetails {
	signers, err := sd.Signers()
	if err != nil || len(signers) == 0 {
		return cms.SignerDetails{}
	}
	return signers[0]
}

func verifyAttached(tok Pivzavr, sd *cms.SignedData, slot Slot, details cms.SignerDetails) error {
	verify := func(opts x509.VerifyOptions) ([][][]*x509.Certificate, error) {
		return sd.Verify(opts)
	}

	anchors := loadTrustAnchors()
	chains, err := verify(verifyOpts(anchors.roots))
	if err == nil {
		return verifyChains(chains, trustCA, details)
	}
	return verifyFallback(tok, sd, slot, details, verify, anchors.keys, i18n.Wrap(err, "Verify signature"))
}

func verifyDetached(tok Pivzavr, sd *cms.SignedData, data io.Reader, slot Slot, details cms.SignerDetails) error {
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, data); err != nil {
		return i18n.Wrap(err, "Read message file")
	}

	verify := func(opts x509.VerifyOptions) ([][][]*x509.Certificate, error) {
		return sd.VerifyDetached(buf.Bytes(), opts)
	}

	anchors := loadTrustAnchors()
	chains, err := verify(verifyOpts(anchors.roots))
	if err == nil {
		return verifyChains(chains, trustCA, details)
	}
	return verifyFallback(tok, sd, slot, details, verify, anchors.keys, i18n.Wrap(err, "Failed to verify signature"))
}

// trustKind describes how the certificate that made a signature was trusted.
type trustKind int

const (
	// trustCA means the certificate chained up to a CA certificate of the
	// trust store, or of the certificate store of the system.
	trustCA trustKind = iota
	// trustSelfSigned means the certificate is the self-signed certificate of
	// the smart card that verifies the signature. Such a card was never
	// enrolled with a CA.
	trustSelfSigned
	// trustPublicKey means the certificate does not chain up to a CA, but its
	// public key is one of the public keys of the trust store.
	trustPublicKey
)

// verifyFallback retries a verification that the CA certificates could not
// verify, in the order the remaining trust anchors are available: the self-signed
// certificate of the smart card in slot, and the public keys that the
// configuration file names. A card that was never enrolled with a CA signs with
// a self-signed certificate, which no CA in the store can vouch for, and a card
// that was enrolled with a CA signs with the key of a certificate whose CA may
// not be in the store at all.
//
// Only the trust anchor changes: the signature, the message digest and the
// validity period are checked again, so a signature that does not match the
// message is not accepted for the sake of a missing CA.
func verifyFallback(tok Pivzavr, sd *cms.SignedData, slot Slot, details cms.SignerDetails, verify func(x509.VerifyOptions) ([][][]*x509.Certificate, error), keys []crypto.PublicKey, verifyErr error) error {
	if cardCert, ok := selfSignedSigner(tok, sd, slot); ok {
		if chains, err := verify(verifyOptsWithRoot(cardCert)); err == nil {
			return verifyChains(chains, trustSelfSigned, details)
		}
	}

	if signerCert, ok := trustedKeySigner(sd, keys); ok {
		if chains, err := verify(verifyOptsWithRoot(signerCert)); err == nil {
			return verifyChains(chains, trustPublicKey, details)
		}
	}

	// The CMS library returns no chains on failure, so a BADSIG status (which
	// requires the signer certificate) cannot be produced here.
	EmitErrSig()
	return verifyErr
}

// trustedKeySigner returns the certificate that made the signature when its
// public key is one of keys. It returns false when the signature holds no
// single signer certificate, or when the key of that certificate is not
// configured, so that a signature cannot be trusted by a key that it was not
// made with.
func trustedKeySigner(sd *cms.SignedData, keys []crypto.PublicKey) (*x509.Certificate, bool) {
	if len(keys) == 0 {
		return nil, false
	}

	signers, err := sd.SignerCertificates()
	if err != nil || len(signers) != 1 {
		return nil, false
	}
	if !matchesPublicKey(signers[0], keys) {
		return nil, false
	}
	return signers[0], true
}

// matchesPublicKey reports whether the public key of cert is one of keys. The
// keys are compared by their DER encoding, so a key that was converted between
// encodings still matches the certificate that carries it.
func matchesPublicKey(cert *x509.Certificate, keys []crypto.PublicKey) bool {
	if cert == nil {
		return false
	}

	want, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return false
	}
	for _, key := range keys {
		got, err := x509.MarshalPKIXPublicKey(key)
		if err == nil && bytes.Equal(want, got) {
			return true
		}
	}
	return false
}

// selfSignedSigner returns the certificate that made the signature when it is
// the self-signed certificate of the smart card in slot. It returns false when
// the signature was not made with the key of the card, so that a certificate
// stored on the card cannot vouch for a signature that it did not make.
func selfSignedSigner(tok Pivzavr, sd *cms.SignedData, slot Slot) (*x509.Certificate, bool) {
	cardCert, err := tok.Certificate(slot)
	if err != nil || cardCert == nil || !isSelfSigned(cardCert) {
		return nil, false
	}

	signers, err := sd.SignerCertificates()
	if err != nil || len(signers) != 1 || !samePublicKey(signers[0], cardCert) {
		return nil, false
	}
	return signers[0], true
}

// verifyChains checks the verified chains of a signature and reports the
// outcome. The chains are those of cms.SignedData.Verify, which has already
// checked the signature and the trust chain, so the certificate constraints and
// the revocation status are what is left to check.
func verifyChains(chains [][][]*x509.Certificate, kind trustKind, details cms.SignerDetails) error {
	chain := leafChain(chains)
	if len(chain) == 0 {
		EmitErrSig()
		return i18n.New("Verified signature without a signer certificate.")
	}

	if err := validateSigningCertificate(chain[0]); err != nil {
		EmitErrSig()
		return err
	}
	if err := checkChainRevocation(chain); err != nil {
		EmitErrSig()
		return err
	}

	warnTrustFallback(kind)

	return reportSignature(chain, kind, details)
}

// warnTrustFallback reports on stderr that a signature was accepted without a CA
// certifying the certificate that made it.
func warnTrustFallback(kind trustKind) {
	switch kind {
	case trustSelfSigned:
		_, _ = i18n.Fprintf(os.Stderr, "WARNING: The signature was made with a self-signed certificate that no CA certifies. It is trusted because it matches the key of the smart card.\n")
	case trustPublicKey:
		_, _ = i18n.Fprintf(os.Stderr, "WARNING: The signature was made with a certificate that no CA certifies. It is trusted because its public key is configured.\n")
	}
}

// reportSignature prints the outcome of a successful verification and emits the
// corresponding GPG status lines. chain is the verified chain of the signer
// certificate, from the certificate that made the signature up to the trust
// anchor.
func reportSignature(chain []*x509.Certificate, kind trustKind, details cms.SignerDetails) error {
	cert := chain[0]
	fpr := CertHexFingerprint(cert)
	_, _ = i18n.Fprintf(os.Stdout, "Signature made using certificate ID 0x%s\n", fpr)
	emitGoodSig(cert)

	_, _ = i18n.Fprintf(os.Stdout, "Good signature. Subject DN: %s\n", formatName(cert.Subject))
	_, _ = i18n.Fprintf(os.Stdout, "Not Before: %s\n", formatTime(cert.NotBefore))
	_, _ = i18n.Fprintf(os.Stdout, "Not After: %s\n", formatTime(cert.NotAfter))
	if !details.SigningTime.IsZero() {
		_, _ = i18n.Fprintf(os.Stdout, "Signing date: %s\n", formatSigningTime(details.SigningTime))
	}
	if name := formatSignatureAlgorithm(details.SignatureAlgorithm); name != "" {
		_, _ = i18n.Fprintf(os.Stdout, "Signature algorithm: %s\n", name)
	}
	printChainOfTrust(chain, kind)

	if kind == trustCA {
		EmitTrustFully()
	} else {
		EmitTrustUltimate()
	}

	return nil
}

// printChainOfTrust prints the certificates of a verified chain with the
// verification status of every node, from the certificate that made the
// signature up to the trust anchor that certifies it. A certificate that is its
// own anchor, as the self-signed certificate of a smart card is, is reported as
// the signer and the anchor at once.
func printChainOfTrust(chain []*x509.Certificate, kind trustKind) {
	_, _ = i18n.Fprintf(os.Stdout, "Chain of Trust:\n")
	for i, cert := range chain {
		role := i18n.Sprintf("intermediate")
		status := i18n.Sprintf("verified")
		switch {
		case i == 0 && i == len(chain)-1:
			role = i18n.Sprintf("signer and trust anchor")
			status = trustAnchorStatus(kind)
		case i == 0:
			role = i18n.Sprintf("signer")
		case i == len(chain)-1:
			role = i18n.Sprintf("root")
			status = trustAnchorStatus(kind)
		}
		_, _ = i18n.Fprintf(os.Stdout, "  %d. [%s] %s (%s) - %s\n", i+1, role, formatName(cert.Subject), CertHexFingerprint(cert), status)
	}
}

// trustAnchorStatus reports how the anchor of a chain was trusted.
func trustAnchorStatus(kind trustKind) string {
	switch kind {
	case trustSelfSigned:
		return i18n.Sprintf("trusted (self-signed card certificate)")
	case trustPublicKey:
		return i18n.Sprintf("trusted (configured public key)")
	}
	return i18n.Sprintf("trusted (CA bundle)")
}

// formatSigningTime renders the signing date in UTC, including the sub-second
// precision of the timestamp when it carries one.
func formatSigningTime(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond() == 0 {
		return t.Format("2006-01-02 15:04:05 MST")
	}
	return t.Format("2006-01-02 15:04:05.999999999 MST")
}

// formatSignatureAlgorithm renders a signature algorithm in a readable form. It
// returns an empty string for an unknown algorithm, so that the algorithm is
// left out of the report rather than being printed as "unknown".
func formatSignatureAlgorithm(algorithm x509.SignatureAlgorithm) string {
	switch algorithm {
	case x509.SHA256WithRSA:
		return "SHA-256 with RSA"
	case x509.SHA384WithRSA:
		return "SHA-384 with RSA"
	case x509.SHA512WithRSA:
		return "SHA-512 with RSA"
	case x509.SHA256WithRSAPSS:
		return "SHA-256 with RSA-PSS"
	case x509.SHA384WithRSAPSS:
		return "SHA-384 with RSA-PSS"
	case x509.SHA512WithRSAPSS:
		return "SHA-512 with RSA-PSS"
	case x509.ECDSAWithSHA256:
		return "SHA-256 with ECDSA"
	case x509.ECDSAWithSHA384:
		return "SHA-384 with ECDSA"
	case x509.ECDSAWithSHA512:
		return "SHA-512 with ECDSA"
	case x509.PureEd25519:
		return "Ed25519"
	case x509.UnknownSignatureAlgorithm:
		return ""
	}
	return algorithm.String()
}

// verifyOpts returns the options a signature is verified with. roots holds the
// CA certificates that are accepted as trust anchors, so a certificate that
// does not chain up to one of them is rejected. Those anchors come from the
// trust store, or from the certificate store of the system when the trust store
// cannot be read.
//
// The certificate of the smart card is deliberately not added as a root: doing
// so would make a signature verify merely because it was made with the card,
// regardless of whether its certificate was enrolled with a CA. A card that was
// not enrolled is handled separately by verifyFallback.
//
// Every extended key usage is accepted here, because the check of crypto/x509
// cannot tell an absent extension from an unconstrained one. The constraint that
// applies to a signing certificate is checked by validateSigningCertificate
// instead, which also reports the usage that is missing.
func verifyOpts(roots *x509.CertPool) x509.VerifyOptions {
	return x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
}

// verifyOptsWithRoot returns the options a signature is verified with when a
// single certificate, the self-signed certificate of a smart card or the
// certificate that carries a configured public key, is the only trust anchor.
func verifyOptsWithRoot(root *x509.Certificate) x509.VerifyOptions {
	roots := x509.NewCertPool()
	roots.AddCert(root)

	return x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
}

// trustAnchors holds the anchors of a verification: the CA certificates that a
// certificate is verified against, and the public keys that a certificate is
// verified against when the CA certificates cannot vouch for it.
type trustAnchors struct {
	roots *x509.CertPool
	keys  []crypto.PublicKey
}

// loadTrustAnchors reads the trust anchors of the pivzavr trust store. Both
// kinds of anchor are read in a single call, so that a verification which falls
// back to the public keys does not read (or download) the store a second time.
//
// A trust store that cannot be read, for example because the machine is offline
// when it is created, yields the certificate store of the system as roots and
// no public keys, and an empty pool as a last resort, so that a verification
// still runs instead of ending in an error.
func loadTrustAnchors() trustAnchors {
	if roots, keys, err := config.TrustAnchors(); err == nil {
		return trustAnchors{roots: roots, keys: keys}
	}
	if roots, err := x509.SystemCertPool(); err == nil {
		return trustAnchors{roots: roots}
	}
	return trustAnchors{roots: x509.NewCertPool()}
}
