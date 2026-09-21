package pivzavr

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"
)

// OpenPGP public-key algorithm IDs (RFC 4880 section 9.1).
const (
	openpgpPubKeyAlgoRSA   byte = 1
	openpgpPubKeyAlgoECDSA byte = 19
)

// openpgpHashID returns the OpenPGP hash algorithm ID (RFC 4880 section 9.4)
// for the given crypto.Hash. The boolean result reports whether h has a
// defined OpenPGP algorithm ID.
func openpgpHashID(h crypto.Hash) (id byte, ok bool) {
	switch h {
	case crypto.SHA1:
		return 2, true
	case crypto.SHA256:
		return 8, true
	case crypto.SHA384:
		return 9, true
	case crypto.SHA512:
		return 10, true
	default:
		return 0, false
	}
}

// Large parts of this file were taken from https://github.com/github/smimesign/blob/v0.1.0/status.go

// This file implements gnupg's "status protocol". When the --status-fd argument
// is passed, gpg will output machine-readable status updates to that fd.
// Details on the "protocol" can be found at https://git.io/vFFKC

type status string

const (
	// BEGIN_SIGNING
	//   Mark the start of the actual signing process. This may be used as an
	//   indication that all requested secret keys are ready for use.
	sBeginSigning status = "BEGIN_SIGNING"

	// SIG_CREATED <type> <pk_algo> <hash_algo> <class> <timestamp> <key_fpr>
	//   A signature has been created using these parameters.
	//   Values for type <type> are:
	//     - D :: detached
	//     - C :: cleartext
	//     - S :: standard
	//   (only the first character should be checked)
	//
	//   <class> are 2 hex digits with the OpenPGP signature class.
	//
	//   Note, that TIMESTAMP may either be a number of seconds since Epoch
	//   or an ISO 8601 string which can be detected by the presence of the
	//   letter 'T'.
	sSigCreated status = "SIG_CREATED"

	// NEWSIG [<signers_uid>]
	//   Is issued right before a signature verification starts.  This is
	//   useful to define a context for parsing ERROR status messages.
	//   arguments are currently defined.  If signers_uid is given and is
	//   not "-" this is the percent escape value of the OpenPGP Signer's
	//   User ID signature sub-packet.
	sNewSig status = "NEWSIG"

	// GOODSIG  <key_id>  <username>
	//   The signature with the key_id is good.  For each signature only one
	//   of the codes GOODSIG, BADSIG, EXPSIG, EXPKEYSIG, REVKEYSIG or
	//   ERRSIG will be emitted.  In the past they were used as a marker
	//   for a new signature; new code should use the NEWSIG status
	//   instead.  The username is the primary one encoded in UTF-8 and %XX
	//   escaped. The fingerprint may be used instead of the long key_id if
	//   it is available.  This is the case with CMS and might eventually
	//   also be available for OpenPGP.
	sGoodSig status = "GOODSIG"

	// BADSIG <key_id> <username>
	//   The signature with the key_id has not been verified okay. The username is
	//   the primary one encoded in UTF-8 and %XX escaped. The fingerprint may be
	//   used instead of the long key_id if it is available. This is the case with
	//   CMS and might eventually also be available for OpenPGP.
	sBadSig status = "BADSIG"

	// ERRSIG <key_id> <pk_algo> <hash_algo> <sig_class> <time> <rc>
	//
	//   It was not possible to check the signature. This may be caused by a
	//   missing public key or an unsupported algorithm. An RC of 4 indicates
	//   unknown algorithm, a 9 indicates a missing public key. The other fields
	//   give more information about this signature. sig_class is a 2 byte hex-value.
	//   The fingerprint may be used instead of the key_id if it is
	//   available. This is the case with gpgsm and might eventually also be
	//   available for OpenPGP.
	//
	//   Note, that TIME may either be the number of seconds since Epoch or an ISO
	//   8601 string. The latter can be detected by the presence of the letter
	//   ‘T’.
	sErrSig status = "ERRSIG"

	// TRUST_
	//   These are several similar status codes:
	//
	//   - TRUST_UNDEFINED <error_token>
	//   - TRUST_NEVER     <error_token>
	//   - TRUST_MARGINAL  [0  [<validation_model>]]
	//   - TRUST_FULLY     [0  [<validation_model>]]
	//   - TRUST_ULTIMATE  [0  [<validation_model>]]
	//
	//   For good signatures one of these status lines are emitted to
	//   indicate the validity of the key used to create the signature.
	//   The error token values are currently only emitted by gpgsm.
	//
	//   VALIDATION_MODEL describes the algorithm used to check the
	//   validity of the key.  The defaults are the standard Web of Trust
	//   model for gpg and the standard X.509 model for gpgsm.  The
	//   defined values are
	//
	//      - pgp   :: The standard PGP WoT.
	//      - shell :: The standard X.509 model.
	//      - chain :: The chain model.
	//      - steed :: The STEED model.
	//      - tofu  :: The TOFU model
	//
	//   Note that the term =TRUST_= in the status names is used for
	//   historic reasons; we now speak of validity.
	sTrustFully status = "TRUST_FULLY"

	// TRUST_ULTIMATE [0  [<validation_model>]]
	//   The key is ultimately trusted.  In the X.509 model this is used for a
	//   self-signed certificate, where the key that signed the signature is
	//   the only thing that vouches for it.
	sTrustUltimate status = "TRUST_ULTIMATE"
)

var (
	_setupStatus sync.Once
	statusFile   *os.File
)

// SetupStatus sets up where status messages will be written to
func SetupStatus(statusFdOpt int) {
	_setupStatus.Do(func() {
		statusFile = statusFileForFd(statusFdOpt)
	})
}

// statusFileForFd resolves a status file descriptor to the file status
// messages should be written to. A non-positive descriptor disables status
// output. Descriptors 1 and 2 are mapped to stdout and stderr, since Git
// always passes --status-fd=1 regardless of platform.
func statusFileForFd(statusFdOpt int) *os.File {
	if statusFdOpt <= 0 {
		return nil
	}

	const (
		unixStdout = 1
		unixStderr = 2
	)

	switch statusFdOpt {
	case unixStdout:
		return os.Stdout
	case unixStderr:
		return os.Stderr
	default:
		// TODO: debugging output if this fails
		return os.NewFile(uintptr(statusFdOpt), "status")
	}
}

func (s status) emitf(format string, args ...interface{}) {
	if statusFile == nil {
		return
	}

	const prefix = "[GNUPG:] "
	_, _ = statusFile.WriteString(prefix)
	_, _ = statusFile.WriteString(string(s))
	_, _ = fmt.Fprintf(statusFile, " "+format+"\n", args...)
}

func (s status) emit() {
	if statusFile == nil {
		return
	}

	const prefix = "[GNUPG:] "
	_, _ = statusFile.WriteString(prefix + string(s) + "\n")
}

// EmitSigCreated emits a status message specifying the signing operation is
// done. The signature type names the kind of signature that was made: "C" for a
// clear text signature, "D" for a detached signature and "S" for a signature
// that carries its content.
func EmitSigCreated(cert *x509.Certificate, sigType string) {
	// SIG_CREATED arguments
	var (
		pkAlgo, hashAlgo, sigClass byte
		now                        int64
		fpr                        string
	)

	switch cert.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		pkAlgo = openpgpPubKeyAlgoRSA
	case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		pkAlgo = openpgpPubKeyAlgoECDSA
	}

	switch cert.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		hashAlgo, _ = openpgpHashID(crypto.SHA1)
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256:
		hashAlgo, _ = openpgpHashID(crypto.SHA256)
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		hashAlgo, _ = openpgpHashID(crypto.SHA384)
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		hashAlgo, _ = openpgpHashID(crypto.SHA512)
	}

	// gpgsm seems to always use 0x00
	sigClass = 0
	now = time.Now().Unix()
	fpr = CertHexFingerprint(cert)

	sSigCreated.emitf("%s %d %d %02x %d %s", sigType, pkAlgo, hashAlgo, sigClass, now, fpr)
}

// leafChain returns the first verification chain, or nil if chains is empty or
// malformed.
func leafChain(chains [][][]*x509.Certificate) []*x509.Certificate {
	if len(chains) == 0 || len(chains[0]) == 0 {
		return nil
	}
	return chains[0][0]
}

// leafCertificate returns the end-entity certificate of the first verified
// chain, or nil if chains is empty or malformed.
func leafCertificate(chains [][][]*x509.Certificate) *x509.Certificate {
	chain := leafChain(chains)
	if len(chain) == 0 {
		return nil
	}
	return chain[0]
}

// EmitGoodSig emits a status message specifying signature was verified successfully
func EmitGoodSig(chains [][][]*x509.Certificate) {
	emitGoodSig(leafCertificate(chains))
}

// emitGoodSig emits a GOODSIG status message for a single certificate.
func emitGoodSig(cert *x509.Certificate) {
	if cert == nil {
		return
	}
	subj := formatName(cert.Subject)
	fpr := CertHexFingerprint(cert)

	sGoodSig.emitf("%s %s", fpr, subj)
}

// EmitBadSig emits a status message specifying signature failed verification
func EmitBadSig(chains [][][]*x509.Certificate) {
	cert := leafCertificate(chains)
	if cert == nil {
		return
	}
	subj := formatName(cert.Subject)
	fpr := CertHexFingerprint(cert)

	sBadSig.emitf("%s %s", fpr, subj)
}

// EmitTrustFully emits a status message indicating the validity of the key used to create the signature
func EmitTrustFully() {
	sTrustFully.emitf("0 shell")
}

// EmitTrustUltimate emits a status message indicating that the key used to
// create the signature is trusted because it signed itself, which is the case
// for a smart card certificate that was not enrolled with a CA.
func EmitTrustUltimate() {
	sTrustUltimate.emitf("0 shell")
}

// EmitBeginSigning emits a status message indicating the beginning of the actual signing process
func EmitBeginSigning() {
	sBeginSigning.emit()
}

// EmitNewSign emits a status message indicating the beginning of the signature verification process
func EmitNewSign() {
	sNewSig.emit()
}

// EmitErrSig emits a status message specifying the signature could not be verified
func EmitErrSig() {
	sErrSig.emit()
}
