# Security Policy

Pivzavr manages the certificates and secrets of PIV smart cards and uses the
private keys on a card to sign and verify data. It is often wired into `git` as
the signing program, so it handles the PIN, the PUK and the card management key
of a smart card as well as the data that is signed. This document explains which
versions are supported, how to report a vulnerability and how the tool is
expected to be used safely.

## Supported versions

Security fixes are made against the latest release only. An older release is not
supported with security updates: upgrade to the latest release before reporting a
problem.

| Version          | Supported          |
| ---------------- | ------------------ |
| `1.4.x` (latest) | :white_check_mark: |
| < `1.4.0`        | :x:                |

The latest release is the newest tag on
<https://github.com/h0tc0d3/pivzavr/releases>.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.** A public report
discloses the problem before a fix is available.

Report a vulnerability through one of the following private channels:

- **Preferred:** use GitHub's private vulnerability reporting. Open the
  [Security tab](https://github.com/h0tc0d3/pivzavr/security) of the repository
  and choose **Report a vulnerability**.
- **Fallback:** email the maintainer at <h0tc0d3@gmail.com> with a subject line
  that starts with `[SECURITY]`.

Please include as much of the following as you can, so that the report can be
reproduced and triaged quickly:

- The version of pivzavr (`pivzavr --help` reports it, or a release tag) and the
  platform (operating system, architecture and Go version).
- The smart card or PKCS#11 module involved, if the problem needs one.
- A description of the vulnerability and the impact you expect it to have.
- Steps to reproduce, ideally a minimal proof of concept.
- Any suggested fix, if you have one.

### What to expect

- **Acknowledgement** of the report within about five business days.
- **An assessment** of the report and, where the problem is confirmed, a plan for
  a fix. The maintainer will keep you informed of the progress.
- **Credit** in the release notes when the fix is published, unless you ask to
  stay anonymous.

Please give the maintainer a reasonable amount of time to release a fix before
disclosing the problem publicly.

## Scope

The following are in scope for a security report:

- The `pivzavr` command and the Go packages under `pkg/` in this repository,
  including how they handle secrets and certificates.
- The secrets of a smart card (PIN, PUK and card management key) and the data
  signed with the keys on a card.

The following are **out of scope**:

- Vulnerabilities in a third-party PKCS#11 module, `pinentry` program, smart card
  firmware or `git` itself. Report those to their own maintainers.
- Problems that need a machine that is already compromised, or that need an
  attacker to control the configuration file, the PKCS#11 module or the pinentry
  binary (see [Trust boundaries](#trust-boundaries)).

## Security model

Pivzavr is built around a few deliberate choices about how secrets are handled.

- **Secrets are entered through pinentry.** The PIN, the PUK and the card
  management key are asked for with the `pinentry` dialog of GnuPG. `pinentry` is
  started as a child process and driven over its standard input and output with
  the Assuan protocol, so a secret never appears on a command line or in an
  environment variable, where other processes on the machine could read it.
- **Attempts are visible before they are used.** Every dialog reports how many
  attempts the card has left for a secret, so the count is known before a secret
  is entered. Input that cannot be a valid PIN or PUK is rejected before the card
  is asked, so a typo does not use up an attempt.
- **The card management key can be stored on the card.** A new management key can
  be generated (`--random`) and kept on the smart card protected by the PIN
  (`--protect 1`), so it does not have to be entered or kept elsewhere.
- **The trust store is downloaded and validated by the toolchain.** Signature
  verification uses a trust store that is assembled from the Mozilla CA store,
  the smart card attestation sources, the `ca-certificate` and `public-key`
  sources of the configuration file, written atomically with `0600` permissions
  and size limited. A configured source is required, so an update that cannot
  read it fails instead of storing a store without a trust anchor that was meant
  to be used. When the store cannot be read or downloaded, verification falls
  back to the certificate store of the operating system.
- **The trust store carries a checksum, not a signature.** `trust.bin` holds the
  CA certificates and the public keys together with a SHA-256 checksum of its
  contents, and a store whose checksum does not match is rejected instead of
  being partly trusted. The checksum detects a store that was edited by hand or
  damaged; it does not protect against an attacker who can read and write the
  file, because such an attacker can recompute it. The store is as trustworthy
  as the user configuration directory it lives in.
- **A signature is verified against the trust store.** The certificate of the
  smart card is not a trust anchor by itself, so a signature normally verifies
  only when its certificate chains up to a CA in the store; a signature made
  with the card does not verify merely because the card is present. Two
  fallbacks exist, and neither of them weakens the checks that were already
  made, because the signature and the message digest are verified again with the
  new trust anchor:
  - A card that was never enrolled with a CA signs with a self-signed
    certificate. Such a signature is accepted with a warning and reported as
    `TRUST_ULTIMATE`, and only when the certificate matches the key of the card
    that is present.
  - A certificate whose public key is named by a `public-key` setting is accepted
    with a warning and reported as `TRUST_ULTIMATE`. This is deliberately a
    trust-on-first-use style pin: the user decides which keys are accepted, so a
    public key that is configured for the wrong card trusts that card. The
    fallback exists so that a signature still verifies after the card was
    re-keyed, or when the CA of an enrolled card is not part of the store.
- **More than the trust chain is checked.** The signer certificate must be an
  end-entity certificate that is permitted to make digital signatures (Key
  Usage and Extended Key Usage), and its validity period must cover the
  signature or the timestamp of the signature. A certificate that is reported as
  revoked by an OCSP responder is rejected.
- **Revocation checking is best effort unless it is made strict.** A certificate
  is checked against the OCSP responders it names and then against the
  responders of the `ocsp-server` settings, which are a fallback for a responder
  that cannot be reached; a configured responder cannot overturn the answer of
  the responder that the certificate names. By default a signature whose
  revocation status could not be determined, because no responder names the
  certificate or none of them answers, is verified with a warning: a responder
  can be unreachable for reasons the signer cannot control. With
  `require-ocsp true` the verification fails instead, so a signature is only
  accepted with a positive OCSP response. An OCSP response is checked against the
  issuer of the certificate, and a stale response is discarded.

## Trust boundaries

Some inputs are trusted by design and are the responsibility of the user:

- **The PKCS#11 module and the pinentry program are user-configured paths.** The
  tool loads a PKCS#11 module (a C library) and launches a pinentry program from
  paths taken from the configuration file or the environment. Only configure
  programs and modules you trust.
- **The configuration file is read from the user configuration directory**
  (`~/.config/pivzavr/config`, or `$XDG_CONFIG_HOME/pivzavr/config`). It contains
  no secrets, and the environment (`PIVZAVR_PINENTRY`, `PIVZAVR_PKCS11_MODULE`,
  `PIVZAVR_SERIAL`) overrides it.
- **The trust store and the sources it is built from are trust anchors.** The
  `ca-certificate` and `public-key` settings name CAs and public keys that
  signatures are verified against, and they are fetched from the URL or the file
  they name. A source is treated as trusted input: name only sources you trust,
  and keep the configuration directory writable by you alone, so that neither the
  sources nor `trust.bin` can be replaced by another user.
- **`--reset` is destructive and needs no secret.** It restores the factory state
  of the PIV applet: the keys and certificates on the card are erased and the
  factory PIN, PUK and management key are restored. This cannot be undone.
- **The factory default management key is well known.** A card that still uses
  the factory management key
  (`010203040506070801020304050607080102030405060708`) or the factory PIN can be
  written to, and its PIV data read, by anyone who has the card. Set your own PIN
  and management key before you rely on a card.
- **The PIV card authentication slot (`9e`) does not require a PIN.** Its private
  key can be used to sign without a login, by design, so treat data signed from
  that slot accordingly.

## Security tooling

The repository runs the following checks in CI on every push and pull request:

- [`gosec`](https://github.com/securego/gosec) for common Go security problems
  (`.github/workflows/gosec.yaml`).
- [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) against
  the Go vulnerability database (`.github/workflows/govulncheck.yaml`).
- [`golangci-lint`](https://golangci-lint.run/) for static analysis
  (`.github/workflows/golangci-lint.yml`).

Dependencies are tracked in `go.mod` and `go.sum`. Run `go install
github.com/h0tc0d3/pivzavr/cmd/pivzavr@latest` or build from source to get the
latest release.
