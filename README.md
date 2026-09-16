# Pivzavr

[![Go Version](https://img.shields.io/github/go-mod/go-version/h0tc0d3/pivzavr)](https://github.com/h0tc0d3/pivzavr/blob/main/go.mod) [![License](https://img.shields.io/github/license/h0tc0d3/pivzavr)](https://github.com/h0tc0d3/pivzavr/blob/main/LICENSE) [![Release](https://img.shields.io/github/v/release/h0tc0d3/pivzavr)](https://github.com/h0tc0d3/pivzavr/releases)

Pivzavr is a command line tool for managing x509 certificates stored on PIV smart cards,
and using those certificates to sign and verify data.

It is fully compatible with how the `git` command line calls external programs to sign and verify commits and tags.

## Original project

Pivzavr is a fork of [cashapp/pivit](https://github.com/cashapp/pivit).

Advantages over the original project:

- Doesn't block access to the smart card with exclusive access. Can work with `gpg-agent` and `ssh-agent` running.
- `Pinentry` from the `GnuPG` package is used for secure PIN entry. This allows password entry in non-interactive shells and improves security.
- Improved certificate data output.
- Added a list of active smart card slots.

## Install

### Go install

```shell
go install github.com/h0tc0d3/pivzavr/cmd/pivzavr@latest
```

## Usage

To set up git to use `pivzavr` to sign and verify signatures run the following commands:

```shell
git config --(local|global) gpg.format x509
git config --(local|global) gpg.x509.program pivzavr
```

Edit the files and add the lines below:

### ~/.gnupg/scdaemon.conf

```text
# Force the reader to be specified
reader-port "Yubico Yubi"

# Enable smart card sharing (resolves conflicts with Yubico Authenticator)
pcsc-shared

# Use the system smart card service (required for most operating systems)
disable-ccid

# Specifies the time to wait (in seconds) before retrying access or releasing a smart card.
card-timeout 1
```

### ~/.gnupg/gpg-agent.conf**

```text
allow-loopback-pinentry
pinentry-program /usr/bin/pinentry-qt
```

Change path to your pinentry program. Avaible values is: `pinentry-qt`, `pinentry-curses`, `pinentry-gtk`, `pinentry-tty`.

Find avaibles: `find /usr -type f -name "pinentry*"`.

Remove the line containing the custom scdaemon path. This allows you to use both the `OpenPGP` smart card application(`gpg --edit-card`) and PIV with `pivzavr`.

`sed -i '/scdaemon-program/d' ~/.gnupg/gpg-agent.conf`

### ~/.gnupg/gpg.conf**

```text
pinentry-mode loopback
```

### Reset and initialize the smart card PIV applet

```shell
pivzavr --reset
```

Reset the smart card's PIV applet and create a new PIN to access it.

### PIV slot support

The PIV module supports multiple slots where keys and certificates can be stored.
Available slots - `9a`, `9c`, `9d`, `9e`, `9b`, `f9`, `82-95`.

- `9a` is the "Authentication" slot. Used for actions like system login.
- `9b` is the "Management Key: slot. Service slot for the management key for the PIV card itself (used to write data to other slots).
- `9c` is the "Digital Signature" slot. Used for document signing, or signing files and executables.
- `9d` is the "Key Management" slot. Used for things like encrypting e-mails or files for the purpose of confidentially.
- `9e` is the "Card Authentication" slot.
  This is the only slot that doesn't require a PIN to access the private key when signing with it, resulting in less friction in usage.
- `f9` is the "Attestation" slot. A dedicated slot containing the factory certificate of authenticity for the device itself.
- `82-95` it the "Retired Key Management" slots. An additional 20 slots that are used to store archived or retired encryption/management keys(moved from main `9a`, `9c`, `9d`, `9e` slots). Example: `8c` slot. These slots can be viewed and used to sign documents.

For more information, see the PIV specification (NIST SP 800-73).

### List active PIV slots

```shell
pivzavr --list
```

Lists the PIV slots that currently hold a certificate, alongside each certificate's fingerprint and subject.
For example:

```text
Slot: 9a (Authentication)
  Fingerprint: 3c9a7f1d5e8b2046af73c1d9e5b8042a6c9f7e1b
  Key Type: ECDSA P-384
  Subject: CN=Grigory Vasilyev,L=Moscow,C=RU,UID=h0tc0d3,emailAddress=h0tc0d3@email

Slot: 9c (Digital Signature)
  Fingerprint: 7f3a9c2e5b8d1046af72c9e3b5d8014c6a9f2e7b
  Key Type: ECDSA P-384
  Subject: CN=Grigory Vasilyev,L=Moscow,C=RU,UID=h0tc0d3,emailAddress=h0tc0d3@email

Slot: f9 (Attestation)
  Fingerprint: 9e4b7a1c6f0d8325ab47e9c1d6f0a83b5c2e7d91
  Key Type: RSA 2048
  Subject: CN=YubiKey PIV Attestation
```

`pivzavr` allows choosing a slot using the `-w` flag.
For each command, if no slot is specified, `9с` is used by default.
For example:

- Signing

  ```shell
  pivzavr -s -u userid [-w slot]
  ```

- Printing a certificate

  ```shell
  pivzavr --print [-w slot]
  ```

### Specifying a smart card by serial number

By default, `pivzavr` expects a single smart card to be attached. If a system has multiple card readers or smart cards,
or to simply ensure pivzavr is talking to the intended smart card, specify the serial number via the `PIVZAVR_SERIAL`
environment variable.

Example:

```shell
PIVZAVR_SERIAL=13078292 pivzavr --print
```

This can be used with any command.

### Print certificate information

```shell
pivzavr --print
```

Prints the certificate stored in the selected slot, alongside its fingerprint and details.
For example:

```bash
> pivzavr --print
Slot:          9c (Digital Signature)
Fingerprint:   7f3a9c2e5b8d1046af72c9e3b5d8014c6a9f2e7b
Serial Number: 482917365204889731546092118374650923847105662739
Key Type:      ECDSA P-384
Not Before:    2026-09-14 00:00:00 UTC
Not After:     2036-09-14 00:00:00 UTC

Subject DN:    CN=Grigory Vasilyev,L=Moscow,C=RU,UID=h0tc0d3,emailAddress=h0tc0d3@email
Issuer DN:     CN=Grigory Vasilyev,L=Moscow,C=RU,UID=h0tc0d3,emailAddress=h0tc0d3@email

-----BEGIN CERTIFICATE-----
MIICJjCCAaugAwIBAgIUbnnsAOGO65HitwPegVaQmqK0IBowCgYIKoZIzj0EAwIw
dDEgMB4GCSqGSIb3DQEJARYRaDB0YzBkM0BnbWFpbC5jb20xFzAVBgoJkiaJk/Is
ZAEBDAdoMHRjMGQzMQswCQYDVQQGEwJSVTEPMA0GA1UEBwwGTW9zY293MRkwFwYD
VQQDDBBHcmlnb3J5IFZhc2lseWV2MB4XDTI2MDkxNDAwMDAwMFoXDTM2MDkxNDAw
MDAwMFowdDEgMB4GCSqGSIb3DQEJARYRaDB0YzBkM0BnbWFpbC5jb20xFzAVBgoJ
kiaJk/IsZAEBDAdoMHRjMGQzMQswCQYDVQQGEwJSVTEPMA0GA1UEBwwGTW9zY293
MRkwFwYDVQQDDBBHcmlnb3J5IFZhc2lseWV2MHYwEAYHKoZIzj0CAQYFK4EEACID
YgAECia+CZsFzMUva7phl1J7GE92acAINp8NrBvFqUQjM9ILs8GCbV+RYXQLXE+V
W4PPgCsfVgSKgGmDrWmWtRaZyValAq+dAzSz/KFDoMc68wGJ+9KUg1KIHRcD7WNm
98ykMAoGCCqGSM49BAMCA2kAMGYCMQChYs0skv3tZ4Q/vzugulE1YJ9Ge/qQc6ah
7/um47eIsnnuTM7eOf36MeQOQf+JOAkCMQCHOjzAjnuTp36mUlxGE0hWchx+y9bP
rawjJAYeN4p6QyQnO2HZgaENjrzCgOQ7aII=
-----END CERTIFICATE-----
```

The certificate's fingerprint is calculated by performing a SHA1 checksum on the raw certificate bytes
and then encoding the checksum as a hex string.

Use the certificate fingerprint to let git know which certificate to use when signing commits and tags:

```shell
FINGERPRINT=$(pivzavr --print | awk '/^Fingerprint:/ {print $2}')
git config --(local|global) user.signingkey $FINGERPRINT
```

### Sign

```text
pivzavr -s [-a] [-b] [-u userid] [--status-fd=[num]] [-t url] [file]
```

- `-a` (`--armor`) - whether to wrap the signature in ASCII armor to make it printable.
- `-b` (`--detach-sign`) - make a detached signature.
- `-u` (`--local-user`) - either an email address or a key fingerprint encoded as a hex string.
  This identifier determines which certificate to use. If an email address is supplied, look for a certificate that contains the given address.
  If a key fingerprint is supplied, look for a certificate where its SHA1 checksum matched the given hex string.
- `--status-fd` - file descriptor to emit status messages to. `1` is stdout, `2` is stderr.
  Any value `0` or below means no status messages will be written.
- `-t` (`--timestamp-authority`) - URL of RFC3161 timestamp authority to use for timestamping.
- `file` - path to the file that will be signed. If no filename is specified, use stdin.

This command may require a physical touch on the smart card and will block until it is touched.

When `git` is set up to sign commits and tags, it'll use the following hardcoded parameters `-sbau [user.signingkey] --status-fd=1`.
`user.signingkey` is taken from git's local/global configuration.

### Verify signature

```shell
pivzavr --verify [file ...]
```

Verifies the signed data specified in the file argument(s).

If no files were specified, read from stdin.
If one or no file paths were specified, assume the signature is attached to the signed data.

Otherwise, the first file contains the signature and the second contains the signed data.
Specify `-` to indicate the signed data should be read from stdin.
If the signature is attached, the signed data file is ignored because the signature already contains it.

### Examples

```shell
pivzavr -sau 7f3a9c2e5b8d1046af72c9e3b5d8014c6a9f2e7b file > file.sig
pivzavr --verify file.sig file
```

```shell
pivzavr -sbu 7f3a9c2e5b8d1046af72c9e3b5d8014c6a9f2e7b file > file.sig
pivzavr --verify file.sig file
```

```text
Signature made using certificate ID 0x7f3a9c2e5b8d1046af72c9e3b5d8014c6a9f2e7b
Good signature from "CN=Grigory Vasilyev,L=Moscow,C=RU,UID=h0tc0d3,emailAddress=h0tc0d3@email"
```
