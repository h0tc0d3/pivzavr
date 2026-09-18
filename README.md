# Pivzavr

[![Go Version](https://img.shields.io/github/go-mod/go-version/h0tc0d3/pivzavr)](https://github.com/h0tc0d3/pivzavr/blob/main/go.mod) [![License](https://img.shields.io/github/license/h0tc0d3/pivzavr)](https://github.com/h0tc0d3/pivzavr/blob/main/LICENSE) [![Release](https://img.shields.io/github/v/release/h0tc0d3/pivzavr)](https://github.com/h0tc0d3/pivzavr/releases)

Pivzavr is a command-line tool for managing X.509 certificates stored on PIV smart cards
and using those certificates to sign and verify data.

It is fully compatible with how `git` invokes external programs to sign and verify commits and tags.

## Original project

Pivzavr is a fork of [cashapp/pivit](https://github.com/cashapp/pivit).

Advantages over the original project:

- Does not require exclusive access to the smart card, so it can run alongside `gpg-agent` and `ssh-agent`.
- Uses `pinentry` from `GnuPG` for secure PIN entry, which allows PIN entry in non-interactive shells and improves security. `pinentry` is launched directly (bypassing `gpg-agent`) and driven over the Assuan protocol, so no external library is required and no PIN ever passes through `gpg`.
- Provides improved certificate data output.
- Reports device information (name, firmware version, serial number, CHUID, CCC, PIN/PUK retries) and the certificates held in the active smart card slots.
- Key generation has been removed because it requires exclusive access to the smart card. To generate keys and move them between slots, use the smart card manufacturer's software, for example <https://github.com/yubico/yubioath-flutter>.

## Install

### Go install

```shell
go install github.com/h0tc0d3/pivzavr/cmd/pivzavr@latest
```

## Configuration

`pivzavr` reads its configuration from `~/.config/pivzavr/config`
(`$XDG_CONFIG_HOME/pivzavr/config` when `XDG_CONFIG_HOME` is set).
The file contains one `key value` setting per line; blank lines and lines
starting with `#` are ignored.

```text
# Path to the pinentry program used for PIN entry.
pinentry /usr/bin/pinentry-qt

# Path to the PKCS#11 module used to talk to the smart card.
pkcs11-module /usr/lib/x86_64-linux-gnu/libykcs11.so

# Serial number of the smart card to use when more than one is connected.
serial 0000000000000000
```

The following environment variables override the configuration file:

- `PIVZAVR_PINENTRY` - path to the pinentry program.
- `PIVZAVR_PKCS11_MODULE` - path to the PKCS#11 module.
- `PIVZAVR_SERIAL` - serial number of the smart card to use when more than one is connected.

Settings are resolved with the following priority, from lowest to highest:

1. Default settings (auto-detected pinentry/PKCS#11 module for the current operating system).
2. The configuration file (`~/.config/pivzavr/config`).
3. Environment variables (`PIVZAVR_PINENTRY`, `PIVZAVR_PKCS11_MODULE`, `PIVZAVR_SERIAL`).

When no pinentry program is configured, `pivzavr` searches for the first
available program in the following order of preference: `pinentry-qt`,
`pinentry-gtk`, `pinentry-curses`, `pinentry-tty`.

## Usage

To configure Git to use `pivzavr` to sign and verify signatures, run the following commands:

```shell
git config --(local|global) gpg.format x509
git config --(local|global) gpg.x509.program pivzavr
```

Add the lines below to these files:

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

### ~/.gnupg/gpg-agent.conf

This file only configures `GnuPG` itself. `pivzavr` launches `pinentry`
directly and does not read `gpg-agent.conf`; configure it through
`~/.config/pivzavr/config` instead (see [Configuration](#configuration)).

```text
pinentry-program /usr/bin/pinentry-qt
```

Change the path to your pinentry program. Available values are: `pinentry-qt`, `pinentry-curses`, `pinentry-gtk`, and `pinentry-tty`.

To find the available programs: `find /usr -type f -name "pinentry*"`.

Remove the line that specifies the custom scdaemon path. This allows you to use both the `OpenPGP` smart card application (`gpg --edit-card`) and PIV with `pivzavr`.

`sed -i '/scdaemon-program/d' ~/.gnupg/gpg-agent.conf`

### Reset and initialize the smart card PIV applet

```shell
pivzavr --reset
```

Resets the smart card's PIV applet and creates a new PIN to access it.

### PIV slot support

The PIV module supports multiple slots where keys and certificates can be stored.
Available slots: `9a`, `9c`, `9d`, `9e`, `9b`, `f9`, and `82-95`.

- `9a` is the "Authentication" slot. It is used for actions such as system login.
- `9b` is the "Management Key" slot. It is a service slot for the PIV card's management key, used to write data to other slots.
- `9c` is the "Digital Signature" slot. It is used for signing documents, files, and executables.
- `9d` is the "Key Management" slot. It is used for encrypting email or files to provide confidentiality.
- `9e` is the "Card Authentication" slot.
  This is the only slot that does not require a PIN to access the private key for signing, resulting in less friction.
- `f9` is the "Attestation" slot. A dedicated slot containing the factory-installed attestation certificate for the device itself.
- `82-95` are the "Retired Key Management" slots. These 20 additional slots are used to store archived or retired encryption and key management keys (moved from the main `9a`, `9c`, `9d`, and `9e` slots), for example the `8c` slot. These slots can be viewed and used to sign documents.

For more information, see the PIV specification (NIST SP 800-73).

### Device information and active PIV slots

```shell
pivzavr --info
```

Prints information about every connected smart card, including its name, firmware version,
serial number, the PIV data objects (CHUID and CCC) and the certificates stored in the active
PIV slots.
For example:

```text
Name:        YubiKey PIV #00000000
Firmware:    5.4.3
Serial:      00000000
CHUID:       53304215D4E739...
CCC:         53304215F0000000...
PIN Retries: 3
PUK Retries: 3

Slot: 9a (Authentication)
  Fingerprint: D34DCF3361CBEEA998138E483CF0AF6E
  Key Type: ECDSA NIST P-384
  Subject DN: CN=Grigory Vasilyev,L=Moscow,C=RU,UID=h0tc0d3,emailAddress=h0tc0d3@email
  Issuer DN: CN=Grigory Vasilyev,L=Moscow,C=RU,UID=h0tc0d3,emailAddress=h0tc0d3@email
  Not Before: 2026-09-14 00:00:00 UTC
  Not After: 2036-09-14 00:00:00 UTC

Slot: 9c (Digital Signature)
  Fingerprint: 9355EBBA189245C53417404EFDDA3F73
  Key Type: ECDSA NIST P-384
  Subject DN: CN=Grigory Vasilyev,L=Moscow,C=RU,UID=h0tc0d3,emailAddress=h0tc0d3@email
  Issuer DN: CN=Grigory Vasilyev,L=Moscow,C=RU,UID=h0tc0d3,emailAddress=h0tc0d3@email
  Not Before: 2026-09-14 00:00:00 UTC
  Not After: 2036-09-14 00:00:00 UTC

Slot: f9 (Attestation)
  Fingerprint: 4802B0A57C3B158035E6B41496435884
  Key Type: RSA 2048
  Subject DN: CN=YubiKey PIV Attestation
  Issuer DN: CN=YubiKey PIV Attestation
  Not Before: 2024-01-01 00:00:00 UTC
  Not After: 2054-01-01 00:00:00 UTC
```

The CHUID and CCC data objects are read from the token when the PKCS#11 module exposes them
(for example `libykcs11` and `opensc-pkcs11`); otherwise they are shown as `(unavailable)`.

The PIN and PUK retry counts are not part of PKCS#11 and are read directly from the PIV applet
over PC/SC (using the same method as `ykman`/`yubico-piv-tool`). This requires a PC/SC
implementation to be available at build time (`libpcsclite-dev` on Linux; the PC/SC framework
is used on macOS and `winscard` on Windows) and at runtime. When the counts cannot be read they
are shown as `(unavailable)`.

You can choose a slot using the `-w` flag.
For each command, if no slot is specified, `9c` is used by default.
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

By default, `pivzavr` expects a single smart card to be attached. If the system has multiple card readers or smart
cards, or you want to ensure `pivzavr` is talking to the intended smart card, specify the serial number with the
`PIVZAVR_SERIAL` environment variable.

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
Fingerprint:   9355EBBA189245C53417404EFDDA3F73
Serial Number: dcfbac9ed51883ee1358033cd7e287fef84ccf51
Key Type:      ECDSA NIST P-384
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

The certificate's fingerprint is calculated by performing a SHA3-256 checksum on the raw certificate bytes and then encoding the first 16 bytes (128 bits) of the checksum as an upper-case hex string.

Use the certificate fingerprint to tell Git which certificate to use when signing commits and tags:

```shell
FINGERPRINT=$(pivzavr --print | awk '/^Fingerprint:/ {print $2}')
git config --(local|global) user.signingkey $FINGERPRINT
```

### Sign

```text
pivzavr -s [-a] [-b] [-u userid] [--status-fd=[num]] [-t url] [file]
```

- `-a` (`--armor`) - wrap the signature in ASCII armor to make it printable.
- `-b` (`--detach-sign`) - create a detached signature.
- `-u` (`--local-user`) - an email address or a key fingerprint encoded as a hex string.
  This identifier determines which certificate to use. If an email address is supplied, `pivzavr` looks for a certificate that contains that address.
  If a key fingerprint is supplied, `pivzavr` looks for a certificate whose SHA3-256 checksum matches the given hex string.
- `--status-fd` - the file descriptor to which status messages are emitted. `1` is stdout and `2` is stderr.
  Any value `0` or below means no status messages will be written.
- `-t` (`--timestamp-authority`) - the URL of the RFC 3161 timestamp authority to use for timestamping.
- `file` - the path to the file to sign. If no filename is specified, the data is read from stdin.

This command may require a physical touch on the smart card and will block until it is touched.

When `git` is configured to sign commits and tags, it uses the following hard-coded parameters: `-sbau [user.signingkey] --status-fd=1`.
`user.signingkey` is taken from Git's local or global configuration.

### Verify signature

```shell
pivzavr --verify [file ...]
```

Verifies the signed data specified in the file argument(s).

If no files are specified, the data is read from stdin.
If one or no file path is specified, the signature is assumed to be attached to the signed data.

Otherwise, the first file contains the signature and the second contains the signed data.
Use `-` to indicate that the signed data should be read from stdin.
If the signature is attached, the signed data file is ignored because the signature already contains it.

### Examples

```shell
pivzavr -sau 9355EBBA189245C53417404EFDDA3F73 file > file.sig
pivzavr --verify file.sig file
```

```shell
pivzavr -sbu 9355EBBA189245C53417404EFDDA3F73 file > file.sig
pivzavr --verify file.sig file
```

```text
Signature made using certificate ID 0x9355EBBA189245C53417404EFDDA3F73
Good signature from "CN=Grigory Vasilyev,L=Moscow,C=RU,UID=h0tc0d3,emailAddress=h0tc0d3@email"
```
