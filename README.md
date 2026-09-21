# Pivzavr

[![Go Version](https://img.shields.io/github/go-mod/go-version/h0tc0d3/pivzavr)](https://github.com/h0tc0d3/pivzavr/blob/master/go.mod) [![License](https://img.shields.io/github/license/h0tc0d3/pivzavr)](https://github.com/h0tc0d3/pivzavr/blob/master/LICENSE.md) [![Release](https://img.shields.io/github/v/release/h0tc0d3/pivzavr)](https://github.com/h0tc0d3/pivzavr/releases)

Pivzavr is a command-line tool for managing X.509 certificates stored on PIV smart cards
and using those certificates to sign and verify data.

It is fully compatible with how `git` invokes external programs to sign and verify commits and tags.

## Features

- Does not require exclusive access to the smart card, so it can run alongside `gpg-agent` and `ssh-agent`.
- Uses `pinentry` from `GnuPG` for secure PIN entry, which allows PIN entry in non-interactive shells and improves security. `pinentry` is launched directly (bypassing `gpg-agent`) and driven over the Assuan protocol, so no external library is required and no PIN ever passes through `gpg`.
- Provides improved certificate data output.
- Translates its messages into the language of the user. English and Russian are included; the `language` setting forces one of them and defaults to the locale of the system.
- Reports device information (name, firmware version, serial number, CHUID, CCC, PIN/PUK retries) and the certificates held in the active smart card slots.
- Reports the attempts that are left in every PIN and PUK dialog, so the count is known before a secret is entered. A blocked PIN is unlocked with the PUK (`--unlock`), and a card whose PUK is used up is restored with a factory reset (`--reset`).
- Changes the secrets and the data objects of a smart card: the PIN (`--set-pin`), the PUK (`--set-puk`), the CHUID and the CCC (`--set-chuid`, `--set-ccc`) and the card management key (`--set-management-key`), which can be generated (`--random`) and stored on the card protected by the PIN (`--protect 1`).
- Verifies signatures against a trust store that holds the Mozilla CA store, the CA certificates of PIV smart cards, the CA certificates named by the `ca-certificate` setting and the public keys named by the `public-key` setting. The store is kept in the configuration directory, is downloaded when it does not exist yet and is refreshed with `--update-trust`, so no CA bundle has to be built into the binary.
- Checks more than the trust chain of a signature: the certificate must be an end-entity certificate that may make digital signatures, its validity period is checked, and its revocation status is looked up with the OCSP responders the certificate names and with the responders of the `ocsp-server` setting. A certificate that the responders report as revoked is rejected, and `require-ocsp` turns an inconclusive check into an error.
- Writes detached signatures to files of their own: `--detach-sign` names exactly one file and writes the signature next to it, with the extension (`-o`, `--ext`) selecting the format of the signature.
- Writes a clear text signature with `--clearsign`, in the style of `gpg --clearsign`: the message is kept readable in front of an armored CMS signature block, and a file that carries one is verified in place.
- Embeds the signature in the file for the formats that have a place for it (`.xml`, `.docx`, `.xlsx`, `.odt`, `.jar`, `.apk`, `.pdf`) and verifies the signature in place.
- Reports the time of signing, the algorithm of the signature and the whole chain of trust when a signature is verified.
- Key generation has been removed because it requires exclusive access to the smart card. To generate keys and move them between slots, use the smart card manufacturer's software, for example <https://github.com/yubico/yubioath-flutter>.

## Install

### Go install

```shell
go install github.com/h0tc0d3/pivzavr/cmd/pivzavr@latest
```

### Build from source

```shell
make
```

Building pivzavr needs no C toolchain. The PKCS#11 module that talks to the smart
card and the PC/SC library that talks to the PIV applet are C libraries, but they
are loaded at run time with
[purego](https://github.com/ebitengine/purego) instead of being linked against,
so neither cgo nor the development headers of the libraries are involved. A
build with `CGO_ENABLED=0` has every feature, and so has a cross-compiled release
binary, for example:

```shell
make GOOS=windows GOARCH=amd64
```

FreeBSD needs one compiler flag for the fake C runtime of purego when it is
built with `CGO_ENABLED=0`, which `make` passes on its own; the support notes of
the purego project describe it for a build that does not go through the Makefile.

## Configuration

`pivzavr` reads its configuration from `~/.config/pivzavr/config`
(`$XDG_CONFIG_HOME/pivzavr/config` when `XDG_CONFIG_HOME` is set).
The file contains one `key value` setting per line; blank lines and lines
starting with `#` are ignored.

```text
# Path to the pinentry program used for PIN entry.
pinentry /usr/bin/pinentry-qt

# Path to the PKCS#11 module used to talk to the smart card. Several modules
# may be named in one setting, separated by ":" (";" on Windows); every module
# is loaded, so that a YubiKey, a Rutoken ECP and a JaCarta can be used at the
# same time. When the setting is absent, the modules that are installed in the
# conventional locations are loaded.
pkcs11-module /usr/lib/x86_64-linux-gnu/libykcs11.so:/usr/lib/x86_64-linux-gnu/librtpkcs11ecp.so

# Serial number of the smart card to use when more than one is connected.
serial 0000000000000000

# Language of the messages: "en" or "ru", or a locale such as "ru_RU.UTF-8".
# When the setting is absent, the language of the system locale (LC_ALL,
# LC_MESSAGES or LANG) is used; a locale that names a language pivzavr is not
# translated into selects English.
language en

# Add a CA certificate to the trust store: a URL of a PEM or DER bundle, or a
# path of a PEM or DER file. May be repeated; a leading ~ is expanded.
ca-certificate https://example.com/company-ca.pem
ca-certificate ~/certs/company-ca.pem

# Add a public key to the trust store: a URL of a PEM or DER public key file,
# or a path of a PEM or DER file. May be repeated; a leading ~ is expanded.
# The key is what a signature is verified against when its certificate cannot
# be verified with a CA, for example when the card was re-keyed or was enrolled
# with a CA that is not in the store.
public-key https://example.com/signer.pem
public-key ~/keys/signer.pem

# Ask an OCSP responder in addition to the responders that a certificate names,
# for example when the responder of a certificate cannot be reached. May be
# repeated.
ocsp-server https://ocsp.example.com

# Refuse to verify a signature whose certificate could not be checked for
# revocation. Off by default; when off, such a signature is verified with a
# warning.
require-ocsp false
```

The following environment variables override the configuration file:

- `PIVZAVR_PINENTRY` - path to the pinentry program.
- `PIVZAVR_PKCS11_MODULE` - path of the PKCS#11 module, or of several of them separated by `:` (`;` on Windows).
- `PIVZAVR_SERIAL` - serial number of the smart card to use when more than one is connected.

Settings are resolved with the following priority, from lowest to highest:

1. Default settings (auto-detected pinentry/PKCS#11 module for the current operating system).
2. The configuration file (`~/.config/pivzavr/config`).
3. Environment variables (`PIVZAVR_PINENTRY`, `PIVZAVR_PKCS11_MODULE`, `PIVZAVR_SERIAL`).

The `language`, `ca-certificate`, `public-key`, `ocsp-server` and `require-ocsp`
settings have no environment variable. The `language` setting is read when
`pivzavr` starts, so it selects the language of every message the command
reports. A `ca-certificate` or a `public-key` is added to the trust store by
`pivzavr --update-trust`; a store that is already present is used as it is, so
run `pivzavr --update-trust` after changing either setting.

When no pinentry program is configured, `pivzavr` searches for the first
available program in the following order of preference: `pinentry-qt`,
`pinentry-gtk`, `pinentry-curses`, `pinentry-tty`.

### PKCS#11 modules and smart card vendors

`pivzavr` talks to a smart card through a PKCS#11 module. The module of the
card's vendor knows the most of it, so the conventional module locations are
searched for the module of the vendor first, and OpenSC (`opensc-pkcs11`) is
used as the fallback:

| Vendor | Module | Recognised as |
| --- | --- | --- |
| Yubico | `libykcs11` | `ykcs11` |
| Aktiv | `librtPKCS11ECP` (Rutoken ECP) | `rtPKCS11` |
| Aladdin | `libjcPKCS11` (JaCarta) | `jcPKCS11` |
| OpenSC | `opensc-pkcs11` | fallback for any card |

The YubiKey module is only considered when a YubiKey is attached, because it
does nothing for another card; the other modules are considered whenever they
are installed. Every module that the configuration names is loaded, and a card
that more than one module exposes is used through the first module that saw it,
so a YubiKey, a Rutoken ECP and a JaCarta are all reachable in one run of
`--info` or of a signing command.

### Trust store

Signatures are verified against the trust store in
`~/.config/pivzavr/trust.bin` (`$XDG_CONFIG_HOME/pivzavr/trust.bin` when
`XDG_CONFIG_HOME` is set). The store holds the CA certificates that a signature
is verified against, the Mozilla CA store, the CA certificates of PIV smart
cards that the Mozilla store does not carry (such as the Yubico attestation
roots and the intermediates that issue YubiKey attestation certificates), and
the CA certificates named by the `ca-certificate` setting of the configuration
file. It also holds the public keys that a signature is verified against when
its certificate cannot be verified with a CA, named by the `public-key` setting.

The store is downloaded and stored the first time a signature is verified, so
a fresh installation can verify signatures without any preparation. The store
is refreshed on demand:

```shell
pivzavr --update-trust
```

The stored store is replaced as a whole, which drops the certificates that
were removed from the Mozilla store as well, and adds the CA certificates and
public keys that the `ca-certificate` and `public-key` settings name. The
Mozilla store and every configured source are required, because a trust anchor
that was clearly meant to be used must not go missing without notice; a smart
card source that cannot be reached only leaves those extra CA certificates out.
When the store cannot be read or downloaded at all, verification falls back to
the certificate store of the operating system.

`trust.bin` is a binary file that holds the CA certificates and the public keys
together with a checksum of its contents. The checksum makes a store that was
edited by hand or damaged detectable: such a store is reported as invalid
instead of being used, and `pivzavr --update-trust` builds it again. The
checksum protects against accidental changes only, not against an attacker who
can rewrite the file and its checksum together; see
[SECURITY.md](SECURITY.md#security-model).

The certificate of the smart card is not a trust anchor by itself: a signature
verifies only when its certificate chains up to a CA in the store. When it does
not, two more trust anchors are tried, in this order:

- The self-signed certificate of the smart card that verifies the signature. A
  smart card that was never enrolled with a CA signs with such a certificate,
  which is accepted with a warning and reported as `TRUST_ULTIMATE`.
- The public keys of the `public-key` setting. A certificate whose public key is
  configured is accepted with a warning and reported as `TRUST_ULTIMATE`, which
  is what makes it possible to verify a signature after the card was re-keyed,
  or when the CA of an enrolled card is not part of the store.

Only the trust anchor changes in either case: the signature, the message digest
and the validity period are checked again, so nothing else about the signature
is forgiven.

## Usage

To configure Git to use `pivzavr` to sign and verify signatures, run the following commands:

```shell
git config --(local|global) gpg.format x509
git config --(local|global) gpg.x509.program pivzavr
```

Run `pivzavr --help` for the list of options and `pivzavr --version` for the
version of the program.

### Shell completions

Completions for bash, zsh and fish are in the `completions` directory of the
repository. Install the file of your shell where it looks for completions:

```shell
# bash
install -Dm 644 completions/pivzavr.bash \
  ~/.local/share/bash-completion/completions/pivzavr

# zsh (a directory of $fpath, or your site-functions directory)
install -Dm 644 completions/_pivzavr ~/.zsh/completions/_pivzavr

# fish
install -Dm 644 completions/pivzavr.fish \
  ~/.config/fish/completions/pivzavr.fish
```

The completions describe the options, the PIV slot references, the signature
file extensions, the management key algorithms and the files that an option
takes.

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

### Smart card PIN, PUK and recovery

Whenever `pivzavr` has to log in to the smart card it asks for the user PIN through `pinentry`. Every dialog shows how many attempts the card has left, so the count is known before a secret is entered as well. A PIN that the card rejects does not end the command either: the dialog is shown again and reports the attempts that are left, so a typo can be corrected without leaving the command. The escalated recovery steps below are used once the card has no attempts left.

- The user PIN has 3 attempts. Once they are used up the card blocks the PIN, and no PIN can unlock it any more. `pivzavr` reports this and points at `--unlock`.
- The PUK has 3 attempts as well. Unlocking the PIN verifies the PUK and resets the PIN and PUK retry counters in one step; the PIN entered in the dialog becomes the PIN of the card.
- Once the PUK attempts are used up the card can only be restored with `--reset`.

The PIN, the PUK and the secrets a card is managed with can be replaced as well: `--set-pin`, `--set-puk`, `--set-chuid`, `--set-ccc` and `--set-management-key` are described below.

#### Unlock the blocked PIN with the PUK

```shell
pivzavr --unlock
```

Asks for the new PIN and then for the PUK, and unlocks the PIN with it. Unlocking does not touch the keys and certificates stored on the card, and it does not put the PIN back to its factory default: it resets the remaining PIN and PUK retry counters, so all attempts are available again, and the PIN entered in the dialog becomes the PIN of the card.

The PUK dialog is slightly larger than the PIN dialog because `pinentry` sizes a dialog to fit the text it is given, which makes the two easy to tell apart.

A rejected PUK is reported in the dialog together with the attempts that are left; when the PUK is used up, `pivzavr` reports that the card must be restored with `--reset`.

Unlocking a PIN requires the YubiKey PKCS#11 module (`libykcs11`), because it maps `C_SetPIN` to the PIV *RESET RETRY COUNTER* command. Other PKCS#11 modules do not implement that command and report an error instead.

#### Reset the smart card PIV applet

```shell
pivzavr --reset
```

Restores the PIV applet to its factory state: the keys and certificates stored in the PIV slots are erased, the PIN, the PUK and the card management key are the factory defaults, and the PIN and PUK retry counters are full again. The factory state is reported when the reset is done:

```text
Reset complete. All PIV data has been cleared from the smart card.
The smart card now has the default PIN, PUK and management key:
  PIN: 123456
  PUK: 12345678
  Management Key: 010203040506070801020304050607080102030405060708
```

No PIN is asked for, and the reset requires neither the PIN, the PUK nor the management key: a PIV card resets itself once its PIN and its PUK are blocked, which is what `pivzavr` does first. A card whose PIN, PUK or management key were changed can therefore be restored with `--reset` as well. To replace the default PIN with a PIN of your own, use `--set-pin`.

This step cannot be undone: keys and certificates that are stored on the card are erased and cannot be recovered. Move them to a backup card or copy them to a safe place before resetting.

#### Change the PIN and the PUK

```shell
pivzavr --set-pin
pivzavr --set-puk
```

`--set-pin` replaces the user PIN of the smart card. The current PIN and the new PIN are asked for through `pinentry`, and the new PIN is entered twice, so that a typo cannot install a PIN that was not meant. A wrong current PIN is reported in the dialog, which is shown again with the number of attempts the card has left, so a typo does not end the command either. A card whose PIN is blocked cannot replace it: the PIN is unlocked with the PUK (`--unlock`) instead.

`--set-puk` replaces the PUK in the same way. A card whose PUK is used up can only be restored with `--reset`.

The PIN and the PUK may contain letters, digits and symbols. The PIN is 6 to 8 characters long and the PUK is exactly 8, which is what the PIV specification requires; an input that cannot be a PIN or PUK is reported in the dialog before the card is asked, so that it does not use up an attempt.

#### Change the card management key

```shell
pivzavr --set-management-key[=ALGO] [--protect 0|1] [--random]
```

Replaces the card management key, which authenticates the commands that write to the PIV application, such as writing a data object. `ALGO` is the algorithm of the new key: `AES128`, `AES192` or `AES256`, all of which the YubiKeys `pivzavr` supports accept. `ALGO` can be left out, and AES256 is then used. The algorithm is written with the option, `--set-management-key=AES128`.

The current management key is asked for as hexadecimal, and an empty entry selects the factory default key (`010203040506070801020304050607080102030405060708`), which is a Triple-DES key. A card that still holds it is recognised, so that a fresh card can be moved to an AES key: the default key authenticates the card and the AES key that was asked for replaces it. The new key is asked for twice and has to have the length the algorithm requires: 16 bytes for `AES128`, 24 bytes for `AES192` and 32 bytes for `AES256`.

- `--random` generates a random key of the given algorithm instead of asking for one. A generated key that is not stored on the card is reported, because it is the only copy:

```text
  Generated management key: 5F3C...
  New management key set.
```

- `--protect 1` stores the new management key on the smart card, protected by the PIN. The PIN is asked for as well, and the key is kept in the data object a PIV card reserves for printed information (`5FC109`), which the card only hands out to a verified PIN. `pivzavr` uses a key that is stored on the card for the commands that need one, so it does not have to be entered any more. `--protect 0` is the default: a key that the card stores is removed, so that the card does not report a key it no longer holds.
- A key that is stored on the card is not reported when it is generated, because it cannot get lost.

`--set-chuid` and `--set-ccc` need the management key as well, and they use a key that is stored on the card instead of asking for one.

#### Write the CHUID and the CCC

```shell
pivzavr --set-chuid
pivzavr --set-ccc
```

`--set-chuid` writes a new Card Holder Unique Identifier and `--set-ccc` a new Card Capability Container: the two data objects that describe the card and its holder. Both are generated in the format a PIV card is initialized with:

- The CHUID holds the FASC-N of a card that is not issued by a federal agency, a random card identifier and an expiration date ten years after the day the object is written.
- The CCC holds the identifier of the PIV application, a random card identifier and the version and capability data of a PIV card.

Both commands read the object back from the smart card and report the value the card stored, so a card that does not keep the data is reported as an error instead of as a success. The objects are also read by `--info`, which reports them as hex strings.

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

Prints information about every connected smart card, including its name, the PKCS#11 module
it is used through, firmware version, serial number, the PIV data objects (CHUID and CCC) and
the certificates stored in the active slots.
Cards of different vendors are all reported, whichever of the installed or configured PKCS#11
modules they need.
For example:

```text
Name:        YubiKey PIV #00000000
Module:      /usr/lib/x86_64-linux-gnu/libykcs11.so
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
over PC/SC. This requires a PC/SC implementation to be present at runtime (pcsc-lite on Linux,
the PC/SC framework on macOS and `winscard.dll` on Windows); it is loaded when it is needed,
which is why the build does not depend on it. When the counts cannot be read they
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

- Updating the trust store

  ```shell
  pivzavr --update-trust
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
pivzavr -s [-a] [-b] [-u userid] [-o file] [--ext ext] [--status-fd=[num]] [-t url] [file]
pivzavr --clearsign [-u userid] [-o file] [--status-fd=[num]] [-t url] [file]
```

- `-a` (`--armor`) - wrap the signature in ASCII armor to make it printable. The armored signature is a CMS/PKCS#7 structure, so it is written as `-----BEGIN PKCS7-----` and is recognized by `openssl cms` and other CMS tools.
- `-b` (`--detach-sign`) - keep the signed data out of the signature. On its own, without `-s`, the option is a command that writes a detached signature file next to the file it signs.
- `--clearsign` - make a clear text signature, in the style of `gpg --clearsign`. It is a command of its own, so it is not combined with `-s` or `-b`; see [Clear text signature](#clear-text-signature).
- `-u` (`--local-user`) - a key fingerprint encoded as a hex string, or an email address from the certificate's Subject DN.
  This identifier determines which certificate to use. If an email address is supplied, `pivzavr` looks for a certificate whose Subject DN carries that address (an address in the Subject Alternative Name is matched as well); the Issuer DN is not considered.
  If a key fingerprint is supplied, `pivzavr` looks for a certificate whose SHA3-256 checksum matches the given hex string.
- `-o` (`--output`) - write the signature to this file instead of the standard output. The extension of the file selects the format of the signature, so `signature.p7m` holds an attached signature and `signature.asc` holds an armored one.
- `--ext` - the extension of the signature file, one of `sig`, `sign`, `sgn`, `p7s`, `p7m`, `asc` or `pem` (with or without the leading dot). The extension selects the format of the signature; `--sign` then keeps the signature out of the standard output, which is what `git` expects.
- `--status-fd` - the file descriptor to which status messages are emitted. `1` is stdout and `2` is stderr.
  Any value `0` or below means no status messages will be written.
- `-t` (`--timestamp-authority`) - the URL of the RFC 3161 timestamp authority to use for timestamping.
- `file` - the path to the file to sign. If no filename is specified, the data is read from stdin.

This command may require a physical touch on the smart card and will block until it is touched.

When `git` is configured to sign commits and tags, it uses the following hard-coded parameters: `-sbau [user.signingkey] --status-fd=1`.
`user.signingkey` is taken from Git's local or global configuration.

### Detach signature

```text
pivzavr -b [-a] [-u userid] [-o file] [--ext ext] [--status-fd=[num]] [-t url] file
```

Creates a detached signature of `file` and writes it to a file of its own. The
command names exactly one file, and the file is left untouched.

The signature file is named after the file that was signed, followed by the
extension of the format that was selected:

| Format              | Extension          | Contents                                                     |
| ------------------- | ------------------ | ------------------------------------------------------------ |
| binary, detached    | `.sig`, `.p7s`     | CMS signature, DER encoded                                    |
| binary, attached    | `.p7m`             | CMS signature with the signed data encapsulated in it         |
| text, detached      | `.asc`, `.pem`     | The detached signature in ASCII armor, a `-----BEGIN PKCS7-----` block (requires `-a`) |

The format is selected by `-o` when it names a file, otherwise by `--ext`, and
otherwise by `-a`: `pivzavr -b -a file` writes `file.asc`, while
`pivzavr -b file` writes `file.sig`. The extensions `.sign` and `.sgn` are
accepted as well and select the binary detached format.

For example:

```shell
pivzavr -b -u 9355EBBA189245C53417404EFDDA3F73 contract.pdf
pivzavr --verify contract.pdf.sig contract.pdf
```

### Clear text signature

```text
pivzavr --clearsign -u userid [-o file] [--status-fd=[num]] [-t url] [file]
```

Creates a clear text signature, in the style of `gpg --clearsign`. The message is
written to the output verbatim, so it stays readable, followed by a blank line
and the detached signature of the message in ASCII armor:

```text
Contract for the delivery of …

-----BEGIN PKCS7-----
MIIC4AYJKoZIhvcNAQcCoIIC0TCCAs0CAQExDTALBglghkgBZQMEAgEwCwYJKoZI
…
-----END PKCS7-----
```

The command names at most one file and reads the message from the standard input
when no file is given; `-o` writes the result to a file instead of the standard
output. The message is signed byte for byte, so it is recovered unchanged when
the signature is verified: `pivzavr --verify signed.txt` reads the message from
the file itself, and no separate message file is needed. A message that holds a
blank line followed by the start of a `PKCS7` block is the one exception: the
signature is looked for from the start of the file, so such a message cannot be
recovered from it. The armored block is a detached CMS/PKCS#7 signature, so the
message that is written in front of it can be checked with other CMS tools as
well, for example with
`openssl cms -verify -binary -in signed.txt -content message.txt`.

`--clearsign` is a command of its own, like `--detach-sign` without `--sign`: it
is run on its own, so it is not combined with `-s` or `-b`. The signature is
always armored, so `-a` is not needed, and `--ext` is not accepted either.

### Sign a container file

```text
pivzavr -s [-u userid] [-o file] [--status-fd=[num]] file
```

A file whose format has a place for a signature of its own has the signature
embedded in it, and the signed file is written next to it with `.signed` before
its extension (`report.pdf` becomes `report.signed.pdf`), or to the file named
with `-o`. The file that was signed is not changed. The supported formats and
the signature scheme each of them uses are:

| Extension       | Signature                                                       |
| --------------- | --------------------------------------------------------------- |
| `.xml`          | An enveloped XML Signature in the document itself               |
| `.docx`, `.xlsx`| An XML Signature in the `_xmlsignatures` package part            |
| `.odt`          | An XML Signature in `META-INF/documentsignatures.xml`            |
| `.jar`, `.apk`  | The JAR signing scheme: `META-INF/MANIFEST.MF`, a `.SF` file and a PKCS#7 signature |
| `.pdf`          | A CMS signature in a signature field added to the document       |

The XML signatures are produced with exclusive canonicalization
(`xml-exc-c14n`) and sign the document, or every part of the package, with a
SHA-256, SHA-384 or SHA-512 digest, whichever the key of the smart card
supports. They record the time of signing in an XAdES `SigningTime` property
that is covered by the signature.

To write a signature file instead of an embedded signature, name a signature
file with `-o` (`-o report.pdf.sig`) or select an extension with `--ext`.
`--detach-sign` always writes a detached signature file.

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

A single file argument is recognised by its name:

- A container file (`.xml`, `.docx`, `.xlsx`, `.odt`, `.jar`, `.apk`, `.pdf`)
  has the signature that is embedded in it verified.
- A detached signature file (`.sig`, `.sign`, `.sgn`, `.p7s`, `.asc`, `.pem`)
  has the file it signs read from the name that is left when the extension is
  removed, so `pivzavr --verify contract.pdf.sig` verifies the signature
  against `contract.pdf`. If that file is not there, the file itself is read as
  an attached signature, as before.
- Any other file is read as an attached signature.

A file that carries a clear text signature, that is, a message followed by a
`-----BEGIN PKCS7-----` block (see [Clear text signature](#clear-text-signature)),
is recognized by its contents rather than by its name: the message is read from
the file itself and the signature is verified against it.

The output reports the certificate that made the signature with its validity
period, the chain of trust that was built for it, the time of signing and the
algorithm the signature was made with:

```text
Signature made using certificate ID 0x9355EBBA189245C53417404EFDDA3F73
Good signature. Subject DN: CN=Grigory Vasilyev,L=Moscow,C=RU,UID=h0tc0d3,emailAddress=h0tc0d3@email
Not Before: 2026-01-01 00:00:00 UTC
Not After: 2027-01-01 00:00:00 UTC
Signing date: 2026-09-21 07:48:00 UTC
Signature algorithm: SHA-384 with ECDSA
Chain of Trust:
  1. [signer] CN=Grigory Vasilyev,L=Moscow,C=RU,UID=h0tc0d3,emailAddress=h0tc0d3@email (9355...) - verified
  2. [root] CN=Russian Trusted Root CA,O=... (B1C4...) - trusted (CA bundle)
```

The certificate that made the signature is checked thoroughly. It is checked
against the trust store described in [Trust store](#trust-store), which is
downloaded the first time a signature is verified; run
`pivzavr --update-trust` to refresh it. The certificate must be an end-entity
certificate, it must be permitted to make digital signatures, and its validity
period must cover the signature (or the time the signature was timestamped).
Its revocation status is looked up with the OCSP responders named in the
certificate and with the responders of the `ocsp-server` settings.

A certificate that a responder reports as revoked is always rejected. When the
revocation status cannot be determined, because the certificate names no
responder and none is configured, or because none of them answers, the signature
is verified with a warning on stderr. Set `require-ocsp true` in the
configuration file to reject a signature whose revocation status could not be
determined as well.

A smart card that was never enrolled with a CA signs with a self-signed
certificate, which is not issued by any CA. Such a signature is accepted with a
warning and reported as `TRUST_ULTIMATE` instead of `TRUST_FULLY`, and only when
the certificate matches the key of the card that is present. A signature whose
certificate a CA does not certify is accepted as well when its public key is one
of the `public-key` settings, which is reported as
`trusted (configured public key)` in the chain of trust. The chain of trust of
such a signature has a single entry, which is reported as the signer and the
trust anchor at once.

### Examples

```shell
pivzavr -sau 9355EBBA189245C53417404EFDDA3F73 file > file.asc
pivzavr --verify file.asc file
```

```shell
pivzavr -bu 9355EBBA189245C53417404EFDDA3F73 file
pivzavr --verify file.sig
```

```shell
pivzavr -b -u 9355EBBA189245C53417404EFDDA3F73 report.pdf
pivzavr --verify report.pdf.sig
```

```shell
pivzavr -s -u 9355EBBA189245C53417404EFDDA3F73 report.pdf
pivzavr --verify report.signed.pdf
```

```shell
pivzavr --clearsign -u 9355EBBA189245C53417404EFDDA3F73 -o contract.txt.asc contract.txt
pivzavr --verify contract.txt.asc
```

```text
Signature made using certificate ID 0x9355EBBA189245C53417404EFDDA3F73
Good signature. Subject DN: CN=Grigory Vasilyev,L=Moscow,C=RU,UID=h0tc0d3,emailAddress=h0tc0d3@email
Not Before: 2026-01-01 00:00:00 UTC
Not After: 2027-01-01 00:00:00 UTC
Signing date: 2026-09-21 07:48:00 UTC
Signature algorithm: SHA-384 with ECDSA
Chain of Trust:
  1. [signer] CN=Grigory Vasilyev,L=Moscow,C=RU,UID=h0tc0d3,emailAddress=h0tc0d3@email (9355...) - verified
  2. [root] CN=Russian Trusted Root CA,O=...,C=RU (B1C4...) - trusted (CA bundle)
```

### Verify a signature made with OpenSSL

pivzavr reads a CMS/PKCS#7 signature either as binary DER or as a PEM armored
block (`-----BEGIN PKCS7-----`, `-----BEGIN CMS-----` or
`-----BEGIN SIGNED MESSAGE-----`). A signature made with `openssl cms -sign`
verifies the same way, but two defaults of `openssl cms` produce a file that
pivzavr cannot read, so both must be changed:

- `openssl cms -sign` canonicalizes the input by default, rewriting line endings
  to CRLF before it hashes the message. The signature is then made over the
  rewritten message, so verifying the original file fails with
  `cms: invalid message digest`. Sign with `-binary` to hash the message exactly
  as it is.

- The default output format of `openssl cms -sign` is S/MIME
  (`multipart/signed`), not a CMS structure. A file written without `-outform`
  is an S/MIME message, which pivzavr cannot parse. Write the signature with
  `-outform DER` for a binary signature, or `-outform PEM` for an armored one.

A detached signature over `file.pdf` is therefore made and verified as follows:

```shell
openssl cms -sign -binary -in file.pdf -signer test.crt -inkey test.key \
  -out file.pdf.p7s -outform DER
pivzavr --verify file.pdf.p7s
```

or, armored:

```shell
openssl cms -sign -binary -in file.pdf -signer test.crt -inkey test.key \
  -out file.pdf.asc -outform PEM
pivzavr --verify file.pdf.asc
```

The certificate that made the signature is still checked as described in
[Verify signature](#verify-signature): it must be trusted, its validity period
must cover the signing time and its revocation status is looked up.

## GOST support

Russian smart cards (Rutoken ECP, JaCarta) sign with GOST R 34.10-2012 and
hash with GOST R 34.11-2012 (Streebog). Both algorithms are implemented in the
`pkg/gost` package, which is self-contained and needs no cgo and no extra
dependency:

- `streebog.go` implements the 256-bit and the 512-bit Streebog hash function of
  RFC 6986. It is validated against the test vectors of RFC 6986 (both example
  messages, with their 256-bit and 512-bit hash codes) and against the
  HMAC-GOST test vectors of RFC 7836, which cover messages of several lengths,
  including a multiple of the block size. The hash codes of the empty message
  and of "The quick brown fox jumps over the lazy dog" match the published
  values.
- `curve.go` implements the elliptic curves of GOST R 34.10-2012 with a prime
  modulus in the canonical form: the 256-bit and the 512-bit parameter set A of
  RFC 7836. The generator of each curve is checked against its subgroup order,
  and the 512-bit parameters reproduce the public key that RFC 7836 derives from
  a private key. Signature verification follows Algorithm II of RFC 7091 and is
  checked against the complete example of that RFC.
- `signature.go` reads the public key of a certificate. Go's `crypto/x509` does
  not implement the GOST algorithms, so a GOST certificate parses with
  `PublicKeyAlgorithm` `UnknownPublicKeyAlgorithm` and a nil `PublicKey`; the
  key is read from `RawSubjectPublicKeyInfo` instead, where the two coordinates
  are held in little-endian byte order next to the object identifier of their
  curve.

`pivzavr --info` and `pivzavr --print` report such a key as
`GOST R 34.10-2012 256 (id-tc26-gost-3410-2012-256-paramSetA)` rather than as
an unknown key type.

**Limitation.** The signature of a GOST signer over the content of a CMS
message is verified with `pkg/gost` (see `verifyGostSignature` in `pkg/cms`), but
the certificate chain of that signature is still built and checked by Go's
`crypto/x509`, which cannot verify the signature of a certificate that a GOST
key made. A chain whose certificates are signed with GOST is therefore reported
as unsupported. Signature verification against a configured `public-key`, which
does not need a chain, is not affected.
