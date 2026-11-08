# telesma-app/ctap

[![Go Reference](https://pkg.go.dev/badge/github.com/telesma-app/ctap.svg)](https://pkg.go.dev/github.com/telesma-app/ctap)
[![Go](https://github.com/telesma-app/ctap/actions/workflows/go.yml/badge.svg)](https://github.com/telesma-app/ctap/actions/workflows/go.yml)

`telesma-app/ctap` is a Go library for direct communication with FIDO2 authenticators. It provides both CTAP commands and a
stateful API for common authenticator workflows.

> [!WARNING]
> This module is under active development. Its public API may change during `v0.x`.

This is not a WebAuthn server library. The `webauthn` package contains only the WebAuthn types needed by this project.

## Features

The library supports CTAP 2.0 through CTAP 2.3. CTAP 2.3 follows the
[February 2026 Proposed Standard](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html).
Available features depend on the capabilities reported by each authenticator.

Main features include:

- credential creation and assertion;
- PIN and built-in user verification (UV);
- credential management and biometric enrollment;
- authenticator configuration and reset;
- legacy and CTAP 2.3 large-blob storage;
- `encIdentifier` and `encCredStoreState` decryption;
- PIN/UV Auth Protocols One and Two;
- format-level attestation-object parsing and packed/FIDO U2F signature verification;
- the `credProtect`, `credBlob`, `largeBlobKey`, `largeBlob`, `minPinLength`, `pinComplexityPolicy`, `hmac-secret`,
  `hmac-secret-mc`, `thirdPartyPayment`, WebAuthn `prf`, and draft `previewSign` extensions.

See the [Go API reference](https://pkg.go.dev/github.com/telesma-app/ctap) for command and type details.

Contributors adding or changing tests should follow the [testing guide](TESTING.md).

### Hardware testing

Automated tests cover the implemented protocol, validation, and state changes. Physical testing covers:

| Authenticator                       | Firmware | Tested connection and protocol                                |
|-------------------------------------|---------:|---------------------------------------------------------------|
| YubiKey 5 Series, FIPS and non-FIPS |    5.7.4 | USB HID and the advertised CTAP 2.1 features                  |
| YubiKey 5 Series RC                 |   5.8 RC | USB HID and a `previewSign` create/sign round trip            |
| Token2 PIN+ Dual                    |     R3.3 | USB HID, CTAP over APDU, and the advertised CTAP 2.1 features |

CTAP 2.2 and 2.3 features not named in the table are based on the specification and automated tests. A feature listed
above may still be unavailable on a specific device.

## Transports

| Transport             | Setup                                                                                                                                                |
|-----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| USB HID               | Uses the cgo-free [`telesma-app/hid`](https://github.com/telesma-app/hid) backend                                                                    |
| TCP CTAPHID stream    | Connects emulators and proxies that expose a stream of complete 64-byte CTAPHID reports; this is not a FIDO transport                                |
| Windows named pipe    | Connects to a running [`telesma-app/windows-proxy`](https://github.com/telesma-app/windows-proxy); see [`examples/namedpipe`](examples/namedpipe)    |
| ISO 7816 / NFC        | PC/SC via `backend/pcsc` or a custom APDU connection; see [`examples/iso7816`](examples/iso7816) |
| Token2 CTAP over APDU | Requires a PC/SC implementation such as [`telesma-app/pcsc`](https://github.com/telesma-app/pcsc); see [`examples/token2`](examples/token2)          |
| Bluetooth LE          | Experimental cgo-free CoreBluetooth backend for FIDO authenticators on macOS amd64/arm64; see [`examples/ble`](examples/ble)                         |

Hybrid and digital-credential transports are not supported. BLE and Token2 support are experimental; the Token2 protocol
is not publicly documented by the vendor.

## Installation

```sh
go get github.com/telesma-app/ctap@latest
```

See [`go.mod`](go.mod) for the required Go version.

## Quick start

Transport adapters enumerate initialized CTAP connections. The authenticator
package builds transport-independent devices and selects one by user presence.
Long-lived discovery and automatic selection belong in an application runtime
such as `telesma-app/kit`.

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/telesma-app/ctap/authenticator"
	directhid "github.com/telesma-app/ctap/backend/hid"
)

func main() {
	ctx := context.Background()
	device, err := authenticator.Select(ctx, directhid.Enumerate)
	if err != nil {
		log.Fatal(err)
	}
	defer device.Close()

	info, err := device.GetInfo(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("versions: %v\nAAGUID: %s\n", info.Versions, info.AAGUID)
}
```

`authenticator.Select` accepts a `backend.Enumerator`, initializes every
reported authenticator, and returns the one that confirms user presence. It
closes every other enumerated device. Direct HID, Windows named pipe, standard
PC/SC, and Token2 expose the same enumerator contract.

## API levels

| Package                                                                                           | Use it for                                                                          |
|---------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| `authenticator`                                                                                   | Stateful workflows, capability checks, PIN/UV handling, and user-presence selection |
| `client`                                                                                          | Sending individual CTAP commands and managing state yourself                        |
| `backend/ble`, `backend/hid`, `backend/hidproxy`, `backend/pcsc`, `backend/tcp`, `backend/token2` | Finding and opening local authenticator endpoints                                   |
| `transport`, `transport/ctapble`, `transport/ctaphid`, `transport/iso7816`, `transport/token2`    | CTAP message boundaries and transport framing                                       |
| `protocol`, `credential`, `attestation`, `extension`, `webauthn`                                  | CTAP constants and data types                                                       |
| `crypto`                                                                                          | Cryptographic helpers                                                               |
| `fips140`                                                                                         | Querying the CTAP FIPS 140-3 policy and matching policy rejections                  |

For a custom transport, implement `transport.Device` and pass it to `authenticator.New`.
Yubico-specific device information and identity operations live in
[`telesma-app/yubico`](https://github.com/telesma-app/yubico).

## PIN and user verification

`authenticator.Device` checks the device capabilities before it starts a workflow. It selects the preferred
PIN/UV protocol and uses permission-based tokens when supported. On older devices, it can use the legacy token flow.

Request only the permissions required by the next commands. Include an RP ID when requesting
`PermissionMakeCredential` or `PermissionGetAssertion`:

```go
token, err := device.GetPinUvAuthTokenUsingPIN(
	ctx,
	pin,
	protocol.PermissionMakeCredential,
	"example.com",
)
```

PIN/UV tokens are secrets. Do not log or store them, and discard them after use. Some configuration and large-blob
operations may work without a token on an authenticator that has no PIN or UV protection.

## FIPS 140-3 mode

The `fips140` package follows Go's process-wide `crypto/fips140.Enabled()` state
and applies the library's algorithm and PIN/UV policy. See the
[FIPS guide](docs/fips140.md) for accepted algorithms, certified-module build
commands and policy limits. This policy does not certify the application or
authenticator.

## Usage notes

- Always close `authenticator.Device`. It owns the transport and runs one command at a time.
- `Device.GetInfo(ctx)` always sends `authenticatorGetInfo` and returns the current device data. The response is also
  cached for capability checks; known state changes invalidate it, and the next check refreshes it lazily.
- Finish assertion and credential-management iterators before sending another command.
- Match CTAP errors as `*transport.CTAPError`, standard status-word errors as `*iso7816.APDUError` from
  [`telesma-app/iso7816`](https://github.com/telesma-app/iso7816), and Token2 status-word errors as
  `*token2.APDUError`.
- Device I/O accepts `context.Context`. Cancellation depends on transport support.
- `ctaphid.Open` and `iso7816.Open` take ownership on success; callers retain ownership on failure.
- `ctaphid.Transport.InitResponse()` returns the cached INIT response without I/O.
- `iso7816.Select`, `CBOR`, and `Deselect` borrow a card. The caller serializes access and closes it on
  `transport.DeviceInvalidatedError`.

## Diagnostic logging

Pass a `diagnostic.Sink` with `options.WithDiagnosticSink` to receive typed,
redacted CTAP exchange events. The [diagnostic logging guide](docs/diagnostics.md)
describes CBOR notation, redaction and callback behavior. Records may retain
identifiers and unredacted unknown or vendor-defined fields; treat them as
sensitive data.

## Examples

Each example is a separate Go module.

| Example                                        | Purpose                                                            | Configuration                                   |
|------------------------------------------------|--------------------------------------------------------------------|-------------------------------------------------|
| [`examples/pin`](examples/pin)                 | List credentials with a PIN                                        | `FIDO2_PIN`                                     |
| [`examples/uv`](examples/uv)                   | List biometric enrollments and credentials with built-in UV        | None                                            |
| [`examples/iso7816`](examples/iso7816)         | Read authenticator information from a standard FIDO smart card     | Optional `PCSC_READER`                          |
| [`examples/token2`](examples/token2)           | List credentials through Token2 and PC/SC                          | `FIDO2_PIN`, optional `PCSC_READER`             |
| [`examples/namedpipe`](examples/namedpipe)     | Ping and list credentials through the Windows proxy                | `FIDO2_PIN`, running proxy                      |
| [`examples/transports`](examples/transports)   | Print `authenticatorGetInfo` for every transport                   | Optional Windows proxy and PC/SC service        |
| [`examples/ble`](examples/ble)                 | Scan BLE authenticators and print `authenticatorGetInfo`           | Optional `-scan` and `-id` flags                |
| [`examples/previewsign`](examples/previewsign) | Create a previewSign key, sign a message, and verify the signature | Optional `FIDO2_PIN`, previewSign authenticator |

Run an example from its directory:

```sh
cd examples/pin
FIDO2_PIN=123456 go run .
```

In PowerShell, set the variable first: `$env:FIDO2_PIN = "123456"`.

The [BLE example guide](examples/ble/README.md) covers scanning, device
selection and macOS Bluetooth authorization.

## Development

```sh
GOWORK=off go test ./...
GOWORK=off go vet ./...
make lint
```

The default test suite does not require hardware. See [TESTING.md](TESTING.md)
for test conventions, separate example modules and opt-in hardware checks.

## License

[Apache License 2.0](LICENSE).

## References

- [Client to Authenticator Protocol 2.0, Proposed Standard](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- [Client to Authenticator Protocol 2.1, Proposed Standard with errata](https://fidoalliance.org/specs/fido-v2.1-ps-20220621/ctap-2.1-spec-plus-errata-v2.1-ps-20220621.html)
- [Client to Authenticator Protocol 2.2, Proposed Standard](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html)
- [Client to Authenticator Protocol 2.3, Proposed Standard](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html)
- [FIDO Registry of Predefined Values 2.3, Proposed Standard](https://fidoalliance.org/specs/common-specs/fido-registry-v2.3-ps-20260105.html)
- [Web Authentication: An API for accessing Public Key Credentials — Level 3](https://www.w3.org/TR/webauthn-3/)
- [Yubico Signing Extension Preview for YubiKey firmware 5.8+](https://developers.yubico.com/Passkeys/Passkey_concepts/Security_key_capabilities/Signing_Extension_Preview.html)
- [WebAuthn Signing Extension, Draft Version 4](https://yubicolabs.github.io/webauthn-sign-extension/4/)
- [The Asynchronous Remote Key Generation (ARKG) Algorithm, Internet-Draft 11](https://datatracker.ietf.org/doc/html/draft-bradleylundberg-cfrg-arkg-11)
- [COSE Algorithms for Two-Party Signing, Internet-Draft 05](https://datatracker.ietf.org/doc/html/draft-lundberg-cose-two-party-signing-algs-05)
- [IANA WebAuthn Registries](https://www.iana.org/assignments/webauthn/webauthn.xhtml)
- [IANA CBOR Object Signing and Encryption (COSE) Registries](https://www.iana.org/assignments/cose/cose.xhtml)
