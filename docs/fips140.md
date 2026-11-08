# FIPS 140-3 mode

[Back to the overview](../README.md).

The `fips140` package follows Go's process-wide `crypto/fips140.Enabled()` state. When enabled, the library:

- filters `MakeCredential` and `previewSign` key-generation algorithms, rejecting a request only when none remain;
- accepts ES256/384/512, ESP256/384/512, Ed25519, RS256/384/512, and PS256/384/512 for key generation;
- requires PIN/UV auth protocol 2; `Device` rejects authenticators that offer only protocol 1;
- rejects local Ed448, secp256k1, RS1, and ARKG-P256 operations; and
- performs large-blob encryption in the Go Cryptographic Module.

Signature verification also accepts generic EdDSA with an Ed25519 key. RSA public keys used locally must meet the
FIPS 186-5 modulus and public-exponent requirements.

The policy controls key-generation algorithms requested by this library and cryptography performed locally. For a
`MakeCredential` response it checks only the declared COSE algorithm, not how the external authenticator generated the
key. Concrete key parameters are checked when the library converts or verifies that key locally.

Build and test with the certified module selection:

```sh
GOFIPS140=certified go build ./...
GOFIPS140=certified go test ./...
GOFIPS140=certified GODEBUG=fips140=only go test ./...
```

Strict mode is a test aid, not the production switch. This policy does not certify the application, environment,
transport, or authenticator. The low-level `crypto/protocolone` package and `crypto.Authenticate` remain policy-free for
wire compatibility and test vectors; callers must keep their direct use outside FIPS operations.
