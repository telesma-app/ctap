# Testing guide

Tests in this repository are organized by the contract they exercise, not by
the implementation function they happen to call.

## Test boundaries

- Unit tests exercise validation, selection, parsing, and state transitions
  without device I/O.
- Wire tests assert the exact CTAP or CTAPHID command, encoded field presence
  and omission, decoded values, status codes, and typed errors.
- Integration tests exercise several layers together through a package-local
  fake transport or device. Tests requiring physical hardware stay outside the
  automated suite and are documented in `README.md`.

Keep arrange, act, and assert phases visually distinct. Use `require` for
preconditions whose failure makes the rest of a test unsafe or meaningless,
and `assert` for independent observations of the result.

## Tables and names

Use a table only when every case describes the same contract and follows the
same setup and assertion path. Case names should describe the condition and
expected outcome, for example `missing token/rejected before I/O`. Do not put
unrelated commands, protocol oracles, malformed-wire cases, and concurrency
sequences into one table merely because their Go shape is similar.

Every migrated scenario must retain its inputs and observable expectations.
In particular, preserve exact wire fields, `errors.Is` and `errors.As` checks,
cache or close state, and assertions that validation performs no I/O.

## Helpers and fixtures

Helpers are package-local, narrow, and live in `test_helpers_test.go` when they
are shared by multiple test files. A helper must:

- accept `testing.TB` where practical and call `Helper()` immediately;
- express protocol setup or an assertion rather than reproduce production
  control flow;
- return fresh mutable slices and maps on every call;
- avoid package-level mutable state and hidden ordering dependencies.

Keep stateful cryptographic, blocking, multiplexing, and cancellation fakes
beside the tests whose behavior they model. Prefer several small domain fakes
over a universal mock with switches for unrelated protocols.

## Concurrency

No test may wait indefinitely on a channel, goroutine, or device operation.
Use a bounded receive helper with a useful timeout diagnostic and register
cleanup for goroutines and devices at construction time. Avoid `t.Parallel()`
when a test owns goroutines or shared fake state. Assertions should verify
close and cancellation ordering directly instead of relying on sleeps.

Before submitting test changes, run the focused package tests, then:

```sh
gofmt -l .
go vet ./...
go test ./...
```

For changes to transport concurrency, also run the race/stress command
documented in the relevant change plan.

## Lint

Install [golangci-lint v2](https://golangci-lint.run/docs/welcome/install/local/)
built with a Go version compatible with `go.mod`, then run:

```sh
make lint
```

This runs the standard linters and `wsl_v5` with its default settings against
the root module, including tests. Examples are separate modules; run
`golangci-lint run ./...` from an example directory to lint it.

## Opt-in BLE hardware test

The BLE hardware test is excluded from normal runs. On macOS, grant Bluetooth
permission to the terminal and make the FIDO authenticator available for
pairing, then run:

```sh
CTAP_BLE_TEST=1 go test ./backend/ble -run TestHardwareGetInfo -v
```

The transport relies on macOS to establish an encrypted link when it accesses
the protected FIDO GATT characteristics. The first run may therefore display a
system pairing prompt; an existing bond is reused without another prompt.

If more than one FIDO BLE authenticator is advertising, select one by its
opaque CoreBluetooth identifier:

```sh
CTAP_BLE_TEST=1 CTAP_BLE_DEVICE_ID=01234567-89AB-CDEF-0123-456789ABCDEF \
  go test ./backend/ble -run TestHardwareGetInfo -v
```
