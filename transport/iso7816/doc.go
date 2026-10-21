// Package iso7816 implements CTAP over ISO 7816.
// Select, CBOR, and Deselect borrow the card; callers serialize access and close
// it on DeviceInvalidatedError. Open returns an owned Transport.
package iso7816
