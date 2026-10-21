// Package transport defines the transport-independent CTAP message boundary.
package transport

import (
	"context"
	"errors"
	"io"

	"github.com/telesma-app/ctap/protocol"
)

// CBORResponse is a transport-independent CTAP response.
type CBORResponse struct {
	StatusCode StatusCode
	Data       []byte
}

// ValidateCBORResponse returns a typed CTAP error for a non-success response.
func ValidateCBORResponse(command protocol.Command, response CBORResponse) (CBORResponse, error) {
	if response.StatusCode != CTAP2_OK {
		return CBORResponse{}, &CTAPError{Command: command, StatusCode: response.StatusCode}
	}

	return response, nil
}

// CTAPError reports a non-success status returned by an authenticator command.
type CTAPError struct {
	Command    protocol.Command
	StatusCode StatusCode
}

func (e *CTAPError) Error() string {
	return e.Command.String() + " failed (" + e.StatusCode.String() + ")"
}

func (e *CTAPError) Unwrap() error {
	return errors.New(e.StatusCode.String())
}

// IOOperation identifies the underlying transport operation which failed.
type IOOperation string

const (
	IORead     IOOperation = "read"
	IOWrite    IOOperation = "write"
	IOTransmit IOOperation = "transmit"
	IOClose    IOOperation = "close"
)

// IOError wraps a connection error and identifies the failed operation.
type IOError struct {
	Operation IOOperation
	Err       error
}

func (e *IOError) Error() string {
	return "transport " + string(e.Operation) + ": " + e.Err.Error()
}

func (e *IOError) Unwrap() error {
	return e.Err
}

// DeviceInvalidatedError marks a connection that must not be reused.
// Owned transports close it before returning; callers must close borrowed connections.
type DeviceInvalidatedError struct {
	Err error
}

func (e *DeviceInvalidatedError) Error() string {
	return e.Err.Error()
}

func (e *DeviceInvalidatedError) Unwrap() error {
	return e.Err
}

// CBOR exchanges one CTAP command byte followed by its CBOR payload.
// Implementations return a CTAPError when the authenticator status is not OK.
type CBOR interface {
	CBOR(ctx context.Context, data []byte) (CBORResponse, error)
}

// Device is an owned CTAP connection.
// Close must be safe alongside CBOR and should unblock it.
type Device interface {
	CBOR
	io.Closer
}
