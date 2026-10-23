package transport

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/telesma-app/ctap/protocol"
)

func TestValidateCBORResponsePreservesSuccess(t *testing.T) {
	want := CBORResponse{StatusCode: CTAP2_OK, Data: []byte{0xa1, 0x01, 0x02}}

	got, err := ValidateCBORResponse(protocol.AuthenticatorGetInfo, want)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := got, want; got.StatusCode != want.StatusCode || ((got.Data == nil) != (want.Data == nil) || !bytes.Equal(got.Data, want.Data)) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestValidateCBORResponseReturnsTypedError(t *testing.T) {
	_, err := ValidateCBORResponse(protocol.AuthenticatorGetInfo, CBORResponse{
		StatusCode: CTAP2_ERR_INVALID_CBOR,
	})

	var ctapErr *CTAPError
	if err := err; !errors.As(err, &ctapErr) {
		t.Fatalf("error %v does not match requested type", err)
	}

	if got, want := ctapErr.Command, protocol.AuthenticatorGetInfo; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := ctapErr.StatusCode, CTAP2_ERR_INVALID_CBOR; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestIOErrorPreservesOperationAndCause(t *testing.T) {
	cause := errors.New("device disconnected")
	err := &IOError{Operation: IORead, Err: cause}

	if got, want := err.Operation, IORead; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	{
		err, want := err, "transport read: device disconnected"
		if err == nil || err.Error() != want {
			t.Errorf("got error %v, want %q", err, want)
		}
	}

	if err, target := err, cause; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	var got *IOError
	if err := err; !errors.As(err, &got) {
		t.Fatalf("error %v does not match requested type", err)
	}

	if got, want := got, err; got != want {
		t.Errorf("got pointer %p, want %p", got, want)
	}
}

func TestIOErrorPreservesTypedCause(t *testing.T) {
	err := &IOError{Operation: IOWrite, Err: io.ErrClosedPipe}

	if err, target := err, io.ErrClosedPipe; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
}

func TestDeviceInvalidatedErrorPreservesCause(t *testing.T) {
	cause := &IOError{Operation: IORead, Err: io.ErrUnexpectedEOF}
	err := &DeviceInvalidatedError{Err: cause}

	{
		err, want := err, "transport read: unexpected EOF"
		if err == nil || err.Error() != want {
			t.Errorf("got error %v, want %q", err, want)
		}
	}

	if err, target := err, io.ErrUnexpectedEOF; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	ioErr, ok := errors.AsType[*IOError](err)
	if got := ok; !got {
		t.Fatalf("got false, want true")
	}

	if got, want := ioErr, cause; got != want {
		t.Errorf("got pointer %p, want %p", got, want)
	}

	invalidatedErr, ok := errors.AsType[*DeviceInvalidatedError](err)
	if got := ok; !got {
		t.Fatalf("got false, want true")
	}

	if got, want := invalidatedErr, err; got != want {
		t.Errorf("got pointer %p, want %p", got, want)
	}
}

func TestStatusCodeName(t *testing.T) {
	name, ok := CTAP2_ERR_NOT_ALLOWED.Name()
	if !ok || name != CTAP2_ERR_NOT_ALLOWED.String() {
		t.Fatalf("known status Name() = %q, %v", name, ok)
	}

	for _, status := range []StatusCode{0x41, 0xe1, 0xf1} {
		if name, ok := status.Name(); ok || name != "" {
			t.Errorf("unknown StatusCode(0x%02x).Name() = %q, %v, want empty, false", byte(status), name, ok)
		}
	}
}
