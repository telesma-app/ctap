package ctaphid

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
)

var transportTestCID = ChannelID{1, 2, 3, 4}

func TestOpenAllocatesChannelAndTransfersDevice(t *testing.T) {
	dev := &initOpenDevice{
		t:        t,
		cid:      transportTestCID,
		response: make(chan []byte, 1),
	}

	transport, err := Open(context.Background(), dev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := transport.init.CID, transportTestCID; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if err := transport.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := dev.closed; !got {
		t.Errorf("got false, want true")
	}
}

func TestOpenCanceledLeavesDeviceOpen(t *testing.T) {
	dev := &failedOpenDevice{}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := Open(ctx, dev)

	if err, target := err, context.Canceled; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	if got := dev.closed; got {
		t.Errorf("got true, want false")
	}
}

func TestOpenInitFailureLeavesDeviceOpen(t *testing.T) {
	dev := &failedOpenDevice{readErr: io.ErrUnexpectedEOF}

	_, err := Open(t.Context(), dev)

	if err, target := err, io.ErrUnexpectedEOF; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	var deviceErr *ctaptransport.IOError
	if err := err; !errors.As(err, &deviceErr) {
		t.Fatalf("error %v does not match requested type", err)
	}

	if got, want := deviceErr.Operation, ctaptransport.IORead; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	if got := invalidated; got {
		t.Errorf("got true, want false")
	}

	if got := dev.closed; got {
		t.Errorf("got true, want false")
	}
}

func TestOpenInitWriteFailureReturnsTypedIOError(t *testing.T) {
	dev := &failedOpenDevice{writeErr: io.ErrClosedPipe}

	_, err := Open(t.Context(), dev)

	if err, target := err, io.ErrClosedPipe; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	var ioErr *ctaptransport.IOError
	if err := err; !errors.As(err, &ioErr) {
		t.Fatalf("error %v does not match requested type", err)
	}

	if got, want := ioErr.Operation, ctaptransport.IOWrite; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	if got := invalidated; got {
		t.Errorf("got true, want false")
	}

	if got := dev.closed; got {
		t.Errorf("got true, want false")
	}
}

func TestTransportCBORPreCanceledWritesNothing(t *testing.T) {
	dev := newOrderedDevice(t)
	transport := newTestTransport(dev, transportTestCID)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := transport.CBOR(ctx, []byte{byte(protocol.AuthenticatorSelection)})
	if err, target := err, context.Canceled; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	if got := dev.writes; len(got) != 0 {
		t.Errorf("got non-empty value %#v", got)
	}
}

func TestTransportCommandsCloseDeviceAfterWriteFailure(t *testing.T) {
	tests := []struct {
		name string
		call func(*Transport) error
	}{
		{
			name: "CBOR",
			call: func(transport *Transport) error {
				_, err := transport.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorGetInfo)})
				return err
			},
		},
		{
			name: "Ping",
			call: func(transport *Transport) error {
				_, err := transport.Ping(t.Context(), []byte("ping"))
				return err
			},
		},
		{name: "Wink", call: func(transport *Transport) error { return transport.Wink(t.Context()) }},
		{name: "Lock", call: func(transport *Transport) error { return transport.Lock(t.Context(), 1) }},
		{name: "Cancel", call: func(transport *Transport) error { return transport.Cancel(t.Context()) }},
		{
			name: "Vendor",
			call: func(transport *Transport) error {
				_, err := transport.Vendor(t.Context(), CTAPHID_VENDOR_FIRST, nil)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dev := &failedOpenDevice{writeErr: io.ErrClosedPipe}
			transport := newTestTransport(dev, transportTestCID)

			err := test.call(transport)

			if err, target := err, io.ErrClosedPipe; !errors.Is(err, target) {
				t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
			}

			var ioErr *ctaptransport.IOError
			if err := err; !errors.As(err, &ioErr) {
				t.Fatalf("error %v does not match requested type", err)
			}

			if got, want := ioErr.Operation, ctaptransport.IOWrite; got != want {
				t.Errorf("got %#v, want %#v", got, want)
			}

			invalidatedErr, ok := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
			if got := ok; !got {
				t.Fatalf("got false, want true")
			}

			if got, want := invalidatedErr.Err, ioErr; got != want {
				t.Errorf("got pointer %p, want %p", got, want)
			}

			if got := dev.closed; !got {
				t.Errorf("got false, want true")
			}
		})
	}
}

func TestTransportCBORKeepsDeviceOpenAfterResponseError(t *testing.T) {
	tests := []struct {
		name      string
		command   Command
		data      []byte
		wantError error
		wantCode  Error
	}{
		{
			name:      "invalid response message",
			command:   CTAPHID_CBOR,
			wantError: ErrInvalidResponseMessage,
		},
		{
			name:      "unexpected command",
			command:   CTAPHID_PING,
			wantError: ErrUnexpectedCommand,
		},
		{
			name:     "invalid channel",
			command:  CTAPHID_ERROR,
			data:     []byte{byte(ERR_INVALID_CHANNEL)},
			wantCode: ERR_INVALID_CHANNEL,
		},
		{
			name:    "CTAP error",
			command: CTAPHID_CBOR,
			data:    []byte{byte(ctaptransport.CTAP2_ERR_INVALID_CBOR)},
		},
		{
			name:    "other CTAPHID error",
			command: CTAPHID_ERROR,
			data:    []byte{byte(ERR_INVALID_LEN)},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dev := newResponseDevice(rawResponseReport(transportTestCID, test.command, test.data))
			transport := newTestTransport(dev, transportTestCID)

			_, err := transport.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorGetInfo)})

			if test.wantError != nil {
				if err, target := err, test.wantError; !errors.Is(err, target) {
					t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
				}
			} else if test.wantCode != 0 {
				requireCTAPHIDError(t, err, test.wantCode)
			} else {
				if err == nil {
					t.Fatalf("expected an error")
				}
			}

			_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
			if got := invalidated; got {
				t.Errorf("got true, want false")
			}

			if got := dev.isClosed(); got {
				t.Errorf("got true, want false")
			}

			if err := transport.Close(); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestTransportCBORContinuesOnSameChannelAfterUnexpectedCommand(t *testing.T) {
	dev := newResponseDevice(
		rawResponseReport(transportTestCID, CTAPHID_PING, nil),
		rawResponseReport(transportTestCID, CTAPHID_CBOR, []byte{byte(ctaptransport.CTAP2_OK)}),
	)
	transport := newTestTransport(dev, transportTestCID)

	t.Cleanup(func() {
		if err := transport.Close(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	_, err := transport.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorGetInfo)})
	if err, target := err, ErrUnexpectedCommand; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	if got := dev.isClosed(); got {
		t.Errorf("got true, want false")
	}

	response, err := transport.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorGetInfo)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := response.StatusCode, ctaptransport.CTAP2_OK; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got := dev.isClosed(); got {
		t.Errorf("got true, want false")
	}
}

func TestOpenDrainsReportsForOtherChannelsBeforeAllocation(t *testing.T) {
	dev := newMultiplexedDevice(transportTestCID)
	foreignReport := make([]byte, hidPacketSize)
	foreignCID := ChannelID{5, 6, 7, 8}
	copy(foreignReport, foreignCID[:])

	foreignReport[4] = 0 // Continuation packet without an initial packet.
	dev.reads <- foreignReport

	transport, err := Open(t.Context(), dev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Cleanup(func() {
		if err := transport.Close(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	if got, want := transport.init.CID, dev.cid; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	response, err := transport.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorGetInfo)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := response.StatusCode, ctaptransport.CTAP2_OK; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestRetryChannelBusyRetriesAfterShortDelay(t *testing.T) {
	attempts := 0

	result, err := retryChannelBusy(t.Context(), func() (string, error) {
		attempts++
		if attempts == 1 {
			return "", &ErrorResponse{ErrorCode: ERR_CHANNEL_BUSY}
		}

		return "ok", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := result, "ok"; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := attempts, 2; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestRetryChannelBusyStopsWhenContextExpires(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()

	attempts := 0

	_, err := retryChannelBusy(ctx, func() (struct{}, error) {
		attempts++
		return struct{}{}, &ErrorResponse{ErrorCode: ERR_CHANNEL_BUSY}
	})

	if err, target := err, context.DeadlineExceeded; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	if got, want := attempts, 1; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestTransportCBORWritesSelectionBeforeCancel(t *testing.T) {
	dev := newOrderedDevice(t)
	transport := newTestTransport(dev, transportTestCID)
	ctx, cancel := context.WithCancel(context.Background())

	resultc := make(chan error, 1)

	go func() {
		_, err := transport.CBOR(ctx, []byte{byte(protocol.AuthenticatorSelection)})
		resultc <- err
	}()

	request := receive(t, dev.writes, "Selection request was not written")
	if got, want := request[5], byte(CTAPHID_CBOR)|INIT_PACKET_BIT; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	cancel()

	select {
	case <-dev.writes:
		t.Fatal("CANCEL was written before the Selection request completed")
	case <-time.After(50 * time.Millisecond):
	}

	close(dev.releaseRequest)

	cancelRequest := receive(t, dev.writes, "CANCEL was not written")
	if got, want := cancelRequest[5], byte(CTAPHID_CANCEL)|INIT_PACKET_BIT; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	err := receive(t, resultc, "Selection cancellation did not complete")
	if err, target := err, context.Canceled; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	if got := invalidated; got {
		t.Errorf("got true, want false")
	}

	response, err := transport.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorGetInfo)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := response.StatusCode, ctaptransport.CTAP2_OK; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestTransportCBORReportsInvalidationWhenCanceledResponseCannotBeDrained(t *testing.T) {
	dev := newCancelDrainErrorDevice()
	transport := newTestTransport(dev, transportTestCID)
	ctx, cancel := context.WithCancel(context.Background())

	resultc := make(chan error, 1)

	go func() {
		_, err := transport.CBOR(ctx, []byte{byte(protocol.AuthenticatorSelection)})
		resultc <- err
	}()

	request := receive(t, dev.writes, "Selection request was not written")
	if got, want := request[5], byte(CTAPHID_CBOR)|INIT_PACKET_BIT; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	cancel()

	cancelRequest := receive(t, dev.writes, "CANCEL was not written")
	if got, want := cancelRequest[5], byte(CTAPHID_CANCEL)|INIT_PACKET_BIT; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	err := receive(t, resultc, "Selection cancellation did not complete")
	if err, target := err, context.Canceled; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	invalidatedErr, ok := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	if got := ok; !got {
		t.Fatalf("got false, want true")
	}

	if err, target := invalidatedErr.Err, context.Canceled; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	if got := dev.isClosed(); !got {
		t.Errorf("got false, want true")
	}
}

func TestTransportCBORCancellationRequiresTerminalResponse(t *testing.T) {
	for _, test := range []struct {
		name        string
		response    []byte
		invalidated bool
	}{
		{name: "completed command", response: []byte{byte(ctaptransport.CTAP2_OK)}},
		{name: "terminal CTAP error", response: []byte{byte(ctaptransport.CTAP2_ERR_INVALID_CBOR)}},
		{name: "missing status", invalidated: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dev := newOrderedDevice(t)
			dev.response = bytes.NewReader(rawResponseMessage(t, transportTestCID, CTAPHID_CBOR, test.response))
			close(dev.releaseRequest)
			transport := newTestTransport(dev, transportTestCID)

			t.Cleanup(func() { _ = transport.Close() })

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			resultc := make(chan error, 1)

			go func() {
				_, err := transport.CBOR(ctx, []byte{byte(protocol.AuthenticatorSelection)})
				resultc <- err
			}()

			receive(t, dev.writes, "Selection request was not written")
			cancel()
			receive(t, dev.writes, "CANCEL was not written")

			err := receive(t, resultc, "cancellation did not complete")
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("CBOR = %v, want context cancellation", err)
			}

			if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); invalidated != test.invalidated {
				t.Fatalf("invalidation = %v, want %v: %v", invalidated, test.invalidated, err)
			}

			if test.invalidated {
				receive(t, transport.device.stopped, "invalidated channel reader is still running")
			} else if _, err := transport.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorGetInfo)}); err != nil {
				t.Fatalf("next CBOR = %v", err)
			}
		})
	}
}

func TestTransportCBORPreservesReadError(t *testing.T) {
	dev := &readErrorDevice{err: io.ErrUnexpectedEOF}
	transport := newTestTransport(dev, transportTestCID)

	_, err := transport.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorSelection)})

	if err, target := err, io.ErrUnexpectedEOF; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	if err, target := err, context.Canceled; errors.Is(err, target) {
		t.Fatalf("got error %v, unexpectedly matches %#v", err, target)
	}

	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	if got := invalidated; !got {
		t.Fatalf("got false, want true")
	}

	if got, want := dev.writes, 1; got != want {
		t.Errorf("got %#v, want %#v; context: %s", got, want, "an unrelated read error must not trigger CTAPHID_CANCEL")
	}

	if got := dev.closed; !got {
		t.Errorf("got false, want true")
	}
}

func TestTransportCBORDoesNotCancelForContextErrorFromActiveContext(t *testing.T) {
	for _, readErr := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(readErr.Error(), func(t *testing.T) {
			dev := &readErrorDevice{err: readErr}
			transport := newTestTransport(dev, transportTestCID)

			_, err := transport.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorSelection)})

			if err, target := err, readErr; !errors.Is(err, target) {
				t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
			}

			_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
			if got := invalidated; !got {
				t.Fatalf("got false, want true")
			}

			if got, want := dev.writes, 1; got != want {
				t.Errorf("got %#v, want %#v; context: %s", got, want, "an error unrelated to the active context must not trigger CTAPHID_CANCEL")
			}

			if got := dev.closed; !got {
				t.Errorf("got false, want true")
			}
		})
	}
}

func TestTransportCloseCancelsAndInterruptsBlockedCBOR(t *testing.T) {
	dev := newBlockingDevice()
	transport := newTestTransport(dev, transportTestCID)
	resultc := make(chan error, 1)

	go func() {
		_, err := transport.CBOR(context.Background(), []byte{byte(protocol.AuthenticatorSelection)})
		resultc <- err
	}()

	receive(t, dev.writes, "Selection request was not written")

	if err := transport.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cancelRequest := receive(t, dev.writes, "CANCEL was not written before Close")
	if got, want := cancelRequest[5], byte(CTAPHID_CANCEL)|INIT_PACKET_BIT; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	err := receive(t, resultc, "Close did not interrupt Selection")
	if err, target := err, io.ErrClosedPipe; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	var deviceErr *ctaptransport.IOError
	if err := err; !errors.As(err, &deviceErr) {
		t.Fatalf("error %v does not match requested type", err)
	}

	if got, want := deviceErr.Operation, ctaptransport.IORead; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	if got := invalidated; !got {
		t.Fatalf("got false, want true")
	}
}

func TestTransportCloseReturnsTypedIOError(t *testing.T) {
	dev := &failedOpenDevice{closeErr: io.ErrClosedPipe}
	transport := newTestTransport(dev, transportTestCID)

	err := transport.Close()

	if err, target := err, io.ErrClosedPipe; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	var ioErr *ctaptransport.IOError
	if err := err; !errors.As(err, &ioErr) {
		t.Fatalf("error %v does not match requested type", err)
	}

	if got, want := ioErr.Operation, ctaptransport.IOClose; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	if got := invalidated; got {
		t.Errorf("got true, want false")
	}

	if got := dev.closed; !got {
		t.Errorf("got false, want true")
	}
}

func TestTransportCloseInterruptsBlockedWrite(t *testing.T) {
	dev := &blockedWriteDevice{started: make(chan struct{}), closed: make(chan struct{})}
	transport := newTestTransport(dev, transportTestCID)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(func() {
		cancel()

		_ = transport.device.Close()
	})

	resultc := make(chan error, 1)

	go func() {
		_, err := transport.CBOR(ctx, []byte{byte(protocol.AuthenticatorGetInfo)})
		resultc <- err
	}()

	receive(t, dev.started, "CBOR write did not start")

	closec := make(chan error, 1)
	go func() { closec <- transport.Close() }()

	if err := receive(t, closec, "Close waited for the blocked write"); err != nil {
		t.Fatal(err)
	}

	err := receive(t, resultc, "Close did not interrupt the blocked write")
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("CBOR = %v, want closed connection", err)
	}

	ioErr, ok := errors.AsType[*ctaptransport.IOError](err)
	if !ok || ioErr.Operation != ctaptransport.IOWrite {
		t.Fatalf("CBOR = %v, want typed write error", err)
	}

	if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); !invalidated {
		t.Fatalf("CBOR = %v, want invalidation", err)
	}
}

type blockedWriteDevice struct {
	started chan struct{}
	closed  chan struct{}
}

func (d *blockedWriteDevice) Read(ctx context.Context, _ []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.closed:
		return 0, io.ErrClosedPipe
	}
}

func (d *blockedWriteDevice) Write(ctx context.Context, _ []byte) (int, error) {
	close(d.started)

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.closed:
		return 0, io.ErrClosedPipe
	}
}

func (d *blockedWriteDevice) Close() error {
	close(d.closed)
	return nil
}

type orderedDevice struct {
	response       *bytes.Reader
	responses      chan []byte
	writes         chan []byte
	releaseRequest chan struct{}
	cancelWritten  chan struct{}
	cborWrites     int
}

func newOrderedDevice(t *testing.T) *orderedDevice {
	t.Helper()

	return &orderedDevice{
		response: bytes.NewReader(rawResponseMessage(
			t,
			transportTestCID,
			CTAPHID_CBOR,
			[]byte{byte(ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL)},
		)),
		responses:      make(chan []byte, 1),
		writes:         make(chan []byte, 2),
		releaseRequest: make(chan struct{}),
		cancelWritten:  make(chan struct{}),
	}
}

func (d *orderedDevice) Read(ctx context.Context, p []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.cancelWritten:
		if d.response.Len() > 0 {
			return d.response.Read(p)
		}

		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case response := <-d.responses:
			return copy(p, response), nil
		}
	}
}

func (d *orderedDevice) Write(ctx context.Context, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	d.writes <- bytes.Clone(p)

	switch p[5] {
	case byte(CTAPHID_CBOR) | INIT_PACKET_BIT:
		d.cborWrites++
		if d.cborWrites == 1 {
			<-d.releaseRequest
		} else {
			d.responses <- rawResponseReport(
				transportTestCID,
				CTAPHID_CBOR,
				[]byte{byte(ctaptransport.CTAP2_OK)},
			)
		}
	case byte(CTAPHID_CANCEL) | INIT_PACKET_BIT:
		close(d.cancelWritten)
	}

	return len(p), nil
}

func (d *orderedDevice) Close() error { return nil }

type blockingDevice struct {
	writes        chan []byte
	closed        chan struct{}
	cancelWritten bool
	once          sync.Once
}

type cancelDrainErrorDevice struct {
	writes        chan []byte
	cancelWritten chan struct{}
	closed        chan struct{}
	closeOnce     sync.Once
}

func newCancelDrainErrorDevice() *cancelDrainErrorDevice {
	return &cancelDrainErrorDevice{
		writes:        make(chan []byte, 2),
		cancelWritten: make(chan struct{}),
		closed:        make(chan struct{}),
	}
}

func (d *cancelDrainErrorDevice) Read(ctx context.Context, _ []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.cancelWritten:
		return 0, io.ErrUnexpectedEOF
	case <-d.closed:
		return 0, io.ErrClosedPipe
	}
}

func (d *cancelDrainErrorDevice) Write(ctx context.Context, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	d.writes <- bytes.Clone(p)

	if p[5] == byte(CTAPHID_CANCEL)|INIT_PACKET_BIT {
		close(d.cancelWritten)
	}

	return len(p), nil
}

func (d *cancelDrainErrorDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}

func (d *cancelDrainErrorDevice) isClosed() bool {
	select {
	case <-d.closed:
		return true
	default:
		return false
	}
}

type readErrorDevice struct {
	err    error
	writes int
	closed bool
}

func (d *readErrorDevice) Read(_ context.Context, _ []byte) (int, error) {
	return 0, d.err
}

func (d *readErrorDevice) Write(_ context.Context, p []byte) (int, error) {
	d.writes++
	return len(p), nil
}

func (d *readErrorDevice) Close() error {
	d.closed = true
	return nil
}

type responseDevice struct {
	mu        sync.Mutex
	responses [][]byte
	reads     chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newResponseDevice(responses ...[]byte) *responseDevice {
	return &responseDevice{
		responses: responses,
		reads:     make(chan []byte, 1),
		closed:    make(chan struct{}),
	}
}

func (d *responseDevice) Read(ctx context.Context, p []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.closed:
		return 0, io.ErrClosedPipe
	case response := <-d.reads:
		return copy(p, response), nil
	}
}

func (d *responseDevice) Write(ctx context.Context, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	d.mu.Lock()

	var response []byte
	if len(d.responses) > 0 {
		response = d.responses[0]
		d.responses = d.responses[1:]
	}
	d.mu.Unlock()

	if response != nil {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-d.closed:
			return 0, io.ErrClosedPipe
		case d.reads <- bytes.Clone(response):
		}
	}

	return len(p), nil
}

func (d *responseDevice) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
	})

	return nil
}

func (d *responseDevice) isClosed() bool {
	select {
	case <-d.closed:
		return true
	default:
		return false
	}
}

func newBlockingDevice() *blockingDevice {
	return &blockingDevice{
		writes: make(chan []byte, 1),
		closed: make(chan struct{}),
	}
}

func (d *blockingDevice) Read(ctx context.Context, _ []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.closed:
		return 0, io.ErrClosedPipe
	}
}

func (d *blockingDevice) Write(_ context.Context, p []byte) (int, error) {
	d.writes <- bytes.Clone(p)

	if p[5] == byte(CTAPHID_CANCEL)|INIT_PACKET_BIT {
		d.cancelWritten = true
	}

	return len(p), nil
}

func (d *blockingDevice) Close() error {
	if !d.cancelWritten {
		return errors.New("device closed before CTAPHID_CANCEL")
	}

	d.once.Do(func() { close(d.closed) })

	return nil
}

type initOpenDevice struct {
	t        *testing.T
	cid      ChannelID
	response chan []byte
	closed   bool
}

type failedOpenDevice struct {
	readErr  error
	writeErr error
	closeErr error
	closed   bool
}

func (d *failedOpenDevice) Read(ctx context.Context, _ []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	if d.readErr != nil {
		return 0, d.readErr
	}

	return 0, io.EOF
}

func (d *failedOpenDevice) Write(ctx context.Context, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	if d.writeErr != nil {
		return 0, d.writeErr
	}

	return len(p), nil
}

func (d *failedOpenDevice) Close() error {
	d.closed = true
	return d.closeErr
}

func (d *initOpenDevice) Write(_ context.Context, p []byte) (int, error) {
	d.t.Helper()

	if got, want := len(p), hidReportPacketSize; got != want {
		d.t.Fatalf("got length %d, want %d", got, want)
	}

	if got, want := p[5], byte(CTAPHID_INIT)|INIT_PACKET_BIT; got != want {
		d.t.Errorf("got %#v, want %#v", got, want)
	}

	nonce := bytes.Clone(p[8:16])
	response := append(bytes.Clone(nonce), d.cid[:]...)

	response = append(response, 2, 1, 0, 0, byte(CAPABILITY_CBOR))
	d.response <- rawResponseMessage(d.t, BROADCAST_CID, CTAPHID_INIT, response)

	close(d.response)

	return len(p), nil
}

func (d *initOpenDevice) Read(ctx context.Context, p []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case response, ok := <-d.response:
		if !ok {
			return 0, io.EOF
		}

		return copy(p, response), nil
	}
}

func (d *initOpenDevice) Close() error {
	d.closed = true
	return nil
}
