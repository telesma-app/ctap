package iso7816

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	ctaptransport "github.com/telesma-app/ctap/transport"
	baseiso7816 "github.com/telesma-app/iso7816"
)

var (
	selectAPDU = []byte{0x00, 0xa4, 0x04, 0x00, 0x08, 0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01, 0x00}
	cborAPDU   = []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00}
	endAPDU    = []byte{0x80, 0x12, 0x01, 0x00}
	fidoReply  = []byte{'F', 'I', 'D', 'O', '_', '2', '_', '0', 0x90, 0x00}
)

func newFakeTransport(t *testing.T, exchanges ...exchange) (*Transport, *fakeCard) {
	t.Helper()
	card := &fakeCard{t: t, exchanges: append([]exchange{{request: selectAPDU, response: fidoReply}}, exchanges...)}

	transport, err := Open(t.Context(), card)
	if err != nil {
		t.Fatal(err)
	}

	return transport, card
}

func TestOpenFailureLeavesCardOwnedByCaller(t *testing.T) {
	for _, test := range []exchange{
		{response: []byte{0x6a, 0x82}},
		{response: []byte{0x90}},
		{response: []byte{'X', 0x90, 0x00}},
		{err: io.ErrClosedPipe},
	} {
		test.request = selectAPDU
		card := &fakeCard{t: t, exchanges: []exchange{test}}

		transport, err := Open(t.Context(), card)
		if transport != nil || err == nil {
			t.Fatalf("Open = %v, %v; want failed initialization", transport, err)
		}

		if test.err != nil && !errors.Is(err, test.err) {
			t.Fatalf("initialization error was lost: %v", err)
		}

		if card.closeCalls != 0 {
			t.Fatalf("Close calls = %d, want 0", card.closeCalls)
		}
	}
}

func TestOpenCancellationLeavesCardOwnedByCaller(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	card := &fakeCard{t: t, exchanges: []exchange{{request: selectAPDU, err: context.Canceled, after: cancel}}}
	if _, err := Open(ctx, card); !errors.Is(err, context.Canceled) {
		t.Fatalf("Open = %v, want context cancellation", err)
	}

	if card.closeCalls != 0 {
		t.Fatalf("Close calls = %d, want 0", card.closeCalls)
	}
}

func TestCloseEndsSessionAndClosesCardOnce(t *testing.T) {
	transport, card := newFakeTransport(t,
		exchange{request: cborAPDU, response: []byte{0x00, 0xa0, 0x90, 0x00}},
		exchange{request: cborAPDU, response: []byte{0x00, 0xa0, 0x90, 0x00}},
		exchange{request: endAPDU, response: []byte{0x90, 0x00}},
	)
	for range 2 {
		if _, err := transport.CBOR(t.Context(), []byte{0x04}); err != nil {
			t.Fatal(err)
		}
	}

	for range 2 {
		if err := transport.Close(); err != nil {
			t.Fatal(err)
		}
	}

	if card.closeCalls != 1 || len(card.exchanges) != 0 {
		t.Fatalf("Close calls = %d, remaining APDUs = %d", card.closeCalls, len(card.exchanges))
	}
}

func TestCloseReturnsTypedIOError(t *testing.T) {
	transport, card := newFakeTransport(t, exchange{request: endAPDU, response: []byte{0x90, 0x00}})
	card.closeErr = errors.New("reader unavailable")
	err := transport.Close()

	ioErr, ok := errors.AsType[*ctaptransport.IOError](err)
	if !ok || ioErr.Operation != ctaptransport.IOClose || !errors.Is(err, card.closeErr) {
		t.Fatalf("Close = %v, want typed close error", err)
	}

	if card.closeCalls != 1 {
		t.Fatalf("Close calls = %d, want 1", card.closeCalls)
	}
}

func TestCloseClosesCardWhenEndSessionFails(t *testing.T) {
	for _, test := range []exchange{
		{response: []byte{0x6a, 0x86}},
		{err: io.ErrClosedPipe},
	} {
		test.request = endAPDU
		transport, card := newFakeTransport(t, test)

		err := transport.Close()
		if test.err != nil {
			if !errors.Is(err, test.err) {
				t.Fatalf("Close = %v, want %v", err, test.err)
			}
		} else {
			apduErr, ok := errors.AsType[*baseiso7816.APDUError](err)
			if !ok || apduErr.SW1 != 0x6a || apduErr.SW2 != 0x86 {
				t.Fatalf("Close = %v, want status 6a86", err)
			}
		}

		if card.closeCalls != 1 || len(card.exchanges) != 0 {
			t.Fatalf("Close calls = %d, remaining APDUs = %d", card.closeCalls, len(card.exchanges))
		}
	}
}

func TestCBORClosesCardAfterTransmitFailure(t *testing.T) {
	transport, card := newFakeTransport(t, exchange{request: cborAPDU, err: io.ErrClosedPipe})

	_, err := transport.CBOR(t.Context(), []byte{0x04})
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("CBOR = %v, want I/O failure", err)
	}

	if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); !invalidated {
		t.Fatalf("CBOR = %v, want invalidation", err)
	}

	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}

	if card.closeCalls != 1 {
		t.Fatalf("Close calls = %d, want 1", card.closeCalls)
	}
}

func TestCBORClosesCardAfterInterruptedChaining(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	data := bytes.Repeat([]byte{0xaa}, 241)
	data[0] = 0x01
	transport, card := newFakeTransport(t, exchange{
		request:  append([]byte{0x90, 0x10, 0x00, 0x00, 0xf0}, data[:240]...),
		response: []byte{0x90, 0x00},
		after:    cancel,
	})

	_, err := transport.CBOR(ctx, data)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CBOR = %v, want context cancellation", err)
	}

	if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); !invalidated {
		t.Fatal("interrupted command did not invalidate the device")
	}

	if card.closeCalls != 1 {
		t.Fatal("CBOR returned without closing the invalidated card")
	}

	if _, err := transport.CBOR(t.Context(), []byte{0x04}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("next CBOR = %v, want closed connection", err)
	}

	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}

	if card.closeCalls != 1 || len(card.exchanges) != 0 {
		t.Fatalf("closes = %d, remaining APDUs = %d", card.closeCalls, len(card.exchanges))
	}
}

func TestCBORPreservesCardAfterProtocolError(t *testing.T) {
	transport, card := newFakeTransport(t,
		exchange{request: cborAPDU, response: []byte{byte(ctaptransport.CTAP1_ERR_INVALID_COMMAND), 0x90, 0x00}},
		exchange{request: endAPDU, response: []byte{0x90, 0x00}},
	)

	_, err := transport.CBOR(t.Context(), []byte{0x04})
	if _, ok := errors.AsType[*ctaptransport.CTAPError](err); !ok {
		t.Fatalf("CBOR = %v, want CTAP error", err)
	}

	if card.closeCalls != 0 {
		t.Fatal("protocol error closed card")
	}

	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCBORProtocolCancellation(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())

		cancelReply := []byte{0x6a, 0x86}
		if accepted {
			cancelReply = []byte{byte(ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL), 0x90, 0x00}
		}

		transport, card := newFakeTransport(t,
			exchange{request: cborAPDU, response: []byte{0x02, 0x91, 0x00}, after: cancel},
			exchange{request: []byte{0x80, 0x11, 0x11, 0x00, 0x00}, response: cancelReply},
		)
		_, err := transport.CBOR(ctx, []byte{0x04})

		cancel()

		if !errors.Is(err, context.Canceled) {
			t.Fatalf("CBOR = %v, want context cancellation", err)
		}

		_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
		if invalidated == accepted || (card.closeCalls != 0) == accepted {
			t.Fatalf("accepted = %v, invalidated = %v, Close calls = %d", accepted, invalidated, card.closeCalls)
		}

		if accepted {
			card.exchanges = append(card.exchanges, exchange{request: endAPDU, response: []byte{0x90, 0x00}})
		}

		if err := transport.Close(); err != nil {
			t.Fatal(err)
		}

		if card.closeCalls != 1 || len(card.exchanges) != 0 {
			t.Fatalf("Close calls = %d, remaining APDUs = %d", card.closeCalls, len(card.exchanges))
		}
	}
}

func TestCloseInterruptsBlockedTransmit(t *testing.T) {
	card := &blockingCard{t: t, started: make(chan struct{}), closed: make(chan struct{})}

	transport, err := Open(t.Context(), card)
	if err != nil {
		t.Fatal(err)
	}

	resultc := make(chan error, 1)

	go func() {
		_, err := transport.CBOR(t.Context(), []byte{0x04})
		resultc <- err
	}()

	receive(t, card.started, "card transmit did not start")

	closec := make(chan error, 1)
	go func() { closec <- transport.Close() }()

	if err := receive(t, closec, "Close waited for the blocked CBOR"); err != nil {
		t.Fatal(err)
	}

	err = receive(t, resultc, "blocked transmit did not stop after Close")

	ioErr, ok := errors.AsType[*ctaptransport.IOError](err)
	if !ok || ioErr.Operation != ctaptransport.IOTransmit || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("CBOR = %v, want typed I/O failure", err)
	}

	if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); !invalidated {
		t.Fatalf("CBOR = %v, want invalidation", err)
	}

	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
}

type blockingCard struct {
	t       *testing.T
	started chan struct{}
	closed  chan struct{}
}

func (c *blockingCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	if bytes.Equal(apdu, selectAPDU) {
		return fidoReply, nil
	}

	if !bytes.Equal(apdu, cborAPDU) {
		c.t.Errorf("APDU = %x, want CBOR; Close must skip END during a command", apdu)
	}

	close(c.started)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, io.ErrClosedPipe
	}
}

func (c *blockingCard) Close() error {
	close(c.closed)
	return nil
}

func receive[T any](t testing.TB, ch <-chan T, message string) T {
	t.Helper()

	select {
	case value := <-ch:
		return value
	case <-time.After(time.Second):
		t.Fatal(message)

		var zero T

		return zero
	}
}
