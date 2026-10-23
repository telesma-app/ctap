package token2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
)

type exchange struct {
	request  []byte
	response []byte
	err      error
	after    func()
}

type fakeCard struct {
	t          *testing.T
	exchanges  []exchange
	closeErr   error
	closed     bool
	closeCalls int
}

func (c *fakeCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	c.t.Helper()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if got := c.exchanges; len(got) == 0 {
		c.t.Fatalf("got empty value %#v, want non-empty; context: %s", got, fmt.Sprintf("unexpected APDU: %x", apdu))
	}

	next := c.exchanges[0]

	c.exchanges = c.exchanges[1:]
	if got, want := apdu, next.request; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		c.t.Errorf("got %#v, want %#v", got, want)
	}

	response := bytes.Clone(next.response)
	if next.after != nil {
		next.after()
	}

	return response, next.err
}

func (c *fakeCard) Close() error {
	c.closeCalls++
	c.closed = true

	return c.closeErr
}

func newFakeTransport(t *testing.T, exchanges ...exchange) (*Transport, *fakeCard) {
	t.Helper()
	card := &fakeCard{t: t, exchanges: append([]exchange{
		{request: []byte{0x00, 0xa4, 0x04, 0x00, 0x08, 0xf0, 0x00, 0x00, 0x01, 0x4f, 0x74, 0x70, 0x01}, response: []byte{0x61, 0x04}},
		{request: []byte{0x00, 0xc0, 0x00, 0x00, 0x04}, response: []byte{'1', '0', '0', '0', 0x90, 0x00}},
	}, exchanges...)}

	transport, err := New(context.Background(), card)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return transport, card
}

func TestCBORShortAPDU(t *testing.T) {
	transport, card := newFakeTransport(t, exchange{
		request:  []byte{0x80, 0xc5, 0x03, 0x00, 0x01, 0x04},
		response: []byte{0x00, 0xa1, 0x01, 0x02, 0x90, 0x00},
	})

	response, err := transport.CBOR(context.Background(), []byte{0x04})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       []byte{0xa1, 0x01, 0x02},
		}, response
		if got.StatusCode != want.StatusCode || ((got.Data == nil) != (want.Data == nil) || !bytes.Equal(got.Data, want.Data)) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
}

func TestCBORExtendedAPDUAndGetResponse(t *testing.T) {
	command := append([]byte{0x06}, bytes.Repeat([]byte{0xaa}, 255)...)
	wantAPDU := append([]byte{0x80, 0xc5, 0x03, 0x00, 0x00, 0x01, 0x00}, command...)
	transport, card := newFakeTransport(t,
		exchange{request: wantAPDU, response: []byte{0x00, 0xa1, 0x61, 0x02}},
		exchange{request: []byte{0x80, 0xc0, 0x00, 0x00, 0x02}, response: []byte{0x01, 0x02, 0x90, 0x00}},
	)

	response, err := transport.CBOR(context.Background(), command)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       []byte{0xa1, 0x01, 0x02},
		}, response
		if got.StatusCode != want.StatusCode || ((got.Data == nil) != (want.Data == nil) || !bytes.Equal(got.Data, want.Data)) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
}

func TestCBORReturnsTypedCTAPError(t *testing.T) {
	transport, _ := newFakeTransport(t, exchange{
		request:  []byte{0x80, 0xc5, 0x03, 0x00, 0x01, 0x04},
		response: []byte{byte(ctaptransport.CTAP2_ERR_INVALID_CBOR), 0x90, 0x00},
	})

	_, err := transport.CBOR(context.Background(), []byte{0x04})

	var ctapErr *ctaptransport.CTAPError
	if err := err; !errors.As(err, &ctapErr) {
		t.Fatalf("error %v does not match requested type", err)
	}

	if got, want := ctapErr.Command, protocol.AuthenticatorGetInfo; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := ctapErr.StatusCode, ctaptransport.CTAP2_ERR_INVALID_CBOR; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestCBORReturnsAPDUError(t *testing.T) {
	transport, _ := newFakeTransport(t, exchange{
		request:  []byte{0x80, 0xc5, 0x03, 0x00, 0x01, 0x04},
		response: []byte{0x6a, 0x82},
	})

	_, err := transport.CBOR(context.Background(), []byte{0x04})

	var apduErr *APDUError
	if err := err; !errors.As(err, &apduErr) {
		t.Fatalf("error %v does not match requested type", err)
	}

	if got, want := apduErr.SW1, byte(0x6a); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := apduErr.SW2, byte(0x82); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestNewRejectsMalformedSelectResponse(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{{
		request:  []byte{0x00, 0xa4, 0x04, 0x00, 0x08, 0xf0, 0x00, 0x00, 0x01, 0x4f, 0x74, 0x70, 0x01},
		response: []byte{0x90},
	}}}

	_, err := New(context.Background(), card)
	if err, target := err, ErrInvalidResponse; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
}

func TestCloseDelegatesToCard(t *testing.T) {
	transport, card := newFakeTransport(t)
	if err := transport.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := transport.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := card.closed; !got {
		t.Errorf("got false, want true")
	}

	if got, want := card.closeCalls, 1; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestCloseReturnsTypedIOError(t *testing.T) {
	transport, card := newFakeTransport(t)
	wantErr := errors.New("reader unavailable")
	card.closeErr = wantErr

	err := transport.Close()

	if err, target := err, wantErr; !errors.Is(err, target) {
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

	if got := card.closed; !got {
		t.Errorf("got false, want true")
	}
}

func TestNewPropagatesTransmitError(t *testing.T) {
	wantErr := errors.New("transmit failed")
	card := &fakeCard{t: t, exchanges: []exchange{{
		request: []byte{0x00, 0xa4, 0x04, 0x00, 0x08, 0xf0, 0x00, 0x00, 0x01, 0x4f, 0x74, 0x70, 0x01},
		err:     wantErr,
	}}}

	_, err := New(context.Background(), card)
	if err, target := err, wantErr; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	var ioErr *ctaptransport.IOError
	if err := err; !errors.As(err, &ioErr) {
		t.Fatalf("error %v does not match requested type", err)
	}

	if got, want := ioErr.Operation, ctaptransport.IOTransmit; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	if got := invalidated; got {
		t.Errorf("got true, want false")
	}

	if got := card.closed; got {
		t.Errorf("got true, want false; context: %s", "the caller retains ownership when initialization fails")
	}
}

func TestCBORClosesCardAfterTransmitFailure(t *testing.T) {
	wantErr := errors.New("transmit failed")
	transport, card := newFakeTransport(t, exchange{
		request: []byte{0x80, 0xc5, 0x03, 0x00, 0x01, 0x04},
		err:     wantErr,
	})

	_, err := transport.CBOR(context.Background(), []byte{0x04})

	if err, target := err, wantErr; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	var ioErr *ctaptransport.IOError
	if err := err; !errors.As(err, &ioErr) {
		t.Fatalf("error %v does not match requested type", err)
	}

	if got, want := ioErr.Operation, ctaptransport.IOTransmit; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	invalidatedErr, ok := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	if got := ok; !got {
		t.Fatalf("got false, want true")
	}

	if got, want := invalidatedErr.Err, ioErr; got != want {
		t.Errorf("got pointer %p, want %p", got, want)
	}

	if got := card.closed; !got {
		t.Errorf("got false, want true")
	}

	if err := transport.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := card.closeCalls, 1; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestCBORClosesCardAfterContextErrorFromActiveContext(t *testing.T) {
	transport, card := newFakeTransport(t, exchange{
		request: []byte{0x80, 0xc5, 0x03, 0x00, 0x01, 0x04},
		err:     context.DeadlineExceeded,
	})

	_, err := transport.CBOR(context.Background(), []byte{0x04})

	if err, target := err, context.DeadlineExceeded; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	if got := invalidated; !got {
		t.Fatalf("got false, want true")
	}

	if got := card.closed; !got {
		t.Errorf("got false, want true; context: %s", "an unrelated context error still means transmit failed")
	}
}

func TestCBORChecksContextBeforeChainedTransmit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	transport, card := newFakeTransport(t, exchange{
		request:  []byte{0x80, 0xc5, 0x03, 0x00, 0x01, 0x04},
		response: []byte{0x00, 0x61, 0x04},
		after:    cancel,
	})

	_, err := transport.CBOR(ctx, []byte{0x04})
	if err, target := err, context.Canceled; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}

	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	if got := invalidated; got {
		t.Errorf("got true, want false")
	}

	if got := card.closed; got {
		t.Errorf("got true, want false")
	}
}

func TestCBORPreservesSuccessfulResponseWhenContextIsCanceledConcurrently(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	transport, card := newFakeTransport(t, exchange{
		request:  []byte{0x80, 0xc5, 0x03, 0x00, 0x01, 0x04},
		response: []byte{0x00, 0x90, 0x00},
		after:    cancel,
	})

	response, err := transport.CBOR(ctx, []byte{0x04})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := response.StatusCode, ctaptransport.CTAP2_OK; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
}

func TestNewPreCanceledDoesNotTransmit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	card := &fakeCard{t: t}

	_, err := New(ctx, card)
	if err, target := err, context.Canceled; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
}

func TestCloseInterruptsBlockedTransmit(t *testing.T) {
	card := newBlockingCard()
	transport := &Transport{card: ioCard{Card: card}}
	resultc := make(chan error, 1)

	go func() {
		_, err := transport.CBOR(context.Background(), []byte{0x04})
		resultc <- err
	}()

	receive(t, card.started, "card transmit did not start")

	if err := transport.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := receive(t, resultc, "blocked transmit did not stop after close")
	if err, target := err, io.ErrClosedPipe; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	var ioErr *ctaptransport.IOError
	if err := err; !errors.As(err, &ioErr) {
		t.Fatalf("error %v does not match requested type", err)
	}

	if got, want := ioErr.Operation, ctaptransport.IOTransmit; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	if got := invalidated; !got {
		t.Fatalf("got false, want true")
	}
}

type blockingCard struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func newBlockingCard() *blockingCard {
	return &blockingCard{
		started: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (c *blockingCard) Transmit(ctx context.Context, _ []byte) ([]byte, error) {
	c.once.Do(func() { close(c.started) })

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
