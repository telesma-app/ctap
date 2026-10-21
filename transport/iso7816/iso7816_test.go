package iso7816

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	baseiso7816 "github.com/telesma-app/iso7816"
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
	closeCalls int
}

func (c *fakeCard) Transmit(_ context.Context, apdu []byte) ([]byte, error) {
	c.t.Helper()
	if c.closeCalls != 0 {
		return nil, io.ErrClosedPipe
	}
	if len(c.exchanges) == 0 {
		c.t.Fatalf("unexpected APDU: %x", apdu)
	}
	next := c.exchanges[0]
	c.exchanges = c.exchanges[1:]
	if got, want := apdu, next.request; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		c.t.Errorf("got %#v, want %#v", got, want)
	}
	if next.after != nil {
		next.after()
	}
	return next.response, next.err
}

func (c *fakeCard) Close() error {
	c.closeCalls++
	return c.closeErr
}

func newSelectedCard(t *testing.T, exchanges ...exchange) *fakeCard {
	t.Helper()
	card := &fakeCard{t: t, exchanges: append([]exchange{{
		request:  commandBytes(t, selectAppletCommand),
		response: append([]byte(protocol.FIDO_2_0), 0x90, 0x00),
	}}, exchanges...)}

	_, err := Select(t.Context(), card)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(func() {
		if card.closeCalls != 0 {
			t.Errorf("borrowed card closed %d times", card.closeCalls)
		}
	})
	return card
}

func commandBytes(t testing.TB, command baseiso7816.Command) []byte {
	t.Helper()
	apdu, err := command.MarshalBinary()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return apdu
}

func TestCTAP23ControlCommands(t *testing.T) {
	{
		want, got := []byte{0x80, 0x11, 0x00, 0x00, 0x00}, commandBytes(t, getResponseCommand)
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := []byte{0x80, 0x11, 0x11, 0x00, 0x00}, commandBytes(t, cancelGetResponseCommand)
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := []byte{0x80, 0x12, 0x01, 0x00}, commandBytes(t, deselectAppletCommand)
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestSelectReturnsAdvertisedVersion(t *testing.T) {
	for _, want := range []protocol.Version{protocol.FIDO_2_0, protocol.U2F_V2} {
		card := &fakeCard{t: t, exchanges: []exchange{{
			request:  commandBytes(t, selectAppletCommand),
			response: append([]byte(want), 0x90, 0x00),
		}}}
		got, err := Select(t.Context(), card)
		if err != nil || got != want {
			t.Fatalf("Select = %q, %v; want %q", got, err, want)
		}
		if len(card.exchanges) != 0 || card.closeCalls != 0 {
			t.Fatalf("remaining APDUs = %d, closes = %d", len(card.exchanges), card.closeCalls)
		}
	}
}

func TestSelectReassemblesChainedSelectionResponse(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{
		{request: commandBytes(t, selectAppletCommand), response: []byte("FIDO_"), err: nil},
	}}
	card.exchanges[0].response = append(card.exchanges[0].response, 0x61, 0x03)
	card.exchanges = append(card.exchanges, exchange{
		request:  []byte{0x00, 0xc0, 0x00, 0x00, 0x03},
		response: []byte{'2', '_', '0', 0x90, 0x00},
	})

	_, err := Select(t.Context(), card)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSelectRejectsUnsupportedSelectionVersion(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{{
		request:  commandBytes(t, selectAppletCommand),
		response: append([]byte("OTHER"), 0x90, 0x00),
	}}}

	_, err := Select(t.Context(), card)

	if err, target := err, ErrUnsupportedVersion; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
	if card.closeCalls != 0 {
		t.Error("Select closed the borrowed card")
	}
}

func TestCBORShortAPDU(t *testing.T) {
	card := newSelectedCard(t, exchange{
		request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		response: []byte{0x00, 0xa1, 0x01, 0x02, 0x90, 0x00},
	})

	response, err := CBOR(context.Background(), card, []byte{0x04})

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

func TestCBORUsesShortCommandChaining(t *testing.T) {
	command := append([]byte{0x01}, bytes.Repeat([]byte{0xaa}, 249)...)
	card := newSelectedCard(t,
		exchange{
			request: slices.Concat(
				[]byte{0x90, 0x10, 0x00, 0x00, 0xf0},
				command[:shortCommandFragmentSize],
			),
			response: []byte{0x90, 0x00},
		},
		exchange{
			request: slices.Concat(
				[]byte{0x80, 0x10, 0x80, 0x00, 0x0a},
				command[shortCommandFragmentSize:],
				[]byte{0x00},
			),
			response: []byte{0x00, 0x90, 0x00},
		},
	)

	response, err := CBOR(context.Background(), card, command)

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

func TestCBORReassemblesISOResponseChaining(t *testing.T) {
	card := newSelectedCard(t,
		exchange{
			request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
			response: []byte{0x00, 0xa1, 0x61, 0x02},
		},
		exchange{
			request:  []byte{0x80, 0xc0, 0x00, 0x00, 0x02},
			response: []byte{0x01, 0x9f, 0x01},
		},
		exchange{
			request:  []byte{0x80, 0xc0, 0x00, 0x00, 0x01},
			response: []byte{0x02, 0x90, 0x00},
		},
	)

	response, err := CBOR(context.Background(), card, []byte{0x04})

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

func TestCBORPollsStatusResponses(t *testing.T) {
	card := newSelectedCard(t,
		exchange{
			request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
			response: []byte{0x01, 0x91, 0x00},
		},
		exchange{
			request:  commandBytes(t, getResponseCommand),
			response: []byte{0x02, 0x91, 0x00},
		},
		exchange{
			request:  commandBytes(t, getResponseCommand),
			response: []byte{0x00, 0xa0, 0x90, 0x00},
		},
	)

	response, err := CBOR(context.Background(), card, []byte{0x04})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       []byte{0xa0},
		}, response
		if got.StatusCode != want.StatusCode || ((got.Data == nil) != (want.Data == nil) || !bytes.Equal(got.Data, want.Data)) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
}

func TestCBORCancelsStatusPollingWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	card := newSelectedCard(t,
		exchange{
			request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
			response: []byte{0x02, 0x91, 0x00},
			after:    cancel,
		},
		exchange{
			request:  commandBytes(t, cancelGetResponseCommand),
			response: []byte{byte(ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL), 0x90, 0x00},
		},
	)

	_, err := CBOR(ctx, card, []byte{0x04})

	if err, target := err, context.Canceled; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
}

func TestCBORInvalidatesSessionWhenStatusCancellationIsRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	card := newSelectedCard(t,
		exchange{
			request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
			response: []byte{0x02, 0x91, 0x00},
			after:    cancel,
		},
		exchange{
			request:  commandBytes(t, cancelGetResponseCommand),
			response: []byte{0x6a, 0x86},
		},
	)

	_, err := CBOR(ctx, card, []byte{0x04})

	if err, target := err, context.Canceled; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	if got := invalidated; !got {
		t.Fatalf("got false, want true")
	}
	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
}

func TestCBORPreservesFinalResponseWhenContextIsCanceledConcurrently(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	card := newSelectedCard(t, exchange{
		request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		response: []byte{0x00, 0xa0, 0x90, 0x00},
		after:    cancel,
	})

	response, err := CBOR(ctx, card, []byte{0x04})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := response.StatusCode, ctaptransport.CTAP2_OK; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	{
		want, got := []byte{0xa0}, response.Data
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
}

func TestCBORReturnsTypedCTAPError(t *testing.T) {
	card := newSelectedCard(t, exchange{
		request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		response: []byte{byte(ctaptransport.CTAP2_ERR_INVALID_CBOR), 0x90, 0x00},
	})

	_, err := CBOR(context.Background(), card, []byte{0x04})

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

func TestCBORReturnsTypedAPDUError(t *testing.T) {
	card := newSelectedCard(t, exchange{
		request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		response: []byte{0x6a, 0x82},
	})

	_, err := CBOR(context.Background(), card, []byte{0x04})

	var apduErr *baseiso7816.APDUError
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

func TestCBORRejectsMalformedResponses(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
	}{
		{name: "missing status word", response: []byte{0x90}},
		{name: "missing CTAP status", response: []byte{0x90, 0x00}},
		{name: "missing polling status", response: []byte{0x91, 0x00}},
		{name: "extra polling status", response: []byte{0x01, 0x02, 0x91, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			card := newSelectedCard(t, exchange{
				request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
				response: tt.response,
			})

			_, err := CBOR(context.Background(), card, []byte{0x04})

			if err, target := err, baseiso7816.ErrInvalidResponse; !errors.Is(err, target) {
				t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
			}
		})
	}
}

func TestCBORRejectsUnexpectedIntermediateData(t *testing.T) {
	command := append([]byte{0x01}, bytes.Repeat([]byte{0xaa}, shortCommandFragmentSize)...)
	card := newSelectedCard(t, exchange{
		request: slices.Concat(
			[]byte{0x90, 0x10, 0x00, 0x00, 0xf0},
			command[:shortCommandFragmentSize],
		),
		response: []byte{0x01, 0x90, 0x00},
	})

	_, err := CBOR(context.Background(), card, command)

	if err, target := err, baseiso7816.ErrInvalidResponse; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
}

func TestCBORRejectsOversizedCommandBeforeIO(t *testing.T) {
	card := newSelectedCard(t)

	_, largeErr := CBOR(
		context.Background(),
		card,
		make([]byte, maxMessageSize+1),
	)

	if err, target := largeErr, ErrCommandTooLarge; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
}

func TestSelectPropagatesTransmitError(t *testing.T) {
	wantErr := errors.New("transmit failed")
	card := &fakeCard{t: t, exchanges: []exchange{{
		request: commandBytes(t, selectAppletCommand),
		err:     wantErr,
	}}}

	_, err := Select(t.Context(), card)

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
	if !invalidated {
		t.Error("transmit failure did not invalidate the card")
	}
	if card.closeCalls != 0 {
		t.Error("Select closed the borrowed card")
	}
}

func TestCBORInvalidatesTransportWithoutClosingCardAfterTransmitFailure(t *testing.T) {
	wantErr := errors.New("transmit failed")
	card := newSelectedCard(t, exchange{
		request: []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		err:     wantErr,
	})

	_, err := CBOR(context.Background(), card, []byte{0x04})

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
	if got := invalidated; !got {
		t.Fatalf("got false, want true")
	}
}

func TestCBORInvalidatesAfterTransmitCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	card := newSelectedCard(t, exchange{
		request: []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		err:     context.Canceled,
		after:   cancel,
	})

	_, err := CBOR(ctx, card, []byte{0x04})

	if err, target := err, context.Canceled; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	if !invalidated {
		t.Error("canceled transmit did not invalidate the card")
	}
}

func TestSelectPreCanceledDoesNotTransmit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	card := &fakeCard{t: t}

	_, err := Select(ctx, card)

	if err, target := err, context.Canceled; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
}

func TestSelectOnceForMultipleCBOR(t *testing.T) {
	card := newSelectedCard(t,
		exchange{request: []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00}, response: []byte{0x00, 0xa0, 0x90, 0x00}},
		exchange{request: []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00}, response: []byte{0x00, 0xa0, 0x90, 0x00}},
		exchange{request: commandBytes(t, deselectAppletCommand), response: []byte{0x90, 0x00}},
	)
	for range 2 {
		if _, err := CBOR(t.Context(), card, []byte{0x04}); err != nil {
			t.Fatal(err)
		}
	}
	if err := Deselect(t.Context(), card); err != nil {
		t.Fatal(err)
	}
	if len(card.exchanges) != 0 {
		t.Fatalf("remaining APDUs: %v", card.exchanges)
	}
}

func TestSelectSelectionErrorsLeaveCardOpen(t *testing.T) {
	for _, response := range [][]byte{{0x6a, 0x82}, {0x90}} {
		card := &fakeCard{t: t, exchanges: []exchange{{
			request: commandBytes(t, selectAppletCommand), response: response,
		}}}
		if _, err := Select(t.Context(), card); err == nil {
			t.Fatal("expected selection error")
		}
		if card.closeCalls != 0 {
			t.Fatal("failed initialization closed borrowed card")
		}
	}
}

func TestSelectCancellationLeavesCardOpen(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	card := &fakeCard{t: t, exchanges: []exchange{{
		request: commandBytes(t, selectAppletCommand), err: context.Canceled, after: cancel,
	}}}
	if _, err := Select(ctx, card); !errors.Is(err, context.Canceled) {
		t.Fatalf("Select = %v, want context cancellation", err)
	}
	if card.closeCalls != 0 {
		t.Fatal("canceled initialization closed borrowed card")
	}
}

func TestDeselectPreservesErrorsAndLeavesCardOpen(t *testing.T) {
	tests := []struct {
		name        string
		response    []byte
		err         error
		wantErr     error
		wantAPDU    bool
		invalidated bool
	}{
		{name: "success", response: []byte{0x90, 0x00}},
		{name: "rejected", response: []byte{0x6a, 0x86}, wantAPDU: true},
		{name: "malformed", response: []byte{0x90}, wantErr: baseiso7816.ErrInvalidResponse},
		{name: "I/O failure", err: io.ErrClosedPipe, wantErr: io.ErrClosedPipe, invalidated: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			card := newSelectedCard(t, exchange{
				request: commandBytes(t, deselectAppletCommand), response: test.response, err: test.err,
			})
			err := Deselect(t.Context(), card)
			if !errors.Is(err, test.wantErr) && !test.wantAPDU {
				t.Fatalf("Deselect = %v, want %v", err, test.wantErr)
			}
			if test.wantAPDU {
				apduErr, ok := errors.AsType[*baseiso7816.APDUError](err)
				if !ok || apduErr.SW1 != 0x6a || apduErr.SW2 != 0x86 {
					t.Fatalf("Deselect = %v, want status 6a86", err)
				}
			}
			if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); invalidated != test.invalidated {
				t.Fatalf("Deselect invalidation = %v, want %v", invalidated, test.invalidated)
			}
			if len(card.exchanges) != 0 {
				t.Fatal("END was not transmitted")
			}
		})
	}
}

func TestDeselectCancellationLeavesCardOpen(t *testing.T) {
	for _, preCanceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		card := newSelectedCard(t, exchange{
			request: commandBytes(t, deselectAppletCommand), err: context.Canceled, after: cancel,
		})
		if preCanceled {
			cancel()
		}
		err := Deselect(ctx, card)
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Deselect = %v, want context cancellation", err)
		}
		if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); invalidated == preCanceled {
			t.Fatalf("preCanceled = %v, invalidation = %v", preCanceled, invalidated)
		}
		if preCanceled && len(card.exchanges) != 1 {
			t.Fatal("pre-canceled END transmitted an APDU")
		}
	}
}

func TestCBORCancellationDuringPolling(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	card := newSelectedCard(t,
		exchange{request: []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00}, response: []byte{0x02, 0x91, 0x00}},
		exchange{request: commandBytes(t, getResponseCommand), err: context.Canceled, after: cancel},
		exchange{request: commandBytes(t, cancelGetResponseCommand), response: []byte{byte(ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL), 0x90, 0x00}},
	)
	_, err := CBOR(ctx, card, []byte{0x04})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CBOR = %v, want context cancellation", err)
	}
	if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); invalidated {
		t.Fatalf("successful protocol cancellation invalidated transport: %v", err)
	}
	if len(card.exchanges) != 0 {
		t.Fatal("protocol cancellation was not transmitted")
	}
}

func TestCBORCancellationBetweenCommandFragmentsInvalidates(t *testing.T) {
	for _, size := range []int{241, 481} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			data := bytes.Repeat([]byte{0xaa}, size)
			data[0] = byte(protocol.AuthenticatorMakeCredential)
			card := newSelectedCard(t, exchange{
				request:  append([]byte{0x90, 0x10, 0x00, 0x00, 0xf0}, data[:240]...),
				response: []byte{0x90, 0x00},
				after:    cancel,
			})

			_, err := CBOR(ctx, card, data)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("CBOR = %v, want context cancellation", err)
			}
			if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); !invalidated {
				t.Fatal("partially transmitted command did not invalidate the card")
			}
			if len(card.exchanges) != 0 {
				t.Fatal("first command fragment was not transmitted")
			}
		})
	}
}

func TestCBORCancellationBetweenResponseFragmentsInvalidates(t *testing.T) {
	for _, sw1 := range []byte{0x61, 0x9f} {
		t.Run(fmt.Sprintf("%x", sw1), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			card := newSelectedCard(t, exchange{
				request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
				response: []byte{0x00, sw1, 0x01},
				after:    cancel,
			})

			_, err := CBOR(ctx, card, []byte{0x04})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("CBOR = %v, want context cancellation", err)
			}
			if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); !invalidated {
				t.Fatal("partially received response did not invalidate the card")
			}
		})
	}
}

func TestCBORPreCanceledKeepsCardUsable(t *testing.T) {
	card := newSelectedCard(t, exchange{
		request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		response: []byte{0x00, 0xa0, 0x90, 0x00},
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := CBOR(ctx, card, []byte{0x04})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CBOR = %v, want context cancellation", err)
	}
	if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); invalidated {
		t.Fatal("pre-canceled command invalidated the card")
	}
	if len(card.exchanges) != 1 {
		t.Fatal("pre-canceled command transmitted an APDU")
	}
	if _, err := CBOR(t.Context(), card, []byte{0x04}); err != nil {
		t.Fatalf("next CBOR = %v", err)
	}
}

func TestSelectCancellationBetweenResponseFragmentsInvalidates(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	card := &fakeCard{t: t, exchanges: []exchange{{
		request:  commandBytes(t, selectAppletCommand),
		response: append([]byte("FIDO_"), 0x61, 0x03),
		after:    cancel,
	}}}
	_, err := Select(ctx, card)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Select = %v, want context cancellation", err)
	}
	if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); !invalidated {
		t.Fatal("partially received SELECT response did not invalidate the card")
	}
	if card.closeCalls != 0 {
		t.Fatal("Select closed the borrowed card")
	}
}
