package authenticator

import (
	"context"
	"errors"
	"iter"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/telesma-app/ctap/backend"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
)

func TestSelectReturnsOnlyDeviceWithoutSelection(t *testing.T) {
	transport := newSelectionTransport(t, nil, nil)

	selected, err := Select(t.Context(), transportEnumerator(transport))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := selected.transport, transport; got != want {
		t.Errorf("got pointer %p, want %p", got, want)
	}

	if got := transport.selectionCalled.Load(); got {
		t.Errorf("got true, want false")
	}

	if got := transport.closed.Load(); got {
		t.Errorf("got true, want false")
	}
}

func TestSelectReturnsConfirmedDeviceAndClosesOthers(t *testing.T) {
	confirmed := make(chan struct{})
	first := newSelectionTransport(t, nil, nil)
	second := newSelectionTransport(t, confirmed, nil)

	type selectionResult struct {
		device *Device
		err    error
	}

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	result := make(chan selectionResult, 1)

	go func() {
		device, err := Select(ctx, transportEnumerator(first, second))
		result <- selectionResult{device: device, err: err}
	}()

	receive(t, first.selectionStarted, "first selection did not start")
	receive(t, second.selectionStarted, "second selection did not start")
	close(confirmed)

	selected := receive(t, result, "selection did not complete")
	if err := selected.err; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := selected.device.transport, second; got != want {
		t.Errorf("got pointer %p, want %p", got, want)
	}

	if got := first.closed.Load(); !got {
		t.Errorf("got false, want true")
	}

	if got := second.closed.Load(); got {
		t.Errorf("got true, want false")
	}
}

func TestSelectContinuesAfterCandidateError(t *testing.T) {
	wantErr := errors.New("candidate unavailable")
	transport := newSelectionTransport(t, nil, nil)
	enumerate := func(context.Context) iter.Seq2[ctaptransport.Device, error] {
		return func(yield func(ctaptransport.Device, error) bool) {
			if yield(nil, wantErr) {
				yield(transport, nil)
			}
		}
	}

	selected, err := Select(t.Context(), enumerate)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := selected.transport, transport; got != want {
		t.Errorf("got pointer %p, want %p", got, want)
	}
}

func TestSelectClosesTransportRejectedByAuthenticator(t *testing.T) {
	wantErr := errors.New("not a CTAP authenticator")
	rejected := newSelectionTransport(t, nil, nil)
	rejected.infoErr = wantErr
	accepted := newSelectionTransport(t, nil, nil)

	selected, err := Select(t.Context(), transportEnumerator(rejected, accepted))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := selected.transport, accepted; got != want {
		t.Errorf("got pointer %p, want %p", got, want)
	}

	if got := rejected.closed.Load(); !got {
		t.Errorf("got false, want true")
	}
}

func transportEnumerator(transports ...ctaptransport.Device) backend.Enumerator {
	return func(context.Context) iter.Seq2[ctaptransport.Device, error] {
		return func(yield func(ctaptransport.Device, error) bool) {
			for _, transport := range transports {
				if !yield(transport, nil) {
					return
				}
			}
		}
	}
}

type selectionTransport struct {
	info              []byte
	infoErr           error
	ready             <-chan struct{}
	resultErr         error
	closeOnce         sync.Once
	selectionCallOnce sync.Once
	close             chan struct{}
	selectionStarted  chan struct{}
	selectionCalled   atomic.Bool
	closed            atomic.Bool
}

func newSelectionTransport(
	t testing.TB,
	ready <-chan struct{},
	resultErr error,
) *selectionTransport {
	t.Helper()

	transport := &selectionTransport{
		info: encodeCBOR(t, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_1},
		}),
		ready:            ready,
		resultErr:        resultErr,
		close:            make(chan struct{}),
		selectionStarted: make(chan struct{}),
	}
	t.Cleanup(func() { _ = transport.Close() })

	return transport
}

func (t *selectionTransport) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	switch protocol.Command(request[0]) {
	case protocol.AuthenticatorGetInfo:
		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       t.info,
		}, t.infoErr

	case protocol.AuthenticatorSelection:
		t.selectionCalled.Store(true)
		t.selectionCallOnce.Do(func() { close(t.selectionStarted) })

		select {
		case <-ctx.Done():
			return ctaptransport.CBORResponse{}, ctx.Err()
		case <-t.close:
			return ctaptransport.CBORResponse{}, errors.New("transport closed")
		case <-t.ready:
			return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}, t.resultErr
		}

	default:
		panic("unexpected CTAP command")
	}
}

func (t *selectionTransport) Close() error {
	t.closeOnce.Do(func() {
		t.closed.Store(true)
		close(t.close)
	})

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
