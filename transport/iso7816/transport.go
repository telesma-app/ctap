package iso7816

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	ctaptransport "github.com/telesma-app/ctap/transport"
	baseiso7816 "github.com/telesma-app/iso7816"
)

// Card is a closable APDU connection.
// Close must be safe during Transmit and should unblock it.
type Card interface {
	baseiso7816.Card
	io.Closer
}

// Transport owns a card, serializes CTAP commands, and closes on invalidation.
type Transport struct {
	card      Card
	mu        sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

var _ ctaptransport.Device = (*Transport)(nil)

// Open selects FIDO and takes ownership of card on success.
// On failure, the caller retains ownership.
func Open(ctx context.Context, card Card) (*Transport, error) {
	if _, err := Select(ctx, card); err != nil {
		return nil, err
	}

	return &Transport{card: card}, nil
}

// CBOR exchanges one CTAP command on the selected applet.
func (t *Transport) CBOR(ctx context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	response, err := CBOR(ctx, t.card, data)
	if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); invalidated {
		_ = t.Close()
	}

	return response, err
}

// Close closes the card once, deselecting FIDO first if no command is active.
func (t *Transport) Close() error {
	t.closeOnce.Do(func() {
		if t.mu.TryLock() {
			defer t.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			t.closeErr = Deselect(ctx, t.card)
		}

		closeErr := t.card.Close()
		if closeErr != nil {
			closeErr = &ctaptransport.IOError{Operation: ctaptransport.IOClose, Err: closeErr}
		}
		t.closeErr = errors.Join(t.closeErr, closeErr)
	})

	return t.closeErr
}
