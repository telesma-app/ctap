// Package token2 implements Token2's proprietary CTAP-over-APDU tunnel over a
// raw smart-card APDU connection such as pcsc.Card.
package token2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
)

var (
	ErrInvalidResponse = errors.New("token2: invalid APDU response")
	ErrCommandTooLarge = errors.New("token2: CTAP command is too large")
)

var appletAID = []byte{0xf0, 0x00, 0x00, 0x01, 0x4f, 0x74, 0x70, 0x01}

const (
	claToken2      = 0x80
	insCTAP        = 0xc5
	insGetResponse = 0xc0
	maxCommandSize = 0xffff
)

// Card is the raw APDU subset implemented by pcsc.Card.
type Card interface {
	io.Closer
	Transmit(ctx context.Context, apdu []byte) ([]byte, error)
}

type ioCard struct {
	Card
}

func (c ioCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	response, err := c.Card.Transmit(ctx, apdu)
	if err != nil {
		return response, &ctaptransport.IOError{Operation: ctaptransport.IOTransmit, Err: err}
	}

	return response, nil
}

func (c ioCard) Close() error {
	err := c.Card.Close()
	if err != nil {
		return &ctaptransport.IOError{Operation: ctaptransport.IOClose, Err: err}
	}

	return nil
}

// APDUError reports a non-success ISO 7816 status word.
type APDUError struct {
	SW1 byte
	SW2 byte
}

func (e *APDUError) Error() string {
	return fmt.Sprintf("token2: APDU failed (SW=%02x%02x)", e.SW1, e.SW2)
}

// Transport carries CTAP commands through the Token2 applet.
type Transport struct {
	card      ioCard
	mu        sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

var _ ctaptransport.Device = (*Transport)(nil)

// New selects the Token2 applet and returns an initialized transport. The
// caller retains ownership of card if initialization fails.
func New(ctx context.Context, card Card) (*Transport, error) {
	t := &Transport{card: ioCard{Card: card}}

	selectAPDU := slices.Concat([]byte{0x00, 0xa4, 0x04, 0x00, byte(len(appletAID))}, appletAID)
	if _, err := t.exchange(ctx, selectAPDU); err != nil {
		return nil, fmt.Errorf("token2: select applet: %w", err)
	}

	return t, nil
}

// CBOR sends a CTAP command byte and CBOR payload through INS C5/P1 03. The
// context is passed to each APDU transmission.
func (t *Transport) CBOR(ctx context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	if len(data) < 1 {
		return ctaptransport.CBORResponse{}, errors.New("token2: empty CTAP command")
	}

	if len(data) > maxCommandSize {
		return ctaptransport.CBORResponse{}, ErrCommandTooLarge
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}

	response, err := t.exchange(ctx, commandAPDU(data))
	if err != nil {
		return ctaptransport.CBORResponse{}, t.closeOnIOError(ctx, err)
	}

	if len(response) < 1 {
		return ctaptransport.CBORResponse{}, ErrInvalidResponse
	}

	return ctaptransport.ValidateCBORResponse(protocol.Command(data[0]), ctaptransport.CBORResponse{
		StatusCode: ctaptransport.StatusCode(response[0]),
		Data:       response[1:],
	})
}

func (t *Transport) closeOnIOError(ctx context.Context, err error) error {
	ioErr, ok := errors.AsType[*ctaptransport.IOError](err)
	if !ok || ioErr.Operation != ctaptransport.IOTransmit {
		return err
	}

	if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
		return err
	}

	_ = t.Close()

	return &ctaptransport.DeviceInvalidatedError{Err: err}
}

func commandAPDU(data []byte) []byte {
	header := []byte{claToken2, insCTAP, 0x03, 0x00}
	if len(data) <= 0xff {
		return slices.Concat(header, []byte{byte(len(data))}, data)
	}

	return slices.Concat(header, []byte{0x00, byte(len(data) >> 8), byte(len(data))}, data)
}

func (t *Transport) exchange(ctx context.Context, apdu []byte) ([]byte, error) {
	cla := apdu[0]

	response, err := t.card.Transmit(ctx, apdu)
	if err != nil {
		return nil, err
	}

	var data []byte

	for {
		if len(response) < 2 {
			return nil, ErrInvalidResponse
		}

		body := response[:len(response)-2]
		sw1, sw2 := response[len(response)-2], response[len(response)-1]

		data = append(data, body...)

		switch sw1 {
		case 0x90:
			if sw2 != 0x00 {
				return nil, &APDUError{SW1: sw1, SW2: sw2}
			}

			return data, nil
		case 0x61:
			response, err = t.card.Transmit(ctx, []byte{cla, insGetResponse, 0x00, 0x00, sw2})
			if err != nil {
				return nil, err
			}
		default:
			return nil, &APDUError{SW1: sw1, SW2: sw2}
		}
	}
}

// Close closes the underlying card.
func (t *Transport) Close() error {
	t.closeOnce.Do(func() {
		t.closeErr = t.card.Close()
	})

	return t.closeErr
}
