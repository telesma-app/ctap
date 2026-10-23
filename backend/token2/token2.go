// Package token2 connects cards exposing Token2's proprietary CTAP applet.
package token2

import (
	"context"
	"errors"
	"iter"

	backendpcsc "github.com/telesma-app/ctap/backend/pcsc"
	ctaptransport "github.com/telesma-app/ctap/transport"
	token2transport "github.com/telesma-app/ctap/transport/token2"
	nativepcsc "github.com/telesma-app/pcsc"
)

// Devices returns PC/SC readers whose card accepts the Token2 CTAP applet.
func Devices(ctx context.Context) iter.Seq2[*nativepcsc.ReaderInfo, error] {
	return func(yield func(*nativepcsc.ReaderInfo, error) bool) {
		for reader, err := range backendpcsc.Devices(ctx) {
			if err != nil {
				yield(nil, err)
				return
			}

			transport, err := Open(ctx, reader.Name)
			if isUnsupportedCard(err) {
				continue
			}

			if err != nil {
				if !yield(nil, err) {
					return
				}

				continue
			}

			if err := transport.Close(); err != nil {
				if !yield(nil, err) {
					return
				}

				continue
			}

			if !yield(reader, nil) {
				return
			}
		}
	}
}

// Open connects to the card in reader and selects the Token2 CTAP applet.
func Open(ctx context.Context, reader string) (*token2transport.Transport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	card, err := nativepcsc.Open(
		reader,
		nativepcsc.WithShareMode(nativepcsc.ShareModeExclusive),
		nativepcsc.WithDisconnectDisposition(nativepcsc.DispositionResetCard),
	)
	if err != nil {
		return nil, err
	}

	transport, err := token2transport.New(ctx, card)
	if err != nil {
		return nil, errors.Join(err, card.Close())
	}

	return transport, nil
}

// Enumerate opens inserted PC/SC cards as Token2 CTAP transports.
func Enumerate(ctx context.Context) iter.Seq2[ctaptransport.Device, error] {
	return func(yield func(ctaptransport.Device, error) bool) {
		for reader, err := range backendpcsc.Devices(ctx) {
			if err != nil {
				yield(nil, err)
				return
			}

			transport, err := Open(ctx, reader.Name)
			if isUnsupportedCard(err) {
				continue
			}

			if !yield(transport, err) {
				return
			}
		}
	}
}

func isUnsupportedCard(err error) bool {
	var apduErr *token2transport.APDUError
	return errors.As(err, &apduErr) || errors.Is(err, token2transport.ErrInvalidResponse)
}
