package iso7816

import (
	"context"
	"errors"
	"fmt"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	baseiso7816 "github.com/telesma-app/iso7816"
)

var (
	ErrCommandTooLarge    = errors.New("iso7816: CTAP command is too large")
	ErrUnsupportedVersion = errors.New("iso7816: unsupported FIDO applet version")
)

const (
	claISO                = 0x00
	claCTAP               = 0x80
	insSelect             = 0xa4
	insNFCCTAPMsg         = 0x10
	insNFCCTAPGetResponse = 0x11
	insNFCCTAPControl     = 0x12
	p1SelectByName        = 0x04
	p1SupportsGetResponse = 0x80
	p1EndCTAPMsg          = 0x01
	// CTAP 2.3 NFC cancellation.
	p1Cancel                 = 0x11
	shortCommandFragmentSize = 240
	maxMessageSize           = 0xffff

	statusKeepalive baseiso7816.StatusWord = 0x9100
)

var (
	selectAppletCommand = baseiso7816.Command{
		CLA:      claISO,
		INS:      insSelect,
		P1:       p1SelectByName,
		Data:     []byte{0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01},
		Le:       256,
		Encoding: baseiso7816.EncodingShort,
	}
	getResponseCommand = baseiso7816.Command{
		CLA:      claCTAP,
		INS:      insNFCCTAPGetResponse,
		Le:       256,
		Encoding: baseiso7816.EncodingShort,
	}
	cancelGetResponseCommand = baseiso7816.Command{
		CLA:      claCTAP,
		INS:      insNFCCTAPGetResponse,
		P1:       p1Cancel,
		Le:       256,
		Encoding: baseiso7816.EncodingShort,
	}
	deselectAppletCommand = baseiso7816.Command{
		CLA:      claCTAP,
		INS:      insNFCCTAPControl,
		P1:       p1EndCTAPMsg,
		Encoding: baseiso7816.EncodingShort,
	}
)

type ioCard struct {
	baseiso7816.Card
}

func (c ioCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	response, err := c.Card.Transmit(ctx, apdu)
	if err != nil {
		return response, &ctaptransport.IOError{Operation: ctaptransport.IOTransmit, Err: err}
	}

	return response, nil
}

func invalidateOnError(err error) error {
	_, ioFailure := errors.AsType[*ctaptransport.IOError](err)
	if ioFailure || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &ctaptransport.DeviceInvalidatedError{Err: err}
	}

	return err
}

// Select activates the FIDO applet and returns its version.
// Call it before CBOR and after switching applets.
func Select(ctx context.Context, rawCard baseiso7816.Card) (protocol.Version, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	card := ioCard{Card: rawCard}
	response, err := baseiso7816.Exchange(
		ctx,
		card,
		selectAppletCommand,
		baseiso7816.WithMoreDataStatusBytes(0x61, 0x9f),
	)
	if err != nil {
		return "", fmt.Errorf("iso7816: select FIDO applet: %w", invalidateOnError(err))
	}
	if err := response.APDUError(); err != nil {
		return "", fmt.Errorf("iso7816: select FIDO applet: %w", err)
	}

	version := protocol.Version(response.Data)
	switch version {
	case protocol.FIDO_2_0, protocol.U2F_V2:
		return version, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedVersion, response.Data)
	}
}

// CBOR exchanges a CTAP command byte and payload with the selected applet.
// An already canceled context preserves the card. Later cancellation invalidates
// it unless a terminal response is received.
func CBOR(ctx context.Context, card baseiso7816.Card, data []byte) (ctaptransport.CBORResponse, error) {
	command := protocol.Command(data[0])
	if len(data) > maxMessageSize {
		return ctaptransport.CBORResponse{}, ErrCommandTooLarge
	}
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}

	response, err := exchangeCTAP(ctx, card, data)
	if err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	if len(response) < 1 {
		return ctaptransport.CBORResponse{}, baseiso7816.ErrInvalidResponse
	}

	return ctaptransport.ValidateCBORResponse(command, ctaptransport.CBORResponse{
		StatusCode: ctaptransport.StatusCode(response[0]),
		Data:       response[1:],
	})
}

func exchangeCTAP(ctx context.Context, rawCard baseiso7816.Card, data []byte) ([]byte, error) {
	card := ioCard{Card: rawCard}
	commands, err := baseiso7816.Chain(baseiso7816.Command{
		CLA:      claCTAP,
		INS:      insNFCCTAPMsg,
		Data:     data,
		Le:       256,
		Encoding: baseiso7816.EncodingShort,
	}, shortCommandFragmentSize)
	if err != nil {
		return nil, err
	}
	commands[len(commands)-1].P1 = p1SupportsGetResponse

	for _, command := range commands[:len(commands)-1] {
		response, err := baseiso7816.Transmit(ctx, card, command)
		if err != nil {
			return nil, invalidateOnError(err)
		}
		if err := response.APDUError(); err != nil {
			return nil, err
		}
		if len(response.Data) != 0 {
			return nil, baseiso7816.ErrInvalidResponse
		}
	}

	response, err := baseiso7816.Exchange(
		ctx,
		card,
		commands[len(commands)-1],
		baseiso7816.WithMoreDataStatusBytes(0x61, 0x9f),
	)
	if err != nil {
		return nil, invalidateOnError(err)
	}

	for response.Status == statusKeepalive {
		if len(response.Data) != 1 {
			return nil, baseiso7816.ErrInvalidResponse
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, cancelPolling(ctx, rawCard, ctxErr)
		}

		response, err = baseiso7816.Exchange(
			ctx,
			card,
			getResponseCommand,
			baseiso7816.WithMoreDataStatusBytes(0x61, 0x9f),
		)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
				return nil, cancelPolling(ctx, rawCard, err)
			}
			return nil, invalidateOnError(err)
		}
	}

	if err := response.APDUError(); err != nil {
		return nil, err
	}

	return response.Data, nil
}

func cancelPolling(ctx context.Context, rawCard baseiso7816.Card, originalErr error) error {
	cancelCtx := context.WithoutCancel(ctx)
	response, err := baseiso7816.Exchange(
		cancelCtx,
		rawCard,
		cancelGetResponseCommand,
		baseiso7816.WithMoreDataStatusBytes(0x61, 0x9f),
	)
	if err == nil && response.Status == baseiso7816.StatusSuccess &&
		len(response.Data) == 1 &&
		ctaptransport.StatusCode(response.Data[0]) == ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL {
		return originalErr
	}

	// No terminal response: the card cannot be reused.
	return &ctaptransport.DeviceInvalidatedError{Err: originalErr}
}

// Deselect disables FIDO without closing the card. Call Select to use FIDO again.
func Deselect(ctx context.Context, rawCard baseiso7816.Card) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	card := ioCard{Card: rawCard}
	response, err := baseiso7816.Transmit(ctx, card, deselectAppletCommand)
	if err == nil {
		err = response.APDUError()
	}
	if err != nil {
		return fmt.Errorf("iso7816: deselect FIDO applet: %w", invalidateOnError(err))
	}

	return nil
}
