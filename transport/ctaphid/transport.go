package ctaphid

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	ghid "github.com/telesma-app/hid"
)

// Transport owns a CTAPHID channel and serializes request/response exchanges.
type Transport struct {
	device     *channelDevice
	init       InitResponse
	mu         sync.Mutex
	writeMu    sync.Mutex // serializes CBOR and CANCEL writes
	activeCBOR atomic.Bool
}

// Device is a HID or proxy connection with contextual I/O.
type Device interface {
	ghid.ContextReadWriter
	io.Closer
}

var _ ctaptransport.Device = (*Transport)(nil)

const (
	channelBusyRetryDelay = 100 * time.Millisecond
	closeCancelTimeout    = 250 * time.Millisecond
)

func retryChannelBusy[T any](ctx context.Context, operation func() (T, error)) (T, error) {
	for {
		result, err := operation()
		if response, ok := errors.AsType[*ErrorResponse](err); !ok || response.ErrorCode != ERR_CHANNEL_BUSY {
			return result, err
		}

		timer := time.NewTimer(channelBusyRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()

			var zero T

			return zero, ctx.Err()

		case <-timer.C:
		}
	}
}

func retryChannelBusyError(ctx context.Context, operation func() error) error {
	_, err := retryChannelBusy(ctx, func() (struct{}, error) {
		return struct{}{}, operation()
	})

	return err
}

func (t *Transport) closeOnIOError(err error) error {
	ioErr, ok := errors.AsType[*ctaptransport.IOError](err)
	if !ok || (ioErr.Operation != ctaptransport.IORead && ioErr.Operation != ctaptransport.IOWrite) {
		return err
	}

	_ = t.device.Close()

	return &ctaptransport.DeviceInvalidatedError{Err: err}
}

// Open allocates a CTAPHID channel and takes ownership of device on success.
// On failure, the caller retains ownership.
func Open(ctx context.Context, device Device) (*Transport, error) {
	var nonce [8]byte
	rand.Read(nonce[:])

	channel := newChannelDevice(device, BROADCAST_CID)

	response, err := retryChannelBusy(ctx, func() (InitResponse, error) {
		return Init(ctx, channel, BROADCAST_CID, nonce)
	})
	if err != nil {
		channel.stop()
		return nil, err
	}

	channel.setCID(response.CID)

	return &Transport{device: channel, init: response}, nil
}

// InitResponse returns the channel allocation response, including after Close.
func (t *Transport) InitResponse() InitResponse {
	return t.init
}

// CBOR exchanges a CTAP command. Cancellation sends CANCEL and drains the response.
// Failed cancellation closes the connection and returns DeviceInvalidatedError.
func (t *Transport) CBOR(ctx context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}

	t.activeCBOR.Store(true)
	defer t.activeCBOR.Store(false)

	response, err := retryChannelBusy(ctx, func() (ctaptransport.CBORResponse, error) {
		return t.exchangeCBOR(ctx, data)
	})

	return response, t.closeOnIOError(err)
}

func (t *Transport) exchangeCBOR(ctx context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	command, err := t.writeCBOR(ctx, data)
	if err != nil {
		return ctaptransport.CBORResponse{}, err
	}

	response, err := readCBORResponse(ctx, t.device, t.init.CID, command)

	ctxErr := ctx.Err()
	if ctxErr == nil || !errors.Is(err, ctxErr) {
		return response, err
	}

	// CANCEL has no reply; drain the original command before reusing the channel.
	cancelCtx := context.WithoutCancel(ctx)
	if cancelErr := t.Cancel(cancelCtx); cancelErr == nil {
		_, drainErr := readCBORResponse(cancelCtx, t.device, t.init.CID, command)

		_, terminalStatus := errors.AsType[*ctaptransport.CTAPError](drainErr)
		if drainErr == nil || terminalStatus {
			return response, err
		}
	}

	_ = t.device.Close()

	return response, &ctaptransport.DeviceInvalidatedError{Err: err}
}

func (t *Transport) writeCBOR(ctx context.Context, data []byte) (protocol.Command, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	return writeCBOR(ctx, t.device, t.init.CID, data)
}

// Ping checks channel liveness and returns the echoed payload.
func (t *Transport) Ping(ctx context.Context, data []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	response, err := retryChannelBusy(ctx, func() (PingResponse, error) {
		return Ping(ctx, t.device, t.init.CID, data)
	})
	if err != nil {
		return nil, t.closeOnIOError(err)
	}

	return response.Bytes, nil
}

// Wink asks the authenticator to signal its physical presence.
func (t *Transport) Wink(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	err := retryChannelBusyError(ctx, func() error {
		return Wink(ctx, t.device, t.init.CID)
	})

	return t.closeOnIOError(err)
}

// Lock controls the CTAPHID channel lock.
func (t *Transport) Lock(ctx context.Context, seconds uint8) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	err := retryChannelBusyError(ctx, func() error {
		return Lock(ctx, t.device, t.init.CID, seconds)
	})

	return t.closeOnIOError(err)
}

// Cancel aborts the active CBOR request on this channel.
func (t *Transport) Cancel(ctx context.Context) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	err := Cancel(ctx, t.device, t.init.CID)

	return t.closeOnIOError(err)
}

// Vendor exchanges one vendor-specific CTAPHID command.
func (t *Transport) Vendor(ctx context.Context, command Command, data []byte) (VendorResponse, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return VendorResponse{}, err
	}

	response, err := retryChannelBusy(ctx, func() (VendorResponse, error) {
		return Vendor(ctx, t.device, t.init.CID, command, data)
	})

	return response, t.closeOnIOError(err)
}

// Close closes the connection, canceling active CBOR first when no write is pending.
func (t *Transport) Close() error {
	if t.activeCBOR.Load() && t.writeMu.TryLock() {
		ctx, cancel := context.WithTimeout(context.Background(), closeCancelTimeout)
		_ = Cancel(ctx, t.device, t.init.CID)

		cancel()
		t.writeMu.Unlock()
	}

	return t.device.Close()
}
