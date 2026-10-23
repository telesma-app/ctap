package ctapble

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/telesma-app/ble"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
)

const (
	// CTAP 2.3 section 11.4.4.3 specifies a short delay for ERR_BUSY but
	// intentionally leaves its duration to the client.
	busyRetryDelay = 100 * time.Millisecond
	// A canceled MSG must reach its terminal response before the connection can
	// carry another command.
	cancelDrainTimeout = time.Second
	// Close has no context, so its best-effort CANCEL needs an implementation
	// timeout; this is not a CTAP protocol constant.
	closeCancelTimeout = 250 * time.Millisecond
)

// Transport owns an initialized CTAP BLE peripheral connection.
type Transport struct {
	peripheral              ble.Peripheral
	fidoControlPoint        ble.Characteristic
	fidoStatusNotifications ble.Subscription
	fidoControlPointLength  int

	commandMu                 sync.Mutex
	fidoControlPointWriteGate chan struct{}
	activeMSG                 atomic.Bool

	closeOnce sync.Once
	closed    chan struct{}
	closeErr  error
}

var _ ctaptransport.Device = (*Transport)(nil)

// Open selects FIDO2, negotiates the control-point length, and enables status
// notifications. Accessing the protected FIDO characteristics may cause the
// operating system to pair and establish an encrypted link. Open waits for
// those GATT operations to complete. The caller retains ownership of peripheral
// on error. The returned Transport owns peripheral on success.
func Open(ctx context.Context, peripheral ble.Peripheral) (*Transport, error) {
	services, err := peripheral.DiscoverServices(ctx)
	if err != nil {
		return nil, &ctaptransport.IOError{Operation: ctaptransport.IORead, Err: err}
	}

	var fidoService ble.Service

	for _, service := range services {
		if service.Primary() && service.UUID() == fidoServiceUUID {
			fidoService = service
			break
		}
	}

	if fidoService == nil {
		return nil, ErrFIDOServiceNotFound
	}

	characteristics, err := fidoService.DiscoverCharacteristics(
		ctx,
		fidoControlPointUUID,
		fidoStatusUUID,
		fidoControlPointLengthUUID,
		fidoServiceRevisionBitfieldUUID,
	)
	if err != nil {
		return nil, &ctaptransport.IOError{Operation: ctaptransport.IORead, Err: err}
	}

	characteristicsByUUID := make(map[ble.UUID]ble.Characteristic, len(characteristics))
	for _, characteristic := range characteristics {
		characteristicsByUUID[characteristic.UUID()] = characteristic
	}

	fidoControlPoint, err := requireCharacteristic(
		characteristicsByUUID,
		fidoControlPointUUID,
		ble.CharacteristicPropertyWrite,
	)
	if err != nil {
		return nil, err
	}

	fidoStatus, err := requireCharacteristic(
		characteristicsByUUID,
		fidoStatusUUID,
		ble.CharacteristicPropertyNotify,
	)
	if err != nil {
		return nil, err
	}

	fidoControlPointLength, err := requireCharacteristic(
		characteristicsByUUID,
		fidoControlPointLengthUUID,
		ble.CharacteristicPropertyRead,
	)
	if err != nil {
		return nil, err
	}

	fidoServiceRevisionBitfield, err := requireCharacteristic(
		characteristicsByUUID,
		fidoServiceRevisionBitfieldUUID,
		ble.CharacteristicPropertyRead|ble.CharacteristicPropertyWrite,
	)
	if err != nil {
		return nil, err
	}

	revisionBitfield, err := fidoServiceRevisionBitfield.Read(ctx)
	if err != nil {
		return nil, &ctaptransport.IOError{Operation: ctaptransport.IORead, Err: err}
	}

	if len(revisionBitfield) == 0 || revisionBitfield[0]&fido2RevisionBit == 0 {
		return nil, ErrFIDO2Unsupported
	}

	if err := fidoServiceRevisionBitfield.Write(ctx, []byte{fido2RevisionBit}); err != nil {
		return nil, &ctaptransport.IOError{Operation: ctaptransport.IOWrite, Err: err}
	}

	fidoControlPointLengthValue, err := fidoControlPointLength.Read(ctx)
	if err != nil {
		return nil, &ctaptransport.IOError{Operation: ctaptransport.IORead, Err: err}
	}

	if len(fidoControlPointLengthValue) != fidoControlPointLengthSize {
		return nil, ErrInvalidFIDOControlPointLength
	}

	controlPointLength := int(binary.BigEndian.Uint16(fidoControlPointLengthValue))
	if controlPointLength < minFIDOControlPointLength || controlPointLength > maxFIDOControlPointLength {
		return nil, ErrInvalidFIDOControlPointLength
	}

	fidoStatusNotifications, err := fidoStatus.Subscribe(ctx)
	if err != nil {
		return nil, &ctaptransport.IOError{Operation: ctaptransport.IORead, Err: err}
	}

	return &Transport{
		peripheral:                peripheral,
		fidoControlPoint:          fidoControlPoint,
		fidoStatusNotifications:   fidoStatusNotifications,
		fidoControlPointLength:    controlPointLength,
		fidoControlPointWriteGate: make(chan struct{}, 1),
		closed:                    make(chan struct{}),
	}, nil
}

func requireCharacteristic(
	characteristics map[ble.UUID]ble.Characteristic,
	uuid ble.UUID,
	properties ble.CharacteristicProperties,
) (ble.Characteristic, error) {
	characteristic := characteristics[uuid]
	if characteristic == nil {
		return nil, fmt.Errorf("%w: %s", ErrFIDOCharacteristicNotFound, uuid)
	}

	if characteristic.Properties()&properties != properties {
		return nil, fmt.Errorf("%w: %s", ErrInvalidCharacteristicProperties, uuid)
	}

	return characteristic, nil
}

// CBOR exchanges one CTAP2 command. Canceling ctx sends CANCEL and drains the
// terminal MSG response before another command can start.
func (t *Transport) CBOR(ctx context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	t.commandMu.Lock()
	defer t.commandMu.Unlock()

	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}

	if len(data) == 0 {
		return ctaptransport.CBORResponse{}, errors.New("ctapble: empty CBOR request")
	}

	t.activeMSG.Store(true)
	defer t.activeMSG.Store(false)

	response, err := retryBusy(ctx, func() (responseFrame, error) {
		return t.exchange(ctx, MSG, data)
	})
	if err != nil {
		return ctaptransport.CBORResponse{}, t.closeOnIOError(err)
	}

	if len(response.data) == 0 {
		return ctaptransport.CBORResponse{}, ErrInvalidFrame
	}

	command := protocol.Command(data[0])

	return ctaptransport.ValidateCBORResponse(command, ctaptransport.CBORResponse{
		StatusCode: ctaptransport.StatusCode(response.data[0]),
		Data:       response.data[1:],
	})
}

// Ping checks BLE transport liveness and returns the echoed payload.
func (t *Transport) Ping(ctx context.Context, data []byte) ([]byte, error) {
	t.commandMu.Lock()
	defer t.commandMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	response, err := retryBusy(ctx, func() (responseFrame, error) {
		return t.exchange(ctx, PING, data)
	})
	if err != nil {
		return nil, t.closeOnIOError(err)
	}

	return response.data, nil
}

func retryBusy[T any](ctx context.Context, operation func() (T, error)) (T, error) {
	for {
		result, err := operation()

		response, busy := errors.AsType[*ErrorResponse](err)
		if !busy || response.ErrorCode != ERR_BUSY {
			return result, err
		}

		timer := time.NewTimer(busyRetryDelay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}

			var zero T

			return zero, ctx.Err()
		case <-timer.C:
		}
	}
}

type exchangeResult struct {
	frame responseFrame
	err   error
}

func (t *Transport) exchange(ctx context.Context, command Command, data []byte) (responseFrame, error) {
	if err := t.writeRequest(ctx, command, data); err != nil {
		return responseFrame{}, err
	}

	result := make(chan exchangeResult, 1)

	go func() {
		response, err := t.readResponse(command)
		result <- exchangeResult{frame: response, err: err}
	}()

	select {
	case response := <-result:
		return response.frame, response.err
	case <-ctx.Done():
		if command != MSG {
			_ = t.Close()
			return responseFrame{}, &ctaptransport.DeviceInvalidatedError{Err: ctx.Err()}
		}

		originalErr := ctx.Err()

		cancelCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cancelDrainTimeout)
		defer cancel()

		return t.cancelAndDrain(cancelCtx, originalErr, result)
	}
}

func (t *Transport) cancelAndDrain(
	ctx context.Context,
	originalErr error,
	result <-chan exchangeResult,
) (responseFrame, error) {
	if err := t.cancel(ctx); err != nil {
		_ = t.Close()
		return responseFrame{}, &ctaptransport.DeviceInvalidatedError{Err: originalErr}
	}

	select {
	case response := <-result:
		if isDeviceIOError(response.err) {
			_ = t.Close()
			return responseFrame{}, &ctaptransport.DeviceInvalidatedError{Err: originalErr}
		}

		return response.frame, originalErr
	case <-ctx.Done():
		_ = t.Close()
		return responseFrame{}, &ctaptransport.DeviceInvalidatedError{Err: originalErr}
	}
}

func (t *Transport) readResponse(command Command) (responseFrame, error) {
	var assembler responseFrameAssembler

	for {
		fragment, err := t.fidoStatusNotification()
		if err != nil {
			return responseFrame{}, err
		}

		response, err := assembler.addFragment(fragment)
		if err != nil {
			return responseFrame{}, err
		}

		if response == nil {
			continue
		}

		switch response.status {
		case KEEPALIVE:
			if len(response.data) != keepaliveDataLength {
				return responseFrame{}, ErrInvalidFrame
			}

			continue
		case ERROR:
			code, err := decodeErrorCode(response.data)
			if err != nil {
				return responseFrame{}, err
			}

			return responseFrame{}, &ErrorResponse{ErrorCode: code}
		case command:
			return *response, nil
		default:
			return responseFrame{}, fmt.Errorf("%w: got 0x%02x, want 0x%02x", ErrUnexpectedStatus, response.status, command)
		}
	}
}

func (t *Transport) fidoStatusNotification() ([]byte, error) {
	select {
	case <-t.closed:
		return nil, &ctaptransport.IOError{Operation: ctaptransport.IORead, Err: ble.ErrClosed}
	case value, ok := <-t.fidoStatusNotifications.Listen():
		if !ok {
			err := t.fidoStatusNotifications.Close()
			if err == nil {
				err = io.EOF
			}

			return nil, &ctaptransport.IOError{Operation: ctaptransport.IORead, Err: err}
		}

		return value, nil
	}
}

func (t *Transport) writeRequest(ctx context.Context, command Command, data []byte) error {
	fragments, err := fragmentFrame(command, data, t.fidoControlPointLength)
	if err != nil {
		return err
	}

	select {
	case t.fidoControlPointWriteGate <- struct{}{}:
		defer func() { <-t.fidoControlPointWriteGate }()
	case <-ctx.Done():
		return &ctaptransport.IOError{Operation: ctaptransport.IOWrite, Err: ctx.Err()}
	}

	for _, fragment := range fragments {
		if err := t.fidoControlPoint.Write(ctx, fragment); err != nil {
			return &ctaptransport.IOError{Operation: ctaptransport.IOWrite, Err: err}
		}
	}

	return nil
}

func (t *Transport) cancel(ctx context.Context) error {
	return t.writeRequest(ctx, CANCEL, nil)
}

func isDeviceIOError(err error) bool {
	ioErr, ok := errors.AsType[*ctaptransport.IOError](err)
	return ok && (ioErr.Operation == ctaptransport.IORead || ioErr.Operation == ctaptransport.IOWrite)
}

func (t *Transport) closeOnIOError(err error) error {
	if !isDeviceIOError(err) {
		return err
	}

	_ = t.Close()

	return &ctaptransport.DeviceInvalidatedError{Err: err}
}

// Close cancels an active CBOR command, disables notifications, and closes the
// peripheral. It is safe to call concurrently with an exchange or another Close.
func (t *Transport) Close() error {
	t.closeOnce.Do(func() {
		var cancelErr error

		if t.activeMSG.Load() {
			ctx, cancel := context.WithTimeout(context.Background(), closeCancelTimeout)
			cancelErr = t.cancel(ctx)
			cancel()
		}

		close(t.closed)

		if cancelErr != nil {
			t.closeErr = errors.Join(
				wrapClose(t.peripheral.Close()),
				wrapClose(t.fidoStatusNotifications.Close()),
			)

			return
		}

		t.closeErr = errors.Join(
			wrapClose(t.fidoStatusNotifications.Close()),
			wrapClose(t.peripheral.Close()),
		)
	})

	return t.closeErr
}

func wrapClose(err error) error {
	if err == nil {
		return nil
	}

	return &ctaptransport.IOError{Operation: ctaptransport.IOClose, Err: err}
}
