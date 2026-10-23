package ctapble

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/telesma-app/ble"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
)

type fakePeripheral struct {
	services             []ble.Service
	discoverServiceUUIDs []ble.UUID
	closed               chan struct{}
	once                 sync.Once
}

func receiveTest[T any](t *testing.T, values <-chan T) T {
	t.Helper()

	select {
	case value := <-values:
		return value
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for test event")

		var zero T

		return zero
	}
}

func (p *fakePeripheral) DiscoverServices(_ context.Context, uuids ...ble.UUID) ([]ble.Service, error) {
	p.discoverServiceUUIDs = append(p.discoverServiceUUIDs, uuids...)
	return p.services, nil
}

func (p *fakePeripheral) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

type fakeService struct {
	uuid            ble.UUID
	primary         bool
	characteristics []ble.Characteristic
}

func (s *fakeService) UUID() ble.UUID { return s.uuid }
func (s *fakeService) Primary() bool  { return s.primary }
func (s *fakeService) DiscoverCharacteristics(context.Context, ...ble.UUID) ([]ble.Characteristic, error) {
	return s.characteristics, nil
}

type fakeCharacteristic struct {
	uuid       ble.UUID
	properties ble.CharacteristicProperties
	read       []byte
	sub        *fakeSubscription

	mu       sync.Mutex
	writes   [][]byte
	onWrite  func([]byte)
	writeErr func([]byte) error
}

func (c *fakeCharacteristic) UUID() ble.UUID                           { return c.uuid }
func (c *fakeCharacteristic) Properties() ble.CharacteristicProperties { return c.properties }
func (c *fakeCharacteristic) Read(context.Context) ([]byte, error)     { return c.read, nil }
func (c *fakeCharacteristic) Subscribe(context.Context) (ble.Subscription, error) {
	return c.sub, nil
}

func (c *fakeCharacteristic) Write(_ context.Context, value []byte) error {
	value = bytes.Clone(value)

	c.mu.Lock()
	c.writes = append(c.writes, value)
	onWrite := c.onWrite
	writeErr := c.writeErr
	c.mu.Unlock()

	if onWrite != nil {
		onWrite(value)
	}

	if writeErr != nil {
		return writeErr(value)
	}

	return nil
}

func (c *fakeCharacteristic) values() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([][]byte(nil), c.writes...)
}

type fakeSubscription struct {
	values chan []byte
	once   sync.Once
}

func (s *fakeSubscription) Listen() <-chan []byte { return s.values }
func (s *fakeSubscription) Close() error {
	s.once.Do(func() { close(s.values) })
	return nil
}

func newFakeTransport(t *testing.T) (*Transport, *fakeCharacteristic, *fakeSubscription, *fakePeripheral) {
	t.Helper()

	subscription := &fakeSubscription{values: make(chan []byte, 32)}
	controlPoint := &fakeCharacteristic{
		uuid:       fidoControlPointUUID,
		properties: ble.CharacteristicPropertyWrite,
	}
	peripheral := &fakePeripheral{closed: make(chan struct{})}
	transport := &Transport{
		peripheral:                peripheral,
		fidoControlPoint:          controlPoint,
		fidoStatusNotifications:   subscription,
		fidoControlPointLength:    20,
		fidoControlPointWriteGate: make(chan struct{}, 1),
		closed:                    make(chan struct{}),
	}

	t.Cleanup(func() { _ = transport.Close() })

	return transport, controlPoint, subscription, peripheral
}

func TestOpenInitializesFIDOService(t *testing.T) {
	subscription := &fakeSubscription{values: make(chan []byte, 1)}
	fidoControlPoint := &fakeCharacteristic{uuid: fidoControlPointUUID, properties: ble.CharacteristicPropertyWrite}
	fidoStatus := &fakeCharacteristic{uuid: fidoStatusUUID, properties: ble.CharacteristicPropertyNotify, sub: subscription}
	fidoControlPointLength := &fakeCharacteristic{
		uuid:       fidoControlPointLengthUUID,
		properties: ble.CharacteristicPropertyRead,
		read:       []byte{0x00, 0x40},
	}
	fidoServiceRevisionBitfield := &fakeCharacteristic{
		uuid:       fidoServiceRevisionBitfieldUUID,
		properties: ble.CharacteristicPropertyRead | ble.CharacteristicPropertyWrite,
		read:       []byte{fido2RevisionBit},
	}
	peripheral := &fakePeripheral{
		closed: make(chan struct{}),
		services: []ble.Service{&fakeService{
			uuid:    fidoServiceUUID,
			primary: true,
			characteristics: []ble.Characteristic{
				fidoControlPoint,
				fidoStatus,
				fidoControlPointLength,
				fidoServiceRevisionBitfield,
			},
		}},
	}

	transport, err := Open(context.Background(), peripheral)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transport.Close() }()

	if transport.fidoControlPointLength != 64 {
		t.Fatalf("fidoControlPointLength = %d, want 64", transport.fidoControlPointLength)
	}

	if len(peripheral.discoverServiceUUIDs) != 0 {
		t.Fatalf("service discovery filter = %v, want all primary services", peripheral.discoverServiceUUIDs)
	}

	if writes := fidoServiceRevisionBitfield.values(); len(writes) != 1 || !bytes.Equal(writes[0], []byte{fido2RevisionBit}) {
		t.Fatalf("revision writes = %x", writes)
	}
}

func TestOpenRejectsUnsupportedRevision(t *testing.T) {
	peripheral := completeFakePeripheral([]byte{0x40}, []byte{0, 20})

	_, err := Open(context.Background(), peripheral)
	if !errors.Is(err, ErrFIDO2Unsupported) {
		t.Fatalf("error = %v, want ErrFIDO2Unsupported", err)
	}
}

func TestOpenRejectsControlPointLength(t *testing.T) {
	for _, value := range [][]byte{{0}, {0, 19}, {2, 1}} {
		peripheral := completeFakePeripheral([]byte{fido2RevisionBit}, value)

		_, err := Open(context.Background(), peripheral)
		if !errors.Is(err, ErrInvalidFIDOControlPointLength) {
			t.Fatalf("value %x: error = %v, want ErrInvalidFIDOControlPointLength", value, err)
		}
	}
}

func completeFakePeripheral(revisionValue, lengthValue []byte) *fakePeripheral {
	subscription := &fakeSubscription{values: make(chan []byte, 1)}

	return &fakePeripheral{
		closed: make(chan struct{}),
		services: []ble.Service{&fakeService{
			uuid:    fidoServiceUUID,
			primary: true,
			characteristics: []ble.Characteristic{
				&fakeCharacteristic{uuid: fidoControlPointUUID, properties: ble.CharacteristicPropertyWrite},
				&fakeCharacteristic{uuid: fidoStatusUUID, properties: ble.CharacteristicPropertyNotify, sub: subscription},
				&fakeCharacteristic{uuid: fidoControlPointLengthUUID, properties: ble.CharacteristicPropertyRead, read: lengthValue},
				&fakeCharacteristic{
					uuid:       fidoServiceRevisionBitfieldUUID,
					properties: ble.CharacteristicPropertyRead | ble.CharacteristicPropertyWrite,
					read:       revisionValue,
				},
			},
		}},
	}
}

func TestCBORSkipsKeepaliveAndParsesResponse(t *testing.T) {
	transport, controlPoint, subscription, _ := newFakeTransport(t)
	controlPoint.onWrite = func(value []byte) {
		if value[0] == byte(MSG) {
			subscription.values <- []byte{byte(KEEPALIVE), 0, 1, 1}

			subscription.values <- []byte{byte(MSG), 0, 3, 0, 0xa1, 0x01}
		}
	}

	response, err := transport.CBOR(context.Background(), []byte{byte(protocol.AuthenticatorGetInfo)})
	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != ctaptransport.CTAP2_OK || !bytes.Equal(response.Data, []byte{0xa1, 0x01}) {
		t.Fatalf("response = %#v", response)
	}
}

func TestCBORRetriesBusy(t *testing.T) {
	transport, controlPoint, subscription, _ := newFakeTransport(t)
	requestCount := 0
	controlPoint.onWrite = func(value []byte) {
		if value[0] != byte(MSG) {
			return
		}

		requestCount++
		if requestCount == 1 {
			subscription.values <- []byte{byte(ERROR), 0, 1, byte(ERR_BUSY)}
		} else {
			subscription.values <- []byte{byte(MSG), 0, 1, 0}
		}
	}

	_, err := transport.CBOR(context.Background(), []byte{byte(protocol.AuthenticatorGetInfo)})
	if err != nil {
		t.Fatal(err)
	}

	if requestCount != 2 {
		t.Fatalf("request count = %d, want 2", requestCount)
	}
}

func TestCBORReturnsEncapsulationError(t *testing.T) {
	transport, controlPoint, subscription, _ := newFakeTransport(t)
	controlPoint.onWrite = func(value []byte) {
		if value[0] == byte(MSG) {
			subscription.values <- []byte{byte(ERROR), 0, 1, byte(ERR_INVALID_LEN)}
		}
	}

	_, err := transport.CBOR(context.Background(), []byte{byte(protocol.AuthenticatorGetInfo)})

	response, ok := errors.AsType[*ErrorResponse](err)
	if !ok || response.ErrorCode != ERR_INVALID_LEN {
		t.Fatalf("error = %v, want ERR_INVALID_LEN", err)
	}
}

func TestCBORReturnsCTAPStatusError(t *testing.T) {
	transport, controlPoint, subscription, _ := newFakeTransport(t)
	controlPoint.onWrite = func(value []byte) {
		if value[0] == byte(MSG) {
			subscription.values <- []byte{byte(MSG), 0, 1, byte(ctaptransport.CTAP1_ERR_INVALID_COMMAND)}
		}
	}

	_, err := transport.CBOR(context.Background(), []byte{byte(protocol.AuthenticatorGetInfo)})

	response, ok := errors.AsType[*ctaptransport.CTAPError](err)
	if !ok || response.Command != protocol.AuthenticatorGetInfo || response.StatusCode != ctaptransport.CTAP1_ERR_INVALID_COMMAND {
		t.Fatalf("error = %v", err)
	}
}

func TestPingReturnsEcho(t *testing.T) {
	transport, controlPoint, subscription, _ := newFakeTransport(t)
	controlPoint.onWrite = func(value []byte) {
		if value[0] == byte(PING) {
			subscription.values <- []byte{byte(PING), 0, 3, 1, 2, 3}
		}
	}

	response, err := transport.Ping(context.Background(), []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(response, []byte{1, 2, 3}) {
		t.Fatalf("response = %x", response)
	}
}

func TestCBORCancelAndDrain(t *testing.T) {
	transport, controlPoint, subscription, _ := newFakeTransport(t)
	requestWritten := make(chan struct{})

	var requestOnce sync.Once

	controlPoint.onWrite = func(value []byte) {
		switch value[0] {
		case byte(MSG):
			requestOnce.Do(func() { close(requestWritten) })
		case byte(CANCEL):
			subscription.values <- []byte{byte(MSG), 0, 1, byte(ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL)}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)

	go func() {
		_, err := transport.CBOR(ctx, []byte{byte(protocol.AuthenticatorGetInfo)})
		result <- err
	}()

	receiveTest(t, requestWritten)
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("CBOR did not return after cancel and drain")
	}

	controlPoint.onWrite = func(value []byte) {
		if value[0] == byte(MSG) {
			subscription.values <- []byte{byte(MSG), 0, 1, 0}
		}
	}

	if _, err := transport.CBOR(context.Background(), []byte{byte(protocol.AuthenticatorGetInfo)}); err != nil {
		t.Fatalf("exchange after drain: %v", err)
	}
}

func TestCBORCancelWriteFailureInvalidatesConnection(t *testing.T) {
	transport, controlPoint, _, peripheral := newFakeTransport(t)
	requestWritten := make(chan struct{})
	controlPoint.onWrite = func(value []byte) {
		if value[0] == byte(MSG) {
			close(requestWritten)
		}
	}
	controlPoint.writeErr = func(value []byte) error {
		if value[0] == byte(CANCEL) {
			return errors.New("write failed")
		}

		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)

	go func() {
		_, err := transport.CBOR(ctx, []byte{byte(protocol.AuthenticatorGetInfo)})
		result <- err
	}()

	receiveTest(t, requestWritten)
	cancel()

	err := receiveTest(t, result)
	if _, ok := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); !ok {
		t.Fatalf("error = %v, want DeviceInvalidatedError", err)
	}

	select {
	case <-peripheral.closed:
	default:
		t.Fatal("peripheral remained open")
	}
}

func TestCancelAndDrainTimeoutInvalidatesConnection(t *testing.T) {
	transport, _, _, peripheral := newFakeTransport(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := transport.cancelAndDrain(ctx, context.Canceled, make(chan exchangeResult))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}

	if _, ok := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); !ok {
		t.Fatalf("error = %v, want DeviceInvalidatedError", err)
	}

	select {
	case <-peripheral.closed:
	default:
		t.Fatal("peripheral remained open")
	}
}

func TestCloseDoesNotBlockOnControlPointWrite(t *testing.T) {
	transport, _, _, peripheral := newFakeTransport(t)
	transport.fidoControlPointWriteGate <- struct{}{}

	transport.activeMSG.Store(true)

	closed := make(chan error, 1)
	go func() { closed <- transport.Close() }()

	if err := receiveTest(t, closed); err != nil {
		t.Fatal(err)
	}

	select {
	case <-peripheral.closed:
	default:
		t.Fatal("peripheral remained open")
	}
}

func TestCloseUnblocksExchangeAndIsConcurrentSafe(t *testing.T) {
	transport, controlPoint, _, peripheral := newFakeTransport(t)
	written := make(chan struct{})

	var once sync.Once

	controlPoint.onWrite = func(value []byte) {
		if value[0] == byte(MSG) {
			once.Do(func() { close(written) })
		}
	}

	result := make(chan error, 1)

	go func() {
		_, err := transport.CBOR(context.Background(), []byte{byte(protocol.AuthenticatorGetInfo)})
		result <- err
	}()

	receiveTest(t, written)

	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()

			_ = transport.Close()
		}()
	}

	closed := make(chan struct{})

	go func() {
		wait.Wait()
		close(closed)
	}()

	receiveTest(t, closed)

	select {
	case <-peripheral.closed:
	case <-time.After(time.Second):
		t.Fatal("peripheral was not closed")
	}

	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock CBOR")
	}
}
