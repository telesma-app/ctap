package authenticator

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/transport/ctaphid"
)

var (
	_ pinger = (*ctaphid.Transport)(nil)
	_ winker = (*ctaphid.Transport)(nil)
	_ locker = (*ctaphid.Transport)(nil)
)

type optionTransport struct {
	response []byte
	err      error
	requests [][]byte
	closed   bool
}

type capabilityTransport struct {
	optionTransport
	pingResponse []byte
	winked       bool
	lockSeconds  uint8
}

func (t *capabilityTransport) Ping(context.Context, []byte) ([]byte, error) {
	return slices.Clone(t.pingResponse), nil
}

func (t *capabilityTransport) Wink(context.Context) error {
	t.winked = true
	return nil
}

func (t *capabilityTransport) Lock(_ context.Context, seconds uint8) error {
	t.lockSeconds = seconds
	return nil
}

func (t *optionTransport) CBOR(_ context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	t.requests = append(t.requests, slices.Clone(data))
	return ctaptransport.CBORResponse{Data: slices.Clone(t.response)}, t.err
}

func (t *optionTransport) Close() error {
	t.closed = true
	return nil
}

func TestNewUsesConfiguredTransport(t *testing.T) {
	transport := &optionTransport{response: encodeCBOR(t, protocol.AuthenticatorGetInfoResponse{
		Versions:           protocol.Versions{protocol.FIDO_2_1},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
	})}

	device, err := New(testContext, transport)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, err := device.GetInfo(testContext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := protocol.Versions{protocol.FIDO_2_1}, info.Versions
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := [][]byte{
			{byte(protocol.AuthenticatorGetInfo)},
			{byte(protocol.AuthenticatorGetInfo)},
		}, transport.requests
		if (got == nil) != (want == nil) || !slices.EqualFunc(got, want, func(got, want []byte) bool {
			return (got == nil) == (want == nil) && bytes.Equal(got, want)
		}) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	if err := device.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := transport.closed; !got {
		t.Errorf("got false, want true")
	}
}

func TestGetInfoAlwaysRequestsCurrentDeviceInfo(t *testing.T) {
	first := protocol.AuthenticatorGetInfoResponse{
		Versions:           protocol.Versions{protocol.FIDO_2_1},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
	}
	second := protocol.AuthenticatorGetInfoResponse{
		Versions:           protocol.Versions{protocol.FIDO_2_3},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
	}
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, first), encodeCBOR(t, second))
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
	})

	got, err := d.GetInfo(testContext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := got.Versions, first.Versions; (got == nil) != (want == nil) || !slices.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	got, err = d.GetInfo(testContext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := got.Versions, second.Versions; (got == nil) != (want == nil) || !slices.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	selected, err := d.requirePinUvAuthProtocol()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := selected, protocol.PinUvAuthProtocolTwo; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	requests := fake.Requests(t)
	if got, want := len(requests), 2; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}
	for _, request := range requests {
		command, _ := request.CTAPPayload(t)
		if got, want := command, protocol.AuthenticatorGetInfo; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestGetInfoCachedReportsValidityWithoutRequestingDeviceInfo(t *testing.T) {
	initial := protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_1},
	}
	current := protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_3},
	}
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, current))
	d := newTestDevice(t, fake, initial)

	got, valid := d.GetInfoCached()
	if got := valid; !got {
		t.Errorf("got false, want true")
	}
	if got, want := got.Versions, initial.Versions; (got == nil) != (want == nil) || !slices.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got := fake.Requests(t); len(got) != 0 {
		t.Errorf("got non-empty value %#v", got)
	}

	d.invalidateInfoLocked()
	got, valid = d.GetInfoCached()
	if got := valid; got {
		t.Errorf("got true, want false")
	}
	if got, want := got.Versions, initial.Versions; (got == nil) != (want == nil) || !slices.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got := fake.Requests(t); len(got) != 0 {
		t.Errorf("got non-empty value %#v", got)
	}

	got, err := d.GetInfo(testContext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := got.Versions, current.Versions; (got == nil) != (want == nil) || !slices.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	got, valid = d.GetInfoCached()
	if got := valid; !got {
		t.Errorf("got false, want true")
	}
	if got, want := got.Versions, current.Versions; (got == nil) != (want == nil) || !slices.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	requests := fake.Requests(t)
	if got, want := len(requests), 1; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}
	command, _ := requests[0].CTAPPayload(t)
	if got, want := command, protocol.AuthenticatorGetInfo; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestGetInfoCachedDoesNotWaitForDeviceRequestMutex(t *testing.T) {
	d := &Device{
		info: protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_1},
		},
		infoValid: true,
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	done := make(chan struct{})
	go func() {
		d.GetInfoCached()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("GetInfoCached waited for the device request mutex")
	}
}

func TestRequirePinUvAuthProtocolSelectsFirstSupported(t *testing.T) {
	tests := []struct {
		name       string
		advertised []protocol.PinUvAuthProtocol
		want       protocol.PinUvAuthProtocol
	}{
		{
			name:       "skips a newer protocol",
			advertised: []protocol.PinUvAuthProtocol{3, protocol.PinUvAuthProtocolTwo},
			want:       protocol.PinUvAuthProtocolTwo,
		},
		{
			name:       "preserves authenticator preference",
			advertised: []protocol.PinUvAuthProtocol{3, protocol.PinUvAuthProtocolOne, protocol.PinUvAuthProtocolTwo},
			want:       protocol.PinUvAuthProtocolOne,
		},
		{
			name:       "uses the first supported protocol",
			advertised: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo, protocol.PinUvAuthProtocolOne},
			want:       protocol.PinUvAuthProtocolTwo,
		},
		{
			name:       "rejects unsupported protocols",
			advertised: []protocol.PinUvAuthProtocol{3, 4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "preserves authenticator preference" {
				skipAuthenticatorFIPS140(t)
			}
			d := &Device{info: protocol.AuthenticatorGetInfoResponse{PinUvAuthProtocols: tt.advertised}}
			got, err := d.requirePinUvAuthProtocol()
			if tt.want == 0 {
				if err, target := err, ErrNotSupported; !errors.Is(err, target) {
					t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got, want := got, tt.want; got != want {
				t.Errorf("got %#v, want %#v", got, want)
			}
		})
	}
}

func TestNewLeavesConfiguredTransportOpenAfterGetInfoFailure(t *testing.T) {
	transport := &optionTransport{err: errors.New("get info failed")}

	_, err := New(testContext, transport)
	if err == nil {
		t.Fatalf("expected an error")
	}
	if got := transport.closed; got {
		t.Errorf("got true, want false")
	}
}

func TestHIDCapabilitiesPreserveDeviceCommands(t *testing.T) {
	transport := &capabilityTransport{pingResponse: []byte("hello")}
	d := &Device{transport: transport}

	if err := d.Ping(testContext, []byte("hello")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := d.Wink(testContext); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := d.Lock(testContext, 7); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := transport.winked; !got {
		t.Errorf("got false, want true")
	}
	if got, want := transport.lockSeconds, uint8(7); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	transport.pingResponse = []byte("different")
	if err, target := d.Ping(testContext, []byte("hello")), ErrPingPongMismatch; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
}

func TestUnsupportedTransportRejectsHIDCommands(t *testing.T) {
	d := &Device{transport: &optionTransport{}}

	if err, target := d.Ping(testContext, nil), ErrNotSupported; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
	if err, target := d.Wink(testContext), ErrNotSupported; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
	if err, target := d.Lock(testContext, 1), ErrNotSupported; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
}

func TestGetAssertionContinuesAfterAssertionWithoutExtensionData(t *testing.T) {
	first := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw:         minimalAuthData(),
		Signature:           []byte{1},
		NumberOfCredentials: 2,
	})
	second := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: minimalAuthData(),
		Signature:   []byte{2},
	})
	fake := testhid.NewCBORDevice(t, testCID, first, second)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{})

	var assertions []protocol.AuthenticatorGetAssertionResponse
	for assertion, err := range d.GetAssertion(testContext, nil, "example.com", []byte("client-data"), nil, nil, nil) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertions = append(assertions, assertion)
	}

	if got, want := len(assertions), 2; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}
	{
		want, got := []byte{1}, assertions[0].Signature
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := []byte{2}, assertions[1].Signature
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestLockRejectsOutOfRangeSeconds(t *testing.T) {
	transport := &capabilityTransport{}
	d := &Device{transport: transport}

	err := d.Lock(testContext, 11)
	if err == nil {
		t.Fatalf("expected an error")
	}
	if got := errors.Is(err, SyntaxError); !got {
		t.Errorf("got false, want true")
	}
	if transport.lockSeconds != 0 {
		t.Fatal("invalid lock duration reached the transport")
	}
}
