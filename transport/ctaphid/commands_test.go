package ctaphid

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
)

func TestCBORSkipsKeepaliveBeforeSuccessResponse(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}
	request := []byte{byte(protocol.AuthenticatorGetInfo)}
	response := []byte{byte(ctaptransport.CTAP2_OK), 0xa1, 0x01, 0x02}
	reads := bytes.NewBuffer(nil)
	reads.Write(rawResponseMessage(t, cid, CTAPHID_KEEPALIVE, []byte{byte(STATUS_PROCESSING)}))
	reads.Write(rawResponseMessage(t, cid, CTAPHID_CBOR, response))

	dev := &scriptedDevice{reads: bytes.NewReader(reads.Bytes())}

	resp, err := CBOR(context.Background(), dev, cid, request)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := resp.StatusCode, ctaptransport.CTAP2_OK; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := resp.Data, response[1:]; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	assertSingleReportRequest(t, dev.writes.Bytes(), cid, CTAPHID_CBOR, request)
}

func TestCBORSkipsResponseForAnotherChannel(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}
	otherCID := ChannelID{5, 6, 7, 8}
	request := []byte{byte(protocol.AuthenticatorGetInfo)}
	response := []byte{byte(ctaptransport.CTAP2_OK), 0xa1, 0x01, 0x02}
	reads := bytes.NewBuffer(nil)
	reads.Write(rawResponseMessage(t, otherCID, CTAPHID_CBOR, response))
	reads.Write(rawResponseMessage(t, cid, CTAPHID_CBOR, response))

	dev := &scriptedDevice{reads: bytes.NewReader(reads.Bytes())}

	resp, err := CBOR(context.Background(), dev, cid, request)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := resp.Data, response[1:]; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestCBORReturnsTypedCTAPError(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}
	request := []byte{byte(protocol.AuthenticatorGetInfo)}
	response := []byte{byte(ctaptransport.CTAP2_ERR_INVALID_CBOR)}
	dev := &scriptedDevice{
		reads: bytes.NewReader(rawResponseMessage(t, cid, CTAPHID_CBOR, response)),
	}

	_, err := CBOR(context.Background(), dev, cid, request)
	if err == nil {
		t.Fatalf("expected an error")
	}

	var ctapErr *ctaptransport.CTAPError
	if got := errors.As(err, &ctapErr); !got {
		t.Fatalf("got false, want true")
	}
	if got, want := ctapErr.Command, protocol.AuthenticatorGetInfo; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := ctapErr.StatusCode, ctaptransport.CTAP2_ERR_INVALID_CBOR; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if container, element := err.Error(), "AuthenticatorGetInfo failed"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}
	assertSingleReportRequest(t, dev.writes.Bytes(), cid, CTAPHID_CBOR, request)
}

func TestCBORReturnsTypedCTAPHIDError(t *testing.T) {
	tests := []struct {
		name string
		code Error
	}{
		{name: "known", code: ERR_INVALID_CHANNEL},
		{name: "unknown", code: Error(0xe1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cid := ChannelID{1, 2, 3, 4}
			request := []byte{byte(protocol.AuthenticatorGetInfo)}
			dev := &scriptedDevice{
				reads: bytes.NewReader(rawResponseMessage(t, cid, CTAPHID_ERROR, []byte{byte(tt.code)})),
			}

			_, err := CBOR(context.Background(), dev, cid, request)
			requireCTAPHIDError(t, err, tt.code)
			assertSingleReportRequest(t, dev.writes.Bytes(), cid, CTAPHID_CBOR, request)
		})
	}
}

func TestCommandsReturnTypedCTAPHIDError(t *testing.T) {
	tests := []struct {
		name        string
		cid         ChannelID
		requestCmd  Command
		requestData []byte
		responseErr Error
		invoke      func(context.Context, *scriptedDevice, ChannelID) error
	}{
		{
			name:        "Init/invalid channel",
			cid:         BROADCAST_CID,
			requestCmd:  CTAPHID_INIT,
			requestData: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			responseErr: ERR_INVALID_CHANNEL,
			invoke: func(ctx context.Context, dev *scriptedDevice, cid ChannelID) error {
				_, err := Init(ctx, dev, cid, [8]byte{1, 2, 3, 4, 5, 6, 7, 8})
				return err
			},
		},
		{
			name:        "Ping/invalid length",
			cid:         ChannelID{1, 2, 3, 4},
			requestCmd:  CTAPHID_PING,
			requestData: []byte("hello"),
			responseErr: ERR_INVALID_LEN,
			invoke: func(ctx context.Context, dev *scriptedDevice, cid ChannelID) error {
				_, err := Ping(ctx, dev, cid, []byte("hello"))
				return err
			},
		},
		{
			name:        "Wink/channel busy",
			cid:         ChannelID{1, 2, 3, 4},
			requestCmd:  CTAPHID_WINK,
			responseErr: ERR_CHANNEL_BUSY,
			invoke: func(ctx context.Context, dev *scriptedDevice, cid ChannelID) error {
				return Wink(ctx, dev, cid)
			},
		},
		{
			name:        "Lock/lock required",
			cid:         ChannelID{1, 2, 3, 4},
			requestCmd:  CTAPHID_LOCK,
			requestData: []byte{1},
			responseErr: ERR_LOCK_REQUIRED,
			invoke: func(ctx context.Context, dev *scriptedDevice, cid ChannelID) error {
				return Lock(ctx, dev, cid, 1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dev := &scriptedDevice{reads: bytes.NewReader(rawResponseMessage(
				t, tt.cid, CTAPHID_ERROR, []byte{byte(tt.responseErr)},
			))}

			err := tt.invoke(context.Background(), dev, tt.cid)
			requireCTAPHIDError(t, err, tt.responseErr)
			assertSingleReportRequest(t, dev.writes.Bytes(), tt.cid, tt.requestCmd, tt.requestData)
		})
	}
}

func TestInitAcceptsExtendedSuccessResponse(t *testing.T) {
	// CTAP 2.3, section 11.2.9.1.3 requires accepting INIT responses longer than 17 bytes.
	nonce := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	allocatedCID := ChannelID{9, 8, 7, 6}
	responseData := append([]byte{}, nonce[:]...)
	responseData = append(responseData, allocatedCID[:]...)
	responseData = append(responseData, 2, 3, 4, 5, byte(CAPABILITY_WINK)|byte(CAPABILITY_CBOR))
	responseData = append(responseData, 0xfe, 0xed)

	dev := &scriptedDevice{
		reads: bytes.NewReader(rawResponseMessage(t, BROADCAST_CID, CTAPHID_INIT, responseData)),
	}

	resp, err := Init(context.Background(), dev, BROADCAST_CID, nonce)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := resp.Nonce, nonce; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := resp.CID, allocatedCID; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := resp.CTAPHIDProtocolVersionIdentifier, byte(2); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := resp.MajorDeviceVersion, byte(3); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := resp.MinorDeviceVersion, byte(4); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := resp.BuildDeviceVersion, byte(5); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got := resp.ImplementsWink(); !got {
		t.Errorf("got false, want true")
	}
	if got := resp.ImplementsCBOR(); !got {
		t.Errorf("got false, want true")
	}
	if got := resp.NotImplementsMSG(); got {
		t.Errorf("got true, want false")
	}

	assertSingleReportRequest(t, dev.writes.Bytes(), BROADCAST_CID, CTAPHID_INIT, nonce[:])
}

func TestInitSkipsAnotherClientResponse(t *testing.T) {
	nonce := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	otherResponse := []byte{8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 2, 3, 4, 5, byte(CAPABILITY_CBOR)}
	response := append([]byte{}, nonce[:]...)
	response = append(response, 9, 8, 7, 6, 2, 3, 4, 5, byte(CAPABILITY_CBOR))
	reads := bytes.NewBuffer(nil)
	reads.Write(rawResponseMessage(t, BROADCAST_CID, CTAPHID_INIT, otherResponse))
	reads.Write(rawResponseMessage(t, BROADCAST_CID, CTAPHID_INIT, response))
	dev := &scriptedDevice{
		reads: bytes.NewReader(reads.Bytes()),
	}

	got, err := Init(context.Background(), dev, BROADCAST_CID, nonce)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := ChannelID{9, 8, 7, 6}, got.CID
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestPingSkipsKeepaliveBeforeSuccessResponse(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}
	data := []byte("hello")
	reads := bytes.NewBuffer(nil)
	reads.Write(rawResponseMessage(t, cid, CTAPHID_KEEPALIVE, []byte{byte(STATUS_PROCESSING)}))
	reads.Write(rawResponseMessage(t, cid, CTAPHID_PING, data))

	dev := &scriptedDevice{reads: bytes.NewReader(reads.Bytes())}

	resp, err := Ping(context.Background(), dev, cid, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := resp.Bytes, data; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	assertSingleReportRequest(t, dev.writes.Bytes(), cid, CTAPHID_PING, data)
}

func TestCancelWritesRequestAndDoesNotReadResponse(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}
	dev := &scriptedDevice{reads: bytes.NewReader(nil)}

	err := Cancel(context.Background(), dev, cid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSingleReportRequest(t, dev.writes.Bytes(), cid, CTAPHID_CANCEL, nil)
}

func TestWinkWritesRequestAndAcceptsEmptySuccessResponse(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}
	dev := &scriptedDevice{
		reads: bytes.NewReader(rawResponseMessage(t, cid, CTAPHID_WINK, nil)),
	}

	err := Wink(context.Background(), dev, cid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSingleReportRequest(t, dev.writes.Bytes(), cid, CTAPHID_WINK, nil)
}

func TestLockRejectsInvalidDuration(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}
	dev := &scriptedDevice{reads: bytes.NewReader(nil)}

	err := Lock(context.Background(), dev, cid, 11)
	if err == nil {
		t.Fatalf("expected an error")
	}
	if got := errors.Is(err, ErrInvalidRequestMessage); !got {
		t.Errorf("got false, want true")
	}
	if got := dev.writes.Bytes(); len(got) != 0 {
		t.Errorf("got non-empty value %#v", got)
	}
}

func TestLockWritesDurationAndAcceptsEmptySuccessResponse(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}
	dev := &scriptedDevice{
		reads: bytes.NewReader(rawResponseMessage(t, cid, CTAPHID_LOCK, nil)),
	}

	err := Lock(context.Background(), dev, cid, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSingleReportRequest(t, dev.writes.Bytes(), cid, CTAPHID_LOCK, []byte{10})
}
