package ctaphid

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func requireCTAPHIDError(t testing.TB, err error, want Error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error")
	}

	var response *ErrorResponse
	if err := err; !errors.As(err, &response) {
		t.Fatalf("error %v does not match requested type", err)
	}
	if got, want := response.ErrorCode, want; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := byte(response.ErrorCode), byte(want); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	{
		err, want := err, want.String()
		if err == nil || err.Error() != want {
			t.Errorf("got error %v, want %q", err, want)
		}
	}
}

func rawResponseMessage(t testing.TB, cid ChannelID, cmd Command, data []byte) []byte {
	t.Helper()

	msg, err := NewMessage(cid, cmd, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	buf := bytes.NewBuffer(nil)
	for _, p := range msg {
		_, err := p.WriteTo(buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	return bytes.Clone(buf.Bytes())
}

func assertSingleReportRequest(t testing.TB, written []byte, cid ChannelID, cmd Command, data []byte) {
	t.Helper()

	if got, want := len(written), hidReportPacketSize; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}
	if got, want := written[0], byte(0); got != want {
		t.Errorf("got %#v, want %#v; context: %s", got, want, "report ID")
	}

	raw := written[1:]
	if got, want := raw[:4], cid[:]; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v; context: %s", got, want, "CID")
	}
	if got, want := raw[4], byte(cmd)|INIT_PACKET_BIT; got != want {
		t.Errorf("got %#v, want %#v; context: %s", got, want, "command")
	}
	if got, want := binary.BigEndian.Uint16(raw[5:7]), uint16(len(data)); got != want {
		t.Errorf("got %#v, want %#v; context: %s", got, want, "BCNT")
	}
	if len(data) == 0 {
		if got := raw[initPacketHeaderSize : initPacketHeaderSize+len(data)]; len(got) != 0 {
			t.Errorf("got non-empty value %#v", got)
		}
	} else {
		if got, want := raw[initPacketHeaderSize:initPacketHeaderSize+len(data)], data; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got, want := raw[initPacketHeaderSize+len(data):], make([]byte, initPacketDataSize-len(data)); (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
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

func newTestTransport(device Device, cid ChannelID) *Transport {
	return &Transport{device: newChannelDevice(device, cid), init: InitResponse{CID: cid}}
}
