package testhid

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/transport/ctaphid"
)

const (
	hidPacketSize                = 64
	hidReportPacketSize          = hidPacketSize + 1
	initPacketBit                = 0x80
	initPacketHeaderSize         = 7
	continuationPacketHeaderSize = 5
	initPacketDataSize           = hidPacketSize - initPacketHeaderSize
	continuationPacketDataSize   = hidPacketSize - continuationPacketHeaderSize
)

type Response struct {
	CID     ctaphid.ChannelID
	Command ctaphid.Command
	Data    []byte
}

func Message(cid ctaphid.ChannelID, command ctaphid.Command, data []byte) Response {
	return Response{CID: cid, Command: command, Data: data}
}

func CBOROK(cid ctaphid.ChannelID, data []byte) Response {
	return Message(cid, ctaphid.CTAPHID_CBOR, append([]byte{byte(ctaptransport.CTAP2_OK)}, data...))
}

func CBORStatus(cid ctaphid.ChannelID, status ctaptransport.StatusCode) Response {
	return Message(cid, ctaphid.CTAPHID_CBOR, []byte{byte(status)})
}

func CTAPHIDError(cid ctaphid.ChannelID, err ctaphid.Error) Response {
	return Message(cid, ctaphid.CTAPHID_ERROR, []byte{byte(err)})
}

func Keepalive(cid ctaphid.ChannelID, status ctaphid.KeepaliveStatusCode) Response {
	return Message(cid, ctaphid.CTAPHID_KEEPALIVE, []byte{byte(status)})
}

type Device struct {
	reads  *bytes.Reader
	writes bytes.Buffer
	closed bool
}

func New(t testing.TB, responses ...Response) *Device {
	t.Helper()

	var reads bytes.Buffer
	for _, response := range responses {
		msg, err := ctaphid.NewMessage(response.CID, response.Command, response.Data)
		if err != nil {
			t.Fatalf("new CTAPHID response message: %v", err)
		}

		var withReportIDs bytes.Buffer
		if _, err := msg.WriteTo(&withReportIDs); err != nil {
			t.Fatalf("encode CTAPHID response message: %v", err)
		}
		reads.Write(stripReportIDs(withReportIDs.Bytes()))
	}

	return &Device{reads: bytes.NewReader(reads.Bytes())}
}

func NewCBORDevice(t testing.TB, cid ctaphid.ChannelID, responses ...[]byte) *Device {
	t.Helper()

	script := make([]Response, 0, len(responses))
	for _, response := range responses {
		script = append(script, CBOROK(cid, response))
	}

	return New(t, script...)
}

func (d *Device) Read(_ context.Context, p []byte) (int, error) {
	return d.reads.Read(p)
}

func (d *Device) Write(_ context.Context, p []byte) (int, error) {
	return d.writes.Write(p)
}

func (d *Device) Close() error {
	d.closed = true
	return nil
}

func (d *Device) Closed() bool {
	return d.closed
}

func (d *Device) Writes() []byte {
	return append([]byte(nil), d.writes.Bytes()...)
}

type Request struct {
	CID     ctaphid.ChannelID
	Command ctaphid.Command
	Data    []byte
}

func (d *Device) Requests(t testing.TB) []Request {
	t.Helper()

	requests, err := ParseRequests(d.writes.Bytes())
	if err != nil {
		t.Fatalf("parse CTAPHID requests: %v", err)
	}

	return requests
}

func (d *Device) FirstRequest(t testing.TB) Request {
	t.Helper()

	requests := d.Requests(t)
	if len(requests) == 0 {
		t.Fatalf("expected at least one CTAPHID request")
	}

	return requests[0]
}

func (d *Device) FirstCTAPPayload(t testing.TB) (protocol.Command, []byte) {
	t.Helper()

	return d.FirstRequest(t).CTAPPayload(t)
}

func (d *Device) FirstCTAPRequestMap(t testing.TB) (protocol.Command, map[uint64]any) {
	t.Helper()

	return d.FirstRequest(t).CTAPRequestMap(t)
}

func ParseRequests(written []byte) ([]Request, error) {
	var requests []Request
	for len(written) > 0 {
		request, consumed, err := parseRequest(written)
		if err != nil {
			return nil, err
		}
		requests = append(requests, request)
		written = written[consumed:]
	}

	return requests, nil
}

func (r Request) CTAPPayload(t testing.TB) (protocol.Command, []byte) {
	t.Helper()

	if r.Command != ctaphid.CTAPHID_CBOR {
		t.Fatalf("expected CTAPHID_CBOR request, got %s", r.Command)
	}
	if len(r.Data) == 0 {
		t.Fatalf("expected CTAP command byte in CTAPHID_CBOR request")
	}

	return protocol.Command(r.Data[0]), append([]byte(nil), r.Data[1:]...)
}

func (r Request) CTAPRequestMap(t testing.TB) (protocol.Command, map[uint64]any) {
	t.Helper()

	command, requestCBOR := r.CTAPPayload(t)
	var request map[uint64]any
	if err := cbor.Unmarshal(requestCBOR, &request); err != nil {
		t.Fatalf("decode CTAP request CBOR: %v", err)
	}

	return command, request
}

func stripReportIDs(packets []byte) []byte {
	stripped := make([]byte, 0, len(packets)/hidReportPacketSize*hidPacketSize)
	for len(packets) >= hidReportPacketSize {
		stripped = append(stripped, packets[1:hidReportPacketSize]...)
		packets = packets[hidReportPacketSize:]
	}

	return stripped
}

func parseRequest(written []byte) (Request, int, error) {
	if len(written) < hidReportPacketSize {
		return Request{}, 0, io.ErrUnexpectedEOF
	}
	if written[0] != 0 {
		return Request{}, 0, fmt.Errorf("unexpected report ID %d", written[0])
	}

	var request Request
	copy(request.CID[:], written[1:5])

	cmd := written[5]
	if cmd&initPacketBit == 0 {
		return Request{}, 0, fmt.Errorf("continuation packet before init packet")
	}
	request.Command = ctaphid.Command(cmd &^ initPacketBit)

	length := int(binary.BigEndian.Uint16(written[6:8]))
	request.Data = make([]byte, 0, length)

	firstPacketDataLen := min(length, initPacketDataSize)
	request.Data = append(request.Data, written[8:8+firstPacketDataLen]...)
	remaining := length - firstPacketDataLen
	consumed := hidReportPacketSize
	expectedSequence := byte(0)

	for remaining > 0 {
		if len(written) < consumed+hidReportPacketSize {
			return Request{}, 0, io.ErrUnexpectedEOF
		}
		if written[consumed] != 0 {
			return Request{}, 0, fmt.Errorf("unexpected report ID %d", written[consumed])
		}
		if !bytes.Equal(written[consumed+1:consumed+5], request.CID[:]) {
			return Request{}, 0, fmt.Errorf("unexpected continuation CID")
		}
		if written[consumed+5] != expectedSequence {
			return Request{}, 0, fmt.Errorf("unexpected continuation sequence")
		}

		dataLen := min(remaining, continuationPacketDataSize)
		start := consumed + 1 + continuationPacketHeaderSize
		request.Data = append(request.Data, written[start:start+dataLen]...)
		remaining -= dataLen
		consumed += hidReportPacketSize
		expectedSequence++
	}

	return request, consumed, nil
}

var _ ctaphid.Device = (*Device)(nil)

// Transport exchanges commands on the scripted device's fixed channel.
type Transport struct {
	*Device
	CID ctaphid.ChannelID
}

func (t Transport) CBOR(ctx context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	return ctaphid.CBOR(ctx, t.Device, t.CID, data)
}
