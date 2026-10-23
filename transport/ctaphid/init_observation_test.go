package ctaphid_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/authenticator"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/options"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/transport/ctaphid"
)

func TestOpenRetainsINITAcrossIndependentSourceReads(t *testing.T) {
	for _, status := range []transport.StatusCode{transport.CTAP2_OK, transport.CTAP1_ERR_INVALID_COMMAND} {
		t.Run(status.String(), func(t *testing.T) {
			dev := newSourceDevice(t, status)

			tr, err := ctaphid.Open(t.Context(), dev)
			if err != nil {
				t.Fatal(err)
			}

			init := tr.InitResponse()

			want := ctaphid.InitResponse{
				Nonce:                            [8]byte(dev.requests[0].Data),
				CID:                              dev.cid,
				CTAPHIDProtocolVersionIdentifier: 2,
				MajorDeviceVersion:               3,
				MinorDeviceVersion:               4,
				BuildDeviceVersion:               5,
				CapabilityFlags:                  0x8d,
			}
			if init != want {
				t.Fatalf("InitResponse = %#v; want %#v", init, want)
			}

			if len(dev.requests) != 1 {
				t.Fatalf("reading INIT sent commands: %#v", dev.requests)
			}

			vendor, err := tr.Vendor(t.Context(), ctaphid.CTAPHID_VENDOR_FIRST, nil)
			if err != nil || !bytes.Equal(vendor.Data, []byte{0xa1, 0xb2}) {
				t.Fatalf("Vendor before GetInfo = %#v, %v", vendor, err)
			}

			auth, err := authenticator.New(t.Context(), tr)
			if status == transport.CTAP2_OK {
				if err != nil {
					t.Fatal(err)
				}

				info, valid := auth.GetInfoCached()
				if !valid {
					t.Fatal("authenticator did not retain eager GetInfo")
				}

				checkGetInfoResult(t, info, nil, status)

				if err := auth.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				checkGetInfoResult(t, protocol.AuthenticatorGetInfoResponse{}, err, status)

				if dev.closeCount != 0 {
					t.Fatal("failed authenticator construction closed the borrowed transport")
				}

				if err := tr.Close(); err != nil {
					t.Fatal(err)
				}
			}

			if dev.closeCount != 1 {
				t.Fatalf("Close calls = %d, want 1", dev.closeCount)
			}

			wantCommands := []ctaphid.Command{
				ctaphid.CTAPHID_INIT, ctaphid.CTAPHID_VENDOR_FIRST, ctaphid.CTAPHID_CBOR,
			}

			var commands []ctaphid.Command
			for _, request := range dev.requests {
				commands = append(commands, request.Command)
				if request.Command == ctaphid.CTAPHID_CBOR && !bytes.Equal(request.Data, []byte{byte(protocol.AuthenticatorGetInfo)}) {
					t.Fatalf("unexpected CBOR request: %#v", request)
				}
			}

			if !reflect.DeepEqual(commands, wantCommands) {
				t.Fatalf("commands = %v, want %v", commands, wantCommands)
			}

			if got := tr.InitResponse(); got != want {
				t.Fatalf("INIT changed after commands and Close: %#v", got)
			}
		})
	}
}

func TestClientGetInfoFailureDoesNotBlockVendor(t *testing.T) {
	dev := newSourceDevice(t, transport.CTAP1_ERR_INVALID_COMMAND)

	tr, err := ctaphid.Open(t.Context(), dev)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tr.Close() }()

	cl, err := client.NewClient(options.WithTransport(tr))
	if err != nil {
		t.Fatal(err)
	}

	if len(dev.requests) != 1 {
		t.Fatal("NewClient performed device I/O")
	}

	info, err := cl.GetInfo(t.Context())
	checkGetInfoResult(t, info, err, dev.status)

	vendor, err := tr.Vendor(t.Context(), ctaphid.CTAPHID_VENDOR_FIRST, nil)
	if err != nil || !bytes.Equal(vendor.Data, []byte{0xa1, 0xb2}) {
		t.Fatalf("Vendor after GetInfo failure = %#v, %v", vendor, err)
	}

	if dev.closeCount != 0 {
		t.Fatal("borrowed transport was closed")
	}
}

func checkGetInfoResult(t *testing.T, info protocol.AuthenticatorGetInfoResponse, err error, status transport.StatusCode) {
	t.Helper()

	if status == transport.CTAP2_OK {
		if err != nil || !reflect.DeepEqual(info.Versions, protocol.Versions{protocol.FIDO_2_0}) {
			t.Fatalf("GetInfo = %#v, %v", info, err)
		}

		return
	}

	var responseErr *transport.CTAPError
	if !errors.As(err, &responseErr) || responseErr.StatusCode != status {
		t.Fatalf("GetInfo error = %v, want status %v", err, status)
	}
}

type sourceDevice struct {
	t          *testing.T
	cid        ctaphid.ChannelID
	status     transport.StatusCode
	responses  chan []byte
	requests   []testhid.Request
	closed     chan struct{}
	closeCount int
}

func newSourceDevice(t *testing.T, status transport.StatusCode) *sourceDevice {
	return &sourceDevice{
		t: t, cid: ctaphid.ChannelID{1, 2, 3, 4}, status: status,
		responses: make(chan []byte, 1), closed: make(chan struct{}),
	}
}

func (d *sourceDevice) Write(_ context.Context, p []byte) (int, error) {
	requests, err := testhid.ParseRequests(p)
	if err != nil {
		return 0, err
	}

	d.requests = append(d.requests, requests...)
	request := requests[0]

	var data []byte

	switch request.Command {
	case ctaphid.CTAPHID_INIT:
		data = append(request.Data, d.cid[:]...)
		data = append(data, 2, 3, 4, 5, 0x8d)
	case ctaphid.CTAPHID_CBOR:
		data = []byte{byte(d.status)}
		if d.status == transport.CTAP2_OK {
			info, err := cbor.Marshal(protocol.AuthenticatorGetInfoResponse{Versions: protocol.Versions{protocol.FIDO_2_0}})
			if err != nil {
				return 0, err
			}

			data = append(data, info...)
		}
	case ctaphid.CTAPHID_VENDOR_FIRST:
		data = []byte{0xa1, 0xb2}
	default:
		d.t.Errorf("unexpected command: %v", request.Command)
	}

	msg, err := ctaphid.NewMessage(request.CID, request.Command, data)
	if err != nil {
		return 0, err
	}

	var encoded bytes.Buffer
	if _, err := msg.WriteTo(&encoded); err != nil {
		return 0, err
	}

	d.responses <- encoded.Bytes()[1:]

	return len(p), nil
}

func (d *sourceDevice) Read(ctx context.Context, p []byte) (int, error) {
	select {
	case data := <-d.responses:
		return copy(p, data), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.closed:
		return 0, io.ErrClosedPipe
	}
}

func (d *sourceDevice) Close() error {
	d.closeCount++
	close(d.closed)

	return nil
}
