package ctaphid

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"testing"

	ctaptransport "github.com/telesma-app/ctap/transport"
)

const (
	getInfoResponseDump = "y2QaNpABawCyAYRmVTJGX1YyaEZJRE9fMl8waEZJRE9fMl8xbEZJRE9fMl8xX1BSRQKFaGNyZWRCbG9ia2NyZctkGjYAZFByb3RlY3RraG1hYy1zZWNyZXRsbGFyZ2VCbG9iS2V5bG1pblBpbkxlbmd0aANQ6rtGzOJBgL+unpbLZBo2AfptKXXPBKxicmv1YnVw9WRwbGF09GhhbHdheXNVdvRoY3JlZE1nbXT1aWF1dGhuckNmZ/VpY2xpZW50y2QaNgJQaW71amxhcmdlQmxvYnP1bnBpblV2QXV0aFRva2Vu9W9zZXRNaW5QSU5MZW5ndGj1cG1ha2VDcmVkVctkGjYDdk5vdFJxZPV1Y3JlZGVudGlhbE1nbXRQcmV2aWV39QUZCAAGggIBBwgIGGAJgmN1c2JjbmZjCoKiY2HLZBo2BGxnJmR0eXBlanB1YmxpYy1rZXmiY2FsZydkdHlwZWpwdWJsaWMta2V5CxkIAAz0DQYOGQEADxggEAYTy2QaNgWhZEZJRE8DFBkBFgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)

type scriptedDevice struct {
	reads  *bytes.Reader
	writes bytes.Buffer
}

func (d *scriptedDevice) Read(_ context.Context, p []byte) (int, error) {
	return d.reads.Read(p)
}

func (d *scriptedDevice) Write(_ context.Context, p []byte) (int, error) {
	return d.writes.Write(p)
}

func (d *scriptedDevice) Close() error { return nil }

func TestMessage_ReadFrom(t *testing.T) {
	m := new(Message)

	resp, _ := base64.StdEncoding.DecodeString(getInfoResponseDump)
	device := bytes.NewReader(resp)

	n, err := m.ReadFrom(device)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := n, int64(len(resp)); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestMessage_ReadFromRejectsInvalidContinuationSequence(t *testing.T) {
	raw := newRawMessage(t)
	raw[hidPacketSize+4] = 1

	m := new(Message)

	_, err := m.ReadFrom(bytes.NewReader(raw))
	if err == nil {
		t.Fatalf("expected an error")
	}

	if got := errors.Is(err, ErrInvalidResponseMessage); !got {
		t.Errorf("got false, want true")
	}
}

func TestMessage_ReadFromRejectsInvalidContinuationCID(t *testing.T) {
	raw := newRawMessage(t)
	raw[hidPacketSize] ^= 0xff

	m := new(Message)

	_, err := m.ReadFrom(bytes.NewReader(raw))
	if err == nil {
		t.Fatalf("expected an error")
	}

	if got := errors.Is(err, ErrInvalidResponseMessage); !got {
		t.Errorf("got false, want true")
	}
}

func TestCBORSkipsUnexpectedResponseCID(t *testing.T) {
	responseCID := ChannelID{9, 9, 9, 9}

	msg, err := NewMessage(responseCID, CTAPHID_CBOR, []byte{byte(ctaptransport.CTAP2_OK)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	reads := bytes.NewBuffer(nil)
	for _, p := range msg {
		_, err := p.WriteTo(reads)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	dev := &scriptedDevice{reads: bytes.NewReader(reads.Bytes())}

	_, err = newTestTransport(dev, ChannelID{1, 2, 3, 4}).CBOR(context.Background(), []byte{0x04})
	if err == nil {
		t.Fatalf("expected an error")
	}

	if err, target := err, io.EOF; !errors.Is(err, target) {
		t.Errorf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	var ioErr *ctaptransport.IOError
	if got := errors.As(err, &ioErr); !got {
		t.Errorf("got false, want true")
	}
}

func newRawMessage(t *testing.T) []byte {
	t.Helper()

	msg, err := NewMessage(ChannelID{1, 2, 3, 4}, CTAPHID_CBOR, bytes.Repeat([]byte{0xaa}, initPacketDataSize+1))
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

	return buf.Bytes()
}
