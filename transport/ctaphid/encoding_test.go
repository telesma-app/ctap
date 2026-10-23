package ctaphid

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"testing"
)

var respPackets = []string{
	`Ri/vTZAAhgamAQICCQOlAQIDOBggASFYIGUwTZr5xmK+EffrDnBoxG3fLYUnqCxMJY++N2PkjG2VIlggGJxNrQ==`,
	`Ri/vTQDlCT2rXnrYQhN0DM0LWCASXti9f+sreUfUi4WEBlgg9LagOl5Yndw64EuM+UAGwRIRo4lJszckFs5EVw==`,
	`Ri/vTQFS7EH2CRYKamtyYXNvdnMua3k=`,
}

func TestNewMessage(t *testing.T) {
	// Write packets into a buffer
	buf := bytes.NewBuffer(nil)

	responsePackets := make([][]byte, 0, len(respPackets))
	for _, pStr := range respPackets {
		p, err := base64.StdEncoding.DecodeString(pStr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		padded := make([]byte, hidPacketSize)
		copy(padded, p)
		responsePackets = append(responsePackets, padded)
		buf.Write(padded)
	}

	// Read a message from it
	m := new(Message)

	_, err := m.ReadFrom(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	{
		// Write it back to another buffer
		buf := bytes.NewBuffer(nil)

		_, err = m.WriteTo(buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		writtenBytes := buf.Bytes()
		if got, want := len(writtenBytes), len(responsePackets)*hidReportPacketSize; got != want {
			t.Fatalf("got length %d, want %d", got, want)
		}

		for i, expectedPacket := range responsePackets {
			chunk := writtenBytes[i*hidReportPacketSize : (i+1)*hidReportPacketSize]
			if got, want := chunk[0], byte(0); got != want {
				t.Errorf("got %#v, want %#v", got, want)
			}

			if got, want := chunk[1:], expectedPacket; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
				t.Errorf("got %#v, want %#v", got, want)
			}
		}
	}
}

func TestNewMessageFramesSpecPayloadBoundaries(t *testing.T) {
	// CTAP 2.3 PS, 11.2.4: with 64-byte packets, init packets carry
	// 57 bytes, continuation packets carry 59 bytes, and max payload is 7609.
	cid := ChannelID{1, 2, 3, 4}

	for _, tc := range []struct {
		name        string
		payloadLen  int
		packetCount int
	}{
		{name: "empty", payloadLen: 0, packetCount: 1},
		{name: "fills init packet", payloadLen: initPacketDataSize, packetCount: 1},
		{name: "requires first continuation", payloadLen: initPacketDataSize + 1, packetCount: 2},
		{name: "maximum payload", payloadLen: 7609, packetCount: 129},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xaa}, tc.payloadLen)

			msg, err := NewMessage(cid, CTAPHID_PING, payload)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got, want := len(msg), tc.packetCount; got != want {
				t.Fatalf("got length %d, want %d", got, want)
			}

			buf := bytes.NewBuffer(nil)

			n, err := msg.WriteTo(buf)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got, want := n, int64(tc.packetCount*hidReportPacketSize); got != want {
				t.Fatalf("got %#v, want %#v", got, want)
			}

			written := buf.Bytes()
			if got, want := len(written), tc.packetCount*hidReportPacketSize; got != want {
				t.Fatalf("got length %d, want %d", got, want)
			}

			for packetIndex := range tc.packetCount {
				chunk := written[packetIndex*hidReportPacketSize : (packetIndex+1)*hidReportPacketSize]
				if got, want := chunk[0], byte(0); got != want {
					t.Errorf("got %#v, want %#v; context: %s", got, want, "report ID")
				}

				raw := chunk[1:]
				if got, want := raw[:4], cid[:]; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
					t.Errorf("got %#v, want %#v; context: %s", got, want, "CID")
				}

				if packetIndex == 0 {
					if got, want := raw[4], byte(CTAPHID_PING)|INIT_PACKET_BIT; got != want {
						t.Errorf("got %#v, want %#v; context: %s", got, want, "init command byte")
					}

					if got, want := binary.BigEndian.Uint16(raw[5:7]), uint16(tc.payloadLen); got != want {
						t.Errorf("got %#v, want %#v; context: %s", got, want, "BCNT")
					}

					dataLen := min(tc.payloadLen, initPacketDataSize)
					if got, want := raw[initPacketHeaderSize:initPacketHeaderSize+dataLen], payload[:dataLen]; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
						t.Errorf("got %#v, want %#v", got, want)
					}

					if got, want := raw[initPacketHeaderSize+dataLen:], make([]byte, initPacketDataSize-dataLen); (got == nil) != (want == nil) || !bytes.Equal(got, want) {
						t.Errorf("got %#v, want %#v", got, want)
					}

					continue
				}

				sequence := packetIndex - 1
				if got, want := raw[4], byte(sequence); got != want {
					t.Errorf("got %#v, want %#v; context: %s", got, want, "continuation sequence")
				}

				offset := initPacketDataSize + sequence*continuationPacketDataSize

				dataLen := min(tc.payloadLen-offset, continuationPacketDataSize)
				if got, want := raw[continuationPacketHeaderSize:continuationPacketHeaderSize+dataLen], payload[offset:offset+dataLen]; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
					t.Errorf("got %#v, want %#v", got, want)
				}

				if got, want := raw[continuationPacketHeaderSize+dataLen:], make([]byte, continuationPacketDataSize-dataLen); (got == nil) != (want == nil) || !bytes.Equal(got, want) {
					t.Errorf("got %#v, want %#v", got, want)
				}
			}
		})
	}
}

func TestNewMessageRejectsPayloadAboveSpecMaximum(t *testing.T) {
	_, err := NewMessage(ChannelID{1, 2, 3, 4}, CTAPHID_PING, bytes.Repeat([]byte{0xaa}, 7610))
	if err == nil {
		t.Fatalf("expected an error")
	}

	if got := errors.Is(err, ErrMessageTooLarge); !got {
		t.Errorf("got false, want true")
	}
}
