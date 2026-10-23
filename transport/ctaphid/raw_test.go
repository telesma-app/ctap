package ctaphid

import (
	"bytes"
	"slices"
	"strconv"
	"testing"
)

func TestMessagePayloadBoundaries(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}

	for _, payloadLen := range []int{
		0,
		initPacketDataSize,
		initPacketDataSize + 1,
		7609,
	} {
		t.Run(strconv.Itoa(payloadLen), func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xa5}, payloadLen)

			message, err := NewMessage(cid, CTAPHID_PING, payload)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got, want := message.CID(), cid; got != want {
				t.Errorf("got %#v, want %#v", got, want)
			}

			if got, want := message.Command(), CTAPHID_PING; got != want {
				t.Errorf("got %#v, want %#v", got, want)
			}

			if got, want := message.DeclaredLength(), uint16(payloadLen); got != want {
				t.Errorf("got %#v, want %#v", got, want)
			}

			if got, want := message.Payload(), payload; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
				t.Errorf("got %#v, want %#v", got, want)
			}
		})
	}
}

func TestMessageOutputReportsCanBeModified(t *testing.T) {
	message, err := NewMessage(
		ChannelID{1, 2, 3, 4},
		CTAPHID_PING,
		bytes.Repeat([]byte{0xa5}, initPacketDataSize+1),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := message.OutputReports()
	reports := message.OutputReports()
	reports[0][1] ^= 0xff
	reports[0], reports[1] = reports[1], reports[0]

	if got, want := message.OutputReports(), want; (got == nil) != (want == nil) || !slices.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestMessageOutputReportBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name        string
		payloadLen  int
		reportCount int
	}{
		{name: "empty", payloadLen: 0, reportCount: 1},
		{name: "init boundary", payloadLen: initPacketDataSize, reportCount: 1},
		{name: "first continuation", payloadLen: initPacketDataSize + 1, reportCount: 2},
		{name: "maximum", payloadLen: 7609, reportCount: 129},
	} {
		t.Run(tc.name, func(t *testing.T) {
			message, err := NewMessage(
				ChannelID{1, 2, 3, 4},
				CTAPHID_PING,
				bytes.Repeat([]byte{0xa5}, tc.payloadLen),
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			reports := message.OutputReports()
			if got, want := len(reports), tc.reportCount; got != want {
				t.Fatalf("got length %d, want %d", got, want)
			}

			for _, report := range reports {
				if got := report[0]; got != 0 {
					t.Errorf("got %#v, want zero value", got)
				}
			}
		})
	}
}
