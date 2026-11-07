package iso7816

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	baseiso7816 "github.com/telesma-app/iso7816"
)

func TestCBORStopsAfterIntermediateAPDURejection(t *testing.T) {
	for _, test := range []struct {
		name     string
		response []byte
		status   baseiso7816.StatusWord
	}{
		{name: "security status", response: []byte{0x69, 0x82}, status: 0x6982},
		{name: "security status with data", response: []byte{0xaa, 0x69, 0x82}, status: 0x6982},
		{name: "keepalive", response: []byte{0x01, 0x91, 0x00}, status: 0x9100},
		{name: "61 continuation", response: []byte{0x61, 0x01}, status: 0x6101},
		{name: "9f continuation", response: []byte{0x9f, 0x01}, status: 0x9f01},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := bytes.Repeat([]byte{0xaa}, 241)
			data[0] = byte(protocol.AuthenticatorMakeCredential)
			card := newSelectedCard(t, exchange{
				request:  append([]byte{0x90, 0x10, 0x00, 0x00, 0xf0}, data[:240]...),
				response: test.response,
			})

			_, err := CBOR(t.Context(), card, data)

			var apduErr *baseiso7816.APDUError
			if !errors.As(err, &apduErr) || apduErr.StatusWord() != test.status {
				t.Fatalf("CBOR = %v, want APDU status %s", err, test.status)
			}

			var invalidated *ctaptransport.DeviceInvalidatedError
			if errors.As(err, &invalidated) {
				t.Fatalf("intermediate rejection invalidated card: %v", err)
			}

			if len(card.exchanges) != 0 {
				t.Fatalf("remaining APDUs = %d", len(card.exchanges))
			}
		})
	}
}

func TestCBORReassemblesResponseAfterChainedCommand(t *testing.T) {
	for _, sw1 := range []byte{0x61, 0x9f} {
		t.Run(fmt.Sprintf("%x", sw1), func(t *testing.T) {
			data := bytes.Repeat([]byte{0xaa}, 241)
			data[0] = byte(protocol.AuthenticatorMakeCredential)
			card := newSelectedCard(t,
				exchange{
					request:  append([]byte{0x90, 0x10, 0x00, 0x00, 0xf0}, data[:240]...),
					response: []byte{0x90, 0x00},
				},
				exchange{
					request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0xaa, 0x00},
					response: []byte{0x00, 0xa1, sw1, 0x02},
				},
				exchange{
					request:  []byte{0x80, 0xc0, 0x00, 0x00, 0x02},
					response: []byte{0x01, 0x02, 0x90, 0x00},
				},
			)

			response, err := CBOR(t.Context(), card, data)
			if err != nil {
				t.Fatal(err)
			}

			if response.StatusCode != ctaptransport.CTAP2_OK || !bytes.Equal(response.Data, []byte{0xa1, 0x01, 0x02}) {
				t.Errorf("CBOR = %#v, want success with a10102", response)
			}

			if len(card.exchanges) != 0 {
				t.Fatalf("remaining APDUs = %d", len(card.exchanges))
			}
		})
	}
}
