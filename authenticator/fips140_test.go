package authenticator

import (
	cryptofips140 "crypto/fips140"
	"errors"
	"testing"

	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapfips140 "github.com/telesma-app/ctap/fips140"
	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/protocol"
)

func TestFIPS140AuthenticatorSelectsPinUvAuthProtocolTwo(t *testing.T) {
	requireAuthenticatorFIPS140(t)

	t.Run("skips protocol one", func(t *testing.T) {
		d := &Device{info: protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{
				protocol.PinUvAuthProtocolOne,
				protocol.PinUvAuthProtocolTwo,
			},
		}}

		got, err := d.requirePinUvAuthProtocol()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if want := protocol.PinUvAuthProtocolTwo; got != want {
			t.Fatalf("protocol = %#v, want %#v", got, want)
		}
	})

	t.Run("rejects protocol one only", func(t *testing.T) {
		d := &Device{info: protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		}}

		_, err := d.requirePinUvAuthProtocol()
		assertAuthenticatorFIPS140NotAllowed(t, err)
	})
}

func TestFIPS140AuthenticatorGetUVRetriesUsesProtocolTwo(t *testing.T) {
	requireAuthenticatorFIPS140(t)

	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
		UvRetries: new(uint(5)),
	}))
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_1},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{
			protocol.PinUvAuthProtocolOne,
			protocol.PinUvAuthProtocolTwo,
		},
		Options: map[protocol.Option]bool{protocol.OptionUserVerification: false},
	})

	retries, err := d.GetUVRetries(testContext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := retries, uint(5); got != want {
		t.Fatalf("retries = %d, want %d", got, want)
	}

	command, request := fake.FirstCTAPRequestMap(t)
	if got, want := command, protocol.AuthenticatorClientPIN; got != want {
		t.Fatalf("command = %#v, want %#v", got, want)
	}

	got, ok := request[uint64(1)].(uint64)
	if !ok || got != uint64(protocol.PinUvAuthProtocolTwo) {
		t.Fatalf("pinUvAuthProtocol = %#v, want %#v", request[uint64(1)], protocol.PinUvAuthProtocolTwo)
	}
}

func TestFIPS140AuthenticatorGetUVRetriesRejectsProtocolOneBeforeIO(t *testing.T) {
	requireAuthenticatorFIPS140(t)

	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Versions:           protocol.Versions{protocol.FIDO_2_1},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options:            map[protocol.Option]bool{protocol.OptionUserVerification: false},
	})

	_, err := d.GetUVRetries(testContext)
	assertAuthenticatorFIPS140NotAllowed(t, err)
	assertNoAuthenticatorIO(t, fake)
}

func TestFIPS140AuthenticatorRejectsBeforeIO(t *testing.T) {
	requireAuthenticatorFIPS140(t)

	t.Run("no approved credential algorithm", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{})
		_, err := d.MakeCredential(
			testContext,
			nil,
			[]byte("client-data"),
			credential.PublicKeyCredentialRpEntity{ID: "example.com"},
			credential.PublicKeyCredentialUserEntity{ID: []byte("user-id")},
			[]credential.PublicKeyCredentialParameters{
				{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmES256K},
				{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmRS1},
			},
			nil,
			nil,
			nil,
			0,
			nil,
		)
		assertAuthenticatorFIPS140NotAllowed(t, err)
		assertNoAuthenticatorIO(t, fake)
	})
}

func requireAuthenticatorFIPS140(t testing.TB) {
	t.Helper()

	if !cryptofips140.Enabled() {
		t.Skip("requires Go FIPS 140-3 mode")
	}
}

func skipAuthenticatorFIPS140(t testing.TB) {
	t.Helper()

	if cryptofips140.Enabled() {
		t.Skip("legacy behavior is not available in Go FIPS 140-3 mode")
	}
}

func assertAuthenticatorFIPS140NotAllowed(t testing.TB, err error) {
	t.Helper()

	if !errors.Is(err, ctapfips140.ErrNotAllowed) {
		t.Fatalf("error = %v, want errors.Is(error, %v)", err, ctapfips140.ErrNotAllowed)
	}
}
