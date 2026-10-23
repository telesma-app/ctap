package authenticator

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
)

func TestMissingPinUvAuthProtocolsReturnsError(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{protocol.OptionClientPIN: false},
	})

	err := d.SetPIN(testContext, "1234")
	if err == nil {
		t.Fatalf("expected an error")
	}

	if got := errors.Is(err, ErrNotSupported); !got {
		t.Errorf("got false, want true")
	}

	assertNoAuthenticatorIO(t, fake)
}

func TestGetPinUvAuthTokenUsingPINValidatesPINBeforeCommand(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options:            map[protocol.Option]bool{protocol.OptionClientPIN: true},
	})

	_, err := d.GetPinUvAuthTokenUsingPIN(testContext, "123\x00", protocol.PermissionCredentialManagement, "")
	if err == nil {
		t.Fatalf("expected an error")
	}

	if container, element := err.Error(), "0x00"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	assertNoAuthenticatorIO(t, fake)
}

func TestGetPinUvAuthTokenUsingPINRequiresPINChangeBeforeCommand(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		ForcePINChange:         true,
		PinComplexityPolicyURL: []byte("https://example.com/pin-policy"),
	})

	_, err := d.GetPinUvAuthTokenUsingPIN(
		testContext,
		"1234",
		protocol.PermissionCredentialManagement,
		"",
	)
	if err, target := err, ErrPinChangeRequired; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	if container, element := err.Error(), "https://example.com/pin-policy"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	assertNoAuthenticatorIO(t, fake)
}

func TestGetPinUvAuthTokenUsingUVUsesPreviewRequestShape(t *testing.T) {
	skipAuthenticatorFIPS140(t)

	keyAgreement := encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
		KeyAgreement: testKeyAgreement(t),
	})
	encryptedToken := encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
		PinUvAuthToken: make([]byte, 16),
	})
	fake := testhid.NewCBORDevice(t, testCID, keyAgreement, encryptedToken)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{
			protocol.PinUvAuthProtocolTwo,
			protocol.PinUvAuthProtocolOne,
		},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification:            true,
			protocol.OptionUvToken:                     true,
			protocol.OptionUserVerificationMgmtPreview: true,
		},
	})

	token, err := d.GetPinUvAuthTokenUsingUV(testContext, protocol.PermissionBioEnrollment, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := len(token), 16; got != want {
		t.Errorf("got length %d, want %d", got, want)
	}

	requests := fake.Requests(t)
	if got, want := len(requests), 2; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	command, request := requests[0].CTAPRequestMap(t)
	if got, want := command, protocol.AuthenticatorClientPIN; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := len(request), 2; got != want {
		t.Errorf("got length %d, want %d", got, want)
	}
	{
		want, got := uint64(protocol.PinUvAuthProtocolOne), request[uint64(1)]
		gotValue, ok := got.(uint64)

		if !ok || gotValue != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := uint64(protocol.ClientPINSubCommandGetKeyAgreement), request[uint64(2)]
		gotValue, ok := got.(uint64)

		if !ok || gotValue != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	command, request = requests[1].CTAPRequestMap(t)
	if got, want := command, protocol.AuthenticatorClientPIN; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := len(request), 3; got != want {
		t.Errorf("got length %d, want %d", got, want)
	}
	{
		want, got := uint64(protocol.PinUvAuthProtocolOne), request[uint64(1)]
		gotValue, ok := got.(uint64)

		if !ok || gotValue != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := uint64(protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions), request[uint64(2)]
		gotValue, ok := got.(uint64)

		if !ok || gotValue != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	if _, ok := request[uint64(3)]; !ok {
		t.Errorf("value does not contain %#v", uint64(3))
	}

	if _, ok := request[uint64(9)]; ok {
		t.Errorf("value unexpectedly contains %#v", uint64(9))
	}

	if _, ok := request[uint64(10)]; ok {
		t.Errorf("value unexpectedly contains %#v", uint64(10))
	}
}

func TestSetPINValidatesPINBeforeCommand(t *testing.T) {
	t.Run("rejects too short PIN", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
			Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
		})

		err := d.SetPIN(testContext, "123")
		if err == nil {
			t.Fatalf("expected an error")
		}

		if container, element := err.Error(), "at least 4"; !strings.Contains(container, element) {
			t.Errorf("value does not contain %#v", element)
		}

		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("honors minPinLength", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
			MinPINLength:       8,
			Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
		})

		err := d.SetPIN(testContext, "1234567")
		if err == nil {
			t.Fatalf("expected an error")
		}

		if container, element := err.Error(), "at least 8"; !strings.Contains(container, element) {
			t.Errorf("value does not contain %#v", element)
		}

		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("honors maxPINLength", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
			MaxPINLength:       8,
			Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
		})

		err := d.SetPIN(testContext, "123456789")
		if err == nil {
			t.Fatalf("expected an error")
		}

		if container, element := err.Error(), "at most 8"; !strings.Contains(container, element) {
			t.Errorf("value does not contain %#v", element)
		}

		assertNoAuthenticatorIO(t, fake)
	})
}

func TestNormalizeAndValidateNewPINAppliesMaximumAfterNFCNormalization(t *testing.T) {
	d := &Device{info: protocol.AuthenticatorGetInfoResponse{
		MaxPINLength: 4,
	}}

	pin, err := d.normalizeAndValidateNewPIN("e\u0301123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := pin, "\u00e9123"; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	_, err = d.normalizeAndValidateNewPIN("12345")
	if err == nil {
		t.Fatalf("expected an error")
	}

	if container, element := err.Error(), "at most 4"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}
}

func TestSetPINAddsPINPolicyURLToAuthenticatorError(t *testing.T) {
	keyAgreement := encodeCBOR(t, &protocol.AuthenticatorClientPINResponse{
		KeyAgreement: testKeyAgreement(t),
	})
	fake := testhid.New(
		t,
		testhid.CBOROK(testCID, keyAgreement),
		testhid.CBORStatus(testCID, ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION),
	)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols:     []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		PinComplexityPolicyURL: []byte("https://example.com/pin-policy"),
		Options:                map[protocol.Option]bool{protocol.OptionClientPIN: false},
	})

	err := d.SetPIN(testContext, "1234")
	if err == nil {
		t.Fatalf("expected an error")
	}

	if container, element := err.Error(), "https://example.com/pin-policy"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	var ctapErr *ctaptransport.CTAPError
	if err := err; !errors.As(err, &ctapErr) {
		t.Fatalf("error %v does not match requested type", err)
	}

	if got, want := ctapErr.StatusCode, ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestSetPINDoesNotRequestGetInfo(t *testing.T) {
	keyAgreement := encodeCBOR(t, &protocol.AuthenticatorClientPINResponse{
		KeyAgreement: testKeyAgreement(t),
	})
	fake := testhid.NewCBORDevice(t, testCID, keyAgreement, nil)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
	})

	if err := d.SetPIN(testContext, "1234"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, valid := d.GetInfoCached()
	if got := valid; got {
		t.Errorf("got true, want false")
	}

	requests := fake.Requests(t)
	if got, want := len(requests), 2; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	for _, request := range requests {
		command, _ := request.CTAPPayload(t)
		if got, want := command, protocol.AuthenticatorClientPIN; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestSetPINInvalidatesInfoAndChangePINRefreshesIt(t *testing.T) {
	keyAgreement := encodeCBOR(t, &protocol.AuthenticatorClientPINResponse{
		KeyAgreement: testKeyAgreement(t),
	})
	currentInfo := encodeCBOR(t, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		Options:            map[protocol.Option]bool{protocol.OptionClientPIN: true},
	})
	fake := testhid.NewCBORDevice(t, testCID, keyAgreement, nil, currentInfo, keyAgreement, nil)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
	})

	if err := d.SetPIN(testContext, "1234"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := d.ChangePIN(testContext, "1234", "5678"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requests := fake.Requests(t)
	if got, want := len(requests), 5; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	commands := make([]protocol.Command, 0, len(requests))
	for _, request := range requests {
		command, _ := request.CTAPPayload(t)
		commands = append(commands, command)
	}
	{
		want, got := []protocol.Command{
			protocol.AuthenticatorClientPIN,
			protocol.AuthenticatorClientPIN,
			protocol.AuthenticatorGetInfo,
			protocol.AuthenticatorClientPIN,
			protocol.AuthenticatorClientPIN,
		}, commands
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestChangePINValidatesNewPINBeforeCommand(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		MinPINLength:       8,
		Options:            map[protocol.Option]bool{protocol.OptionClientPIN: true},
	})

	err := d.ChangePIN(testContext, "1234", "1234567")
	if err == nil {
		t.Fatalf("expected an error")
	}

	if container, element := err.Error(), "at least 8"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	assertNoAuthenticatorIO(t, fake)
}

func TestChangePINRemainsAvailableWhenPINChangeIsRequired(t *testing.T) {
	keyAgreement := encodeCBOR(t, &protocol.AuthenticatorClientPINResponse{
		KeyAgreement: testKeyAgreement(t),
	})
	fake := testhid.NewCBORDevice(t, testCID, keyAgreement, nil)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		ForcePINChange:     true,
		Options:            map[protocol.Option]bool{protocol.OptionClientPIN: true},
	})

	if err := d.ChangePIN(testContext, "1234", "5678"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requests := fake.Requests(t)
	if got, want := len(requests), 2; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	for _, request := range requests {
		command, _ := request.CTAPPayload(t)
		if got, want := command, protocol.AuthenticatorClientPIN; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}
