package authenticator

import (
	"bytes"
	"errors"
	"testing"

	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/protocol"
)

func TestCredentialStoreMutationsDoNotRequestGetInfo(t *testing.T) {
	t.Run("MakeCredential", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
			Format:      attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw: minimalMakeCredentialAuthData(t),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Options: map[protocol.Option]bool{
				protocol.OptionMakeCredentialUvNotRequired: true,
			},
		})

		_, err := d.MakeCredential(
			testContext,
			nil,
			[]byte("client-data"),
			credential.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
			credential.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "user"},
			[]credential.PublicKeyCredentialParameters{{
				Type:      credential.PublicKeyCredentialTypePublicKey,
				Algorithm: -7,
			}},
			nil,
			nil,
			map[protocol.Option]bool{protocol.OptionResidentKeys: true},
			0,
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		requests := fake.Requests(t)
		if got, want := len(requests), 1; got != want {
			t.Fatalf("got length %d, want %d", got, want)
		}

		command, _ := requests[0].CTAPPayload(t)
		if got, want := command, protocol.AuthenticatorMakeCredential; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})

	t.Run("DeleteCredential", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, nil)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{protocol.FIDO_2_1},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Options: map[protocol.Option]bool{
				protocol.OptionCredentialManagement: true,
			},
		})

		err := d.DeleteCredential(
			testContext,
			bytes.Repeat([]byte{0x44}, 32),
			credential.PublicKeyCredentialDescriptor{ID: []byte("credential-id")},
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		requests := fake.Requests(t)
		if got, want := len(requests), 1; got != want {
			t.Fatalf("got length %d, want %d", got, want)
		}

		command, _ := requests[0].CTAPPayload(t)
		if got, want := command, protocol.AuthenticatorCredentialManagement; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})

	t.Run("UpdateUserInformation", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, nil)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{protocol.FIDO_2_1},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Options: map[protocol.Option]bool{
				protocol.OptionCredentialManagement: true,
			},
		})

		err := d.UpdateUserInformation(
			testContext,
			bytes.Repeat([]byte{0x66}, 32),
			credential.PublicKeyCredentialDescriptor{ID: []byte("credential-id")},
			credential.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "updated"},
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		requests := fake.Requests(t)
		if got, want := len(requests), 1; got != want {
			t.Fatalf("got length %d, want %d", got, want)
		}

		command, _ := requests[0].CTAPPayload(t)
		if got, want := command, protocol.AuthenticatorCredentialManagement; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})
}

func TestMakeCredentialDoesNotRequestGetInfoAfterSuccess(t *testing.T) {
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalMakeCredentialAuthData(t),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionMakeCredentialUvNotRequired: true,
		},
	})

	result, err := d.MakeCredential(
		testContext,
		nil,
		[]byte("client-data"),
		credential.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "user"},
		[]credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: -7,
		}},
		nil,
		nil,
		map[protocol.Option]bool{protocol.OptionResidentKeys: true},
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := result.Format, attestation.AttestationStatementFormatIdentifierPacked; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	requests := fake.Requests(t)
	if got, want := len(requests), 1; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	command, _ := requests[0].CTAPPayload(t)
	if got, want := command, protocol.AuthenticatorMakeCredential; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestCredentialManagementUnsupportedIteratorsReturnBeforeCommand(t *testing.T) {
	t.Run("enumerate RPs", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{}})

		var count int
		for rp, err := range d.EnumerateRPs(testContext, nil) {
			count++

			if !credentialManagementResponseIsZero(rp) {
				t.Errorf("got %#v, want zero response", rp)
			}

			if err == nil {
				t.Fatalf("expected an error")
			}

			if got := errors.Is(err, ErrNotSupported); !got {
				t.Errorf("got false, want true")
			}
		}

		if got, want := count, 1; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}

		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("enumerate credentials", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{}})

		var count int
		for cred, err := range d.EnumerateCredentials(testContext, nil, make([]byte, 32)) {
			count++

			if !credentialManagementResponseIsZero(cred) {
				t.Errorf("got %#v, want zero response", cred)
			}

			if err == nil {
				t.Fatalf("expected an error")
			}

			if got := errors.Is(err, ErrNotSupported); !got {
				t.Errorf("got false, want true")
			}
		}

		if got, want := count, 1; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}

		assertNoAuthenticatorIO(t, fake)
	})
}

func TestUpdateUserInformationUsesPreviewCommandForPreviewOnlyDevice(t *testing.T) {
	skipAuthenticatorFIPS140(t)

	info := protocol.AuthenticatorGetInfoResponse{
		Versions:           protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options: map[protocol.Option]bool{
			protocol.OptionCredentialManagementPreview: true,
		},
	}
	fake := testhid.NewCBORDevice(t, testCID, nil, encodeCBOR(t, info))
	d := newTestDevice(t, fake, info)

	err := d.UpdateUserInformation(
		testContext,
		make([]byte, 32),
		credential.PublicKeyCredentialDescriptor{ID: []byte("credential-id")},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id")},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	command, _ := fake.FirstCTAPPayload(t)
	if got, want := command, protocol.PrototypeAuthenticatorCredentialManagement; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}
