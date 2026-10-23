package authenticator

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/ctap/webauthn"
)

func makeCredentialWithExtensions(
	d *Device,
	extInputs *webauthn.CreateAuthenticationExtensionsClientInputs,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	return makeCredentialWithExtensionsAndOptions(d, extInputs, nil)
}

func makeCredentialWithExtensionsAndOptions(
	d *Device,
	extInputs *webauthn.CreateAuthenticationExtensionsClientInputs,
	requestOptions map[protocol.Option]bool,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	return d.MakeCredential(
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
		extInputs,
		requestOptions,
		0,
		nil,
	)
}

func authDataWithExtensionOutputs(t *testing.T, outputs any) []byte {
	t.Helper()

	authData := minimalAuthData()
	if _, ok := outputs.(protocol.CreateExtensionOutputs); ok {
		authData = minimalMakeCredentialAuthData(t)
	}

	authData[32] |= byte(protocol.AuthDataFlagExtensionDataIncluded)

	return append(authData, encodeCBOR(t, outputs)...)
}

func TestMakeCredentialVerifiesEnforcedCredentialProtectionOutput(t *testing.T) {
	tests := []struct {
		name    string
		output  *int
		wantErr error
	}{
		{name: "missing output", wantErr: ErrSpecViolation},
		{name: "weaker output", output: new(1), wantErr: ErrSpecViolation},
		{name: "enforced output", output: new(3)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authData := minimalMakeCredentialAuthData(t)
			if tt.output != nil {
				authData = authDataWithExtensionOutputs(t, protocol.CreateExtensionOutputs{
					CreateCredProtectOutput: protocol.CreateCredProtectOutput{CredProtect: *tt.output},
				})
			}

			response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
				Format:      attestation.AttestationStatementFormatIdentifierPacked,
				AuthDataRaw: authData,
			})
			fake := testhid.NewCBORDevice(t, testCID, response)
			d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
				Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierCredentialProtection},
				Options: map[protocol.Option]bool{
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			})

			_, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
				CreateCredentialProtectionInputs: &webauthn.CreateCredentialProtectionInputs{
					CredentialProtectionPolicy:        extension.CredentialProtectionPolicyUserVerificationRequired,
					EnforceCredentialProtectionPolicy: true,
				},
			})
			if tt.wantErr != nil {
				if err, target := err, tt.wantErr; !errors.Is(err, target) {
					t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if got := fake.Writes(); len(got) == 0 {
				t.Errorf("got empty value %#v, want non-empty", got)
			}
		})
	}
}

func TestMakeCredentialIgnoresOversizedCredentialBlob(t *testing.T) {
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalMakeCredentialAuthData(t),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierCredentialBlob,
			extension.ExtensionIdentifierCredentialProtection,
		},
		MaxCredBlobLength: 32,
		Options: map[protocol.Option]bool{
			protocol.OptionMakeCredentialUvNotRequired: true,
		},
	})

	_, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
		CreateCredentialBlobInputs: &webauthn.CreateCredentialBlobInputs{
			CredBlob: bytes.Repeat([]byte{0xaa}, 33),
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	command, requestCBOR := fake.FirstCTAPPayload(t)
	if got, want := command, protocol.AuthenticatorMakeCredential; got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	var request protocol.AuthenticatorMakeCredentialRequest
	if err := cbor.Unmarshal(requestCBOR, &request); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := request.Extensions.CreateCredBlobInput; got.CredBlob != nil {
		t.Errorf("got %#v, want zero value", got)
	}
}

func TestFalseBooleanExtensionInputsAreNotProcessed(t *testing.T) {
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

		_, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
			CreateHMACSecretInputs:          &webauthn.CreateHMACSecretInputs{HMACCreateSecret: false},
			CreateMinPinLengthInputs:        &webauthn.CreateMinPinLengthInputs{MinPinLength: false},
			CreatePinComplexityPolicyInputs: &webauthn.CreatePinComplexityPolicyInputs{PinComplexityPolicy: false},
			PaymentInputs: &webauthn.PaymentInputs{
				Payment: webauthn.AuthenticationExtensionsPaymentInputs{IsPayment: false},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_, requestCBOR := fake.FirstCTAPPayload(t)

		var request protocol.AuthenticatorMakeCredentialRequest
		if err := cbor.Unmarshal(requestCBOR, &request); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := request.Extensions.CreateHMACSecretInput; got.HMACSecret {
			t.Errorf("got %#v, want zero value", got)
		}

		if got := request.Extensions.CreateMinPinLengthInput; got.MinPinLength {
			t.Errorf("got %#v, want zero value", got)
		}

		if got := request.Extensions.CreatePinComplexityPolicyInput; got.PinComplexityPolicy {
			t.Errorf("got %#v, want zero value", got)
		}

		if got := request.Extensions.CreateThirdPartyPaymentInput; got.ThirdPartyPayment {
			t.Errorf("got %#v, want zero value", got)
		}
	})

	t.Run("GetAssertion", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
			AuthDataRaw: minimalAuthData(),
			Signature:   []byte("signature"),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{})

		var count int
		for _, err := range d.GetAssertion(
			testContext,
			nil,
			"example.com",
			[]byte("client-data"),
			nil,
			&webauthn.GetAuthenticationExtensionsClientInputs{
				GetCredentialBlobInputs: &webauthn.GetCredentialBlobInputs{GetCredBlob: false},
				PaymentInputs: &webauthn.PaymentInputs{
					Payment: webauthn.AuthenticationExtensionsPaymentInputs{IsPayment: false},
				},
			},
			nil,
		) {
			count++

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		}

		if got, want := count, 1; got != want {
			t.Fatalf("got %#v, want %#v", got, want)
		}

		_, requestCBOR := fake.FirstCTAPPayload(t)

		var request protocol.AuthenticatorGetAssertionRequest
		if err := cbor.Unmarshal(requestCBOR, &request); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := request.Extensions.GetCredBlobInput; got.CredBlob {
			t.Errorf("got %#v, want zero value", got)
		}

		if got := request.Extensions.GetThirdPartyPaymentInput; got.ThirdPartyPayment {
			t.Errorf("got %#v, want zero value", got)
		}
	})
}

func TestThirdPartyPaymentExtension(t *testing.T) {
	t.Run("MakeCredential", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
			Format:      attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw: minimalMakeCredentialAuthData(t),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierThirdPartyPayment},
			Options: map[protocol.Option]bool{
				protocol.OptionMakeCredentialUvNotRequired: true,
			},
		})

		_, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
			PaymentInputs: &webauthn.PaymentInputs{
				Payment: webauthn.AuthenticationExtensionsPaymentInputs{IsPayment: true},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		command, requestCBOR := fake.FirstCTAPPayload(t)
		if got, want := command, protocol.AuthenticatorMakeCredential; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}

		var request protocol.AuthenticatorMakeCredentialRequest
		if err := cbor.Unmarshal(requestCBOR, &request); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := request.Extensions.ThirdPartyPayment; !got {
			t.Errorf("got false, want true")
		}
	})

	t.Run("GetAssertion preserves false output", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
			AuthDataRaw: authDataWithExtensionOutputs(t, protocol.GetExtensionOutputs{
				GetThirdPartyPaymentOutput: &protocol.GetThirdPartyPaymentOutput{ThirdPartyPayment: false},
			}),
			Signature: []byte("signature"),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierThirdPartyPayment},
		})

		var assertions []protocol.AuthenticatorGetAssertionResponse

		for assertion, err := range d.GetAssertion(
			testContext,
			nil,
			"example.com",
			[]byte("client-data"),
			nil,
			&webauthn.GetAuthenticationExtensionsClientInputs{
				PaymentInputs: &webauthn.PaymentInputs{
					Payment: webauthn.AuthenticationExtensionsPaymentInputs{IsPayment: true},
				},
			},
			nil,
		) {
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			assertions = append(assertions, assertion)
		}

		if got, want := len(assertions), 1; got != want {
			t.Fatalf("got length %d, want %d", got, want)
		}

		if got := assertions[0].AuthData.Extensions.GetThirdPartyPaymentOutput; got == nil {
			t.Fatalf("got nil, want a non-nil value")
		}

		if got := assertions[0].AuthData.Extensions.ThirdPartyPayment; got {
			t.Errorf("got true, want false")
		}

		command, requestCBOR := fake.FirstCTAPPayload(t)
		if got, want := command, protocol.AuthenticatorGetAssertion; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}

		var request protocol.AuthenticatorGetAssertionRequest
		if err := cbor.Unmarshal(requestCBOR, &request); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := request.Extensions.ThirdPartyPayment; !got {
			t.Errorf("got false, want true")
		}
	})

	t.Run("requires advertised support", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Options: map[protocol.Option]bool{
				protocol.OptionMakeCredentialUvNotRequired: true,
			},
		})

		_, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
			PaymentInputs: &webauthn.PaymentInputs{
				Payment: webauthn.AuthenticationExtensionsPaymentInputs{IsPayment: true},
			},
		})
		if err, target := err, ErrNotSupported; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})
}

func TestCompositeExtensionCapabilitiesAreValidatedBeforeCommand(t *testing.T) {
	tests := []struct {
		name      string
		info      protocol.AuthenticatorGetInfoResponse
		extInputs *webauthn.CreateAuthenticationExtensionsClientInputs
	}{
		{
			name: "credBlob requires credProtect",
			info: protocol.AuthenticatorGetInfoResponse{
				Extensions:        []extension.ExtensionIdentifier{extension.ExtensionIdentifierCredentialBlob},
				MaxCredBlobLength: 32,
			},
			extInputs: &webauthn.CreateAuthenticationExtensionsClientInputs{
				CreateCredentialBlobInputs: &webauthn.CreateCredentialBlobInputs{CredBlob: []byte("blob")},
			},
		},
		{
			name: "credBlob requires minimum maximum length",
			info: protocol.AuthenticatorGetInfoResponse{
				Extensions: []extension.ExtensionIdentifier{
					extension.ExtensionIdentifierCredentialBlob,
					extension.ExtensionIdentifierCredentialProtection,
				},
				MaxCredBlobLength: 31,
			},
			extInputs: &webauthn.CreateAuthenticationExtensionsClientInputs{
				CreateCredentialBlobInputs: &webauthn.CreateCredentialBlobInputs{CredBlob: []byte("blob")},
			},
		},
		{
			name: "hmac-secret-mc requires hmac-secret",
			info: protocol.AuthenticatorGetInfoResponse{
				Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecretMC},
			},
			extInputs: &webauthn.CreateAuthenticationExtensionsClientInputs{
				CreateHMACSecretMCInputs: &webauthn.CreateHMACSecretMCInputs{
					HMACGetSecret: webauthn.HMACGetSecretInput{Salt1: make([]byte, 32)},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := testhid.NewCBORDevice(t, testCID)
			tt.info.Options = map[protocol.Option]bool{
				protocol.OptionMakeCredentialUvNotRequired: true,
			}
			d := newTestDevice(t, fake, tt.info)

			_, err := makeCredentialWithExtensions(d, tt.extInputs)
			if err, target := err, ErrSpecViolation; !errors.Is(err, target) {
				t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
			}

			assertNoAuthenticatorIO(t, fake)
		})
	}
}

func TestGetAssertionRejectsHMACSecretWhenUserPresenceIsDisabledBeforeCommand(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
	})

	var gotErr error
	for _, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		nil,
		&webauthn.GetAuthenticationExtensionsClientInputs{
			GetHMACSecretInputs: &webauthn.GetHMACSecretInputs{
				HMACGetSecret: webauthn.HMACGetSecretInput{Salt1: make([]byte, 32)},
			},
		},
		map[protocol.Option]bool{protocol.OptionUserPresence: false},
	) {
		gotErr = err
	}

	if err, target := gotErr, ErrNotSupported; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	assertNoAuthenticatorIO(t, fake)
}

func TestUnsolicitedExtensionOutputsAreRejectedWithoutPanic(t *testing.T) {
	t.Run("MakeCredential hmac-secret-mc", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
			Format: attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw: authDataWithExtensionOutputs(t, protocol.CreateExtensionOutputs{
				CreateHMACSecretMCOutput: protocol.CreateHMACSecretMCOutput{HMACSecret: make([]byte, 32)},
			}),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Options: map[protocol.Option]bool{
				protocol.OptionMakeCredentialUvNotRequired: true,
			},
		})

		_, err := makeCredentialWithExtensions(d, nil)
		if err, target := err, ErrSpecViolation; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	})

	t.Run("GetAssertion hmac-secret", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
			AuthDataRaw: authDataWithExtensionOutputs(t, protocol.GetExtensionOutputs{
				GetHMACSecretOutput: protocol.GetHMACSecretOutput{HMACSecret: make([]byte, 32)},
			}),
			Signature: []byte("signature"),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{})

		var gotErr error
		for _, err := range d.GetAssertion(
			testContext,
			nil,
			"example.com",
			[]byte("client-data"),
			nil,
			nil,
			nil,
		) {
			gotErr = err
		}

		if err, target := gotErr, ErrSpecViolation; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	})
}

func TestSetLargeBlobsValidatesAndCanonicalizesArray(t *testing.T) {
	info := protocol.AuthenticatorGetInfoResponse{
		MaxSerializedLargeBlobArray: 1024,
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	}

	t.Run("rejects invalid entries", func(t *testing.T) {
		tests := []protocol.LargeBlob{
			{Ciphertext: make([]byte, 15), Nonce: make([]byte, 12)},
			{Ciphertext: make([]byte, 16), Nonce: make([]byte, 11)},
		}
		for _, blob := range tests {
			fake := testhid.NewCBORDevice(t, testCID)
			d := newTestDevice(t, fake, info)

			err := d.SetLargeBlobs(testContext, nil, []protocol.LargeBlob{blob})
			if err, target := err, SyntaxError; !errors.Is(err, target) {
				t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
			}

			assertNoAuthenticatorIO(t, fake)
		}
	})

	t.Run("nil input becomes an empty array", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, nil)
		d := newTestDevice(t, fake, info)

		if err := d.SetLargeBlobs(testContext, nil, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_, requestCBOR := fake.FirstCTAPPayload(t)

		var request protocol.AuthenticatorLargeBlobsRequest
		if err := cbor.Unmarshal(requestCBOR, &request); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := len(request.Set), 17; got != want {
			t.Fatalf("got length %d, want %d", got, want)
		}

		if got, want := request.Set[0], byte(0x80); got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}

		hash := sha256.Sum256(request.Set[:1])
		if got, want := request.Set[1:], hash[:16]; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})
}

func TestValidateMakeCredentialExtensionOutputsRejectsUnsolicitedValues(t *testing.T) {
	err := validateMakeCredentialExtensionOutputs(
		&protocol.CreateExtensionInputs{},
		&webauthn.CreateAuthenticationExtensionsClientInputs{},
		&protocol.CreateExtensionOutputs{
			CreateCredBlobOutput: &protocol.CreateCredBlobOutput{CredBlob: true},
		},
	)
	if err, target := err, ErrSpecViolation; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
}

func TestGetAssertionValidatesHMACSecretSalts(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
	})

	var count int
	for assertion, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		nil,
		&webauthn.GetAuthenticationExtensionsClientInputs{
			GetHMACSecretInputs: &webauthn.GetHMACSecretInputs{
				HMACGetSecret: webauthn.HMACGetSecretInput{Salt1: make([]byte, 31)},
			},
		},
		nil,
	) {
		count++

		if !assertionResponseIsZero(assertion) {
			t.Errorf("got %#v, want zero response", assertion)
		}

		if err == nil {
			t.Fatalf("expected an error")
		}

		if got := errors.Is(err, ErrInvalidSaltSize); !got {
			t.Errorf("got false, want true")
		}
	}

	if got, want := count, 1; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	assertNoAuthenticatorIO(t, fake)
}

func TestMakeCredentialValidatesHMACSecretMCSalts(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierHMACSecret,
			extension.ExtensionIdentifierHMACSecretMC,
		},
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
			Algorithm: cose.AlgorithmES256,
		}},
		nil,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			CreateHMACSecretMCInputs: &webauthn.CreateHMACSecretMCInputs{
				HMACGetSecret: webauthn.HMACGetSecretInput{Salt1: make([]byte, 32), Salt2: make([]byte, 31)},
			},
		},
		nil,
		0,
		nil,
	)
	if err == nil {
		t.Fatalf("expected an error")
	}

	if got := errors.Is(err, ErrInvalidSaltSize); !got {
		t.Errorf("got false, want true")
	}

	assertNoAuthenticatorIO(t, fake)
}

func TestMakeCredentialAllowsFIDO20BuiltInUV(t *testing.T) {
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalMakeCredentialAuthData(t),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_0},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification: true,
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
			Algorithm: cose.AlgorithmES256,
		}},
		nil,
		nil,
		map[protocol.Option]bool{protocol.OptionUserVerification: true},
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := fake.Writes(); len(got) == 0 {
		t.Errorf("got empty value %#v, want non-empty", got)
	}
}

func TestMakeCredentialCredPropsOutputDependsOnCredPropsInput(t *testing.T) {
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalMakeCredentialAuthData(t),
	})
	info := protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionMakeCredentialUvNotRequired: true,
		},
	}
	fake := testhid.NewCBORDevice(t, testCID, response, encodeCBOR(t, info))
	d := newTestDevice(t, fake, info)

	resp, err := d.MakeCredential(
		testContext,
		nil,
		[]byte("client-data"),
		credential.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "user"},
		[]credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}},
		nil,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			CreateCredentialPropertiesInputs: &webauthn.CreateCredentialPropertiesInputs{CredentialProperties: true},
		},
		map[protocol.Option]bool{protocol.OptionResidentKeys: true},
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := resp.ExtensionOutputs.CreateCredentialPropertiesOutputs; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := resp.ExtensionOutputs.CredentialProperties.ResidentKey; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := *resp.ExtensionOutputs.CredentialProperties.ResidentKey; !got {
		t.Errorf("got false, want true")
	}
}

func TestMakeCredentialRequiresMaxCredBlobLengthWhenCredBlobExtensionReported(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierCredentialBlob,
			extension.ExtensionIdentifierCredentialProtection,
		},
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
			Algorithm: cose.AlgorithmES256,
		}},
		nil,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			CreateCredentialBlobInputs: &webauthn.CreateCredentialBlobInputs{CredBlob: []byte("blob")},
		},
		nil,
		0,
		nil,
	)
	if err == nil {
		t.Fatalf("expected an error")
	}

	if container, element := err.Error(), "maxCredBlobLength"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	assertNoAuthenticatorIO(t, fake)
}

func TestHMACSecretPinUvAuthProtocolWirePresence(t *testing.T) {
	tests := []struct {
		name       string
		protocol   protocol.PinUvAuthProtocol
		wantMember bool
	}{
		{name: "protocol one is implicit", protocol: protocol.PinUvAuthProtocolOne},
		{name: "protocol two is explicit", protocol: protocol.PinUvAuthProtocolTwo, wantMember: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := newHMACSecretInput(cose.Key{1: 2}, []byte{3}, []byte{4}, tt.protocol)

			raw, err := cbor.Marshal(input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var fields map[uint64]cbor.RawMessage
			if err := cbor.Unmarshal(raw, &fields); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantMember {
				if _, ok := fields[uint64(4)]; !ok {
					t.Fatalf("value does not contain %#v", uint64(4))
				}
			} else {
				if _, ok := fields[uint64(4)]; ok {
					t.Fatalf("value unexpectedly contains %#v", uint64(4))
				}
			}
		})
	}
}
