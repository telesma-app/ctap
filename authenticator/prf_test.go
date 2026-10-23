package authenticator

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/crypto/protocolone"
	"github.com/telesma-app/ctap/crypto/protocoltwo"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/options"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/webauthn"
)

type prfRoundTripTransport struct {
	t          *testing.T
	privateKey *ecdh.PrivateKey
	result     []byte
	salts      []byte
	requests   [][]byte
}

func newPRFRoundTripTransport(t *testing.T, result []byte) *prfRoundTripTransport {
	t.Helper()

	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return &prfRoundTripTransport{t: t, privateKey: privateKey, result: result}
}

func (t *prfRoundTripTransport) Close() error { return nil }

func (t *prfRoundTripTransport) CBOR(
	_ context.Context,
	data []byte,
) (ctaptransport.CBORResponse, error) {
	t.t.Helper()

	if got := data; len(got) == 0 {
		t.t.Fatalf("got empty value %#v, want non-empty", got)
	}

	t.requests = append(t.requests, bytes.Clone(data))

	switch protocol.Command(data[0]) {
	case protocol.AuthenticatorClientPIN:
		keyAgreement, err := cose.KeyFromP256PublicKey(t.privateKey.PublicKey())
		if err != nil {
			t.t.Fatalf("unexpected error: %v", err)
		}

		return ctaptransport.CBORResponse{Data: encodeCBOR(t.t, &protocol.AuthenticatorClientPINResponse{
			KeyAgreement: keyAgreement,
		})}, nil

	case protocol.AuthenticatorMakeCredential:
		var request protocol.AuthenticatorMakeCredentialRequest
		if err := cbor.Unmarshal(data[1:], &request); err != nil {
			t.t.Fatalf("unexpected error: %v", err)
		}

		encryptedResult := t.encryptResult(request.Extensions.CreateHMACSecretMCInput.HMACSecret)

		authData := minimalMakeCredentialAuthData(t.t)
		authData[32] |= byte(protocol.AuthDataFlagUserPresent |
			protocol.AuthDataFlagUserVerified |
			protocol.AuthDataFlagExtensionDataIncluded)
		authData = append(authData, encodeCBOR(t.t, protocol.CreateExtensionOutputs{
			CreateHMACSecretOutput:   &protocol.CreateHMACSecretOutput{HMACSecret: true},
			CreateHMACSecretMCOutput: protocol.CreateHMACSecretMCOutput{HMACSecret: encryptedResult},
		})...)

		return ctaptransport.CBORResponse{Data: encodeCBOR(t.t, &protocol.AuthenticatorMakeCredentialResponse{
			Format:      attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw: authData,
		})}, nil

	case protocol.AuthenticatorGetAssertion:
		var request protocol.AuthenticatorGetAssertionRequest
		if err := cbor.Unmarshal(data[1:], &request); err != nil {
			t.t.Fatalf("unexpected error: %v", err)
		}

		encryptedResult := t.encryptResult(request.Extensions.HMACSecret)

		authData := minimalAuthData()
		authData[32] = byte(protocol.AuthDataFlagUserPresent |
			protocol.AuthDataFlagUserVerified |
			protocol.AuthDataFlagExtensionDataIncluded)
		authData = append(authData, encodeCBOR(t.t, protocol.GetExtensionOutputs{
			GetHMACSecretOutput: protocol.GetHMACSecretOutput{HMACSecret: encryptedResult},
		})...)

		return ctaptransport.CBORResponse{Data: encodeCBOR(t.t, &protocol.AuthenticatorGetAssertionResponse{
			AuthDataRaw: authData,
			Signature:   []byte("signature"),
		})}, nil
	default:
		t.t.Fatalf("unexpected CTAP command: %v", data[0])
		return ctaptransport.CBORResponse{}, nil
	}
}

func (t *prfRoundTripTransport) encryptResult(input protocol.HMACSecret) []byte {
	t.t.Helper()

	platformPublicKey, err := input.KeyAgreement.P256PublicKey()
	if err != nil {
		t.t.Fatalf("unexpected error: %v", err)
	}

	z, err := t.privateKey.ECDH(platformPublicKey)
	if err != nil {
		t.t.Fatalf("unexpected error: %v", err)
	}

	protocolNumber := input.PinUvAuthProtocol
	if protocolNumber == 0 {
		protocolNumber = protocol.PinUvAuthProtocolOne
	}

	var sharedSecret []byte

	switch protocolNumber {
	case protocol.PinUvAuthProtocolOne:
		sharedSecret = protocolone.KDF(z)
	case protocol.PinUvAuthProtocolTwo:
		sharedSecret, err = protocoltwo.KDF(z)
		if err != nil {
			t.t.Fatalf("unexpected error: %v", err)
		}
	default:
		t.t.Fatalf("unexpected PIN/UV auth protocol: %v", protocolNumber)
	}

	switch protocolNumber {
	case protocol.PinUvAuthProtocolOne:
		t.salts, err = protocolone.Decrypt(sharedSecret, input.SaltEnc)
	case protocol.PinUvAuthProtocolTwo:
		t.salts, err = protocoltwo.Decrypt(sharedSecret, input.SaltEnc)
	}

	if err != nil {
		t.t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := ctapcrypto.Authenticate(
			protocolNumber,
			sharedSecret,
			input.SaltEnc,
		), input.SaltAuth
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.t.Fatalf("got %#v, want %#v", got, want)
		}
	}

	var encryptedResult []byte

	switch protocolNumber {
	case protocol.PinUvAuthProtocolOne:
		encryptedResult, err = protocolone.Encrypt(sharedSecret, t.result)
	case protocol.PinUvAuthProtocolTwo:
		encryptedResult, err = protocoltwo.Encrypt(sharedSecret, t.result)
	}

	if err != nil {
		t.t.Fatalf("unexpected error: %v", err)
	}

	return encryptedResult
}

func newPRFRoundTripDevice(
	t *testing.T,
	transport *prfRoundTripTransport,
	info protocol.AuthenticatorGetInfoResponse,
) *Device {
	t.Helper()

	ctapClient, err := client.NewClient(options.WithTransport(transport))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	d := &Device{transport: transport, ctapClient: ctapClient, info: info, infoValid: true}

	return d
}

func TestMakeCredentialPRFReportsCapabilityWithoutRequiringEvaluation(t *testing.T) {
	tests := []struct {
		name string
		eval webauthn.AuthenticationExtensionsPRFValues
	}{
		{name: "without eval"},
		{name: "eval without hmac-secret-mc", eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
				Format: attestation.AttestationStatementFormatIdentifierPacked,
				AuthDataRaw: authDataWithExtensionOutputs(t, protocol.CreateExtensionOutputs{
					CreateHMACSecretOutput: &protocol.CreateHMACSecretOutput{HMACSecret: true},
				}),
			})
			fake := testhid.NewCBORDevice(t, testCID, response)
			d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
				Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
				Options: map[protocol.Option]bool{
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			})

			resp, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
				PRFInputs: &webauthn.PRFInputs{
					PRF: webauthn.AuthenticationExtensionsPRFInputs{Eval: tt.eval},
				},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := resp.ExtensionOutputs.CreatePRFOutputs; got == nil {
				t.Fatalf("got nil, want a non-nil value")
			}

			if got := resp.ExtensionOutputs.PRF.Enabled; !got {
				t.Errorf("got false, want true")
			}

			if got := resp.ExtensionOutputs.PRF.Results.IsZero(); !got {
				t.Errorf("got false, want true")
			}

			if got := resp.ExtensionOutputs.CreateHMACSecretOutputs; got != nil {
				t.Errorf("got %#v, want nil", got)
			}

			if got, want := len(fake.Requests(t)), 1; got != want {
				t.Fatalf("got length %d, want %d", got, want)
			}

			_, requestCBOR := fake.FirstCTAPPayload(t)

			var request protocol.AuthenticatorMakeCredentialRequest
			if err := cbor.Unmarshal(requestCBOR, &request); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := request.Extensions.CreateHMACSecretInput.HMACSecret; !got {
				t.Errorf("got false, want true")
			}

			if got := request.Extensions.CreateHMACSecretMCInput; !hmacSecretIsZero(got.HMACSecret) {
				t.Errorf("got %#v, want zero value", got)
			}
		})
	}
}

func TestMakeCredentialPRFWithoutHMACSecretReturnsDisabledOutput(t *testing.T) {
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalMakeCredentialAuthData(t),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{protocol.OptionMakeCredentialUvNotRequired: true},
	})

	resp, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
		PRFInputs: &webauthn.PRFInputs{
			PRF: webauthn.AuthenticationExtensionsPRFInputs{
				Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := resp.ExtensionOutputs.CreatePRFOutputs; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := resp.ExtensionOutputs.PRF.Enabled; got {
		t.Errorf("got true, want false")
	}

	_, requestCBOR := fake.FirstCTAPPayload(t)

	var request protocol.AuthenticatorMakeCredentialRequest
	if err := cbor.Unmarshal(requestCBOR, &request); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := request.Extensions.CreateHMACSecretInput; got.HMACSecret {
		t.Errorf("got %#v, want zero value", got)
	}

	if got := request.Extensions.CreateHMACSecretMCInput; !hmacSecretIsZero(got.HMACSecret) {
		t.Errorf("got %#v, want zero value", got)
	}
}

func TestMakeCredentialPRFEvaluatesAtCreationTimeWithExplicitUserVerification(t *testing.T) {
	values := webauthn.AuthenticationExtensionsPRFValues{
		First:  []byte("first"),
		Second: []byte{},
	}
	result := bytes.Repeat([]byte{0xa5}, 64)
	transport := newPRFRoundTripTransport(t, result)
	d := newPRFRoundTripDevice(t, transport, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierHMACSecret,
			extension.ExtensionIdentifierHMACSecretMC,
		},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification:            true,
			protocol.OptionMakeCredentialUvNotRequired: true,
		},
	})

	resp, err := makeCredentialWithExtensionsAndOptions(
		d,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{Eval: values},
			},
		},
		map[protocol.Option]bool{protocol.OptionUserVerification: true},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := resp.ExtensionOutputs.CreatePRFOutputs; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := resp.ExtensionOutputs.CreateHMACSecretMCOutputs; got != nil {
		t.Errorf("got %#v, want nil", got)
	}

	if got := resp.ExtensionOutputs.PRF.Enabled; !got {
		t.Errorf("got false, want true")
	}

	if got, want := resp.ExtensionOutputs.PRF.Results.First, result[:32]; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := resp.ExtensionOutputs.PRF.Results.Second, result[32:]; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := transport.salts, prfSalts(values); (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := len(transport.requests), 2; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	if got, want := transport.requests[1][0], byte(protocol.AuthenticatorMakeCredential); got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	var request protocol.AuthenticatorMakeCredentialRequest
	if err := cbor.Unmarshal(transport.requests[1][1:], &request); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := request.Options[protocol.OptionUserVerification]; !got {
		t.Errorf("got false, want true")
	}

	if got := request.Extensions.CreateHMACSecretInput.HMACSecret; !got {
		t.Errorf("got false, want true")
	}

	if got := request.Extensions.CreateHMACSecretMCInput.HMACSecret.KeyAgreement; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}
}

func TestMakeCredentialRawHMACSecretMCReturnsRawOutput(t *testing.T) {
	salt1 := bytes.Repeat([]byte{0x11}, 32)
	salt2 := bytes.Repeat([]byte{0x22}, 32)
	result := bytes.Repeat([]byte{0x5a}, 64)
	transport := newPRFRoundTripTransport(t, result)
	d := newPRFRoundTripDevice(t, transport, protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_3},
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierHMACSecret,
			extension.ExtensionIdentifierHMACSecretMC,
		},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		Options: map[protocol.Option]bool{
			protocol.OptionMakeCredentialUvNotRequired: true,
		},
	})

	resp, err := makeCredentialWithExtensions(
		d,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			CreateHMACSecretMCInputs: &webauthn.CreateHMACSecretMCInputs{
				HMACGetSecret: webauthn.HMACGetSecretInput{
					Salt1: salt1,
					Salt2: salt2,
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := resp.ExtensionOutputs.CreateHMACSecretMCOutputs; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := resp.ExtensionOutputs.CreatePRFOutputs; got != nil {
		t.Errorf("got %#v, want nil", got)
	}

	if got, want := resp.ExtensionOutputs.HMACGetSecret.Output1, result[:32]; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := resp.ExtensionOutputs.HMACGetSecret.Output2, result[32:]; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := transport.salts, append(bytes.Clone(salt1), salt2...); (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestMakeCredentialPRFEvaluatesAtCreationTimeWithAlwaysUV(t *testing.T) {
	values := webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")}
	result := bytes.Repeat([]byte{0xa5}, 32)
	transport := newPRFRoundTripTransport(t, result)
	d := newPRFRoundTripDevice(t, transport, protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_1},
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierHMACSecret,
			extension.ExtensionIdentifierHMACSecretMC,
		},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification: true,
			protocol.OptionAlwaysUv:         true,
		},
	})
	callerOptions := map[protocol.Option]bool{protocol.OptionUserVerification: false}

	resp, err := makeCredentialWithExtensionsAndOptions(
		d,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{Eval: values},
			},
		},
		callerOptions,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := resp.ExtensionOutputs.CreatePRFOutputs; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := resp.ExtensionOutputs.PRF.Enabled; !got {
		t.Errorf("got false, want true")
	}

	if got, want := resp.ExtensionOutputs.PRF.Results.First, result; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := transport.salts, prfSalts(values); (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got := callerOptions[protocol.OptionUserVerification]; got {
		t.Errorf("got true, want false")
	}

	if got, want := len(transport.requests), 2; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	if got, want := transport.requests[1][0], byte(protocol.AuthenticatorMakeCredential); got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	var request protocol.AuthenticatorMakeCredentialRequest
	if err := cbor.Unmarshal(transport.requests[1][1:], &request); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := request.Options[protocol.OptionUserVerification]; got {
		t.Errorf("got true, want false")
	}

	if got := request.Extensions.CreateHMACSecretMCInput.HMACSecret.KeyAgreement; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}
}

func TestMakeCredentialPRFSkipsCreationTimeEvaluationWithoutExplicitUserVerification(t *testing.T) {
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format: attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: authDataWithExtensionOutputs(t, protocol.CreateExtensionOutputs{
			CreateHMACSecretOutput: &protocol.CreateHMACSecretOutput{HMACSecret: true},
		}),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierHMACSecret,
			extension.ExtensionIdentifierHMACSecretMC,
		},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification:            true,
			protocol.OptionMakeCredentialUvNotRequired: true,
		},
	})
	callerOptions := map[protocol.Option]bool{protocol.OptionUserVerification: false}

	resp, err := makeCredentialWithExtensionsAndOptions(
		d,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{
					Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")},
				},
			},
		},
		callerOptions,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := resp.ExtensionOutputs.CreatePRFOutputs; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := resp.ExtensionOutputs.PRF.Enabled; !got {
		t.Errorf("got false, want true")
	}

	if got := resp.ExtensionOutputs.PRF.Results.IsZero(); !got {
		t.Errorf("got false, want true")
	}

	if got := callerOptions[protocol.OptionUserVerification]; got {
		t.Errorf("got true, want false")
	}

	_, requestCBOR := fake.FirstCTAPPayload(t)

	var request protocol.AuthenticatorMakeCredentialRequest
	if err := cbor.Unmarshal(requestCBOR, &request); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := request.Options[protocol.OptionUserVerification]; got {
		t.Errorf("got true, want false")
	}

	if got := request.Extensions.CreateHMACSecretMCInput; !hmacSecretIsZero(got.HMACSecret) {
		t.Errorf("got %#v, want zero value", got)
	}
}

func TestMakeCredentialPRFRejectsResultsWhenHMACSecretWasNotEnabled(t *testing.T) {
	keyAgreement := encodeCBOR(t, &protocol.AuthenticatorClientPINResponse{
		KeyAgreement: testKeyAgreement(t),
	})
	authData := authDataWithExtensionOutputs(t, protocol.CreateExtensionOutputs{
		CreateHMACSecretOutput:   &protocol.CreateHMACSecretOutput{HMACSecret: false},
		CreateHMACSecretMCOutput: protocol.CreateHMACSecretMCOutput{HMACSecret: make([]byte, 32)},
	})
	authData[32] |= byte(protocol.AuthDataFlagUserVerified)
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: authData,
	})
	fake := testhid.NewCBORDevice(t, testCID, keyAgreement, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierHMACSecret,
			extension.ExtensionIdentifierHMACSecretMC,
		},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification:            true,
			protocol.OptionMakeCredentialUvNotRequired: true,
		},
	})

	_, err := makeCredentialWithExtensionsAndOptions(
		d,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{
					Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")},
				},
			},
		},
		map[protocol.Option]bool{protocol.OptionUserVerification: true},
	)
	if err, target := err, ErrSpecViolation; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
}

func TestGetAssertionPRFInitializesEmptyOutputWhenNoEvaluationIsSent(t *testing.T) {
	tests := []struct {
		name       string
		extensions []extension.ExtensionIdentifier
		prf        webauthn.AuthenticationExtensionsPRFInputs
	}{
		{name: "empty input"},
		{
			name: "unsupported authenticator",
			prf: webauthn.AuthenticationExtensionsPRFInputs{
				Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
				AuthDataRaw: minimalAuthData(),
				Signature:   []byte("signature"),
			})
			fake := testhid.NewCBORDevice(t, testCID, response)
			d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{Extensions: tt.extensions})

			var assertions []protocol.AuthenticatorGetAssertionResponse

			for assertion, err := range d.GetAssertion(
				testContext,
				nil,
				"example.com",
				[]byte("client-data"),
				nil,
				&webauthn.GetAuthenticationExtensionsClientInputs{
					PRFInputs: &webauthn.PRFInputs{PRF: tt.prf},
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

			if got := assertions[0].ExtensionOutputs.GetPRFOutputs; got == nil {
				t.Fatalf("got nil, want a non-nil value")
			}

			if got := assertions[0].ExtensionOutputs.PRF.Results.IsZero(); !got {
				t.Errorf("got false, want true")
			}

			_, requestCBOR := fake.FirstCTAPPayload(t)

			var request protocol.AuthenticatorGetAssertionRequest
			if err := cbor.Unmarshal(requestCBOR, &request); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := request.Extensions.GetHMACSecretInput; !hmacSecretIsZero(got.HMACSecret) {
				t.Errorf("got %#v, want zero value", got)
			}
		})
	}
}

func TestGetAssertionPRFEvaluatesAndReturnsDecryptedResult(t *testing.T) {
	values := webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")}
	result := bytes.Repeat([]byte{0x5a}, 32)
	transport := newPRFRoundTripTransport(t, result)
	d := newPRFRoundTripDevice(t, transport, protocol.AuthenticatorGetInfoResponse{
		Extensions:         []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification: true,
		},
	})

	var assertions []protocol.AuthenticatorGetAssertionResponse

	for assertion, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		nil,
		&webauthn.GetAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{Eval: values},
			},
		},
		map[protocol.Option]bool{protocol.OptionUserVerification: true},
	) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		assertions = append(assertions, assertion)
	}

	if got, want := len(assertions), 1; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	if got := assertions[0].ExtensionOutputs.GetPRFOutputs; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got, want := assertions[0].ExtensionOutputs.PRF.Results.First, result; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got := assertions[0].ExtensionOutputs.PRF.Results.Second; got != nil {
		t.Errorf("got %#v, want nil", got)
	}

	if got, want := transport.salts, prfSalts(values); (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestGetAssertionPRFEvaluatesWithAlwaysUV(t *testing.T) {
	values := webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")}
	result := bytes.Repeat([]byte{0x5a}, 32)
	transport := newPRFRoundTripTransport(t, result)
	d := newPRFRoundTripDevice(t, transport, protocol.AuthenticatorGetInfoResponse{
		Versions:           protocol.Versions{protocol.FIDO_2_1},
		Extensions:         []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification: true,
			protocol.OptionAlwaysUv:         true,
		},
	})
	callerOptions := map[protocol.Option]bool{protocol.OptionUserVerification: false}

	var assertions []protocol.AuthenticatorGetAssertionResponse

	for assertion, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		nil,
		&webauthn.GetAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{Eval: values},
			},
		},
		callerOptions,
	) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		assertions = append(assertions, assertion)
	}

	if got, want := len(assertions), 1; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	if got := assertions[0].ExtensionOutputs.GetPRFOutputs; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got, want := assertions[0].ExtensionOutputs.PRF.Results.First, result; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := transport.salts, prfSalts(values); (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got := callerOptions[protocol.OptionUserVerification]; got {
		t.Errorf("got true, want false")
	}

	if got, want := len(transport.requests), 2; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	if got, want := transport.requests[1][0], byte(protocol.AuthenticatorGetAssertion); got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	var request protocol.AuthenticatorGetAssertionRequest
	if err := cbor.Unmarshal(transport.requests[1][1:], &request); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := request.Options[protocol.OptionUserVerification]; got {
		t.Errorf("got true, want false")
	}

	if got := request.Extensions.HMACSecret.KeyAgreement; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}
}

func TestGetAssertionPRFRejectsResultCountMismatch(t *testing.T) {
	transport := newPRFRoundTripTransport(t, bytes.Repeat([]byte{0x5a}, 64))
	d := newPRFRoundTripDevice(t, transport, protocol.AuthenticatorGetInfoResponse{
		Extensions:         []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification: true,
		},
	})

	var gotErr error
	for _, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		nil,
		&webauthn.GetAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{
					Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")},
				},
			},
		},
		map[protocol.Option]bool{protocol.OptionUserVerification: true},
	) {
		gotErr = err
	}

	if err, target := gotErr, ErrSpecViolation; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
}

func TestGetAssertionPRFRequiresExplicitUserVerification(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification: true,
		},
	})
	callerOptions := map[protocol.Option]bool{protocol.OptionUserVerification: false}

	var gotErr error
	for _, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		nil,
		&webauthn.GetAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{
					Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")},
				},
			},
		},
		callerOptions,
	) {
		gotErr = err
	}

	if err, target := gotErr, ErrBuiltInUVRequired; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	if got := callerOptions[protocol.OptionUserVerification]; got {
		t.Errorf("got true, want false")
	}

	assertNoAuthenticatorIO(t, fake)
}

func TestPRFResultsRequireUserVerification(t *testing.T) {
	keyAgreement := encodeCBOR(t, &protocol.AuthenticatorClientPINResponse{
		KeyAgreement: testKeyAgreement(t),
	})
	assertion := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: authDataWithExtensionOutputs(t, protocol.GetExtensionOutputs{
			GetHMACSecretOutput: protocol.GetHMACSecretOutput{HMACSecret: make([]byte, 32)},
		}),
		Signature: []byte("signature"),
	})
	fake := testhid.NewCBORDevice(t, testCID, keyAgreement, assertion)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Extensions:         []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification: true,
		},
	})

	var gotErr error
	for _, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		nil,
		&webauthn.GetAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{
					Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")},
				},
			},
		},
		map[protocol.Option]bool{protocol.OptionUserVerification: true},
	) {
		gotErr = err
	}

	if err, target := gotErr, ErrSpecViolation; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
}

func TestPRFPreflightFailuresPerformNoAuthenticatorIO(t *testing.T) {
	t.Run("registration rejects even an empty evalByCredential", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Options: map[protocol.Option]bool{
				protocol.OptionMakeCredentialUvNotRequired: true,
			},
		})

		_, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{
					EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{},
				},
			},
		})
		if err, target := err, ErrNotSupported; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("authentication rejects user presence false", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
			Options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
		})

		var gotErr error
		for _, err := range d.GetAssertion(
			testContext,
			nil,
			"example.com",
			[]byte("client-data"),
			nil,
			&webauthn.GetAuthenticationExtensionsClientInputs{
				PRFInputs: &webauthn.PRFInputs{
					PRF: webauthn.AuthenticationExtensionsPRFInputs{
						Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")},
					},
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
	})

	t.Run("authentication requires a PIN UV auth token on a PIN-only device", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
			Options: map[protocol.Option]bool{
				protocol.OptionClientPIN: true,
			},
		})

		var gotErr error
		for _, err := range d.GetAssertion(
			testContext,
			nil,
			"example.com",
			[]byte("client-data"),
			nil,
			&webauthn.GetAuthenticationExtensionsClientInputs{
				PRFInputs: &webauthn.PRFInputs{
					PRF: webauthn.AuthenticationExtensionsPRFInputs{
						Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")},
					},
				},
			},
			nil,
		) {
			gotErr = err
		}

		if err, target := gotErr, ErrPinUvAuthTokenRequired; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("hmac-secret-mc without hmac-secret is an authenticator violation", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecretMC},
			Options: map[protocol.Option]bool{
				protocol.OptionMakeCredentialUvNotRequired: true,
			},
		})

		_, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{},
		})
		if err, target := err, ErrSpecViolation; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})
}

func TestValidateGetPRFInputs(t *testing.T) {
	credentialOne := credential.PublicKeyCredentialDescriptor{ID: []byte("one")}
	credentialTwo := credential.PublicKeyCredentialDescriptor{ID: []byte("two")}
	idOne := base64.RawURLEncoding.EncodeToString(credentialOne.ID)
	idTwo := base64.RawURLEncoding.EncodeToString(credentialTwo.ID)
	first := webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")}
	second := webauthn.AuthenticationExtensionsPRFValues{First: []byte("second")}

	t.Run("empty evalByCredential is allowed without allowList", func(t *testing.T) {
		err := validateGetPRFInputs(webauthn.AuthenticationExtensionsPRFInputs{
			EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{},
		}, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("present empty first is valid", func(t *testing.T) {
		err := validateGetPRFInputs(webauthn.AuthenticationExtensionsPRFInputs{
			EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{
				idOne: {First: []byte{}},
			},
		}, []credential.PublicKeyCredentialDescriptor{credentialOne})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	for _, tt := range []struct {
		name   string
		inputs webauthn.AuthenticationExtensionsPRFInputs
		allow  []credential.PublicKeyCredentialDescriptor
		want   error
	}{
		{
			name: "eval second without first",
			inputs: webauthn.AuthenticationExtensionsPRFInputs{
				Eval: webauthn.AuthenticationExtensionsPRFValues{Second: []byte("second")},
			},
			want: SyntaxError,
		},
		{
			name: "non-empty evalByCredential without allowList",
			inputs: webauthn.AuthenticationExtensionsPRFInputs{
				EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{idOne: first},
			},
			want: ErrNotSupported,
		},
		{
			name: "empty credential ID",
			inputs: webauthn.AuthenticationExtensionsPRFInputs{
				EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{"": first},
			},
			allow: []credential.PublicKeyCredentialDescriptor{credentialOne},
			want:  SyntaxError,
		},
		{
			name: "padded credential ID",
			inputs: webauthn.AuthenticationExtensionsPRFInputs{
				EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{idOne + "=": first},
			},
			allow: []credential.PublicKeyCredentialDescriptor{credentialOne},
			want:  SyntaxError,
		},
		{
			name: "credential ID outside allowList",
			inputs: webauthn.AuthenticationExtensionsPRFInputs{
				EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{idTwo: second},
			},
			allow: []credential.PublicKeyCredentialDescriptor{credentialOne},
			want:  SyntaxError,
		},
		{
			name: "missing required first",
			inputs: webauthn.AuthenticationExtensionsPRFInputs{
				EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{idOne: {}},
			},
			allow: []credential.PublicKeyCredentialDescriptor{credentialOne},
			want:  SyntaxError,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGetPRFInputs(tt.inputs, tt.allow)
			if err, target := err, tt.want; !errors.Is(err, target) {
				t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
			}
		})
	}
}

func TestSelectCTAPGetPRFEvaluation(t *testing.T) {
	credentialOne := credential.PublicKeyCredentialDescriptor{ID: []byte("one")}
	credentialTwo := credential.PublicKeyCredentialDescriptor{ID: []byte("two")}
	idOne := base64.RawURLEncoding.EncodeToString(credentialOne.ID)
	idTwo := base64.RawURLEncoding.EncodeToString(credentialTwo.ID)
	first := webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")}
	second := webauthn.AuthenticationExtensionsPRFValues{First: []byte("second")}

	t.Run("single credential override", func(t *testing.T) {
		got, err := selectCTAPGetPRFEvaluation(webauthn.AuthenticationExtensionsPRFInputs{
			Eval:             second,
			EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{idOne: first},
		}, []credential.PublicKeyCredentialDescriptor{credentialOne})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := got; got == nil {
			t.Fatalf("got nil, want a non-nil value")
		}

		if got, want := *got, first; (got.First == nil) != (want.First == nil) || !bytes.Equal(got.First, want.First) || ((got.Second == nil) != (want.Second == nil) || !bytes.Equal(got.Second, want.Second)) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})

	t.Run("uniform multi-credential inputs are safe", func(t *testing.T) {
		got, err := selectCTAPGetPRFEvaluation(webauthn.AuthenticationExtensionsPRFInputs{
			EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{
				idOne: first,
				idTwo: first,
			},
		}, []credential.PublicKeyCredentialDescriptor{credentialOne, credentialTwo})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := got; got == nil {
			t.Fatalf("got nil, want a non-nil value")
		}

		if got, want := *got, first; (got.First == nil) != (want.First == nil) || !bytes.Equal(got.First, want.First) || ((got.Second == nil) != (want.Second == nil) || !bytes.Equal(got.Second, want.Second)) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})

	for _, tt := range []struct {
		name   string
		inputs webauthn.AuthenticationExtensionsPRFInputs
	}{
		{
			name: "different credential inputs require separate CTAP requests",
			inputs: webauthn.AuthenticationExtensionsPRFInputs{
				EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{
					idOne: first,
					idTwo: second,
				},
			},
		},
		{
			name: "absent and present empty second inputs differ",
			inputs: webauthn.AuthenticationExtensionsPRFInputs{
				EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{
					idOne: first,
					idTwo: {First: []byte("first"), Second: []byte{}},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := selectCTAPGetPRFEvaluation(
				tt.inputs,
				[]credential.PublicKeyCredentialDescriptor{credentialOne, credentialTwo},
			)
			if err, target := err, ErrNotSupported; !errors.Is(err, target) {
				t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
			}
		})
	}
}
