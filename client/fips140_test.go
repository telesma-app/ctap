package client

import (
	"context"
	cryptofips140 "crypto/fips140"
	"errors"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapfips140 "github.com/telesma-app/ctap/fips140"
	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/protocol"
)

func TestFIPS140MakeCredentialFiltersAlgorithms(t *testing.T) {
	requireFIPS140(t)

	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: makeCredentialAuthData(t, testP256CredentialKey(cose.AlgorithmES256)),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	parameters := []credential.PublicKeyCredentialParameters{
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmES256K},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmES256},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmESP256},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmRS1},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmEdDSA},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmEd25519},
	}

	_, err := newTestClient(t, fake).MakeCredential(
		context.Background(),
		0,
		nil,
		testClientDataHash(),
		credential.PublicKeyCredentialRpEntity{ID: "example.com"},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id")},
		parameters,
		nil,
		nil,
		nil,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}

	command, requestCBOR := fake.FirstCTAPPayload(t)
	if command != protocol.AuthenticatorMakeCredential {
		t.Fatalf("command = %v, want %v", command, protocol.AuthenticatorMakeCredential)
	}

	var request protocol.AuthenticatorMakeCredentialRequest
	if err := cbor.Unmarshal(requestCBOR, &request); err != nil {
		t.Fatalf("decode request: %v", err)
	}

	got := make([]cose.Algorithm, 0, len(request.PubKeyCredParams))
	for _, parameter := range request.PubKeyCredParams {
		got = append(got, parameter.Algorithm)
	}
	// AlgorithmEdDSA is dropped too: it does not name a curve.
	want := []cose.Algorithm{cose.AlgorithmES256, cose.AlgorithmESP256, cose.AlgorithmEd25519}
	if !slices.Equal(got, want) {
		t.Fatalf("filtered algorithms = %v, want %v", got, want)
	}
}

func TestFIPS140MakeCredentialRejectsUnapprovedCredentialKey(t *testing.T) {
	requireFIPS140(t)

	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: makeCredentialAuthData(t, testP256CredentialKey(cose.AlgorithmES256K)),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)

	_, err := newTestClient(t, fake).MakeCredential(
		context.Background(),
		0,
		nil,
		testClientDataHash(),
		credential.PublicKeyCredentialRpEntity{ID: "example.com"},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id")},
		[]credential.PublicKeyCredentialParameters{
			{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmES256},
		},
		nil,
		nil,
		nil,
		0,
		nil,
	)
	assertClientFIPS140NotAllowed(t, err)
}

func TestFIPS140MakeCredentialRejectsWithoutApprovedAlgorithmBeforeIO(t *testing.T) {
	requireFIPS140(t)

	fake := testhid.NewCBORDevice(t, testCID)
	_, err := newTestClient(t, fake).MakeCredential(
		context.Background(),
		0,
		nil,
		testClientDataHash(),
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
	assertClientFIPS140NotAllowed(t, err)

	if writes := fake.Writes(); len(writes) != 0 {
		t.Fatalf("transport writes = %x, want none", writes)
	}
}

func TestFIPS140RawClientAllowsPreviewSign(t *testing.T) {
	requireFIPS140(t)

	t.Run("MakeCredential filters key-generation algorithms", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
			Format:      attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw: makeCredentialAuthData(t, testP256CredentialKey(cose.AlgorithmES256)),
		}))
		algorithms := []cose.Algorithm{cose.AlgorithmES256K, cose.AlgorithmES256, cose.AlgorithmRS1}

		_, err := newTestClient(t, fake).MakeCredential(
			context.Background(),
			0,
			nil,
			testClientDataHash(),
			credential.PublicKeyCredentialRpEntity{ID: "example.com"},
			credential.PublicKeyCredentialUserEntity{ID: []byte("user-id")},
			[]credential.PublicKeyCredentialParameters{{
				Type:      credential.PublicKeyCredentialTypePublicKey,
				Algorithm: cose.AlgorithmES256,
			}},
			nil,
			&protocol.CreateExtensionInputs{
				CreatePreviewSignInput: protocol.CreatePreviewSignInput{
					PreviewSign: protocol.PreviewSignGenerateKeyInput{
						Algorithms: algorithms,
					},
				},
			},
			nil,
			0,
			nil,
		)
		if err != nil {
			t.Fatalf("MakeCredential: %v", err)
		}

		if got, want := algorithms, []cose.Algorithm{cose.AlgorithmES256K, cose.AlgorithmES256, cose.AlgorithmRS1}; !slices.Equal(got, want) {
			t.Fatalf("input algorithms = %v, want %v", got, want)
		}

		command, requestCBOR := fake.FirstCTAPPayload(t)
		if command != protocol.AuthenticatorMakeCredential {
			t.Fatalf("command = %v, want %v", command, protocol.AuthenticatorMakeCredential)
		}

		var request protocol.AuthenticatorMakeCredentialRequest
		if err := cbor.Unmarshal(requestCBOR, &request); err != nil {
			t.Fatalf("decode request: %v", err)
		}

		if got, want := request.Extensions.PreviewSign.Algorithms, []cose.Algorithm{cose.AlgorithmES256}; !slices.Equal(got, want) {
			t.Fatalf("previewSign algorithms = %v, want %v", got, want)
		}
	})

	t.Run("GetAssertion passes signing through", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
			AuthDataRaw: minimalAuthData(),
			Signature:   []byte{1},
		}))

		var gotErr error
		for _, err := range newTestClient(t, fake).GetAssertion(
			context.Background(),
			0,
			nil,
			"example.com",
			testClientDataHash(),
			nil,
			&protocol.GetExtensionInputs{
				GetPreviewSignInput: protocol.GetPreviewSignInput{
					PreviewSign: protocol.PreviewSignSignInput{
						KeyHandle:  []byte{},
						ToBeSigned: []byte{},
					},
				},
			},
			nil,
		) {
			gotErr = err
		}

		if gotErr != nil {
			t.Fatalf("GetAssertion: %v", gotErr)
		}

		command, requestCBOR := fake.FirstCTAPPayload(t)
		if command != protocol.AuthenticatorGetAssertion {
			t.Fatalf("command = %v, want %v", command, protocol.AuthenticatorGetAssertion)
		}

		var request protocol.AuthenticatorGetAssertionRequest
		if err := cbor.Unmarshal(requestCBOR, &request); err != nil {
			t.Fatalf("decode request: %v", err)
		}

		if request.Extensions.PreviewSign.KeyHandle == nil || request.Extensions.PreviewSign.ToBeSigned == nil {
			t.Fatalf("previewSign signing input was not preserved: %#v", request.Extensions.PreviewSign)
		}
	})
}

func TestFIPS140RawClientRejectsProtocolOneHMACSecretBeforeIO(t *testing.T) {
	requireFIPS140(t)

	protocols := []struct {
		name              string
		pinUvAuthProtocol protocol.PinUvAuthProtocol
	}{
		{name: "explicit protocol one", pinUvAuthProtocol: protocol.PinUvAuthProtocolOne},
		{name: "legacy protocol-one omission"},
	}
	operations := []struct {
		name   string
		invoke func(testing.TB, *Client, protocol.PinUvAuthProtocol) error
	}{
		{
			name: "MakeCredential hmac-secret-mc",
			invoke: func(t testing.TB, cl *Client, pinUvAuthProtocol protocol.PinUvAuthProtocol) error {
				_, err := cl.MakeCredential(
					context.Background(),
					0,
					nil,
					testClientDataHash(),
					credential.PublicKeyCredentialRpEntity{ID: "example.com"},
					credential.PublicKeyCredentialUserEntity{ID: []byte("user-id")},
					[]credential.PublicKeyCredentialParameters{{
						Type:      credential.PublicKeyCredentialTypePublicKey,
						Algorithm: cose.AlgorithmES256,
					}},
					nil,
					&protocol.CreateExtensionInputs{
						CreateHMACSecretMCInput: protocol.CreateHMACSecretMCInput{
							HMACSecret: protocol.HMACSecret{
								KeyAgreement:      testKeyAgreement(t),
								SaltEnc:           make([]byte, 32),
								SaltAuth:          make([]byte, 16),
								PinUvAuthProtocol: pinUvAuthProtocol,
							},
						},
					},
					nil,
					0,
					nil,
				)

				return err
			},
		},
		{
			name: "GetAssertion hmac-secret",
			invoke: func(t testing.TB, cl *Client, pinUvAuthProtocol protocol.PinUvAuthProtocol) error {
				for _, err := range cl.GetAssertion(
					context.Background(),
					0,
					nil,
					"example.com",
					testClientDataHash(),
					nil,
					&protocol.GetExtensionInputs{
						GetHMACSecretInput: protocol.GetHMACSecretInput{
							HMACSecret: protocol.HMACSecret{
								KeyAgreement:      testKeyAgreement(t),
								SaltEnc:           make([]byte, 32),
								SaltAuth:          make([]byte, 16),
								PinUvAuthProtocol: pinUvAuthProtocol,
							},
						},
					},
					nil,
				) {
					return err
				}

				return errors.New("GetAssertion yielded no policy error")
			},
		},
	}

	for _, operation := range operations {
		for _, protocolCase := range protocols {
			t.Run(operation.name+"/"+protocolCase.name, func(t *testing.T) {
				fake := testhid.NewCBORDevice(t, testCID)
				err := operation.invoke(t, newTestClient(t, fake), protocolCase.pinUvAuthProtocol)
				assertClientFIPS140NotAllowed(t, err)

				if writes := fake.Writes(); len(writes) != 0 {
					t.Fatalf("transport writes = %x, want none", writes)
				}
			})
		}
	}
}

func TestFIPS140ClientRejectsPinUvAuthProtocolOneBeforeIO(t *testing.T) {
	requireFIPS140(t)

	tests := []struct {
		name   string
		invoke func(testing.TB, *Client) error
	}{
		{
			name: "token validation",
			invoke: func(_ testing.TB, cl *Client) error {
				_, err := cl.MakeCredential(
					context.Background(),
					protocol.PinUvAuthProtocolOne,
					pinUvAuthToken(),
					testClientDataHash(),
					credential.PublicKeyCredentialRpEntity{ID: "example.com"},
					credential.PublicKeyCredentialUserEntity{ID: []byte("user-id")},
					[]credential.PublicKeyCredentialParameters{{
						Type:      credential.PublicKeyCredentialTypePublicKey,
						Algorithm: cose.AlgorithmES256,
					}},
					nil,
					nil,
					nil,
					0,
					nil,
				)

				return err
			},
		},
		{
			name: "iterator token validation",
			invoke: func(_ testing.TB, cl *Client) error {
				for _, err := range cl.GetAssertion(
					context.Background(),
					protocol.PinUvAuthProtocolOne,
					pinUvAuthToken(),
					"example.com",
					testClientDataHash(),
					nil,
					nil,
					nil,
				) {
					return err
				}

				return errors.New("GetAssertion yielded no policy error")
			},
		},
		{
			name: "PIN protocol constructor",
			invoke: func(t testing.TB, cl *Client) error {
				return cl.SetPIN(
					context.Background(),
					protocol.PinUvAuthProtocolOne,
					testKeyAgreement(t),
					"1234",
				)
			},
		},
		{
			name: "legacy preview UV",
			invoke: func(t testing.TB, cl *Client) error {
				_, err := cl.GetPinUvAuthTokenUsingUv(context.Background(), testKeyAgreement(t))
				return err
			},
		},
		{
			name: "get PIN retries",
			invoke: func(_ testing.TB, cl *Client) error {
				_, _, err := cl.GetPINRetries(context.Background(), protocol.PinUvAuthProtocolOne)
				return err
			},
		},
		{
			name: "get UV retries",
			invoke: func(_ testing.TB, cl *Client) error {
				_, err := cl.GetUVRetries(context.Background(), protocol.PinUvAuthProtocolOne)
				return err
			},
		},
		{
			name: "get key agreement",
			invoke: func(_ testing.TB, cl *Client) error {
				_, err := cl.GetKeyAgreement(context.Background(), protocol.PinUvAuthProtocolOne)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := testhid.NewCBORDevice(t, testCID)
			err := test.invoke(t, newTestClient(t, fake))
			assertClientFIPS140NotAllowed(t, err)

			if writes := fake.Writes(); len(writes) != 0 {
				t.Fatalf("transport writes = %x, want none", writes)
			}
		})
	}
}

func TestFIPS140GetPINRetriesAllowsOmittedProtocol(t *testing.T) {
	requireFIPS140(t)

	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
		PinRetries: new(uint(8)),
	}))

	retries, _, err := newTestClient(t, fake).GetPINRetries(context.Background(), 0)
	if err != nil {
		t.Fatalf("GetPINRetries: %v", err)
	}

	if got, want := retries, uint(8); got != want {
		t.Fatalf("retries = %d, want %d", got, want)
	}

	assertCTAPRequest(t, fake, expectedCTAPRequest{
		command: protocol.AuthenticatorClientPIN,
		keys:    []uint64{2},
		fields: map[uint64]uint64{
			2: uint64(protocol.ClientPINSubCommandGetPINRetries),
		},
	})
}

func requireFIPS140(t testing.TB) {
	t.Helper()

	if !cryptofips140.Enabled() {
		t.Skip("requires Go FIPS 140-3 mode")
	}
}

func assertClientFIPS140NotAllowed(t testing.TB, err error) {
	t.Helper()

	if !errors.Is(err, ctapfips140.ErrNotAllowed) {
		t.Fatalf("error = %v, want errors.Is(error, %v)", err, ctapfips140.ErrNotAllowed)
	}
}
