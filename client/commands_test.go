package client

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/fips140"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/crypto/protocolone"
	"github.com/telesma-app/ctap/crypto/protocoltwo"
	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/options"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
)

type clientPINTokenCBORFunc func(context.Context, []byte) (ctaptransport.CBORResponse, error)

func (f clientPINTokenCBORFunc) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	return f(ctx, request)
}

func TestGetUVRetriesIncludesPinUvAuthProtocol(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
		UvRetries: new(uint(5)),
	}))

	retries, err := newTestClient(t, fake).GetUVRetries(context.Background(), protocol.PinUvAuthProtocolTwo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := retries, uint(5); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	assertCTAPRequest(t, fake, expectedCTAPRequest{
		command: protocol.AuthenticatorClientPIN,
		keys:    []uint64{1, 2},
		fields: map[uint64]uint64{
			1: uint64(protocol.PinUvAuthProtocolTwo),
			2: uint64(protocol.ClientPINSubCommandGetUVRetries),
		},
	})
}

func TestGetUVRetriesOmitsUnspecifiedPinUvAuthProtocol(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
		UvRetries: new(uint(5)),
	}))

	_, err := newTestClient(t, fake).GetUVRetries(context.Background(), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertCTAPRequest(t, fake, expectedCTAPRequest{
		command: protocol.AuthenticatorClientPIN,
		keys:    []uint64{2},
	})
}

func TestClientUsesConfiguredTransport(t *testing.T) {
	transport := &fakeCBORTransport{
		t:       t,
		request: []byte{byte(protocol.AuthenticatorGetInfo)},
		response: encodeCBOR(t, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_1},
		}),
	}

	client, err := NewClient(options.WithTransport(transport))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	response, err := client.GetInfo(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := protocol.Versions{protocol.FIDO_2_1}, response.Versions
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestClientGetInfoRemainsCompatibleWithFIDO20Response(t *testing.T) {
	transport := &fakeCBORTransport{
		t:       t,
		request: []byte{byte(protocol.AuthenticatorGetInfo)},
		response: encodeCBOR(t, map[uint64]any{
			1: []string{"FIDO_2_0"},
			3: make([]byte, 16),
		}),
	}

	client, err := NewClient(options.WithTransport(transport))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	response, err := client.GetInfo(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := protocol.Versions{protocol.FIDO_2_0}, response.Versions
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	if got, want := response.EffectiveMaxPINLength(), protocol.DefaultMaxPINCodePoints; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got := response.AuthenticatorConfigCommands; got != nil {
		t.Errorf("got %#v, want nil", got)
	}
}

func TestClientUsesConfiguredDecMode(t *testing.T) {
	// {1: ["FIDO_2_1"], 9: [h'ff' encoded as a CBOR text string]}
	responseCBOR := []byte{
		0xa2,
		0x01, 0x81, 0x68, 'F', 'I', 'D', 'O', '_', '2', '_', '1',
		0x09, 0x81, 0x61, 0xff,
	}

	lenientClient, err := NewClient(options.WithTransport(&fakeCBORTransport{
		t:        t,
		request:  []byte{byte(protocol.AuthenticatorGetInfo)},
		response: responseCBOR,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	response, err := lenientClient.GetInfo(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := []credential.AuthenticatorTransport{credential.AuthenticatorTransport(string([]byte{0xff}))}, response.Transports
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	decMode, err := cbor.DecOptions{UTF8: cbor.UTF8RejectInvalid}.DecMode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	strictClient, err := NewClient(
		options.WithDecMode(decMode),
		options.WithTransport(&fakeCBORTransport{
			t:        t,
			request:  []byte{byte(protocol.AuthenticatorGetInfo)},
			response: responseCBOR,
		}),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = strictClient.GetInfo(context.Background())
	if err == nil {
		t.Fatalf("expected an error")
	}

	if container, element := err.Error(), "invalid UTF-8"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}
}

func TestClientRequiresTransport(t *testing.T) {
	_, err := NewClient()
	if err, target := err, ErrTransportNotConfigured; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
}

func TestClientReturnsConfiguredTransportCTAPStatus(t *testing.T) {
	transport := &fakeCBORTransport{
		t:       t,
		request: []byte{byte(protocol.AuthenticatorGetInfo)},
		status:  ctaptransport.CTAP2_ERR_INVALID_CBOR,
	}

	client, err := NewClient(options.WithTransport(transport))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = client.GetInfo(context.Background())

	var ctapErr *ctaptransport.CTAPError
	if err := err; !errors.As(err, &ctapErr) {
		t.Fatalf("error %v does not match requested type", err)
	}

	if got, want := ctapErr.Command, protocol.AuthenticatorGetInfo; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := ctapErr.StatusCode, ctaptransport.CTAP2_ERR_INVALID_CBOR; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestMakeCredentialRequestShapeAndPINAuthParam(t *testing.T) {
	clientDataHash := testClientDataHash()
	token := pinUvAuthToken()
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalMakeCredentialAuthData(t),
	}))

	_, err := newTestClient(t, fake).MakeCredential(
		context.Background(),
		protocol.PinUvAuthProtocolTwo,
		token,
		clientDataHash,
		credential.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "user"},
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	request := assertCTAPRequest(t, fake, expectedCTAPRequest{
		command: protocol.AuthenticatorMakeCredential,
		keys:    []uint64{1, 2, 3, 4, 8, 9},
		fields:  map[uint64]uint64{9: uint64(protocol.PinUvAuthProtocolTwo)},
	})
	if got, want := requestBytes(t, request, uint64(1)), clientDataHash; got == nil != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := requestBytes(t, request, uint64(8)), crypto.Authenticate(protocol.PinUvAuthProtocolTwo, token, clientDataHash); got == nil != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestMakeCredentialMinimalRequestOmitsEmptyExcludeList(t *testing.T) {
	clientDataHash := testClientDataHash()
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalMakeCredentialAuthData(t),
	}))

	resp, err := newTestClient(t, fake).MakeCredential(
		context.Background(),
		0,
		nil,
		clientDataHash,
		credential.PublicKeyCredentialRpEntity{ID: "example.com"},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id")},
		[]credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}},
		[]credential.PublicKeyCredentialDescriptor{},
		nil,
		nil,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := resp.AuthData; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	assertCTAPRequest(t, fake, expectedCTAPRequest{
		command: protocol.AuthenticatorMakeCredential,
		keys:    []uint64{1, 2, 3, 4},
	})
}

func TestMakeCredentialFullRequestShape(t *testing.T) {
	clientDataHash := testClientDataHash()
	token := pinUvAuthToken()
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalMakeCredentialAuthData(t),
	}))

	resp, err := newTestClient(t, fake).MakeCredential(
		context.Background(),
		protocol.PinUvAuthProtocolTwo,
		token,
		clientDataHash,
		credential.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "user"},
		[]credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}},
		[]credential.PublicKeyCredentialDescriptor{{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   []byte("credential-id"),
		}},
		&protocol.CreateExtensionInputs{
			CreateCredProtectInput:  protocol.CreateCredProtectInput{CredProtect: 2},
			CreateLargeBlobKeyInput: protocol.CreateLargeBlobKeyInput{LargeBlobKey: true},
		},
		map[protocol.Option]bool{
			protocol.OptionResidentKeys:     true,
			protocol.OptionUserVerification: false,
		},
		1,
		[]attestation.AttestationStatementFormatIdentifier{
			attestation.AttestationStatementFormatIdentifierPacked,
			attestation.AttestationStatementFormatIdentifierNone,
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := resp.AuthData; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	request := assertCTAPRequest(t, fake, expectedCTAPRequest{
		command: protocol.AuthenticatorMakeCredential,
		keys:    []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
		fields: map[uint64]uint64{
			9:  uint64(protocol.PinUvAuthProtocolTwo),
			10: 1,
		},
	})
	if got, want := requestBytes(t, request, uint64(8)), crypto.Authenticate(protocol.PinUvAuthProtocolTwo, token, clientDataHash); got == nil != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	extensions, ok := request[uint64(6)].(map[any]any)
	if got := ok; !got {
		t.Fatalf("got false, want true")
	}
	{
		want, got := true, extensions["largeBlobKey"]
		gotValue, ok := got.(bool)

		if !ok || gotValue != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestMakeCredentialRejectsInvalidClientDataHashBeforeCommand(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)

	_, err := newTestClient(t, fake).MakeCredential(
		context.Background(),
		0,
		nil,
		[]byte("too-short"),
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
	if err == nil {
		t.Fatalf("expected an error")
	}

	if got := fake.Writes(); len(got) != 0 {
		t.Errorf("got non-empty value %#v", got)
	}
}

func TestMakeCredentialReturnsResponseDecodeErrors(t *testing.T) {
	t.Run("invalid CBOR", func(t *testing.T) {
		fake := testhid.New(t, testhid.CBOROK(testCID, []byte{0xff}))

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
			nil,
			nil,
			0,
			nil,
		)
		if err == nil {
			t.Fatalf("expected an error")
		}
	})

	t.Run("invalid authData", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
			Format:      attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw: []byte{1},
		}))

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
			nil,
			nil,
			0,
			nil,
		)
		if err == nil {
			t.Fatalf("expected an error")
		}
	})
}

func TestGetAssertionRequestShapeAndPINAuthParam(t *testing.T) {
	clientDataHash := testClientDataHash()
	token := pinUvAuthToken()
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: minimalAuthData(),
		Signature:   []byte{1},
	}))

	var assertions int

	for assertion, err := range newTestClient(t, fake).GetAssertion(
		context.Background(),
		protocol.PinUvAuthProtocolTwo,
		token,
		"example.com",
		clientDataHash,
		nil,
		nil,
		nil,
	) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := assertion.AuthData; got == nil {
			t.Fatalf("got nil, want a non-nil value")
		}

		assertions++
	}

	if got, want := assertions, 1; got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	request := assertCTAPRequest(t, fake, expectedCTAPRequest{
		command: protocol.AuthenticatorGetAssertion,
		keys:    []uint64{1, 2, 6, 7},
		fields:  map[uint64]uint64{7: uint64(protocol.PinUvAuthProtocolTwo)},
	})
	if got, want := requestString(t, request, uint64(1)), "example.com"; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := requestBytes(t, request, uint64(2)), clientDataHash; got == nil != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := requestBytes(t, request, uint64(6)), crypto.Authenticate(protocol.PinUvAuthProtocolTwo, token, clientDataHash); got == nil != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestGetAssertionMinimalRequestOmitsEmptyAllowList(t *testing.T) {
	clientDataHash := testClientDataHash()
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: minimalAuthData(),
		Signature:   []byte{1},
	}))

	var assertions int

	for assertion, err := range newTestClient(t, fake).GetAssertion(
		context.Background(),
		0,
		nil,
		"example.com",
		clientDataHash,
		[]credential.PublicKeyCredentialDescriptor{},
		nil,
		nil,
	) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := assertion.AuthData; got == nil {
			t.Fatalf("got nil, want a non-nil value")
		}

		assertions++
	}

	if got, want := assertions, 1; got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	command, request := fake.FirstCTAPRequestMap(t)
	if got, want := command, protocol.AuthenticatorGetAssertion; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	assertRequestKeys(t, request, 1, 2)
}

func TestGetAssertionFullRequestShape(t *testing.T) {
	clientDataHash := testClientDataHash()
	token := pinUvAuthToken()
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: minimalAuthData(),
		Signature:   []byte{1},
	}))

	var assertions int

	for assertion, err := range newTestClient(t, fake).GetAssertion(
		context.Background(),
		protocol.PinUvAuthProtocolTwo,
		token,
		"example.com",
		clientDataHash,
		[]credential.PublicKeyCredentialDescriptor{{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   []byte("credential-id"),
		}},
		&protocol.GetExtensionInputs{
			GetCredBlobInput:     protocol.GetCredBlobInput{CredBlob: true},
			GetLargeBlobKeyInput: protocol.GetLargeBlobKeyInput{LargeBlobKey: true},
		},
		map[protocol.Option]bool{
			protocol.OptionUserPresence:     true,
			protocol.OptionUserVerification: false,
		},
	) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := assertion.AuthData; got == nil {
			t.Fatalf("got nil, want a non-nil value")
		}

		assertions++
	}

	if got, want := assertions, 1; got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	request := assertCTAPRequest(t, fake, expectedCTAPRequest{
		command: protocol.AuthenticatorGetAssertion,
		keys:    []uint64{1, 2, 3, 4, 5, 6, 7},
		fields:  map[uint64]uint64{7: uint64(protocol.PinUvAuthProtocolTwo)},
	})
	if got, want := requestBytes(t, request, uint64(6)), crypto.Authenticate(protocol.PinUvAuthProtocolTwo, token, clientDataHash); got == nil != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	extensions, ok := request[uint64(4)].(map[any]any)
	if got := ok; !got {
		t.Fatalf("got false, want true")
	}
	{
		want, got := true, extensions["largeBlobKey"]
		gotValue, ok := got.(bool)

		if !ok || gotValue != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestGetAssertionRejectsInvalidClientDataHashBeforeCommand(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)

	var yielded int
	for assertion, err := range newTestClient(t, fake).GetAssertion(
		context.Background(),
		0,
		nil,
		"example.com",
		[]byte("too-short"),
		nil,
		nil,
		nil,
	) {
		yielded++

		if !assertionResponseIsZero(assertion) {
			t.Errorf("got %#v, want zero response", assertion)
		}

		if err == nil {
			t.Fatalf("expected an error")
		}
	}

	if got, want := yielded, 1; got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	if got := fake.Writes(); len(got) != 0 {
		t.Errorf("got non-empty value %#v", got)
	}
}

func TestGetAssertionFetchesNextAssertions(t *testing.T) {
	first := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw:         minimalAuthData(),
		Signature:           []byte{1},
		NumberOfCredentials: 3,
	})
	second := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: minimalAuthData(),
		Signature:   []byte{2},
	})
	third := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: minimalAuthData(),
		Signature:   []byte{3},
	})
	fake := testhid.NewCBORDevice(t, testCID, first, second, third)

	var signatures [][]byte

	for assertion, err := range newTestClient(t, fake).GetAssertion(
		context.Background(),
		0,
		nil,
		"example.com",
		testClientDataHash(),
		nil,
		nil,
		nil,
	) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		signatures = append(signatures, assertion.Signature)
	}

	{
		want, got := [][]byte{{1}, {2}, {3}}, signatures
		if (got == nil) != (want == nil) || !slices.EqualFunc(got, want, func(got, want []byte) bool {
			return (got == nil) == (want == nil) && bytes.Equal(got, want)
		}) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}

	requests := fake.Requests(t)
	if got, want := len(requests), 3; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	command, _ := requests[0].CTAPPayload(t)
	if got, want := command, protocol.AuthenticatorGetAssertion; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	for _, request := range requests[1:] {
		command, body := request.CTAPPayload(t)
		if got, want := command, protocol.AuthenticatorGetNextAssertion; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}

		if got := body; len(got) != 0 {
			t.Errorf("got non-empty value %#v", got)
		}
	}
}

func TestGetAssertionStopsBeforeGetNextAssertionWhenIteratorStops(t *testing.T) {
	first := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw:         minimalAuthData(),
		Signature:           []byte{1},
		NumberOfCredentials: 2,
	})
	fake := testhid.NewCBORDevice(t, testCID, first)

	var assertions int

	for assertion, err := range newTestClient(t, fake).GetAssertion(
		context.Background(),
		0,
		nil,
		"example.com",
		testClientDataHash(),
		nil,
		nil,
		nil,
	) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		{
			want, got := []byte{1}, assertion.Signature
			if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
				t.Errorf("got %#v, want %#v", got, want)
			}
		}

		assertions++

		break
	}

	if got, want := assertions, 1; got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	if got, want := len(fake.Requests(t)), 1; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}
}

func TestGetAssertionReturnsResponseDecodeErrors(t *testing.T) {
	t.Run("invalid CBOR", func(t *testing.T) {
		fake := testhid.New(t, testhid.CBOROK(testCID, []byte{0xff}))

		var yielded int
		for assertion, err := range newTestClient(t, fake).GetAssertion(
			context.Background(),
			0,
			nil,
			"example.com",
			testClientDataHash(),
			nil,
			nil,
			nil,
		) {
			yielded++

			if !assertionResponseIsZero(assertion) {
				t.Errorf("got %#v, want zero response", assertion)
			}

			if err == nil {
				t.Fatalf("expected an error")
			}
		}

		if got, want := yielded, 1; got != want {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	})

	t.Run("invalid authData", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
			AuthDataRaw: []byte{1},
			Signature:   []byte{1},
		}))

		var yielded int
		for assertion, err := range newTestClient(t, fake).GetAssertion(
			context.Background(),
			0,
			nil,
			"example.com",
			testClientDataHash(),
			nil,
			nil,
			nil,
		) {
			yielded++

			if !assertionResponseIsZero(assertion) {
				t.Errorf("got %#v, want zero response", assertion)
			}

			if err == nil {
				t.Fatalf("expected an error")
			}
		}

		if got, want := yielded, 1; got != want {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	})
}

func TestClientPINRequestShapes(t *testing.T) {
	t.Run("set PIN", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, nil)

		err := newTestClient(t, fake).SetPIN(context.Background(), protocol.PinUvAuthProtocolTwo, testKeyAgreement(t), "1234")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		request := assertCTAPRequest(t, fake, expectedCTAPRequest{
			command: protocol.AuthenticatorClientPIN,
			keys:    []uint64{1, 2, 3, 4, 5},
			fields: map[uint64]uint64{
				1: uint64(protocol.PinUvAuthProtocolTwo),
				2: uint64(protocol.ClientPINSubCommandSetPIN),
			},
		})
		if got, want := len(requestBytes(t, request, 4)), 32; got != want {
			t.Errorf("got length %d, want %d", got, want)
		}

		if got, want := len(requestBytes(t, request, 5)), 80; got != want {
			t.Errorf("got length %d, want %d", got, want)
		}
	})

	t.Run("change PIN", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, nil)

		err := newTestClient(t, fake).ChangePIN(context.Background(), protocol.PinUvAuthProtocolTwo, testKeyAgreement(t), "1234", "5678")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		request := assertCTAPRequest(t, fake, expectedCTAPRequest{
			command: protocol.AuthenticatorClientPIN,
			keys:    []uint64{1, 2, 3, 4, 5, 6},
			fields: map[uint64]uint64{
				1: uint64(protocol.PinUvAuthProtocolTwo),
				2: uint64(protocol.ClientPINSubCommandChangePIN),
			},
		})
		if got, want := len(requestBytes(t, request, 4)), 32; got != want {
			t.Errorf("got length %d, want %d", got, want)
		}

		if got, want := len(requestBytes(t, request, 5)), 80; got != want {
			t.Errorf("got length %d, want %d", got, want)
		}

		if got, want := len(requestBytes(t, request, 6)), 32; got != want {
			t.Errorf("got length %d, want %d", got, want)
		}
	})

	t.Run("get PIN token validates PIN before command", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)

		_, err := newTestClient(t, fake).GetPinToken(context.Background(), protocol.PinUvAuthProtocolTwo, testKeyAgreement(t), "123\x00")
		if err == nil {
			t.Fatalf("expected an error")
		}

		if got := fake.Writes(); len(got) != 0 {
			t.Errorf("got non-empty value %#v", got)
		}
	})

	t.Run("get PIN/UV auth token with permissions validates PIN before command", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)

		_, err := newTestClient(t, fake).GetPinUvAuthTokenUsingPinWithPermissions(
			context.Background(),
			protocol.PinUvAuthProtocolTwo,
			testKeyAgreement(t),
			"123\x00",
			protocol.PermissionCredentialManagement,
			"",
		)
		if err == nil {
			t.Fatalf("expected an error")
		}

		if got := fake.Writes(); len(got) != 0 {
			t.Errorf("got non-empty value %#v", got)
		}
	})

	t.Run("returned PIN and UV tokens remain caller-owned", func(t *testing.T) {
		for _, testCase := range []struct {
			name              string
			pinUvAuthProtocol protocol.PinUvAuthProtocol
			subCommand        protocol.ClientPINSubCommand
			requestKeys       []uint64
			getToken          func(*Client, cose.Key) ([]byte, error)
		}{
			{
				name:              "legacy PIN",
				pinUvAuthProtocol: protocol.PinUvAuthProtocolTwo,
				subCommand:        protocol.ClientPINSubCommandGetPinToken,
				requestKeys:       []uint64{1, 2, 3, 6},
				getToken: func(client *Client, keyAgreement cose.Key) ([]byte, error) {
					return client.GetPinToken(
						context.Background(),
						protocol.PinUvAuthProtocolTwo,
						keyAgreement,
						"1234",
					)
				},
			},
			{
				name:              "permissioned PIN",
				pinUvAuthProtocol: protocol.PinUvAuthProtocolTwo,
				subCommand:        protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions,
				requestKeys:       []uint64{1, 2, 3, 6, 9, 10},
				getToken: func(client *Client, keyAgreement cose.Key) ([]byte, error) {
					return client.GetPinUvAuthTokenUsingPinWithPermissions(
						context.Background(),
						protocol.PinUvAuthProtocolTwo,
						keyAgreement,
						"1234",
						protocol.PermissionGetAssertion,
						"example.com",
					)
				},
			},
			{
				name:              "preview UV",
				pinUvAuthProtocol: protocol.PinUvAuthProtocolOne,
				subCommand:        protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions,
				requestKeys:       []uint64{1, 2, 3},
				getToken: func(client *Client, keyAgreement cose.Key) ([]byte, error) {
					return client.GetPinUvAuthTokenUsingUv(
						context.Background(),
						keyAgreement,
					)
				},
			},
			{
				name:              "permissioned UV",
				pinUvAuthProtocol: protocol.PinUvAuthProtocolTwo,
				subCommand:        protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions,
				requestKeys:       []uint64{1, 2, 3, 9, 10},
				getToken: func(client *Client, keyAgreement cose.Key) ([]byte, error) {
					return client.GetPinUvAuthTokenUsingUvWithPermissions(
						context.Background(),
						protocol.PinUvAuthProtocolTwo,
						keyAgreement,
						protocol.PermissionGetAssertion,
						"example.com",
					)
				},
			},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				if fips140.Enabled() && testCase.pinUvAuthProtocol == protocol.PinUvAuthProtocolOne {
					t.Skip("legacy preview UV requires PIN/UV auth protocol 1")
				}

				authenticatorPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				keyAgreement, err := cose.KeyFromP256PublicKey(authenticatorPrivateKey.PublicKey())
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				wantKeyAgreementX := slices.Clone(keyAgreement[cose.EC2KeyParameterX].([]byte))
				wantKeyAgreementY := slices.Clone(keyAgreement[cose.EC2KeyParameterY].([]byte))

				wantTokenLength := 32
				if testCase.pinUvAuthProtocol == protocol.PinUvAuthProtocolOne {
					wantTokenLength = 16
				}

				wantToken := bytes.Repeat([]byte{0x52}, wantTokenLength)

				var sentRequest []byte

				transport := clientPINTokenCBORFunc(func(
					_ context.Context,
					request []byte,
				) (ctaptransport.CBORResponse, error) {
					sentRequest = slices.Clone(request)
					if got := request; len(got) == 0 {
						t.Fatalf("got empty value %#v, want non-empty", got)
					}

					if got, want := protocol.Command(request[0]), protocol.AuthenticatorClientPIN; got != want {
						t.Fatalf("got %#v, want %#v", got, want)
					}

					var clientPIN protocol.AuthenticatorClientPINRequest
					if err := cbor.Unmarshal(request[1:], &clientPIN); err != nil {
						t.Fatalf("unexpected error: %v", err)
					}

					platformPublicKey, err := clientPIN.KeyAgreement.P256PublicKey()
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}

					z, err := authenticatorPrivateKey.ECDH(platformPublicKey)
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					defer clear(z)

					var sharedSecret []byte

					switch testCase.pinUvAuthProtocol {
					case protocol.PinUvAuthProtocolOne:
						sharedSecret = protocolone.KDF(z)
					case protocol.PinUvAuthProtocolTwo:
						sharedSecret, err = protocoltwo.KDF(z)
						if err != nil {
							t.Fatalf("unexpected error: %v", err)
						}
					default:
						t.Fatalf("unexpected PIN/UV auth protocol: %d", testCase.pinUvAuthProtocol)
					}

					defer clear(sharedSecret)

					var encryptedToken []byte

					switch testCase.pinUvAuthProtocol {
					case protocol.PinUvAuthProtocolOne:
						encryptedToken, err = protocolone.Encrypt(sharedSecret, wantToken)
					case protocol.PinUvAuthProtocolTwo:
						encryptedToken, err = protocoltwo.Encrypt(sharedSecret, wantToken)
					}

					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}

					return ctaptransport.CBORResponse{
						StatusCode: ctaptransport.CTAP2_OK,
						Data: encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
							PinUvAuthToken: encryptedToken,
						}),
					}, nil
				})

				client, err := NewClient(options.WithTransport(transport))
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				token, err := testCase.getToken(client, keyAgreement)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if got, want := token, wantToken; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
					t.Errorf("got %#v, want %#v", got, want)
				}
				{
					want, got := wantKeyAgreementX, keyAgreement[cose.EC2KeyParameterX]
					gotValue, ok := got.([]byte)

					if !ok || ((gotValue == nil) != (want == nil) || !bytes.Equal(gotValue, want)) {
						t.Errorf("got %#v, want %#v", got, want)
					}
				}
				{
					want, got := wantKeyAgreementY, keyAgreement[cose.EC2KeyParameterY]
					gotValue, ok := got.([]byte)

					if !ok || ((gotValue == nil) != (want == nil) || !bytes.Equal(gotValue, want)) {
						t.Errorf("got %#v, want %#v", got, want)
					}
				}

				var requestFields map[uint64]any
				if err := cbor.Unmarshal(sentRequest[1:], &requestFields); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				assertRequestKeys(t, requestFields, testCase.requestKeys...)

				if got, want := requestFields[uint64(1)], uint64(testCase.pinUvAuthProtocol); got != want {
					t.Errorf("got %#v, want %#v", got, want)
				}
				{
					want, got := uint64(testCase.subCommand), requestFields[uint64(2)]
					gotValue, ok := got.(uint64)

					if !ok || gotValue != want {
						t.Errorf("got %#v, want %#v", got, want)
					}
				}
			})
		}
	})

	t.Run("get preview UV token omits permissions and RP ID", func(t *testing.T) {
		if fips140.Enabled() {
			t.Skip("legacy preview UV requires PIN/UV auth protocol 1")
		}

		fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
			PinUvAuthToken: make([]byte, 16),
		}))

		token, err := newTestClient(t, fake).GetPinUvAuthTokenUsingUv(
			context.Background(),
			testKeyAgreement(t),
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := len(token), 16; got != want {
			t.Errorf("got length %d, want %d", got, want)
		}

		assertCTAPRequest(t, fake, expectedCTAPRequest{
			command: protocol.AuthenticatorClientPIN,
			keys:    []uint64{1, 2, 3},
			fields: map[uint64]uint64{
				1: uint64(protocol.PinUvAuthProtocolOne),
				2: uint64(protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions),
			},
		})
	})

	t.Run("get permissioned UV token includes permissions and RP ID", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
			PinUvAuthToken: make([]byte, 48),
		}))

		token, err := newTestClient(t, fake).GetPinUvAuthTokenUsingUvWithPermissions(
			context.Background(),
			protocol.PinUvAuthProtocolTwo,
			testKeyAgreement(t),
			protocol.PermissionGetAssertion,
			"example.com",
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := len(token), 32; got != want {
			t.Errorf("got length %d, want %d", got, want)
		}

		request := assertCTAPRequest(t, fake, expectedCTAPRequest{
			command: protocol.AuthenticatorClientPIN,
			keys:    []uint64{1, 2, 3, 9, 10},
			fields:  map[uint64]uint64{9: uint64(protocol.PermissionGetAssertion)},
		})
		if got, want := requestString(t, request, uint64(10)), "example.com"; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})
}

func TestBioEnrollmentRequestShapeAndPINAuthParam(t *testing.T) {
	token := pinUvAuthToken()
	timeoutMilliseconds := uint(1000)
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorBioEnrollmentResponse{}))

	_, err := newTestClient(t, fake).EnrollBegin(context.Background(), false, protocol.PinUvAuthProtocolTwo, token, timeoutMilliseconds)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	request := assertCTAPRequest(t, fake, expectedCTAPRequest{
		command: protocol.AuthenticatorBioEnrollment,
		keys:    []uint64{1, 2, 3, 4, 5},
		fields: map[uint64]uint64{
			1: uint64(protocol.BioModalityFingerprint),
			2: uint64(protocol.BioEnrollmentSubCommandEnrollBegin),
		},
	})

	params := protocol.BioEnrollmentSubCommandParams{TimeoutMilliseconds: timeoutMilliseconds}
	paramsCBOR := encodeCBOR(t, params)
	expectedParam := crypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		token,
		slices.Concat([]byte{byte(protocol.BioModalityFingerprint), byte(protocol.BioEnrollmentSubCommandEnrollBegin)}, paramsCBOR),
	)

	if got, want := requestBytes(t, request, uint64(5)), expectedParam; got == nil != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestCredentialManagementRequestShapeAndPINAuthParam(t *testing.T) {
	token := pinUvAuthToken()
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorCredentialManagementResponse{}))

	_, err := newTestClient(t, fake).GetCredsMetadata(context.Background(), false, protocol.PinUvAuthProtocolTwo, token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	request := assertCTAPRequest(t, fake, expectedCTAPRequest{
		command: protocol.AuthenticatorCredentialManagement,
		keys:    []uint64{1, 3, 4},
		fields: map[uint64]uint64{
			1: uint64(protocol.CredentialManagementSubCommandGetCredsMetadata),
			3: uint64(protocol.PinUvAuthProtocolTwo),
		},
	})
	{
		want, got := crypto.Authenticate(protocol.PinUvAuthProtocolTwo, token, []byte{byte(protocol.CredentialManagementSubCommandGetCredsMetadata)}), request[uint64(4)]
		gotValue, ok := got.([]byte)

		if !ok || ((gotValue == nil) != (want == nil) || !bytes.Equal(gotValue, want)) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestCredentialEnumerationRejectsMissingOrZeroTotals(t *testing.T) {
	token := pinUvAuthToken()
	tests := []struct {
		name     string
		response protocol.AuthenticatorCredentialManagementResponse
		field    string
		invoke   func(*Client) error
	}{
		{
			name:  "RPs missing total",
			field: "totalRPs",
			invoke: func(cl *Client) error {
				for _, err := range cl.EnumerateRPs(context.Background(), false, protocol.PinUvAuthProtocolTwo, token) {
					return err
				}

				return nil
			},
		},
		{
			name:     "RPs zero total",
			response: protocol.AuthenticatorCredentialManagementResponse{TotalRPs: 0},
			field:    "totalRPs",
			invoke: func(cl *Client) error {
				for _, err := range cl.EnumerateRPs(context.Background(), false, protocol.PinUvAuthProtocolTwo, token) {
					return err
				}

				return nil
			},
		},
		{
			name:  "credentials missing total",
			field: "totalCredentials",
			invoke: func(cl *Client) error {
				for _, err := range cl.EnumerateCredentials(context.Background(), false, protocol.PinUvAuthProtocolTwo, token, make([]byte, 32)) {
					return err
				}

				return nil
			},
		},
		{
			name:     "credentials zero total",
			response: protocol.AuthenticatorCredentialManagementResponse{TotalCredentials: 0},
			field:    "totalCredentials",
			invoke: func(cl *Client) error {
				for _, err := range cl.EnumerateCredentials(context.Background(), false, protocol.PinUvAuthProtocolTwo, token, make([]byte, 32)) {
					return err
				}

				return nil
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &tc.response))

			err := tc.invoke(newTestClient(t, fake))
			if err == nil {
				t.Fatalf("expected an error")
			}

			if container, element := err.Error(), "spec violation"; !strings.Contains(container, element) {
				t.Errorf("value does not contain %#v", element)
			}

			if container, element := err.Error(), tc.field; !strings.Contains(container, element) {
				t.Errorf("value does not contain %#v", element)
			}
		})
	}
}

func TestNormalizeSelectionError(t *testing.T) {
	keepaliveCanceled := &ctaptransport.CTAPError{
		Command:    protocol.AuthenticatorSelection,
		StatusCode: ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL,
	}

	t.Run("expected cancellation status", func(t *testing.T) {
		if err := normalizeSelectionError(keepaliveCanceled); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("cancel write error is preserved", func(t *testing.T) {
		cancelWriteErr := errors.New("cancel write failed")

		err := normalizeSelectionError(cancelWriteErr)
		if err, target := err, cancelWriteErr; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	})

	t.Run("unrelated CTAP status is preserved", func(t *testing.T) {
		want := &ctaptransport.CTAPError{
			Command:    protocol.AuthenticatorSelection,
			StatusCode: ctaptransport.CTAP1_ERR_INVALID_COMMAND,
		}

		err := normalizeSelectionError(want)
		if err, target := err, want; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	})
}

func TestLargeBlobsRequestShapeAndPINAuthParam(t *testing.T) {
	token := pinUvAuthToken()
	set := []byte("large-blob-fragment")
	offset := uint(7)
	length := uint(9)
	fake := testhid.NewCBORDevice(t, testCID, nil)

	resp, err := newTestClient(t, fake).LargeBlobs(context.Background(), protocol.PinUvAuthProtocolTwo, token, 0, set, offset, length)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := resp.Config; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}

	request := assertCTAPRequest(t, fake, expectedCTAPRequest{
		command: protocol.AuthenticatorLargeBlobs,
		keys:    []uint64{2, 3, 4, 5, 6},
		fields: map[uint64]uint64{
			3: uint64(offset),
			4: uint64(length),
			6: uint64(protocol.PinUvAuthProtocolTwo),
		},
	})
	if got, want := requestBytes(t, request, uint64(2)), set; got == nil != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	padding := bytes.Repeat([]byte{0xff}, 32)
	offsetBin := make([]byte, 4)
	binary.LittleEndian.PutUint32(offsetBin, uint32(offset))

	hash := sha256.Sum256(set)
	expectedParam := crypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		token,
		slices.Concat(padding, []byte{0x0c, 0x00}, offsetBin, hash[:]),
	)

	if got, want := requestBytes(t, request, uint64(5)), expectedParam; got == nil != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestLargeBlobsPreservesZeroLengthReadAndWritePresence(t *testing.T) {
	t.Run("get zero", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, protocol.AuthenticatorLargeBlobsResponse{Config: []byte{}}))

		resp, err := newTestClient(t, fake).LargeBlobs(context.Background(), 0, nil, 0, nil, 0, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := resp.Config; got == nil {
			t.Fatalf("got nil, want a non-nil value")
		}

		if got := resp.Config; len(got) != 0 {
			t.Fatalf("got non-empty value %#v", got)
		}

		assertCTAPRequest(t, fake, expectedCTAPRequest{
			command: protocol.AuthenticatorLargeBlobs,
			keys:    []uint64{1, 3},
			fields:  map[uint64]uint64{1: 0},
		})
	})

	t.Run("set empty", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, nil)

		_, err := newTestClient(t, fake).LargeBlobs(context.Background(), 0, nil, 0, []byte{}, 0, 17)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		command, request := fake.FirstCTAPRequestMap(t)
		if got, want := command, protocol.AuthenticatorLargeBlobs; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}

		assertRequestKeys(t, request, 2, 3, 4)

		if got := requestBytes(t, request, 2); len(got) != 0 {
			t.Errorf("got non-empty value %#v", got)
		}
	})
}

func TestConfigRequestShapeAndPINAuthParam(t *testing.T) {
	token := pinUvAuthToken()
	fake := testhid.NewCBORDevice(t, testCID, nil)
	minPINLengthRPIDs := []string{"example.com"}
	params := protocol.SetMinPINLengthConfigSubCommandParams{
		NewMinPINLength:   new(uint(8)),
		MinPINLengthRPIDs: minPINLengthRPIDs,
		ForceChangePIN:    true,
	}

	err := newTestClient(t, fake).SetMinPINLength(context.Background(), protocol.PinUvAuthProtocolTwo, token, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	request := assertCTAPRequest(t, fake, expectedCTAPRequest{
		command: protocol.AuthenticatorConfig,
		keys:    []uint64{1, 2, 3, 4},
		fields: map[uint64]uint64{
			1: uint64(protocol.ConfigSubCommandSetMinPINLength),
			3: uint64(protocol.PinUvAuthProtocolTwo),
		},
	})

	paramsCBOR := encodeCBOR(t, params)
	expectedParam := crypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		token,
		slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte{0x0d, byte(protocol.ConfigSubCommandSetMinPINLength)}, paramsCBOR),
	)

	if got, want := requestBytes(t, request, uint64(4)), expectedParam; got == nil != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestConfigRequestWithoutTokenOmitsAuthorization(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID, nil)

	err := newTestClient(t, fake).SetMinPINLength(context.Background(), 0, nil, protocol.SetMinPINLengthConfigSubCommandParams{
		NewMinPINLength: new(uint(8)),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	command, request := fake.FirstCTAPRequestMap(t)
	if got, want := command, protocol.AuthenticatorConfig; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	assertRequestKeys(t, request, 1, 2)

	params, ok := request[uint64(2)].(map[any]any)
	if !ok || len(params) != 1 || params[uint64(1)] != uint64(8) {
		t.Errorf("got %#v, want map[1:8]", request[uint64(2)])
	}
}

func TestSetMinPINLengthPreservesZeroMinimumAndOmitsEquivalentZeroValues(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID, nil)

	err := newTestClient(t, fake).SetMinPINLength(
		context.Background(),
		0,
		nil,
		protocol.SetMinPINLengthConfigSubCommandParams{
			NewMinPINLength:   new(uint(0)),
			MinPINLengthRPIDs: []string{},
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	command, request := fake.FirstCTAPRequestMap(t)
	if got, want := command, protocol.AuthenticatorConfig; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	assertRequestKeys(t, request, 1, 2)

	params, ok := request[uint64(2)].(map[any]any)
	if got := ok; !got {
		t.Fatalf("got false, want true")
	}

	if len(params) != 1 || params[uint64(1)] != uint64(0) {
		t.Errorf("got %#v, want map[1:0]", params)
	}
}

func TestEnableLongTouchForResetRequestShape(t *testing.T) {
	t.Run("without authorization", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, nil)

		err := newTestClient(t, fake).EnableLongTouchForReset(context.Background(), 0, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		assertCTAPRequest(t, fake, expectedCTAPRequest{
			command: protocol.AuthenticatorConfig,
			keys:    []uint64{1},
			fields:  map[uint64]uint64{1: uint64(protocol.ConfigSubCommandEnableLongTouchForReset)},
		})
	})

	t.Run("with authorization", func(t *testing.T) {
		token := pinUvAuthToken()
		fake := testhid.NewCBORDevice(t, testCID, nil)

		err := newTestClient(t, fake).EnableLongTouchForReset(
			context.Background(),
			protocol.PinUvAuthProtocolTwo,
			token,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		request := assertCTAPRequest(t, fake, expectedCTAPRequest{
			command: protocol.AuthenticatorConfig,
			keys:    []uint64{1, 3, 4},
			fields:  map[uint64]uint64{3: uint64(protocol.PinUvAuthProtocolTwo)},
		})
		expectedParam := crypto.Authenticate(
			protocol.PinUvAuthProtocolTwo,
			token,
			slices.Concat(
				bytes.Repeat([]byte{0xff}, 32),
				[]byte{0x0d, byte(protocol.ConfigSubCommandEnableLongTouchForReset)},
			),
		)

		if got, want := requestBytes(t, request, uint64(4)), expectedParam; got == nil != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})
}

func TestProtectedCommandsRejectInvalidTokenBeforeTransport(t *testing.T) {
	t.Run("BioEnrollment", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)

		_, err := newTestClient(t, fake).EnrollBegin(
			context.Background(),
			false,
			protocol.PinUvAuthProtocolTwo,
			nil,
			0,
		)
		if err == nil {
			t.Fatalf("expected an error")
		}

		if got := fake.Writes(); len(got) != 0 {
			t.Errorf("got non-empty value %#v", got)
		}
	})

	t.Run("CredentialManagement", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)

		_, err := newTestClient(t, fake).GetCredsMetadata(
			context.Background(),
			false,
			protocol.PinUvAuthProtocolTwo,
			make([]byte, 16),
		)
		if err == nil {
			t.Fatalf("expected an error")
		}

		if got := fake.Writes(); len(got) != 0 {
			t.Errorf("got non-empty value %#v", got)
		}
	})
}
