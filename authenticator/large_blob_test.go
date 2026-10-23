package authenticator

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/ctap/webauthn"
)

func TestDirectLargeBlobMakeCredential(t *testing.T) {
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalMakeCredentialAuthData(t),
		UnsignedExtensionOutputs: map[extension.ExtensionIdentifier]any{
			extension.ExtensionIdentifierLargeBlob: protocol.CreateLargeBlobOutput{Supported: true},
		},
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Versions:   protocol.Versions{protocol.FIDO_2_3},
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierLargeBlob},
	})

	result, err := makeCredentialWithLargeBlob(t, d, &webauthn.LargeBlobInputs{
		LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{
			Support: extension.LargeBlobSupportRequired,
		},
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := result.ExtensionOutputs.LargeBlobOutputs; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := result.ExtensionOutputs.LargeBlob.Supported; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := *result.ExtensionOutputs.LargeBlob.Supported; !got {
		t.Errorf("got false, want true")
	}

	command, payload := fake.FirstCTAPPayload(t)
	if got, want := command, protocol.AuthenticatorMakeCredential; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	var request protocol.AuthenticatorMakeCredentialRequest
	if err := cbor.Unmarshal(payload, &request); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := request.Extensions.LargeBlob.Support, extension.LargeBlobSupportRequired; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got := request.Extensions.CreateLargeBlobKeyInput; got.LargeBlobKey {
		t.Errorf("got %#v, want zero value", got)
	}
}

func TestLegacyLargeBlobMakeCredential(t *testing.T) {
	key := make([]byte, 32)
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:       attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw:  minimalMakeCredentialAuthData(t),
		LargeBlobKey: key,
	})
	info := legacyLargeBlobInfo()
	fake := testhid.NewCBORDevice(t, testCID, response, encodeCBOR(t, info))
	d := newTestDevice(t, fake, info)

	result, err := makeCredentialWithLargeBlob(t, d, &webauthn.LargeBlobInputs{
		LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{
			Support: extension.LargeBlobSupportRequired,
		},
	}, map[protocol.Option]bool{protocol.OptionResidentKeys: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := result.ExtensionOutputs.LargeBlobOutputs; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := result.ExtensionOutputs.LargeBlob.Supported; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := *result.ExtensionOutputs.LargeBlob.Supported; !got {
		t.Errorf("got false, want true")
	}

	command, payload := fake.FirstCTAPPayload(t)
	if got, want := command, protocol.AuthenticatorMakeCredential; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	var request protocol.AuthenticatorMakeCredentialRequest
	if err := cbor.Unmarshal(payload, &request); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := request.Extensions.LargeBlobKey; !got {
		t.Errorf("got false, want true")
	}

	if got := request.Extensions.CreateLargeBlobInput; got.LargeBlob.Support != "" {
		t.Errorf("got %#v, want zero value", got)
	}
}

func TestLegacyLargeBlobMakeCredentialValidatesKeyRequestCorrelation(t *testing.T) {
	t.Run("requested preferred key is required in response", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
			Format:      attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw: minimalMakeCredentialAuthData(t),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, legacyLargeBlobInfo())

		_, err := makeCredentialWithLargeBlob(t, d, &webauthn.LargeBlobInputs{
			LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{
				Support: extension.LargeBlobSupportPreferred,
			},
		}, map[protocol.Option]bool{protocol.OptionResidentKeys: true})
		if err, target := err, ErrSpecViolation; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		if container, element := err.Error(), "omitted"; !strings.Contains(container, element) {
			t.Errorf("value does not contain %#v", element)
		}

		_, payload := fake.FirstCTAPPayload(t)

		var request protocol.AuthenticatorMakeCredentialRequest
		if err := cbor.Unmarshal(payload, &request); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := request.Extensions.LargeBlobKey; !got {
			t.Errorf("got false, want true")
		}
	})

	t.Run("key without CTAP extension input is unsolicited", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
			Format:       attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw:  minimalMakeCredentialAuthData(t),
			LargeBlobKey: make([]byte, 32),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, legacyLargeBlobInfo())

		_, err := makeCredentialWithLargeBlob(t, d, &webauthn.LargeBlobInputs{
			LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{
				Support: extension.LargeBlobSupportPreferred,
			},
		}, nil)
		if err, target := err, ErrSpecViolation; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		if container, element := err.Error(), "unsolicited"; !strings.Contains(container, element) {
			t.Errorf("value does not contain %#v", element)
		}

		_, payload := fake.FirstCTAPPayload(t)

		var request protocol.AuthenticatorMakeCredentialRequest
		if err := cbor.Unmarshal(payload, &request); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := request.Extensions.CreateLargeBlobKeyInput; got.LargeBlobKey {
			t.Errorf("got %#v, want zero value", got)
		}
	})
}

func TestMakeCredentialRejectsUnsolicitedLargeBlobResponseWithoutClientInput(t *testing.T) {
	t.Run("legacy key", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
			Format:       attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw:  minimalMakeCredentialAuthData(t),
			LargeBlobKey: make([]byte, 32),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, legacyLargeBlobInfo())

		_, err := makeCredentialWithLargeBlob(t, d, nil, nil)
		if err, target := err, ErrSpecViolation; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	})

	t.Run("direct output", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
			Format:      attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw: minimalMakeCredentialAuthData(t),
			UnsignedExtensionOutputs: map[extension.ExtensionIdentifier]any{
				extension.ExtensionIdentifierLargeBlob: protocol.CreateLargeBlobOutput{Supported: true},
			},
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions:   protocol.Versions{protocol.FIDO_2_3},
			Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierLargeBlob},
		})

		_, err := makeCredentialWithLargeBlob(t, d, nil, nil)
		if err, target := err, ErrSpecViolation; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	})
}

func TestGetAssertionRejectsUnsolicitedLargeBlobResponseWithoutClientInput(t *testing.T) {
	t.Run("legacy key", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
			AuthDataRaw:  minimalAuthData(),
			Signature:    []byte("signature"),
			LargeBlobKey: make([]byte, 32),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, legacyLargeBlobInfo())

		_, err := getAssertionsWithLargeBlob(d, nil, nil)
		if err, target := err, ErrSpecViolation; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	})

	t.Run("direct output", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
			AuthDataRaw: minimalAuthData(),
			Signature:   []byte("signature"),
			UnsignedExtensionOutputs: map[extension.ExtensionIdentifier]any{
				extension.ExtensionIdentifierLargeBlob: protocol.GetLargeBlobOutput{Written: new(false)},
			},
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions:   protocol.Versions{protocol.FIDO_2_3},
			Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierLargeBlob},
		})

		_, err := getAssertionsWithLargeBlob(d, nil, nil)
		if err, target := err, ErrSpecViolation; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	})
}

func TestDirectLargeBlobGetAssertionRead(t *testing.T) {
	want := []byte("direct large blob")

	compressed, err := ctapcrypto.CompressLargeBlobData(want)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	originalSize := uint(len(want))
	response := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: minimalAuthData(),
		Signature:   []byte("signature"),
		UnsignedExtensionOutputs: map[extension.ExtensionIdentifier]any{
			extension.ExtensionIdentifierLargeBlob: protocol.GetLargeBlobOutput{
				Blob:         compressed,
				OriginalSize: &originalSize,
			},
		},
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Versions:   protocol.Versions{protocol.FIDO_2_3},
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierLargeBlob},
	})

	assertions, gotErr := getAssertionsWithLargeBlob(d, nil, &webauthn.LargeBlobInputs{
		LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Read: new(true)},
	})
	if err := gotErr; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := len(assertions), 1; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	if got := assertions[0].ExtensionOutputs.LargeBlobOutputs; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := assertions[0].ExtensionOutputs.LargeBlob.Blob; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got, want := assertions[0].ExtensionOutputs.LargeBlob.Blob, want; (got == nil) != (want == nil) || !slices.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	command, payload := fake.FirstCTAPPayload(t)
	if got, want := command, protocol.AuthenticatorGetAssertion; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	var request protocol.AuthenticatorGetAssertionRequest
	if err := cbor.Unmarshal(payload, &request); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := request.Extensions.LargeBlob.Read; !got {
		t.Errorf("got false, want true")
	}

	if got := request.Extensions.GetLargeBlobKeyInput; got.LargeBlobKey {
		t.Errorf("got %#v, want zero value", got)
	}
}

func TestDirectLargeBlobGetAssertionPreservesEmptyWrite(t *testing.T) {
	response := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: minimalAuthData(),
		Signature:   []byte("signature"),
		UnsignedExtensionOutputs: map[extension.ExtensionIdentifier]any{
			extension.ExtensionIdentifierLargeBlob: protocol.GetLargeBlobOutput{Written: new(true)},
		},
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Versions:   protocol.Versions{protocol.FIDO_2_3},
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierLargeBlob},
	})
	allowList := []credential.PublicKeyCredentialDescriptor{{
		Type: credential.PublicKeyCredentialTypePublicKey,
		ID:   []byte("credential-id"),
	}}

	assertions, gotErr := getAssertionsWithLargeBlob(d, allowList, &webauthn.LargeBlobInputs{
		LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Write: []byte{}},
	})
	if err := gotErr; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := len(assertions), 1; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	if got := assertions[0].ExtensionOutputs.LargeBlob.Written; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := *assertions[0].ExtensionOutputs.LargeBlob.Written; !got {
		t.Errorf("got false, want true")
	}

	_, payload := fake.FirstCTAPPayload(t)

	var request protocol.AuthenticatorGetAssertionRequest
	if err := cbor.Unmarshal(payload, &request); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	params := request.Extensions.LargeBlob
	if got := params.Write; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := params.OriginalSize; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := *params.OriginalSize; got != 0 {
		t.Errorf("got %#v, want zero value", got)
	}

	uncompressed, err := ctapcrypto.DecompressLargeBlobData(params.Write, *params.OriginalSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := uncompressed; len(got) != 0 {
		t.Errorf("got non-empty value %#v", got)
	}
}

func TestLegacyLargeBlobGetAssertionBuffersAllAssertionsBeforeRead(t *testing.T) {
	firstKey := make([]byte, 32)
	firstKey[0] = 1
	secondKey := make([]byte, 32)
	secondKey[0] = 2
	want := []byte("legacy large blob")

	encrypted, err := ctapcrypto.EncryptLargeBlob(firstKey, want)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	first := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw:         minimalAuthData(),
		Signature:           []byte{1},
		NumberOfCredentials: 2,
		LargeBlobKey:        firstKey,
	})
	second := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw:  minimalAuthData(),
		Signature:    []byte{2},
		LargeBlobKey: secondKey,
	})
	array := encodeLargeBlobConfig(t, []protocol.LargeBlob{encrypted})
	largeBlobs := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{Config: array})
	fake := testhid.NewCBORDevice(t, testCID, first, second, largeBlobs)
	d := newTestDevice(t, fake, legacyLargeBlobInfo())

	assertions, gotErr := getAssertionsWithLargeBlob(d, nil, &webauthn.LargeBlobInputs{
		LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Read: new(true)},
	})
	if err := gotErr; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := len(assertions), 2; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	if got := assertions[0].ExtensionOutputs.LargeBlob.Blob; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got, want := assertions[0].ExtensionOutputs.LargeBlob.Blob, want; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got := assertions[1].ExtensionOutputs.LargeBlob.Blob; got != nil {
		t.Errorf("got %#v, want nil", got)
	}

	requests := fake.Requests(t)
	if got, want := len(requests), 3; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	commands := make([]protocol.Command, 0, len(requests))
	for _, request := range requests {
		command, _ := request.CTAPPayload(t)
		commands = append(commands, command)
	}
	{
		want, got := []protocol.Command{
			protocol.AuthenticatorGetAssertion,
			protocol.AuthenticatorGetNextAssertion,
			protocol.AuthenticatorLargeBlobs,
		}, commands
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	_, payload := requests[0].CTAPPayload(t)

	var request protocol.AuthenticatorGetAssertionRequest
	if err := cbor.Unmarshal(payload, &request); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := request.Extensions.LargeBlobKey; !got {
		t.Errorf("got false, want true")
	}

	if got := request.Extensions.GetLargeBlobInput; got.LargeBlob.Read || got.LargeBlob.Write != nil || got.LargeBlob.OriginalSize != nil {
		t.Errorf("got %#v, want zero value", got)
	}
}

func TestLegacyLargeBlobGetAssertionWrite(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1

	oldBlob, err := ctapcrypto.EncryptLargeBlob(key, []byte("old"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertion := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw:  minimalAuthData(),
		Signature:    []byte("signature"),
		LargeBlobKey: key,
	})
	read := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{
		Config: encodeLargeBlobConfig(t, []protocol.LargeBlob{oldBlob}),
	})
	write := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{})
	fake := testhid.NewCBORDevice(t, testCID, assertion, read, write)
	d := newTestDevice(t, fake, legacyLargeBlobInfo())
	allowList := []credential.PublicKeyCredentialDescriptor{{
		Type: credential.PublicKeyCredentialTypePublicKey,
		ID:   []byte("credential-id"),
	}}
	want := []byte("updated")

	assertions, gotErr := getAssertionsWithLargeBlob(d, allowList, &webauthn.LargeBlobInputs{
		LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Write: want},
	})
	if err := gotErr; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := len(assertions), 1; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	if got := assertions[0].ExtensionOutputs.LargeBlob.Written; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := *assertions[0].ExtensionOutputs.LargeBlob.Written; !got {
		t.Errorf("got false, want true")
	}

	requests := fake.Requests(t)
	if got, want := len(requests), 3; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	command, payload := requests[2].CTAPPayload(t)
	if got, want := command, protocol.AuthenticatorLargeBlobs; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	var request protocol.AuthenticatorLargeBlobsRequest
	if err := cbor.Unmarshal(payload, &request); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		got, limit := len(request.Set), 16
		if got < limit {
			t.Fatalf("got %v, want greater than or equal to %v", got, limit)
		}
	}

	serialized := request.Set[:len(request.Set)-16]

	checksum := sha256.Sum256(serialized)
	if got, want := request.Set[len(request.Set)-16:], checksum[:16]; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	var stored []protocol.LargeBlob
	if err := cbor.Unmarshal(serialized, &stored); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := len(stored), 1; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	got, err := ctapcrypto.DecryptLargeBlob(key, stored[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := got, want; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestLegacyLargeBlobReadReturnsMatchedDecompressionError(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	malformed := encryptRawLargeBlob(t, key, []byte{0xff}, 8)
	assertion := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw:  minimalAuthData(),
		Signature:    []byte("signature"),
		LargeBlobKey: key,
	})
	largeBlobs := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{
		Config: encodeLargeBlobConfig(t, []protocol.LargeBlob{malformed}),
	})
	fake := testhid.NewCBORDevice(t, testCID, assertion, largeBlobs)
	d := newTestDevice(t, fake, legacyLargeBlobInfo())

	_, gotErr := getAssertionsWithLargeBlob(d, nil, &webauthn.LargeBlobInputs{
		LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Read: new(true)},
	})
	if err := gotErr; err == nil {
		t.Fatalf("expected an error")
	}
}

func TestLegacyLargeBlobWriteReplacesAEADMatchWithoutDecompressing(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	malformed := encryptRawLargeBlob(t, key, []byte{0xff}, 8)
	assertion := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw:  minimalAuthData(),
		Signature:    []byte("signature"),
		LargeBlobKey: key,
	})
	read := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{
		Config: encodeLargeBlobConfig(t, []protocol.LargeBlob{malformed}),
	})
	write := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{})
	fake := testhid.NewCBORDevice(t, testCID, assertion, read, write)
	d := newTestDevice(t, fake, legacyLargeBlobInfo())
	allowList := []credential.PublicKeyCredentialDescriptor{{
		Type: credential.PublicKeyCredentialTypePublicKey,
		ID:   []byte("credential-id"),
	}}
	want := []byte("replacement")

	assertions, gotErr := getAssertionsWithLargeBlob(d, allowList, &webauthn.LargeBlobInputs{
		LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Write: want},
	})
	if err := gotErr; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := len(assertions), 1; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	requests := fake.Requests(t)
	if got, want := len(requests), 3; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	_, payload := requests[2].CTAPPayload(t)

	var request protocol.AuthenticatorLargeBlobsRequest
	if err := cbor.Unmarshal(payload, &request); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	serialized := request.Set[:len(request.Set)-16]

	var stored []protocol.LargeBlob
	if err := cbor.Unmarshal(serialized, &stored); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := len(stored), 1; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	got, err := ctapcrypto.DecryptLargeBlob(key, stored[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := got, want; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestLargeBlobInputValidationUsesReadPresence(t *testing.T) {
	presentFalse := new(false)

	t.Run("MakeCredential rejects present read", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, legacyLargeBlobInfo())

		_, err := makeCredentialWithLargeBlob(t, d, &webauthn.LargeBlobInputs{
			LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Read: presentFalse},
		}, nil)
		if err, target := err, SyntaxError; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("GetAssertion rejects present read with write", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, legacyLargeBlobInfo())
		allowList := []credential.PublicKeyCredentialDescriptor{{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   []byte("credential-id"),
		}}

		_, err := getAssertionsWithLargeBlob(d, allowList, &webauthn.LargeBlobInputs{
			LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{
				Read:  presentFalse,
				Write: []byte("blob"),
			},
		})
		if err, target := err, SyntaxError; !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}

		assertNoAuthenticatorIO(t, fake)
	})
}

func TestLargeBlobRejectsMutuallyExclusiveAuthenticatorCapabilities(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierLargeBlob,
			extension.ExtensionIdentifierLargeBlobKey,
		},
		Options: map[protocol.Option]bool{protocol.OptionLargeBlobs: true},
	})

	_, gotErr := getAssertionsWithLargeBlob(d, nil, &webauthn.LargeBlobInputs{
		LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Read: new(true)},
	})
	if err, target := gotErr, ErrSpecViolation; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}

	assertNoAuthenticatorIO(t, fake)
}

func makeCredentialWithLargeBlob(
	t *testing.T,
	d *Device,
	inputs *webauthn.LargeBlobInputs,
	requestOptions map[protocol.Option]bool,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	t.Helper()

	return d.MakeCredential(
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
		&webauthn.CreateAuthenticationExtensionsClientInputs{LargeBlobInputs: inputs},
		requestOptions,
		0,
		nil,
	)
}

func getAssertionsWithLargeBlob(
	d *Device,
	allowList []credential.PublicKeyCredentialDescriptor,
	inputs *webauthn.LargeBlobInputs,
) ([]protocol.AuthenticatorGetAssertionResponse, error) {
	var assertions []protocol.AuthenticatorGetAssertionResponse

	for assertion, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		allowList,
		&webauthn.GetAuthenticationExtensionsClientInputs{LargeBlobInputs: inputs},
		nil,
	) {
		if err != nil {
			return nil, err
		}

		assertions = append(assertions, assertion)
	}

	return assertions, nil
}

func legacyLargeBlobInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Versions:                    protocol.Versions{protocol.FIDO_2_1},
		Extensions:                  []extension.ExtensionIdentifier{extension.ExtensionIdentifierLargeBlobKey},
		MaxSerializedLargeBlobArray: 2048,
		Options:                     map[protocol.Option]bool{protocol.OptionLargeBlobs: true},
	}
}

func encodeLargeBlobConfig(t *testing.T, blobs []protocol.LargeBlob) []byte {
	t.Helper()

	serialized, err := marshalLargeBlobArray(blobs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sum := sha256.Sum256(serialized)

	return append(serialized, sum[:16]...)
}

func encryptRawLargeBlob(t *testing.T, key, plaintext []byte, originalSize uint) protocol.LargeBlob {
	t.Helper()

	const nonceSize = 12

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	additionalData := make([]byte, 12)
	copy(additionalData, "blob")
	binary.LittleEndian.PutUint64(additionalData[4:], uint64(originalSize))
	sealed := gcm.Seal(nil, nil, plaintext, additionalData)

	return protocol.LargeBlob{
		Ciphertext: slices.Clone(sealed[nonceSize:]),
		Nonce:      slices.Clone(sealed[:nonceSize]),
		OrigSize:   originalSize,
	}
}

func TestLargeBlobsUsesDefaultMaxMsgSizeWhenMissing(t *testing.T) {
	encodedBlobs := encodeCBOR(t, []protocol.LargeBlob{})
	sum := sha256.Sum256(encodedBlobs)
	response := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{
		Config: append(encodedBlobs, sum[:16]...),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})

	blobs, err := d.GetLargeBlobs(testContext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := blobs; len(got) != 0 {
		t.Errorf("got non-empty value %#v", got)
	}

	command, requestCBOR := fake.FirstCTAPPayload(t)
	if got, want := command, protocol.AuthenticatorLargeBlobs; got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	var request map[uint64]any
	if err := cbor.Unmarshal(requestCBOR, &request); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := uint64(960), request[uint64(1)]
		gotValue, ok := got.(uint64)

		if !ok || gotValue != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestGetLargeBlobsReadsAllFullFragments(t *testing.T) {
	want := []protocol.LargeBlob{{
		Ciphertext: bytes.Repeat([]byte{0xaa}, 32),
		Nonce:      bytes.Repeat([]byte{0xbb}, 12),
		OrigSize:   16,
	}}

	encodedBlobs, err := marshalLargeBlobArray(want)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sum := sha256.Sum256(encodedBlobs)
	config := slices.Concat(encodedBlobs, sum[:16])

	const maxFragmentLength = 16

	chunks := slices.Collect(slices.Chunk(config, maxFragmentLength))
	{
		got, limit := len(chunks), 2
		if got <= limit {
			t.Fatalf("got %v, want greater than %v", got, limit)
		}
	}

	responses := make([][]byte, len(chunks))
	for i, chunk := range chunks {
		responses[i] = encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{Config: chunk})
	}

	fake := testhid.NewCBORDevice(t, testCID, responses...)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		MaxMsgSize: uint(maxFragmentLength + 64),
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})

	got, err := d.GetLargeBlobs(testContext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := got, want; (got == nil) != (want == nil) || !slices.EqualFunc(got, want, func(got, want protocol.LargeBlob) bool {
		return (got.Ciphertext == nil) == (want.Ciphertext == nil) &&
			bytes.Equal(got.Ciphertext, want.Ciphertext) &&
			(got.Nonce == nil) == (want.Nonce == nil) &&
			bytes.Equal(got.Nonce, want.Nonce) &&
			got.OrigSize == want.OrigSize
	}) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := len(fake.Requests(t)), len(chunks); got != want {
		t.Errorf("got length %d, want %d", got, want)
	}
}

func TestGetLargeBlobsStopsAfterTrailingEmptyFragment(t *testing.T) {
	encodedBlobs := encodeCBOR(t, []protocol.LargeBlob{})
	sum := sha256.Sum256(encodedBlobs)
	config := slices.Concat(encodedBlobs, sum[:16])
	maxMsgSize := uint(len(config) + 64)

	fake := testhid.NewCBORDevice(
		t,
		testCID,
		encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{Config: config}),
		encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{Config: []byte{}}),
	)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		MaxMsgSize: maxMsgSize,
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})

	blobs, err := d.GetLargeBlobs(testContext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := blobs; len(got) != 0 {
		t.Errorf("got non-empty value %#v", got)
	}

	requests := fake.Requests(t)
	if got, want := len(requests), 2; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	command, request := requests[1].CTAPRequestMap(t)
	if got, want := command, protocol.AuthenticatorLargeBlobs; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	{
		want, got := uint64(len(config)), request[uint64(3)]
		gotValue, ok := got.(uint64)

		if !ok || gotValue != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestLargeBlobsReturnsIntegrityErrorForCorruptConfig(t *testing.T) {
	encodedBlobs := encodeCBOR(t, []protocol.LargeBlob{{Ciphertext: []byte{0xaa}}})
	response := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{
		Config: append(encodedBlobs, bytes.Repeat([]byte{0x00}, 16)...),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})

	_, err := d.GetLargeBlobs(testContext)
	if err, target := err, ErrLargeBlobsIntegrityCheck; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
}

func TestLargeBlobsReturnsInvalidArrayError(t *testing.T) {
	invalidArray := []byte{0xff}
	sum := sha256.Sum256(invalidArray)
	response := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{
		Config: append(invalidArray, sum[:16]...),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})

	_, err := d.GetLargeBlobs(testContext)
	if err, target := err, SyntaxError; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
}

func TestSetLargeBlobsUsesDefaultMaxMsgSizeWhenMissing(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols:          []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		MaxSerializedLargeBlobArray: 2048,
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})
	blob := protocol.LargeBlob{
		Ciphertext: bytes.Repeat([]byte{0xaa}, 1000),
		Nonce:      bytes.Repeat([]byte{0xbb}, 12),
	}

	err := d.SetLargeBlobs(testContext, make([]byte, 32), []protocol.LargeBlob{blob})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	command, requestCBOR := fake.FirstCTAPPayload(t)
	if got, want := command, protocol.AuthenticatorLargeBlobs; got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	var request map[uint64]any
	if err := cbor.Unmarshal(requestCBOR, &request); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	set, ok := request[uint64(2)].([]byte)
	if got := ok; !got {
		t.Fatalf("got false, want true")
	}

	if got, want := len(set), 960; got != want {
		t.Errorf("got length %d, want %d", got, want)
	}
	{
		want, got := uint64(0), request[uint64(3)]
		gotValue, ok := got.(uint64)

		if !ok || gotValue != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestSetLargeBlobsRequiresReportedMaxSerializedLargeBlobArray(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})

	err := d.SetLargeBlobs(testContext, make([]byte, 32), []protocol.LargeBlob{})
	if err == nil {
		t.Fatalf("expected an error")
	}

	if container, element := err.Error(), "maxSerializedLargeBlobArray"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	assertNoAuthenticatorIO(t, fake)
}
