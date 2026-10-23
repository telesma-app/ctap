package protocol

import (
	"bytes"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/extension"
)

func TestLargeBlobKeyExtensionInputs(t *testing.T) {
	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name  string
		input any
	}{
		{
			name: "MakeCredential",
			input: CreateExtensionInputs{
				CreateLargeBlobKeyInput: CreateLargeBlobKeyInput{LargeBlobKey: true},
			},
		},
		{
			name: "GetAssertion",
			input: GetExtensionInputs{
				GetLargeBlobKeyInput: GetLargeBlobKeyInput{LargeBlobKey: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := encMode.Marshal(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			{
				want, got := []byte{
					0xa1,
					0x6c, 'l', 'a', 'r', 'g', 'e', 'B', 'l', 'o', 'b', 'K', 'e', 'y',
					0xf5,
				}, encoded
				if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
					t.Errorf("got %#v, want %#v", got, want)
				}
			}
		})
	}
}

func TestPreviewSignExtensionWireTypes(t *testing.T) {
	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	flags := AuthDataFlagUserPresent

	createEncoded, err := encMode.Marshal(CreateExtensionInputs{
		CreatePreviewSignInput: CreatePreviewSignInput{
			PreviewSign: PreviewSignGenerateKeyInput{
				Algorithms: []cose.Algorithm{cose.AlgorithmESP256SplitARKGPlaceholder},
				Flags:      &flags,
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var create map[string]map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(createEncoded, &create); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := create["previewSign"]; !ok {
		t.Fatalf("value does not contain %#v", "previewSign")
	}

	var algorithms []cose.Algorithm
	if err := cbor.Unmarshal(create["previewSign"][3], &algorithms); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := []cose.Algorithm{cose.AlgorithmESP256SplitARKGPlaceholder}, algorithms
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	var gotFlags AuthDataFlag
	if err := cbor.Unmarshal(create["previewSign"][4], &gotFlags); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := gotFlags, flags; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	unattended := AuthDataFlag(0)

	unattendedEncoded, err := encMode.Marshal(CreateExtensionInputs{
		CreatePreviewSignInput: CreatePreviewSignInput{
			PreviewSign: PreviewSignGenerateKeyInput{
				Algorithms: []cose.Algorithm{cose.AlgorithmESP256SplitARKGPlaceholder},
				Flags:      &unattended,
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	create = nil
	if err := cbor.Unmarshal(unattendedEncoded, &create); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := create["previewSign"][uint64(4)]; !ok {
		t.Errorf("value does not contain %#v; context: %s", uint64(4), "explicit unattended flags must not be omitted")
	}

	if err := cbor.Unmarshal(create["previewSign"][4], &gotFlags); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := gotFlags; got != 0 {
		t.Errorf("got %#v, want zero value", got)
	}

	outputEncoded, err := encMode.Marshal(CreateExtensionOutputs{
		CreatePreviewSignOutput: CreatePreviewSignOutput{
			PreviewSign: &PreviewSignOutput{Flags: &unattended},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var output map[string]map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(outputEncoded, &output); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := output["previewSign"][uint64(4)]; !ok {
		t.Fatalf("value does not contain %#v", uint64(4))
	}

	if err := cbor.Unmarshal(output["previewSign"][4], &gotFlags); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := gotFlags; got != 0 {
		t.Errorf("got %#v, want zero value", got)
	}

	outputEncoded, err = encMode.Marshal(GetExtensionOutputs{
		GetPreviewSignOutput: GetPreviewSignOutput{
			PreviewSign: &PreviewSignOutput{Signature: []byte{}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output = nil
	if err := cbor.Unmarshal(outputEncoded, &output); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := output["previewSign"][uint64(6)]; !ok {
		t.Errorf("value does not contain %#v; context: %s", uint64(6), "present empty signature must not be omitted")
	}

	additionalArguments := []byte{0xa1, 0x03, 0x26}

	getEncoded, err := encMode.Marshal(GetExtensionInputs{
		GetPreviewSignInput: GetPreviewSignInput{
			PreviewSign: PreviewSignSignInput{
				KeyHandle:           []byte{},
				ToBeSigned:          []byte{},
				AdditionalArguments: additionalArguments,
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var get map[string]map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(getEncoded, &get); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := get["previewSign"]; !ok {
		t.Fatalf("value does not contain %#v", "previewSign")
	}

	for _, key := range []uint64{2, 6, 7} {
		if _, ok := get["previewSign"][key]; !ok {
			t.Errorf("value does not contain %#v", key)
		}
	}

	var keyHandle, toBeSigned, gotAdditionalArguments []byte
	if err := cbor.Unmarshal(get["previewSign"][2], &keyHandle); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := cbor.Unmarshal(get["previewSign"][6], &toBeSigned); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := cbor.Unmarshal(get["previewSign"][7], &gotAdditionalArguments); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := keyHandle; len(got) != 0 {
		t.Errorf("got non-empty value %#v", got)
	}

	if got := toBeSigned; len(got) != 0 {
		t.Errorf("got non-empty value %#v", got)
	}

	if got, want := gotAdditionalArguments, additionalArguments; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestPreviewSignAttestationIsNestedInUnsignedExtensionOutputs(t *testing.T) {
	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	attestationObject := []byte{0xa0}

	encoded, err := encMode.Marshal(AuthenticatorMakeCredentialResponse{
		UnsignedExtensionOutputs: map[extension.ExtensionIdentifier]any{
			extension.ExtensionIdentifierPreviewSign: PreviewSignUnsignedOutput{
				AttestationObject: attestationObject,
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var response map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(encoded, &response); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := response[uint64(6)]; !ok {
		t.Fatalf("value does not contain %#v", uint64(6))
	}

	if _, ok := response[uint64(7)]; ok {
		t.Errorf("value unexpectedly contains %#v", uint64(7))
	}

	var unsignedOutputs map[string]cbor.RawMessage
	if err := cbor.Unmarshal(response[6], &unsignedOutputs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := unsignedOutputs["previewSign"]; !ok {
		t.Fatalf("value does not contain %#v", "previewSign")
	}

	var previewSign map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(unsignedOutputs["previewSign"], &previewSign); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := previewSign[uint64(7)]; !ok {
		t.Fatalf("value does not contain %#v", uint64(7))
	}

	var gotAttestationObject []byte
	if err := cbor.Unmarshal(previewSign[7], &gotAttestationObject); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := gotAttestationObject, attestationObject; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestPreviewSignOutputPreservesPresentEmptySignature(t *testing.T) {
	var output GetExtensionOutputs
	if err := cbor.Unmarshal(
		[]byte{0xa1, 0x6b, 'p', 'r', 'e', 'v', 'i', 'e', 'w', 'S', 'i', 'g', 'n', 0xa1, 0x06, 0x40},
		&output,
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := output.PreviewSign; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := output.PreviewSign.Signature; got == nil {
		t.Errorf("got nil, want a non-nil value")
	}

	if got := output.PreviewSign.Signature; len(got) != 0 {
		t.Errorf("got non-empty value %#v", got)
	}
}

func TestLargeBlobKeyExtensionInputIsOmittedWhenAbsent(t *testing.T) {
	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	createEncoded, err := encMode.Marshal(CreateExtensionInputs{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := []byte{0xa0}, createEncoded
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	getEncoded, err := encMode.Marshal(GetExtensionInputs{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := []byte{0xa0}, getEncoded
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestDirectLargeBlobExtensionWireTypes(t *testing.T) {
	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	createEncoded, err := encMode.Marshal(CreateExtensionInputs{
		CreateLargeBlobInput: CreateLargeBlobInput{
			LargeBlob: CreateLargeBlobParams{Support: extension.LargeBlobSupportRequired},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var create map[string]map[string]any
	if err := cbor.Unmarshal(createEncoded, &create); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := "required", create["largeBlob"]["support"]
		gotValue, ok := got.(string)

		if !ok || gotValue != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	emptyBlob := []byte{}

	getEncoded, err := encMode.Marshal(GetExtensionInputs{
		GetLargeBlobInput: GetLargeBlobInput{
			LargeBlob: GetLargeBlobParams{
				Write:        emptyBlob,
				OriginalSize: new(uint(0)),
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var get map[string]map[string]any
	if err := cbor.Unmarshal(getEncoded, &get); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := get["largeBlob"]["write"]; !ok {
		t.Fatalf("value does not contain %#v", "write")
	}

	write, ok := get["largeBlob"]["write"].([]byte)
	if !ok {
		t.Fatalf("largeBlob.write has type %T, want []byte", get["largeBlob"]["write"])
	}

	if len(write) != 0 {
		t.Errorf("got non-empty largeBlob.write %#v", write)
	}
	{
		want, got := uint64(0), get["largeBlob"]["originalSize"]
		gotValue, ok := got.(uint64)

		if !ok || gotValue != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	getEncoded, err = encMode.Marshal(GetExtensionInputs{
		GetLargeBlobInput: GetLargeBlobInput{
			LargeBlob: GetLargeBlobParams{Read: true},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	get = nil
	if err := cbor.Unmarshal(getEncoded, &get); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := true, get["largeBlob"]["read"]
		gotValue, ok := got.(bool)

		if !ok || gotValue != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	if _, ok := get["largeBlob"]["write"]; ok {
		t.Errorf("value unexpectedly contains %#v", "write")
	}

	if _, ok := get["largeBlob"]["originalSize"]; ok {
		t.Errorf("value unexpectedly contains %#v", "originalSize")
	}

	outputEncoded, err := encMode.Marshal(GetLargeBlobOutput{Blob: []byte{}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var output map[string]any
	if err := cbor.Unmarshal(outputEncoded, &output); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := output["blob"]; !ok {
		t.Fatalf("value does not contain %#v", "blob")
	}

	blob, ok := output["blob"].([]byte)
	if !ok {
		t.Fatalf("blob has type %T, want []byte", output["blob"])
	}

	if len(blob) != 0 {
		t.Errorf("got non-empty blob %#v", blob)
	}

	outputEncoded, err = encMode.Marshal(GetLargeBlobOutput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output = nil
	if err := cbor.Unmarshal(outputEncoded, &output); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := output["blob"]; ok {
		t.Errorf("value unexpectedly contains %#v", "blob")
	}
}

func TestLargeBlobUnsignedOutputsPreserveUnknownExtensionsAndProvideTypedAccessors(t *testing.T) {
	raw, err := cbor.Marshal(map[uint64]any{
		6: map[string]any{
			"largeBlob":      map[string]any{"supported": false},
			"vendor.example": map[string]any{"value": uint64(42)},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var makeCredential AuthenticatorMakeCredentialResponse
	if err := cbor.Unmarshal(raw, &makeCredential); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := makeCredential.UnsignedExtensionOutputs; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if _, ok := makeCredential.UnsignedExtensionOutputs[extension.ExtensionIdentifier("vendor.example")]; !ok {
		t.Fatalf("value does not contain %#v", extension.ExtensionIdentifier("vendor.example"))
	}

	makeCredentialOutput, err := makeCredential.LargeBlobUnsignedExtensionOutput()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := makeCredentialOutput; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := makeCredentialOutput.Supported; got {
		t.Fatalf("got true, want false")
	}

	raw, err = cbor.Marshal(map[uint64]any{
		8: map[string]any{
			"largeBlob": map[string]any{
				"written":      false,
				"blob":         []byte{},
				"originalSize": uint64(0),
			},
			"vendor.example": true,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var getAssertion AuthenticatorGetAssertionResponse
	if err := cbor.Unmarshal(raw, &getAssertion); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := getAssertion.UnsignedExtensionOutputs[extension.ExtensionIdentifier("vendor.example")]; !ok {
		t.Fatalf("value does not contain %#v", extension.ExtensionIdentifier("vendor.example"))
	}

	output, err := getAssertion.LargeBlobUnsignedExtensionOutput()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := output; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := output.Written; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := *output.Written; got {
		t.Fatalf("got true, want false")
	}

	if got := output.Blob; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := output.Blob; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}

	if got := output.OriginalSize; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got := *output.OriginalSize; got != 0 {
		t.Fatalf("got %#v, want zero value", got)
	}
}
