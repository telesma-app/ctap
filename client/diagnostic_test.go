package client

import (
	"context"
	"encoding/hex"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	ctapdiag "github.com/telesma-app/ctap/diagnostic"
	"github.com/telesma-app/ctap/options"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
)

func TestRenderDiagnosticRedactsTaggedFieldsAndShowsOtherFields(t *testing.T) {
	secret := []byte("pin-hash-canary")
	request := protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: protocol.PinUvAuthProtocolOne,
		SubCommand:        protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions,
		PinHashEnc:        secret,
		RPID:              "engineers.example",
	}
	configured := options.NewOptions()

	raw, err := configured.EncMode.Marshal(request)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		diagnosticMessageSchema{typeInfo: reflect.TypeFor[protocol.AuthenticatorClientPINRequest]()},
	)

	if got := diagnostic.Error; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}

	if container, element := diagnostic.Notation, diagnosticRedacted; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, "h'/[REDACTED]/'"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, "engineers.example"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, hex.EncodeToString(secret); strings.Contains(container, element) {
		t.Errorf("value unexpectedly contains %#v", element)
	}
	{
		want, got := []string{"PinHashEnc"}, diagnostic.RedactedFields
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestDiagnosticRedactionPreservesCBORMajorType(t *testing.T) {
	configured := options.NewOptions()
	formatter := diagnosticFormatter{decoder: configured.DecMode}

	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"unsigned integer", uint64(42), `/[REDACTED]/ 0`},
		{"negative integer", int64(-42), `/[REDACTED]/ -1`},
		{"byte string", []byte("secret-canary"), `h'/[REDACTED]/'`},
		{"text string", "secret-canary", `/[REDACTED]/ ""`},
		{"array", []any{"secret-canary"}, "[\n  /[REDACTED]/\n]"},
		{"map", map[string]any{"secret": "secret-canary"}, "{\n  /[REDACTED]/\n}"},
		{"tag", cbor.Tag{Number: 24, Content: []byte("secret-canary")}, `24(h'/[REDACTED]/')`},
		{"boolean", true, `/[REDACTED]/ false`},
		{"null", nil, `/[REDACTED]/ null`},
		{"undefined", cbor.SimpleValue(23), `/[REDACTED]/ undefined`},
		{"float", 1.5, `/[REDACTED]/ 0.0`},
		{"simple value", cbor.SimpleValue(16), `/[REDACTED]/ simple(0)`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoder := configured.EncMode
			if _, ok := test.value.(cbor.Tag); ok {
				encoder, _ = cbor.EncOptions{}.EncMode()
			}

			raw, err := encoder.Marshal(test.value)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			notation, err := formatter.redactedNotation(raw, 0)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got, want := notation, test.want; got != want {
				t.Errorf("got %#v, want %#v", got, want)
			}

			if container, element := notation, "secret-canary"; strings.Contains(container, element) {
				t.Errorf("value unexpectedly contains %#v", element)
			}
		})
	}
}

func TestRenderDiagnosticRedactsNestedExtensionFields(t *testing.T) {
	salt := []byte("salt-canary")
	request := protocol.AuthenticatorGetAssertionRequest{
		RPID:           "engineers.example",
		ClientDataHash: make([]byte, 32),
		Extensions: protocol.GetExtensionInputs{
			GetHMACSecretInput: protocol.GetHMACSecretInput{
				HMACSecret: protocol.HMACSecret{
					SaltEnc: salt,
				},
			},
		},
	}
	configured := options.NewOptions()

	raw, err := configured.EncMode.Marshal(request)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		diagnosticMessageSchema{typeInfo: reflect.TypeFor[protocol.AuthenticatorGetAssertionRequest]()},
	)

	if got := diagnostic.Error; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}

	if container, element := diagnostic.Notation, diagnosticRedacted; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, hex.EncodeToString(salt); strings.Contains(container, element) {
		t.Errorf("value unexpectedly contains %#v", element)
	}
	{
		want, got := []string{
			"Extensions.HMACSecret.SaltAuth",
			"Extensions.HMACSecret.SaltEnc",
		}, diagnostic.RedactedFields
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestRenderDiagnosticPreservesUnknownFields(t *testing.T) {
	configured := options.NewOptions()

	raw, err := configured.EncMode.Marshal(map[uint64]any{
		2:  uint64(protocol.ClientPINSubCommandGetPINRetries),
		10: "engineers.example",
		99: "unknown-field-canary",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		diagnosticMessageSchema{typeInfo: reflect.TypeFor[protocol.AuthenticatorClientPINRequest]()},
	)

	if got := diagnostic.Error; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}

	if container, element := diagnostic.Notation, "engineers.example"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, "unknown-field-canary"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, "/subCommand/ 2:"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, "/rpId/ 10:"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}
}

func TestRenderDiagnosticPreservesNestedUnknownFieldsAndRedactsKnownWrongType(t *testing.T) {
	configured := options.NewOptions()

	raw, err := configured.EncMode.Marshal(map[uint64]any{
		2: uint64(protocol.ClientPINSubCommandGetPINRetries),
		6: map[string]any{"unexpected": "secret-canary"},
		99: map[uint64]any{
			1: "nested-unknown-canary",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	diagnostic, subCommand := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		diagnosticMessageSchema{typeInfo: reflect.TypeFor[protocol.AuthenticatorClientPINRequest]()},
	)

	if got := diagnostic.Error; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}

	if got, want := subCommand, uint64(protocol.ClientPINSubCommandGetPINRetries); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if container, element := diagnostic.Notation, "nested-unknown-canary"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, diagnosticRedacted; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, "secret-canary"; strings.Contains(container, element) {
		t.Errorf("value unexpectedly contains %#v", element)
	}
	{
		want, got := []string{"PinHashEnc"}, diagnostic.RedactedFields
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestRenderDiagnosticUsesExplicitAndDerivedFieldNames(t *testing.T) {
	configured := options.NewOptions()

	raw, err := configured.EncMode.Marshal(map[uint64]any{
		1: "none",
		2: []byte("auth-data-canary"),
		3: map[string]any{"alg": -7},
		4: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		diagnosticMessageSchema{typeInfo: reflect.TypeFor[protocol.AuthenticatorMakeCredentialResponse]()},
	)

	if got := diagnostic.Error; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}

	if container, element := diagnostic.Notation, "/fmt/ 1:"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, "/authData/ 2:"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, "/attStmt/ 3:"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, "/epAtt/ 4:"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, "auth-data-canary"; strings.Contains(container, element) {
		t.Errorf("value unexpectedly contains %#v", element)
	}
	{
		want, got := []string{"AuthDataRaw"}, diagnostic.RedactedFields
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestRenderDiagnosticRedactsPreviewSignDataToBeSigned(t *testing.T) {
	toBeSigned := []byte("preview-sign-tbs-canary")
	request := protocol.AuthenticatorGetAssertionRequest{
		RPID:           "example.com",
		ClientDataHash: make([]byte, 32),
		Extensions: protocol.GetExtensionInputs{
			GetPreviewSignInput: protocol.GetPreviewSignInput{
				PreviewSign: protocol.PreviewSignSignInput{
					KeyHandle:  []byte("key-handle-canary"),
					ToBeSigned: toBeSigned,
				},
			},
		},
	}
	configured := options.NewOptions()

	raw, err := configured.EncMode.Marshal(request)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requestSchema, _ := exchangeSchemas(protocol.AuthenticatorGetAssertion)

	diagnostic, _ := renderDiagnostic(configured.DecMode, configured.EncMode, raw, requestSchema)

	if got := diagnostic.Error; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}

	if container, element := diagnostic.Notation, "key-handle-canary"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, hex.EncodeToString(toBeSigned); strings.Contains(container, element) {
		t.Errorf("value unexpectedly contains %#v", element)
	}
	{
		want, got := []string{"Extensions.PreviewSign.ToBeSigned"}, diagnostic.RedactedFields
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestRenderDiagnosticUsesProtocolSpellingOverrides(t *testing.T) {
	tests := []struct {
		name   string
		key    uint64
		schema reflect.Type
		want   string
	}{
		{"rpId", 1, reflect.TypeFor[protocol.AuthenticatorGetAssertionRequest](), "/rpId/ 1:"},
		{"rpIDHash", 4, reflect.TypeFor[protocol.AuthenticatorCredentialManagementResponse](), "/rpIDHash/ 4:"},
		{"templateId", 4, reflect.TypeFor[protocol.AuthenticatorBioEnrollmentResponse](), "/templateId/ 4:"},
	}
	configured := options.NewOptions()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := configured.EncMode.Marshal(map[uint64]any{test.key: "value"})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			diagnostic, _ := renderDiagnostic(
				configured.DecMode,
				configured.EncMode,
				raw,
				diagnosticMessageSchema{typeInfo: test.schema},
			)
			if got := diagnostic.Error; len(got) != 0 {
				t.Fatalf("got non-empty value %#v", got)
			}

			if container, element := diagnostic.Notation, test.want; !strings.Contains(container, element) {
				t.Errorf("value does not contain %#v", element)
			}
		})
	}
}

func TestRenderDiagnosticUsesConfigSubCommandParamsSchema(t *testing.T) {
	configured := options.NewOptions()

	raw, err := configured.EncMode.Marshal(map[uint64]any{
		1: uint64(protocol.ConfigSubCommandSetMinPINLength),
		2: map[uint64]any{
			1:  8,
			4:  true,
			99: "vendor-param-canary",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requestSchema, _ := exchangeSchemas(protocol.AuthenticatorConfig)

	diagnostic, subCommand := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		requestSchema,
	)

	if got := diagnostic.Error; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}

	if got, want := subCommand, uint64(protocol.ConfigSubCommandSetMinPINLength); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if container, element := diagnostic.Notation, "/subCommandParams/ 2:"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, "/newMinPINLength/ 1:"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, "/pinComplexityPolicy/ 4:"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, "vendor-param-canary"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}
}

func TestRenderDiagnosticRedactsKnownUnsignedExtensionOutputFields(t *testing.T) {
	secret := []byte("large-blob-canary")
	configured := options.NewOptions()

	raw, err := configured.EncMode.Marshal(map[uint64]any{
		8: map[string]any{
			"largeBlob": map[string]any{
				"written":      true,
				"blob":         secret,
				"originalSize": 42,
			},
			"vendor.example": map[string]any{
				"debug": "vendor-canary",
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, responseSchema := exchangeSchemas(protocol.AuthenticatorGetAssertion)

	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		responseSchema,
	)

	if got := diagnostic.Error; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}

	if container, element := diagnostic.Notation, "/unsignedExtensionOutputs/ 8:"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, `"written": true`; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, `"blob": h'/[REDACTED]/'`; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, `"originalSize": 42`; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, "vendor-canary"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, hex.EncodeToString(secret); strings.Contains(container, element) {
		t.Errorf("value unexpectedly contains %#v", element)
	}
	{
		want, got := []string{"UnsignedExtensionOutputs.Blob"}, diagnostic.RedactedFields
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestRenderDiagnosticShowsSafeMakeCredentialUnsignedExtensionOutputs(t *testing.T) {
	configured := options.NewOptions()

	raw, err := configured.EncMode.Marshal(map[uint64]any{
		6: map[string]any{
			"largeBlob": map[string]any{
				"supported": true,
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, responseSchema := exchangeSchemas(protocol.AuthenticatorMakeCredential)

	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		responseSchema,
	)

	if got := diagnostic.Error; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}

	if container, element := diagnostic.Notation, "/unsignedExtensionOutputs/ 6:"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, `"supported": true`; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, diagnosticRedacted; strings.Contains(container, element) {
		t.Errorf("value unexpectedly contains %#v", element)
	}

	if got := diagnostic.RedactedFields; len(got) != 0 {
		t.Errorf("got non-empty value %#v", got)
	}
}

func TestRenderDiagnosticWithoutSchemaShowsRawCBOR(t *testing.T) {
	configured := options.NewOptions()

	raw, err := configured.EncMode.Marshal(map[uint64]any{
		99: []any{"vendor", map[string]any{"future": true}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		diagnosticMessageSchema{},
	)

	if got := diagnostic.Error; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}

	if container, element := diagnostic.Notation, "vendor"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := diagnostic.Notation, "future"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}
}

func TestRenderDiagnosticHasDeterministicMapOrder(t *testing.T) {
	configured := options.NewOptions()

	raw, err := configured.EncMode.Marshal(map[uint64]any{
		10: "example.com",
		2:  uint64(protocol.ClientPINSubCommandGetPINRetries),
		1:  uint64(protocol.PinUvAuthProtocolOne),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		diagnosticMessageSchema{typeInfo: reflect.TypeFor[protocol.AuthenticatorClientPINRequest]()},
	)

	if got := diagnostic.Error; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}

	want := "{\n" +
		"  /pinUvAuthProtocol/ 1: 1,\n" +
		"  /subCommand/ 2: 1,\n" +
		"  /rpId/ 10: \"example.com\"\n" +
		"}"
	if got := diagnostic.Notation; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestRenderDiagnosticPrettyPrintsNestedCollections(t *testing.T) {
	configured := options.NewOptions()

	raw, err := configured.EncMode.Marshal(map[uint64]any{
		99: []any{
			map[string]any{
				"empty": []any{},
				"value": true,
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		diagnosticMessageSchema{},
	)

	if got := diagnostic.Error; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}

	want := "{\n" +
		"  99: [\n" +
		"    {\n" +
		"      \"empty\": [],\n" +
		"      \"value\": true\n" +
		"    }\n" +
		"  ]\n" +
		"}"
	if got := diagnostic.Notation; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestRenderDiagnosticRejectsMalformedCBORWithoutNotation(t *testing.T) {
	configured := options.NewOptions()
	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		[]byte{0xa1, 0x06},
		diagnosticMessageSchema{typeInfo: reflect.TypeFor[protocol.AuthenticatorClientPINRequest]()},
	)

	if got := diagnostic.Error; len(got) == 0 {
		t.Errorf("got empty value %#v, want non-empty", got)
	}

	if got := diagnostic.Notation; len(got) != 0 {
		t.Errorf("got non-empty value %#v", got)
	}
}

func TestLowerCamel(t *testing.T) {
	if got, want := lowerCamel("ClientDataHash"), "clientDataHash"; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := lowerCamel("PINComplexityPolicy"), "pinComplexityPolicy"; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := lowerCamel("AAGUID"), "aaguid"; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := lowerCamel("MaxRPIDsForSetMinPINLength"), "maxRPIDsForSetMinPINLength"; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestExchangeLogsStructuredRedactedDiagnostic(t *testing.T) {
	requestSecret := []byte("request-secret")
	responseSecret := []byte("response-secret")
	request := protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: protocol.PinUvAuthProtocolOne,
		SubCommand:        protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions,
		PinHashEnc:        requestSecret,
		RPID:              "engineers.example",
	}
	configured := options.NewOptions()

	requestBody, err := configured.EncMode.Marshal(request)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	responseBody, err := configured.EncMode.Marshal(map[uint64]any{
		2:  responseSecret,
		99: "response-unknown-canary",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var events []ctapdiag.Exchange

	transport := &fakeCBORTransport{
		t:        t,
		request:  append([]byte{byte(protocol.AuthenticatorClientPIN)}, requestBody...),
		response: responseBody,
	}

	client, err := NewClient(
		options.WithDiagnosticSink(func(_ context.Context, event ctapdiag.Exchange) {
			events = append(events, event)
		}),
		options.WithTransport(transport),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = client.exchange(context.Background(), transport.request)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := len(events), 1; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	event := events[0]
	if got, want := event.Command, protocol.AuthenticatorClientPIN; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := event.SubCommand, uint64(protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := event.Request.Bytes, len(requestBody); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := event.Response.Bytes, len(responseBody); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got := event.Status; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got, want := *event.Status, ctaptransport.CTAP2_OK; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if container, element := event.Request.Notation, "engineers.example"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := event.Request.Notation, "REDACTED"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := event.Request.Notation, hex.EncodeToString(requestSecret); strings.Contains(container, element) {
		t.Errorf("value unexpectedly contains %#v", element)
	}
	{
		want, got := []string{"PinHashEnc"}, event.Request.RedactedFields
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	if container, element := event.Response.Notation, "REDACTED"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := event.Response.Notation, "response-unknown-canary"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	if container, element := event.Response.Notation, hex.EncodeToString(responseSecret); strings.Contains(container, element) {
		t.Errorf("value unexpectedly contains %#v", element)
	}
	{
		want, got := []string{"PinUvAuthToken"}, event.Response.RedactedFields
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}
