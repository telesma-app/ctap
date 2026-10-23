package webauthn

import (
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestCreateAuthenticationExtensionsClientInputsJSON(t *testing.T) {
	encoded, err := json.Marshal(CreateAuthenticationExtensionsClientInputs{
		CreateCredentialPropertiesInputs: &CreateCredentialPropertiesInputs{CredentialProperties: true},
		PRFInputs:                        &PRFInputs{},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(encoded), `{"credProps":true,"prf":{}}`; got != want {
		t.Fatalf("JSON = %s, want %s", got, want)
	}
}

func TestLargeBlobOutputsPreserveOptionalPresence(t *testing.T) {
	for name, decode := range map[string]func([]byte, any) error{
		"CBOR": cbor.Unmarshal,
		"JSON": json.Unmarshal,
	} {
		t.Run(name, func(t *testing.T) {
			var absent AuthenticationExtensionsLargeBlobOutputs
			if err := decode([]byte(largeBlobOutputEncoding(name, false)), &absent); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := absent.Supported; got != nil {
				t.Fatalf("got %#v, want nil", got)
			}

			if got := absent.Written; got != nil {
				t.Fatalf("got %#v, want nil", got)
			}

			if got := absent.Blob; got != nil {
				t.Fatalf("got %#v, want nil", got)
			}

			var present AuthenticationExtensionsLargeBlobOutputs
			if err := decode([]byte(largeBlobOutputEncoding(name, true)), &present); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := present.Supported; got == nil {
				t.Fatalf("got nil, want a non-nil value")
			}

			if got := *present.Supported; got {
				t.Fatalf("got true, want false")
			}

			if got := present.Written; got == nil {
				t.Fatalf("got nil, want a non-nil value")
			}

			if got := *present.Written; got {
				t.Fatalf("got true, want false")
			}

			if got := present.Blob; got == nil {
				t.Fatalf("got nil, want a non-nil value")
			}

			if got := present.Blob; len(got) != 0 {
				t.Fatalf("got non-empty value %#v", got)
			}
		})
	}
}

func TestLargeBlobOutputsPreservePresentEmptyBlob(t *testing.T) {
	for name, encode := range map[string]func(any) ([]byte, error){
		"CBOR": cbor.Marshal,
		"JSON": json.Marshal,
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := encode(AuthenticationExtensionsLargeBlobOutputs{Blob: []byte{}})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var present map[string]any
			if name == "CBOR" {
				if err := cbor.Unmarshal(encoded, &present); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err := json.Unmarshal(encoded, &present); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if _, ok := present["blob"]; !ok {
				t.Fatalf("value does not contain %#v", "blob")
			}

			encoded, err = encode(AuthenticationExtensionsLargeBlobOutputs{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var absent map[string]any
			if name == "CBOR" {
				if err := cbor.Unmarshal(encoded, &absent); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err := json.Unmarshal(encoded, &absent); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if _, ok := absent["blob"]; ok {
				t.Fatalf("value unexpectedly contains %#v", "blob")
			}
		})
	}
}

func TestLargeBlobInputsPreservePresentEmptyWrite(t *testing.T) {
	for name, encode := range map[string]func(any) ([]byte, error){
		"CBOR": cbor.Marshal,
		"JSON": json.Marshal,
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := encode(AuthenticationExtensionsLargeBlobInputs{Write: []byte{}})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var present map[string]any
			if name == "CBOR" {
				if err := cbor.Unmarshal(encoded, &present); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err := json.Unmarshal(encoded, &present); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if _, ok := present["write"]; !ok {
				t.Fatalf("value does not contain %#v", "write")
			}

			encoded, err = encode(AuthenticationExtensionsLargeBlobInputs{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var absent map[string]any
			if name == "CBOR" {
				if err := cbor.Unmarshal(encoded, &absent); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err := json.Unmarshal(encoded, &absent); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if _, ok := absent["write"]; ok {
				t.Fatalf("value unexpectedly contains %#v", "write")
			}
		})
	}
}

func TestLargeBlobInputsPreservePresentFalseRead(t *testing.T) {
	for name, encode := range map[string]func(any) ([]byte, error){
		"CBOR": cbor.Marshal,
		"JSON": json.Marshal,
	} {
		t.Run(name, func(t *testing.T) {
			read := false

			encoded, err := encode(AuthenticationExtensionsLargeBlobInputs{Read: &read})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var fields map[string]any
			if name == "CBOR" {
				if err := cbor.Unmarshal(encoded, &fields); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err := json.Unmarshal(encoded, &fields); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if _, ok := fields["read"]; !ok {
				t.Fatalf("value does not contain %#v", "read")
			}
			{
				want, got := false, fields["read"]
				gotValue, ok := got.(bool)

				if !ok || gotValue != want {
					t.Fatalf("got %#v, want %#v", got, want)
				}
			}

			var decoded AuthenticationExtensionsLargeBlobInputs
			if name == "CBOR" {
				if err := cbor.Unmarshal(encoded, &decoded); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err := json.Unmarshal(encoded, &decoded); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if got := decoded.Read; got == nil {
				t.Fatalf("got nil, want a non-nil value")
			}

			if got := *decoded.Read; got {
				t.Fatalf("got true, want false")
			}
		})
	}
}

func largeBlobOutputEncoding(format string, present bool) string {
	if format == "JSON" {
		if present {
			return `{"supported":false,"written":false,"blob":""}`
		}

		return `{}`
	}

	if present {
		return string([]byte{
			0xa3,
			0x69, 's', 'u', 'p', 'p', 'o', 'r', 't', 'e', 'd', 0xf4,
			0x67, 'w', 'r', 'i', 't', 't', 'e', 'n', 0xf4,
			0x64, 'b', 'l', 'o', 'b', 0x40,
		})
	}

	return string([]byte{0xa0})
}

func TestAuthenticationExtensionsPRFValuesJSONPreservesPresentEmptySecond(t *testing.T) {
	encoded, err := json.Marshal(AuthenticationExtensionsPRFValues{
		First:  []byte{},
		Second: []byte{},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(encoded), `{"first":"","second":""}`; got != want {
		t.Fatalf("JSON = %s, want %s", got, want)
	}
}

func TestAuthenticationExtensionsPRFOutputsJSONFollowCeremony(t *testing.T) {
	create, err := json.Marshal(CreatePRFOutputs{})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(create), `{"prf":{"enabled":false}}`; got != want {
		t.Fatalf("create JSON = %s, want %s", got, want)
	}

	get, err := json.Marshal(GetPRFOutputs{})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(get), `{"prf":{}}`; got != want {
		t.Fatalf("get JSON = %s, want %s", got, want)
	}
}

func TestCredentialPropertiesOutputJSONDistinguishesFalseFromUnknown(t *testing.T) {
	residentKey := false

	known, err := json.Marshal(CreateCredentialPropertiesOutputs{
		CredentialProperties: CredentialPropertiesOutput{ResidentKey: &residentKey},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(known), `{"credProps":{"rk":false}}`; got != want {
		t.Fatalf("known JSON = %s, want %s", got, want)
	}

	unknown, err := json.Marshal(CreateCredentialPropertiesOutputs{})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(unknown), `{"credProps":{}}`; got != want {
		t.Fatalf("unknown JSON = %s, want %s", got, want)
	}
}
