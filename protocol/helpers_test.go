package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/credential"
)

func TestAuthenticatorGetInfoResponseUsesZeroSentinelsForEquivalentOrInvalidValues(t *testing.T) {
	raw, err := cbor.Marshal(map[uint64]any{
		4:  map[string]bool{string(OptionClientPIN): false},
		5:  uint64(0),
		12: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp AuthenticatorGetInfoResponse
	if err := cbor.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := resp.MaxMsgSize; got != 0 {
		t.Fatalf("got %#v, want zero value", got)
	}

	if got := resp.ForcePINChange; got {
		t.Fatalf("got true, want false")
	}

	clientPIN, ok := resp.Options[OptionClientPIN]
	if got := ok; !got {
		t.Fatalf("got false, want true")
	}

	if got := clientPIN; got {
		t.Fatalf("got true, want false")
	}

	_, ok = resp.Options[OptionUserVerification]
	if got := ok; got {
		t.Fatalf("got true, want false")
	}

	if got := resp.MinPINLength; got != 0 {
		t.Fatalf("got %#v, want zero value", got)
	}

	if got := resp.LongTouchForReset; got != nil {
		t.Fatalf("got %#v, want nil", got)
	}
}

func TestAuthenticatorGetInfoResponseOmitsAbsentOptionalScalarsJSON(t *testing.T) {
	raw, err := json.Marshal(AuthenticatorGetInfoResponse{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text := string(raw)
	for _, absentField := range []string{
		"maxMsgSize",
		"forcePINChange",
		"preferredPlatformUvAttempts",
		"uvModality",
		"uvCountSinceLastPinEntry",
		"longTouchForReset",
		"pinComplexityPolicy",
		"pinComplexityPolicyURL",
		"maxPINLength",
		"encCredStoreState",
	} {
		if container, element := text, absentField; strings.Contains(container, element) {
			t.Fatalf("value unexpectedly contains %#v", element)
		}
	}

	zero := uint(0)
	disabled := false

	raw, err = json.Marshal(AuthenticatorGetInfoResponse{
		UvModality:               (*UserVerify)(&zero),
		UvCountSinceLastPinEntry: &zero,
		LongTouchForReset:        &disabled,
		PinComplexityPolicy:      &disabled,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text = string(raw)
	for _, presentValue := range []string{
		`"uvModality":0`,
		`"uvCountSinceLastPinEntry":0`,
		`"longTouchForReset":false`,
		`"pinComplexityPolicy":false`,
	} {
		if container, element := text, presentValue; !strings.Contains(container, element) {
			t.Fatalf("value does not contain %#v", element)
		}
	}
}

func TestAuthenticatorGetInfoResponseEffectiveDefaults(t *testing.T) {
	var resp AuthenticatorGetInfoResponse
	if got, want := resp.EffectiveMaxMsgSize(), DefaultMaxMsgSize; got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	if got, want := resp.EffectiveMinPINLength(), DefaultMinPINCodePoints; got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	if got, want := resp.EffectiveMaxPINLength(), DefaultMaxPINCodePoints; got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	resp.MaxMsgSize = 2048
	resp.MinPINLength = 8
	resp.MaxPINLength = 48

	if got, want := resp.EffectiveMaxMsgSize(), uint(2048); got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	if got, want := resp.EffectiveMinPINLength(), uint(8); got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	if got, want := resp.EffectiveMaxPINLength(), uint(48); got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestAuthenticatorGetInfoResponseCTAP23TypedFields(t *testing.T) {
	policyURL := []byte("https://example.com/pin-policy")

	raw, err := cbor.Marshal(map[uint64]any{
		1:  []string{"FIDO_2_3"},
		9:  []string{"usb", "future-transport"},
		21: []uint64{math.MaxUint64},
		22: []string{"packed"},
		26: []string{"nfc"},
		28: policyURL,
		31: []uint64{uint64(ConfigSubCommandSetMinPINLength)},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp AuthenticatorGetInfoResponse
	if err := cbor.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := []credential.AuthenticatorTransport{
			credential.AuthenticatorTransportUSB,
			credential.AuthenticatorTransport("future-transport"),
		}, resp.Transports
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := []credential.AuthenticatorTransport{credential.AuthenticatorTransportNFC}, resp.TransportsForReset
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := []VendorCommandID{VendorCommandID(math.MaxUint64)}, resp.VendorPrototypeConfigCommands
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := []attestation.AttestationStatementFormatIdentifier{
			attestation.AttestationStatementFormatIdentifierPacked,
		}, resp.AttestationFormats
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := []ConfigSubCommand{ConfigSubCommandSetMinPINLength}, resp.AuthenticatorConfigCommands
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}

	if got, want := resp.PinComplexityPolicyURL, policyURL; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	if got, want := resp.PinComplexityPolicyURLString(), string(policyURL); got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestAuthenticatorGetInfoResponseEncodesConfigCommandsAsArray(t *testing.T) {
	resp := AuthenticatorGetInfoResponse{
		AuthenticatorConfigCommands: []ConfigSubCommand{
			ConfigSubCommandToggleAlwaysUv,
			ConfigSubCommandSetMinPINLength,
		},
	}

	raw, err := cbor.Marshal(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var fields map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := fields[31]; len(got) == 0 {
		t.Fatalf("got empty value %#v, want non-empty", got)
	}

	if got, want := fields[31][0]&0xe0, byte(0x80); got != want {
		t.Fatalf("got %#v, want %#v; context: %s", got, want, "authenticatorConfigCommands must be a CBOR array")
	}

	var commands []uint64
	if err := cbor.Unmarshal(fields[31], &commands); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := []uint64{2, 3}, commands
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}

	raw, err = json.Marshal(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var jsonFields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &jsonFields); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		var want, got any
		if err := json.Unmarshal([]byte(`[2, 3]`), &want); err != nil {
			t.Fatalf("decode expected JSON: %v", err)
		}

		if err := json.Unmarshal([]byte(string(jsonFields["authenticatorConfigCommands"])), &got); err != nil {
			t.Fatalf("decode actual JSON: %v", err)
		} else if !bytes.Equal(canonicalJSONValue(t, got), canonicalJSONValue(t, want)) {
			t.Fatalf("got JSON %#v, want %#v", got, want)
		}
	}
}

func canonicalJSONValue(t testing.TB, value any) []byte {
	t.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode JSON value: %v", err)
	}

	return encoded
}

func TestAuthenticatorGetInfoResponseDecodesFIDO20WithoutNewFields(t *testing.T) {
	raw, err := cbor.Marshal(map[uint64]any{
		1: []string{"FIDO_2_0"},
		4: map[string]bool{string(OptionResidentKeys): false},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp AuthenticatorGetInfoResponse
	if err := cbor.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := Versions{FIDO_2_0}, resp.Versions
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}

	if got := resp.MaxPINLength; got != 0 {
		t.Fatalf("got %#v, want zero value", got)
	}

	if got := resp.AuthenticatorConfigCommands; got != nil {
		t.Fatalf("got %#v, want nil", got)
	}

	if got := resp.PinComplexityPolicyURLString(); len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}

	if got, want := resp.EffectiveMaxPINLength(), DefaultMaxPINCodePoints; got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestCredentialManagementOptionalScalarsPreservePresence(t *testing.T) {
	raw, err := cbor.Marshal(map[uint64]any{
		1:  uint64(0),
		2:  uint64(0),
		5:  uint64(0),
		9:  uint64(0),
		10: uint64(0),
		12: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp AuthenticatorCredentialManagementResponse
	if err := cbor.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := *resp.ExistingResidentCredentialsCount, uint(0); got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	if got, want := *resp.MaxPossibleRemainingResidentCredentialsCount, uint(0); got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	if got := resp.TotalRPs; got != 0 {
		t.Fatalf("got %#v, want zero value", got)
	}

	if got := resp.TotalCredentials; got != 0 {
		t.Fatalf("got %#v, want zero value", got)
	}

	if got := resp.CredProtect; got != 0 {
		t.Fatalf("got %#v, want zero value", got)
	}

	if got := *resp.ThirdPartyPayment; got {
		t.Fatalf("got true, want false")
	}

	raw, err = cbor.Marshal(AuthenticatorCredentialManagementResponse{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var fields map[uint64]any
	if err := cbor.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, key := range []uint64{1, 2, 5, 9, 10, 12} {
		if _, ok := fields[key]; ok {
			t.Fatalf("value unexpectedly contains %#v", key)
		}
	}
}

func TestMakeCredentialEnterpriseAttestationTreatsFalseAsAbsent(t *testing.T) {
	raw, err := cbor.Marshal(map[uint64]any{4: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp AuthenticatorMakeCredentialResponse
	if err := cbor.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := resp.EnterpriseAttestation; got {
		t.Fatalf("got true, want false")
	}

	var absent AuthenticatorMakeCredentialResponse
	if err := cbor.Unmarshal([]byte{0xa0}, &absent); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := absent.EnterpriseAttestation; got {
		t.Fatalf("got true, want false")
	}
}

func TestAttestationStatementAccessorsAcceptNormativeWireShapes(t *testing.T) {
	t.Run("packed self attestation omits x5c", func(t *testing.T) {
		resp := AuthenticatorMakeCredentialResponse{AttestationStatement: map[string]any{
			"alg": int64(-7),
			"sig": []byte{1, 2, 3},
		}}

		statement, ok := resp.PackedAttestationStatementFormat()
		if got := ok; !got {
			t.Fatalf("got false, want true")
		}

		if got := statement.X509Chain; got != nil {
			t.Fatalf("got %#v, want nil", got)
		}
	})

	t.Run("FIDO U2F accepts generic decoded x5c array", func(t *testing.T) {
		certificate := []byte{1, 2, 3}
		resp := AuthenticatorMakeCredentialResponse{AttestationStatement: map[string]any{
			"x5c": []any{certificate},
			"sig": []byte{4, 5, 6},
		}}

		statement, ok := resp.FIDOU2FAttestationStatementFormat()
		if got := ok; !got {
			t.Fatalf("got false, want true")
		}
		{
			want, got := [][]byte{certificate}, statement.X509Chain
			if (got == nil) != (want == nil) || !slices.EqualFunc(got, want, func(got, want []byte) bool {
				return (got == nil) == (want == nil) && bytes.Equal(got, want)
			}) {
				t.Fatalf("got %#v, want %#v", got, want)
			}
		}
	})

	t.Run("TPM does not require non-standard aikCert", func(t *testing.T) {
		certificate := []byte{1, 2, 3}
		resp := AuthenticatorMakeCredentialResponse{AttestationStatement: map[string]any{
			"ver":      "2.0",
			"alg":      int64(-7),
			"x5c":      []any{certificate},
			"sig":      []byte{4},
			"certInfo": []byte{5},
			"pubArea":  []byte{6},
		}}

		statement, ok := resp.TPMAttestationStatementFormat()
		if got := ok; !got {
			t.Fatalf("got false, want true")
		}
		{
			want, got := [][]byte{certificate}, statement.X509Chain
			if (got == nil) != (want == nil) || !slices.EqualFunc(got, want, func(got, want []byte) bool {
				return (got == nil) == (want == nil) && bytes.Equal(got, want)
			}) {
				t.Fatalf("got %#v, want %#v", got, want)
			}
		}
	})
}

func TestAuthenticatorGetInfoResponseMaxCredBlobLengthPresence(t *testing.T) {
	var resp AuthenticatorGetInfoResponse

	value, ok := resp.MaxCredBlobLengthValue()
	if got := ok; got {
		t.Fatalf("got true, want false")
	}

	if got, want := value, uint(0); got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	resp.MaxCredBlobLength = 32

	value, ok = resp.MaxCredBlobLengthValue()
	if got := ok; !got {
		t.Fatalf("got false, want true")
	}

	if got, want := value, uint(32); got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestParseGetAssertionAuthDataRejectsShortData(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		make([]byte, 36),
	} {
		_, err := ParseGetAssertionAuthData(data)
		if err == nil {
			t.Fatalf("expected an error")
		}
	}
}

func TestParseMakeCredentialAuthDataRejectsTruncatedAttestedCredentialData(t *testing.T) {
	data := make([]byte, 37)
	data[32] = byte(AuthDataFlagAttestedCredentialDataIncluded)

	_, err := ParseMakeCredentialAuthData(data)
	if err == nil {
		t.Fatalf("expected an error")
	}

	data = append(data, make([]byte, 16)...)

	_, err = ParseMakeCredentialAuthData(data)
	if err == nil {
		t.Fatalf("expected an error")
	}

	data = append(data, 0, 2, 0x01)

	_, err = ParseMakeCredentialAuthData(data)
	if err == nil {
		t.Fatalf("expected an error")
	}
}

func TestParseAuthDataRejectsMissingOrNonMapExtensionData(t *testing.T) {
	for _, suffix := range [][]byte{
		nil,
		{0xf6}, // null
		{0x80}, // array
	} {
		data := make([]byte, 37)
		data[32] = byte(AuthDataFlagExtensionDataIncluded)
		data = append(data, suffix...)

		_, err := ParseMakeCredentialAuthData(data)
		if err == nil {
			t.Fatalf("expected an error")
		}

		_, err = ParseGetAssertionAuthData(data)
		if err == nil {
			t.Fatalf("expected an error")
		}
	}
}

func TestParseAuthDataRejectsTrailingBytes(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "without extension flag",
			data: append(make([]byte, 37), 0x00),
		},
		{
			name: "after extension map",
			data: func() []byte {
				data := make([]byte, 37)
				data[32] = byte(AuthDataFlagExtensionDataIncluded)

				return append(data, 0xa0, 0x00)
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseMakeCredentialAuthData(test.data)
			if err == nil {
				t.Fatalf("expected an error")
			}

			_, err = ParseGetAssertionAuthData(test.data)
			if err == nil {
				t.Fatalf("expected an error")
			}
		})
	}
}

func TestParseAuthDataRejectsReservedFlags(t *testing.T) {
	for _, flag := range []byte{1 << 1, 1 << 5} {
		data := make([]byte, 37)
		data[32] = flag

		_, err := ParseGetAssertionAuthData(data)
		if err == nil {
			t.Fatalf("expected an error; context: %s", fmt.Sprintf("reserved flag 0x%02x", flag))
		}
	}
}
