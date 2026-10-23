package authenticator

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"

	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/ctap/webauthn"
)

func validateCreatePRF(
	info protocol.AuthenticatorGetInfoResponse,
	pinUvAuthToken []byte,
	inputs *webauthn.CreateAuthenticationExtensionsClientInputs,
	options map[protocol.Option]bool,
) (*webauthn.AuthenticationExtensionsPRFValues, error) {
	// WebAuthn L3 CR § 10.1.4 (registration client processing):
	// https://www.w3.org/TR/2026/CR-webauthn-3-20260526/#prf-extension
	// evalByCredential is forbidden during registration, while eval itself is
	// optional. hmac-secret advertises whether the new credential supports PRF;
	// hmac-secret-mc is only needed for the optional creation-time evaluation.
	if inputs.PRFInputs == nil {
		return nil, nil
	}

	if inputs.PRF.EvalByCredential != nil {
		return nil, &ErrorWithMessage{Err: ErrNotSupported, Message: "evalByCredential is not supported during registration"}
	}

	evalPresent, err := validateOptionalPRFValues("eval", inputs.PRF.Eval)
	if err != nil {
		return nil, err
	}

	supportsHMACSecret, supportsHMACSecretMC, err := prfCapabilities(info)
	if err != nil {
		return nil, err
	}

	if !evalPresent || !supportsHMACSecret || !supportsHMACSecretMC {
		return nil, nil
	}
	// Device accepts final CTAP options and does not rewrite them to implement
	// WebAuthn's UserVerificationRequirement override. Since creation-time PRF
	// evaluation is optional, omit hmac-secret-mc unless the CTAP request will
	// perform UV.
	if !userVerificationWillBePerformed(info, pinUvAuthToken, options) {
		return nil, nil
	}

	return new(inputs.PRF.Eval), nil
}

func validateGetPRF(
	info protocol.AuthenticatorGetInfoResponse,
	pinUvAuthToken []byte,
	allowList []credential.PublicKeyCredentialDescriptor,
	inputs *webauthn.GetAuthenticationExtensionsClientInputs,
	options map[protocol.Option]bool,
) (*webauthn.AuthenticationExtensionsPRFValues, error) {
	// WebAuthn L3 CR § 10.1.4 (authentication client processing):
	// https://www.w3.org/TR/2026/CR-webauthn-3-20260526/#prf-extension
	if inputs.PRFInputs == nil {
		return nil, nil
	}

	evaluation, err := selectCTAPGetPRFEvaluation(inputs.PRF, allowList)
	if err != nil {
		return nil, err
	}

	supportsHMACSecret, _, err := prfCapabilities(info)
	if err != nil {
		return nil, err
	}

	if evaluation == nil || !supportsHMACSecret {
		return nil, nil
	}

	if err := validateHMACSecretUserPresence(options); err != nil {
		return nil, err
	}
	// Unlike creation-time evaluation, an authentication PRF evaluation was
	// explicitly requested. Require a CTAP UV mechanism instead of silently
	// changing the caller's options.
	if !userVerificationWillBePerformed(info, pinUvAuthToken, options) {
		return nil, prfUserVerificationRequiredError(info)
	}

	return evaluation, nil
}

func userVerificationWillBePerformed(
	info protocol.AuthenticatorGetInfoResponse,
	pinUvAuthToken []byte,
	options map[protocol.Option]bool,
) bool {
	// CTAP 2.1 PS §§ 6.1.2, 6.2.2 (alwaysUv compatibility processing):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#op-makecred-step-options
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-getAssert-authnr-alg
	return pinUvAuthToken != nil ||
		options[protocol.OptionUserVerification] ||
		alwaysUVEnabled(info) && info.Options[protocol.OptionUserVerification]
}

func prfCapabilities(info protocol.AuthenticatorGetInfoResponse) (bool, bool, error) {
	// CTAP 2.3 PS § 12.8 requires hmac-secret whenever hmac-secret-mc is
	// advertised.
	// https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-hmac-secret-make-cred-extension
	supportsHMACSecret := slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecret)

	supportsHMACSecretMC := slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecretMC)
	if supportsHMACSecretMC && !supportsHMACSecret {
		return false, false, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device reports hmac-secret-mc without dependent hmac-secret extension"}
	}

	return supportsHMACSecret, supportsHMACSecretMC, nil
}

func validateOptionalPRFValues(name string, values webauthn.AuthenticationExtensionsPRFValues) (bool, error) {
	// WebAuthn L3 CR § 10.1.4 defines first as required whenever an
	// AuthenticationExtensionsPRFValues dictionary is present and second as
	// optional:
	// https://www.w3.org/TR/2026/CR-webauthn-3-20260526/#prf-extension
	if values.First != nil {
		return true, nil
	}

	if values.Second != nil {
		return false, &ErrorWithMessage{Err: SyntaxError, Message: fmt.Sprintf("%s.second requires %s.first", name, name)}
	}

	return false, nil
}

func validateRequiredPRFValues(name string, values webauthn.AuthenticationExtensionsPRFValues) error {
	// WebAuthn L3 CR § 10.1.4 (AuthenticationExtensionsPRFValues.first):
	// https://www.w3.org/TR/2026/CR-webauthn-3-20260526/#prf-extension
	if values.First == nil {
		return &ErrorWithMessage{Err: SyntaxError, Message: fmt.Sprintf("%s.first is required", name)}
	}

	return nil
}

func validateGetPRFInputs(
	inputs webauthn.AuthenticationExtensionsPRFInputs,
	allowList []credential.PublicKeyCredentialDescriptor,
) error {
	// WebAuthn L3 CR § 10.1.4, authentication steps 1 and 2.
	// https://www.w3.org/TR/2026/CR-webauthn-3-20260526/#prf-extension
	if _, err := validateOptionalPRFValues("eval", inputs.Eval); err != nil {
		return err
	}

	if len(inputs.EvalByCredential) == 0 {
		return nil
	}

	if len(allowList) == 0 {
		return &ErrorWithMessage{Err: ErrNotSupported, Message: "non-empty evalByCredential requires a non-empty allowList"}
	}

	allowedCredentialIDs := make(map[string]struct{}, len(allowList))
	for _, descriptor := range allowList {
		allowedCredentialIDs[base64.RawURLEncoding.EncodeToString(descriptor.ID)] = struct{}{}
	}

	for encodedID, values := range inputs.EvalByCredential {
		credentialID, err := base64.RawURLEncoding.Strict().DecodeString(encodedID)
		if encodedID == "" || err != nil || base64.RawURLEncoding.EncodeToString(credentialID) != encodedID {
			return &ErrorWithMessage{Err: SyntaxError, Message: "evalByCredential contains an invalid base64url credential ID"}
		}

		if _, ok := allowedCredentialIDs[encodedID]; !ok {
			return &ErrorWithMessage{Err: SyntaxError, Message: "evalByCredential credential ID is not present in allowList"}
		}

		if err := validateRequiredPRFValues("evalByCredential", values); err != nil {
			return err
		}
	}

	return nil
}

func selectPRFEvaluationForCredential(
	inputs webauthn.AuthenticationExtensionsPRFInputs,
	credentialID []byte,
) *webauthn.AuthenticationExtensionsPRFValues {
	encodedID := base64.RawURLEncoding.EncodeToString(credentialID)
	if values, ok := inputs.EvalByCredential[encodedID]; ok {
		return new(values)
	}

	if inputs.Eval.First != nil {
		return new(inputs.Eval)
	}

	return nil
}

func selectCTAPGetPRFEvaluation(
	inputs webauthn.AuthenticationExtensionsPRFInputs,
	allowList []credential.PublicKeyCredentialDescriptor,
) (*webauthn.AuthenticationExtensionsPRFValues, error) {
	if err := validateGetPRFInputs(inputs, allowList); err != nil {
		return nil, err
	}

	if len(inputs.EvalByCredential) == 0 {
		return selectPRFEvaluationForCredential(inputs, nil), nil
	}

	// This is a limitation of Device.GetAssertion, not WebAuthn input
	// validation. WebAuthn selects evalByCredential after knowing the credential
	// that will be returned, while CTAP permits the authenticator to select any
	// applicable credential from allowList. A single CTAP request is therefore
	// safe only when every possible credential resolves to the same inputs.
	// https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-getAssert-authnr-alg

	var (
		reference    *webauthn.AuthenticationExtensionsPRFValues
		referenceSet bool
	)

	seenCredentialIDs := make(map[string]struct{}, len(allowList))
	for _, descriptor := range allowList {
		encodedID := base64.RawURLEncoding.EncodeToString(descriptor.ID)
		if _, seen := seenCredentialIDs[encodedID]; seen {
			continue
		}

		seenCredentialIDs[encodedID] = struct{}{}

		effective := selectPRFEvaluationForCredential(inputs, descriptor.ID)

		if !referenceSet {
			reference = effective
			referenceSet = true

			continue
		}

		if !equalOptionalPRFValues(reference, effective) {
			return nil, &ErrorWithMessage{Err: ErrNotSupported, Message: "Device.GetAssertion cannot apply different credential-specific PRF inputs in one CTAP request; issue one request per credential"}
		}
	}

	return reference, nil
}

func equalOptionalPRFValues(a, b *webauthn.AuthenticationExtensionsPRFValues) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}

	// A present empty BufferSource is different from an absent member. In
	// particular, second=[] requests SHA-256(domain || empty), while a nil
	// second requests no second PRF evaluation at all.
	return (a.First == nil) == (b.First == nil) &&
		slices.Equal(a.First, b.First) &&
		(a.Second == nil) == (b.Second == nil) &&
		slices.Equal(a.Second, b.Second)
}

func prfUserVerificationRequiredError(info protocol.AuthenticatorGetInfoResponse) error {
	// WebAuthn L3 CR § 10.1.4 exposes only the user-verified hmac-secret PRF,
	// overriding UserVerificationRequirement when necessary. Device operates at
	// the CTAP-options layer and reports the authorization action its caller must
	// explicitly supply instead of performing that override itself.
	// https://www.w3.org/TR/2026/CR-webauthn-3-20260526/#prf-extension
	if info.Options[protocol.OptionUserVerification] {
		return &ErrorWithMessage{Err: ErrBuiltInUVRequired, Message: "PRF evaluation requires options[uv]=true or a pinUvAuthToken"}
	}

	if info.Options[protocol.OptionClientPIN] && !info.Options[protocol.OptionNoMcGaPermissionsWithClientPin] {
		return &ErrorWithMessage{Err: ErrPinUvAuthTokenRequired, Message: "PRF evaluation requires user verification"}
	}

	if configured, ok := info.Options[protocol.OptionUserVerification]; ok && !configured {
		return &ErrorWithMessage{Err: ErrUvNotConfigured, Message: "PRF evaluation requires configured user verification"}
	}

	return &ErrorWithMessage{Err: ErrNotSupported, Message: "device cannot perform the user verification required for PRF evaluation"}
}

func prfSalts(values webauthn.AuthenticationExtensionsPRFValues) []byte {
	// WebAuthn L3 CR § 10.1.4 (registration step 2 and authentication
	// step 5): hash each supplied PRF input with the WebAuthn PRF context before
	// passing it to CTAP hmac-secret.
	// https://www.w3.org/TR/2026/CR-webauthn-3-20260526/#prf-extension
	first := hashPRFInput(values.First)
	if values.Second == nil {
		return first
	}

	return slices.Concat(first, hashPRFInput(values.Second))
}

func validatePRFResultLength(values webauthn.AuthenticationExtensionsPRFValues, result []byte) error {
	// CTAP 2.3 PS § 12.7 returns exactly one output per supplied salt.
	// https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-hmac-secret-extension
	want := 32
	if values.Second != nil {
		want = 64
	}

	if len(result) != want {
		return &ErrorWithMessage{Err: ErrSpecViolation, Message: fmt.Sprintf("device returned %d PRF result bytes, want %d", len(result), want)}
	}

	return nil
}

func hashPRFInput(input []byte) []byte {
	// WebAuthn L3 CR § 10.1.4:
	// SHA-256(UTF8Encode("WebAuthn PRF") || 0x00 || input).
	// https://www.w3.org/TR/2026/CR-webauthn-3-20260526/#prf-extension
	hasher := sha256.New()
	hasher.Write([]byte("WebAuthn PRF"))
	hasher.Write([]byte{0x00})
	hasher.Write(input)

	return hasher.Sum(nil)
}
