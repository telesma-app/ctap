package authenticator

import (
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/ctap/webauthn"
)

func credentialProtectionValue(policy extension.CredentialProtectionPolicy) (int, error) {
	// CTAP 2.1 PS § 12.1.1 (credentialProtectionPolicy-to-credProtect mapping):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension
	switch policy {
	case extension.CredentialProtectionPolicyUserVerificationOptional:
		return 0x01, nil
	case extension.CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList:
		return 0x02, nil
	case extension.CredentialProtectionPolicyUserVerificationRequired:
		return 0x03, nil
	default:
		return 0, &ErrorWithMessage{Err: SyntaxError, Message: "invalid credential protection policy"}
	}
}

func validateCredentialBlobSupport(info protocol.AuthenticatorGetInfoResponse) (uint, error) {
	// CTAP 2.1 PS §§ 6.4, 12.2, 12.2.1 (credBlob feature detection):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#getinfo-maxcredbloblength
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credBlob-extension
	if !slices.Contains(info.Extensions, extension.ExtensionIdentifierCredentialBlob) {
		return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support credBlob extension"}
	}

	if !slices.Contains(info.Extensions, extension.ExtensionIdentifierCredentialProtection) {
		return 0, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device reports credBlob without dependent credProtect extension"}
	}

	maxCredBlobLength, ok := info.MaxCredBlobLengthValue()
	if !ok {
		return 0, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device reports credBlob extension without maxCredBlobLength"}
	}

	if maxCredBlobLength < 32 {
		return 0, &ErrorWithMessage{Err: ErrSpecViolation, Message: fmt.Sprintf("device reports maxCredBlobLength %d, want at least 32", maxCredBlobLength)}
	}

	return maxCredBlobLength, nil
}

func validateHMACSecretMCSupport(info protocol.AuthenticatorGetInfoResponse) error {
	// CTAP 2.3 PS § 12.8 (hmac-secret-mc depends on hmac-secret):
	// https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-hmac-secret-make-cred-extension
	if !slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecretMC) {
		return &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support hmac-secret-mc extension"}
	}

	if !slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecret) {
		return &ErrorWithMessage{Err: ErrSpecViolation, Message: "device reports hmac-secret-mc without dependent hmac-secret extension"}
	}

	return nil
}

func validateHMACSecretUserPresence(options map[protocol.Option]bool) error {
	// CTAP 2.0 PS § 9.1 (hmac-secret GetAssertion requires user consent):
	// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#sctn-hmac-secret-extension
	if up, ok := options[protocol.OptionUserPresence]; ok && !up {
		return &ErrorWithMessage{Err: ErrNotSupported, Message: "hmac-secret requires user presence"}
	}

	return nil
}

func unexpectedExtensionOutput(name string) error {
	return &ErrorWithMessage{Err: ErrSpecViolation, Message: fmt.Sprintf("device returned unsolicited %s extension output", name)}
}

func validateMakeCredentialExtensionOutputs(
	request *protocol.CreateExtensionInputs,
	clientInputs *webauthn.CreateAuthenticationExtensionsClientInputs,
	outputs *protocol.CreateExtensionOutputs,
) error {
	// CTAP 2.0 PS § 9.1 and CTAP 2.1 PS §§ 12.1, 12.2, 12.4, 12.5
	// define the MakeCredential outputs for hmac-secret, credProtect, credBlob,
	// and minPinLength. In particular, credProtect and hmac-secret outputs must
	// not be returned when their inputs were absent.
	// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#sctn-hmac-secret-extension
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credBlob-extension
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-minpinlength-extension
	// CTAP 2.3 PS §§ 12.6, 12.8 define pinComplexityPolicy and
	// hmac-secret-mc MakeCredential outputs.
	// https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#current-pin-complexity-policy
	// https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-hmac-secret-make-cred-extension
	if outputs != nil {
		if outputs.CredProtect != 0 {
			if request.CredProtect == 0 {
				return unexpectedExtensionOutput("credProtect")
			}

			if outputs.CredProtect < 0x01 || outputs.CredProtect > 0x03 {
				return &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned invalid credProtect extension output"}
			}
		}

		if outputs.CreateCredBlobOutput != nil && request.CredBlob == nil {
			return unexpectedExtensionOutput("credBlob")
		}

		if outputs.MinPinLength != 0 && !request.MinPinLength {
			return unexpectedExtensionOutput("minPinLength")
		}

		if outputs.CreatePinComplexityPolicyOutput != nil && !request.PinComplexityPolicy {
			return unexpectedExtensionOutput("pinComplexityPolicy")
		}

		if outputs.CreateHMACSecretOutput != nil && !request.CreateHMACSecretInput.HMACSecret {
			return unexpectedExtensionOutput("hmac-secret")
		}

		if outputs.CreateHMACSecretMCOutput.HMACSecret != nil && request.CreateHMACSecretMCInput.HMACSecret.KeyAgreement == nil {
			return unexpectedExtensionOutput("hmac-secret-mc")
		}
	}

	if request.CredBlob != nil && (outputs == nil || outputs.CreateCredBlobOutput == nil) {
		return &ErrorWithMessage{Err: ErrSpecViolation, Message: "device did not return credBlob extension output"}
	}

	if request.CreateHMACSecretInput.HMACSecret && (outputs == nil || outputs.CreateHMACSecretOutput == nil) {
		return &ErrorWithMessage{Err: ErrSpecViolation, Message: "device did not return hmac-secret extension output"}
	}

	if request.CreateHMACSecretMCInput.HMACSecret.KeyAgreement != nil &&
		(outputs == nil || outputs.CreateHMACSecretMCOutput.HMACSecret == nil) {
		return &ErrorWithMessage{Err: ErrSpecViolation, Message: "device did not return hmac-secret-mc extension output"}
	}

	if clientInputs.CreateCredentialProtectionInputs == nil ||
		!clientInputs.EnforceCredentialProtectionPolicy ||
		clientInputs.CredentialProtectionPolicy == extension.CredentialProtectionPolicyUserVerificationOptional {
		return nil
	}

	// CTAP 2.1 PS § 12.1.1 (enforceCredentialProtectionPolicy and the
	// authenticator's effective credProtect value):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension
	if outputs == nil || outputs.CredProtect == 0 {
		return &ErrorWithMessage{Err: ErrSpecViolation, Message: "device did not confirm enforced credProtect policy"}
	}

	if outputs.CredProtect < request.CredProtect {
		return &ErrorWithMessage{Err: ErrSpecViolation, Message: fmt.Sprintf(
			"device returned credProtect policy %d, weaker than enforced policy %d",
			outputs.CredProtect,
			request.CredProtect,
		)}
	}

	return nil
}

func validateGetAssertionExtensionOutputs(
	request *protocol.GetExtensionInputs,
	outputs *protocol.GetExtensionOutputs,
) error {
	// CTAP 2.0 PS § 9.1, CTAP 2.1 PS § 12.2, and CTAP 2.3 PS § 12.9
	// define the GetAssertion outputs for hmac-secret, credBlob, and
	// thirdPartyPayment after processing their corresponding inputs.
	// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#sctn-hmac-secret-extension
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credBlob-extension
	// https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-thirdPartyPayment-extension
	if outputs != nil && outputs.CredBlob != nil && !request.CredBlob {
		return unexpectedExtensionOutput("credBlob")
	}

	if outputs != nil && outputs.HMACSecret != nil && request.HMACSecret.KeyAgreement == nil {
		return unexpectedExtensionOutput("hmac-secret")
	}

	if outputs != nil && outputs.GetThirdPartyPaymentOutput != nil && !request.ThirdPartyPayment {
		return unexpectedExtensionOutput("thirdPartyPayment")
	}

	if request.CredBlob && (outputs == nil || outputs.CredBlob == nil) {
		return &ErrorWithMessage{Err: ErrSpecViolation, Message: "device did not return credBlob extension output"}
	}

	if request.ThirdPartyPayment && (outputs == nil || outputs.GetThirdPartyPaymentOutput == nil) {
		return &ErrorWithMessage{Err: ErrSpecViolation, Message: "device did not return thirdPartyPayment extension output"}
	}

	return nil
}

func marshalLargeBlobArray(blobs []protocol.LargeBlob) ([]byte, error) {
	// CTAP 2.1 PS §§ 6.10, 6.10.3 (large-blob array and map):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorLargeBlobs
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#large-blob
	// Each map contains an AEAD_AES_256_GCM ciphertext, including its 16-byte
	// authentication tag, and an exactly 12-byte nonce. The array is encoded
	// using the CTAP2 canonical CBOR encoding form.
	if blobs == nil {
		blobs = []protocol.LargeBlob{}
	}

	for i, blob := range blobs {
		if len(blob.Ciphertext) < 16 {
			return nil, &ErrorWithMessage{Err: SyntaxError, Message: fmt.Sprintf("large blob %d ciphertext must contain at least a 16-byte authentication tag", i)}
		}

		if len(blob.Nonce) != 12 {
			return nil, &ErrorWithMessage{Err: SyntaxError, Message: fmt.Sprintf("large blob %d nonce must be exactly 12 bytes", i)}
		}
	}

	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}

	return encMode.Marshal(blobs)
}
