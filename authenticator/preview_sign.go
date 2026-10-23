package authenticator

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/internal/fips140policy"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/ctap/webauthn"
)

func validateCreatePreviewSign(
	info protocol.AuthenticatorGetInfoResponse,
	pinUvAuthToken []byte,
	inputs *webauthn.PreviewSignInputs,
	options map[protocol.Option]bool,
) (*protocol.PreviewSignGenerateKeyInput, error) {
	if inputs == nil {
		return nil, nil
	}

	if inputs.PreviewSign.GenerateKey == nil {
		return nil, &ErrorWithMessage{Err: ErrNotSupported, Message: "previewSign generateKey is required for MakeCredential"}
	}

	if inputs.PreviewSign.SignByCredential != nil {
		return nil, &ErrorWithMessage{Err: ErrNotSupported, Message: "previewSign signByCredential is not supported by MakeCredential"}
	}

	if len(inputs.PreviewSign.GenerateKey.Algorithms) == 0 {
		return nil, &ErrorWithMessage{Err: SyntaxError, Message: "previewSign generateKey.algorithms must not be empty"}
	}

	algorithms, err := fips140policy.FilterPreviewSignAlgorithms(inputs.PreviewSign.GenerateKey.Algorithms)
	if err != nil {
		return nil, err
	}

	if !slices.Contains(info.Extensions, extension.ExtensionIdentifierPreviewSign) {
		return nil, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support previewSign extension"}
	}

	flags := protocol.AuthDataFlagUserPresent
	// WebAuthn previewSign derives this policy from the original
	// UserVerificationRequirement. Device receives resolved CTAP options and an
	// optional token instead, so the closest available signal is whether this
	// CTAP request will perform UV.
	if userVerificationWillBePerformed(info, pinUvAuthToken, options) {
		flags |= protocol.AuthDataFlagUserVerified
	}

	return &protocol.PreviewSignGenerateKeyInput{
		Algorithms: algorithms,
		Flags:      &flags,
	}, nil
}

func validateGetPreviewSign(
	info protocol.AuthenticatorGetInfoResponse,
	allowList []credential.PublicKeyCredentialDescriptor,
	inputs *webauthn.PreviewSignInputs,
) (*protocol.PreviewSignSignInput, error) {
	if inputs == nil {
		return nil, nil
	}

	if inputs.PreviewSign.GenerateKey != nil {
		return nil, &ErrorWithMessage{Err: ErrNotSupported, Message: "previewSign generateKey is not supported by GetAssertion"}
	}

	if inputs.PreviewSign.SignByCredential == nil {
		return nil, &ErrorWithMessage{Err: ErrNotSupported, Message: "previewSign signByCredential is required for GetAssertion"}
	}

	if !slices.Contains(info.Extensions, extension.ExtensionIdentifierPreviewSign) {
		return nil, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support previewSign extension"}
	}

	if len(allowList) == 0 {
		return nil, &ErrorWithMessage{Err: ErrNotSupported, Message: "previewSign requires a non-empty allowList"}
	}

	if len(inputs.PreviewSign.SignByCredential) != len(allowList) {
		return nil, &ErrorWithMessage{Err: ErrNotSupported, Message: "previewSign signByCredential must contain exactly one entry for each allowed credential"}
	}

	allowedCredentialIDs := make(map[string]struct{}, len(allowList))
	for _, descriptor := range allowList {
		allowedCredentialIDs[base64.RawURLEncoding.EncodeToString(descriptor.ID)] = struct{}{}
	}

	for encodedID := range inputs.PreviewSign.SignByCredential {
		credentialID, err := base64.RawURLEncoding.Strict().DecodeString(encodedID)
		if encodedID == "" || err != nil || base64.RawURLEncoding.EncodeToString(credentialID) != encodedID {
			return nil, &ErrorWithMessage{Err: SyntaxError, Message: "previewSign signByCredential contains an invalid base64url credential ID"}
		}

		if _, ok := allowedCredentialIDs[encodedID]; !ok {
			return nil, &ErrorWithMessage{Err: SyntaxError, Message: "previewSign signByCredential credential ID is not present in allowList"}
		}
	}

	var signInputs *webauthn.PreviewSignSignInputs

	for _, descriptor := range allowList {
		encodedID := base64.RawURLEncoding.EncodeToString(descriptor.ID)

		candidate := inputs.PreviewSign.SignByCredential[encodedID]
		if err := validatePreviewSignSignInputs(candidate); err != nil {
			return nil, err
		}

		if signInputs == nil {
			signInputs = &candidate
			continue
		}

		if !equalPreviewSignSignInputs(*signInputs, candidate) {
			return nil, &ErrorWithMessage{Err: ErrNotSupported, Message: "Device.GetAssertion cannot apply different credential-specific previewSign inputs in one CTAP request; issue one request per credential"}
		}
	}

	return &protocol.PreviewSignSignInput{
		KeyHandle:           signInputs.KeyHandle,
		ToBeSigned:          signInputs.ToBeSigned,
		AdditionalArguments: signInputs.AdditionalArguments,
	}, nil
}

func validatePreviewSignSignInputs(signInputs webauthn.PreviewSignSignInputs) error {
	if signInputs.KeyHandle == nil {
		return &ErrorWithMessage{Err: SyntaxError, Message: "previewSign signByCredential.keyHandle is required"}
	}

	if signInputs.ToBeSigned == nil {
		return &ErrorWithMessage{Err: SyntaxError, Message: "previewSign signByCredential.tbs is required"}
	}

	if signInputs.AdditionalArguments != nil && len(signInputs.AdditionalArguments) == 0 {
		return &ErrorWithMessage{Err: SyntaxError, Message: "previewSign signByCredential.additionalArgs must contain a CBOR map"}
	}

	if signInputs.AdditionalArguments != nil {
		if err := validateCOSESignArguments(signInputs.AdditionalArguments); err != nil {
			return err
		}
	}

	return nil
}

func equalPreviewSignSignInputs(a, b webauthn.PreviewSignSignInputs) bool {
	return bytes.Equal(a.KeyHandle, b.KeyHandle) &&
		bytes.Equal(a.ToBeSigned, b.ToBeSigned) &&
		bytes.Equal(a.AdditionalArguments, b.AdditionalArguments)
}

func validateCOSESignArguments(encoded []byte) error {
	decMode, err := cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF}.DecMode()
	if err != nil {
		return fmt.Errorf("create COSE signing arguments decoder: %w", err)
	}

	var arguments map[any]cbor.RawMessage
	if err := decMode.Unmarshal(encoded, &arguments); err != nil || arguments == nil {
		return &ErrorWithMessage{Err: SyntaxError, Message: "previewSign signByCredential.additionalArgs must contain a CBOR map"}
	}

	var algorithm cbor.RawMessage

	for label, value := range arguments {
		switch label := label.(type) {
		case uint64:
			if label == 3 {
				algorithm = value
			}
		case int64:
			if label == 3 {
				algorithm = value
			}
		case string:
		default:
			return &ErrorWithMessage{Err: SyntaxError, Message: "previewSign signByCredential.additionalArgs contains a non-COSE label"}
		}
	}

	if algorithm == nil {
		return &ErrorWithMessage{Err: SyntaxError, Message: "previewSign signByCredential.additionalArgs is missing alg"}
	}

	var algorithmValue any
	if err := cbor.Unmarshal(algorithm, &algorithmValue); err != nil {
		return &ErrorWithMessage{Err: SyntaxError, Message: "previewSign signByCredential.additionalArgs contains an invalid alg"}
	}

	switch algorithmValue.(type) {
	case uint64, int64, string:
		return nil
	default:
		return &ErrorWithMessage{Err: SyntaxError, Message: "previewSign signByCredential.additionalArgs alg must be an integer or text string"}
	}
}

func createPreviewSignOutput(
	request *protocol.PreviewSignGenerateKeyInput,
	response protocol.AuthenticatorMakeCredentialResponse,
) (*webauthn.PreviewSignOutputs, error) {
	unsignedOutput, err := response.PreviewSignUnsignedExtensionOutput()
	if err != nil {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: fmt.Sprintf("device returned malformed previewSign unsigned output: %v", err)}
	}

	var signedOutput *protocol.PreviewSignOutput
	if response.AuthData.Flags.ExtensionDataIncluded() {
		signedOutput = response.AuthData.Extensions.PreviewSign
	}

	if request == nil {
		if signedOutput != nil || unsignedOutput != nil {
			return nil, unexpectedExtensionOutput("previewSign")
		}

		return nil, nil
	}

	if signedOutput == nil {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device did not return previewSign MakeCredential output"}
	}

	if unsignedOutput == nil || unsignedOutput.AttestationObject == nil {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device did not return previewSign signing-key attestation"}
	}

	if signedOutput.Algorithm == nil || signedOutput.Flags != nil || signedOutput.Signature != nil {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned invalid previewSign MakeCredential output"}
	}

	if !slices.Contains(request.Algorithms, *signedOutput.Algorithm) {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned a previewSign algorithm that was not requested"}
	}

	var signingKeyAttestation protocol.AuthenticatorMakeCredentialResponse
	if err := cbor.Unmarshal(unsignedOutput.AttestationObject, &signingKeyAttestation); err != nil {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: fmt.Sprintf("device returned malformed previewSign signing-key attestation: %v", err)}
	}

	if signingKeyAttestation.Format == "" || signingKeyAttestation.AuthDataRaw == nil || signingKeyAttestation.AttestationStatement == nil {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned incomplete previewSign signing-key attestation"}
	}

	innerAuthData, err := protocol.ParseMakeCredentialAuthData(signingKeyAttestation.AuthDataRaw)
	if err != nil {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: fmt.Sprintf("device returned malformed previewSign signing-key authData: %v", err)}
	}

	if innerAuthData.AttestedCredentialData == nil || innerAuthData.Extensions == nil || innerAuthData.Extensions.PreviewSign == nil {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned incomplete previewSign signing-key authData"}
	}

	innerOutput := innerAuthData.Extensions.PreviewSign
	if innerOutput.Flags == nil || innerOutput.Algorithm != nil || innerOutput.Signature != nil ||
		*innerOutput.Flags != *request.Flags {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned invalid previewSign signing-key flags"}
	}

	if !bytes.Equal(innerAuthData.RPIDHash, response.AuthData.RPIDHash) {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned a mismatched previewSign signing-key RP ID hash"}
	}

	if innerAuthData.Flags != response.AuthData.Flags {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned mismatched previewSign signing-key authData flags"}
	}

	if innerAuthData.SignCount != 0 {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned a non-zero previewSign signing-key signature counter"}
	}

	if response.AuthData.AttestedCredentialData == nil ||
		innerAuthData.AttestedCredentialData.AAGUID != response.AuthData.AttestedCredentialData.AAGUID {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned a mismatched previewSign signing-key AAGUID"}
	}

	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}

	publicKey, err := encMode.Marshal(innerAuthData.AttestedCredentialData.CredentialPublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal previewSign public key: %w", err)
	}

	attestationObject, err := encMode.Marshal(attestation.Object{
		Format:    signingKeyAttestation.Format,
		AuthData:  signingKeyAttestation.AuthDataRaw,
		Statement: signingKeyAttestation.AttestationStatement,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal previewSign attestation object: %w", err)
	}

	return &webauthn.PreviewSignOutputs{
		PreviewSign: webauthn.AuthenticationExtensionsPreviewSignOutputs{
			GeneratedKey: &webauthn.PreviewSignGeneratedKey{
				KeyHandle:         innerAuthData.AttestedCredentialData.CredentialID,
				PublicKey:         publicKey,
				Algorithm:         *signedOutput.Algorithm,
				AttestationObject: attestationObject,
			},
		},
	}, nil
}

func getPreviewSignOutput(
	request *protocol.PreviewSignSignInput,
	response protocol.AuthenticatorGetAssertionResponse,
) (*webauthn.PreviewSignOutputs, error) {
	_, unsignedOutput := response.UnsignedExtensionOutputs[extension.ExtensionIdentifierPreviewSign]

	var signedOutput *protocol.PreviewSignOutput
	if response.AuthData.Flags.ExtensionDataIncluded() {
		signedOutput = response.AuthData.Extensions.PreviewSign
	}

	if request == nil {
		if signedOutput != nil || unsignedOutput {
			return nil, unexpectedExtensionOutput("previewSign")
		}

		return nil, nil
	}

	if unsignedOutput {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned previewSign unsigned output for GetAssertion"}
	}

	if signedOutput == nil {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device did not return previewSign GetAssertion output"}
	}

	if signedOutput.Algorithm != nil || signedOutput.Flags != nil || signedOutput.Signature == nil {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned invalid previewSign GetAssertion output"}
	}

	return &webauthn.PreviewSignOutputs{
		PreviewSign: webauthn.AuthenticationExtensionsPreviewSignOutputs{
			Signature: signedOutput.Signature,
		},
	}, nil
}
