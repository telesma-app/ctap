package authenticator

import (
	"context"
	"slices"

	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/ctap/webauthn"
)

type largeBlobBackend uint8

const (
	largeBlobBackendNone largeBlobBackend = iota
	largeBlobBackendDirect
	largeBlobBackendLegacy
)

func largeBlobBackendForInfo(info protocol.AuthenticatorGetInfoResponse) (largeBlobBackend, error) {
	direct := slices.Contains(info.Extensions, extension.ExtensionIdentifierLargeBlob)
	legacyKey := slices.Contains(info.Extensions, extension.ExtensionIdentifierLargeBlobKey)
	legacyArray := info.Options[protocol.OptionLargeBlobs]

	if direct && (legacyKey || legacyArray) {
		return largeBlobBackendNone, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device reports mutually exclusive largeBlob and largeBlobKey/largeBlobs capabilities"}
	}

	if direct {
		return largeBlobBackendDirect, nil
	}

	if legacyKey && legacyArray {
		return largeBlobBackendLegacy, nil
	}

	return largeBlobBackendNone, nil
}

func (d *Device) resolveLegacyLargeBlobOutputs(
	ctx context.Context,
	pinUvAuthToken []byte,
	read bool,
	write []byte,
	assertions []protocol.AuthenticatorGetAssertionResponse,
) ([]*webauthn.LargeBlobOutputs, error) {
	// CTAP 2.3 PS §§ 6.10.4-6.10.6 (reading and updating per-credential
	// large-blob data through largeBlobKey and authenticatorLargeBlobs):
	// https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorLargeBlobs
	outputs := make([]*webauthn.LargeBlobOutputs, len(assertions))
	for i := range outputs {
		outputs[i] = &webauthn.LargeBlobOutputs{}
	}

	if read {
		blobs, err := d.getLargeBlobsLocked(ctx)
		if err != nil {
			// A failed client-side read is represented by an output without blob.
			return outputs, nil
		}

		for i := range assertions {
			key := assertions[i].LargeBlobKey
			if len(key) == 0 {
				continue
			}

			for _, encrypted := range blobs {
				compressed, err := crypto.OpenLargeBlob(key, encrypted)
				if err != nil {
					continue
				}

				blob, err := crypto.DecompressLargeBlobData(compressed, encrypted.OrigSize)
				if err != nil {
					return nil, err
				}

				outputs[i].LargeBlob.Blob = blob

				break
			}
		}

		return outputs, nil
	}

	written := false
	outputs[0].LargeBlob.Written = &written

	key := assertions[0].LargeBlobKey
	if len(key) == 0 {
		return outputs, nil
	}

	blobs, err := d.getLargeBlobsLocked(ctx)
	if err != nil {
		return outputs, nil
	}

	replacement, err := crypto.EncryptLargeBlob(key, write)
	if err != nil {
		return nil, err
	}

	replaced := false

	for i, encrypted := range blobs {
		if _, err := crypto.OpenLargeBlob(key, encrypted); err == nil {
			blobs[i] = replacement
			replaced = true

			break
		}
	}

	if !replaced {
		blobs = append(blobs, replacement)
	}

	if err := d.setLargeBlobsLocked(ctx, pinUvAuthToken, blobs); err != nil {
		return outputs, nil
	}

	written = true

	return outputs, nil
}

func validateCreateLargeBlob(
	info protocol.AuthenticatorGetInfoResponse,
	inputs *webauthn.LargeBlobInputs,
	requestOptions map[protocol.Option]bool,
) (largeBlobBackend, extension.LargeBlobSupport, bool, error) {
	// CTAP 2.3 PS §§ 12.3-12.4 (largeBlobKey and largeBlob inputs for
	// authenticatorMakeCredential):
	// https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-largeBlobKey-extension
	// https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-largeBlob-extension
	if inputs == nil {
		return largeBlobBackendNone, "", false, nil
	}

	if inputs.LargeBlob.Read != nil || inputs.LargeBlob.Write != nil {
		return largeBlobBackendNone, "", false, &ErrorWithMessage{Err: SyntaxError, Message: "largeBlob read and write are only valid for GetAssertion"}
	}

	support := inputs.LargeBlob.Support
	if support == "" {
		support = extension.LargeBlobSupportPreferred
	}

	if support != extension.LargeBlobSupportPreferred && support != extension.LargeBlobSupportRequired {
		return largeBlobBackendNone, "", false, &ErrorWithMessage{Err: SyntaxError, Message: "largeBlob support must be preferred or required"}
	}

	backend, err := largeBlobBackendForInfo(info)
	if err != nil {
		return largeBlobBackendNone, "", false, err
	}

	legacyKeyRequested := false

	switch backend {
	case largeBlobBackendLegacy:
		if requestOptions[protocol.OptionResidentKeys] {
			legacyKeyRequested = true
		} else if support == extension.LargeBlobSupportRequired {
			return largeBlobBackendNone, "", false, &ErrorWithMessage{Err: ErrNotSupported, Message: "legacy large blobs require a discoverable credential"}
		}
	case largeBlobBackendNone:
		if support == extension.LargeBlobSupportRequired {
			return largeBlobBackendNone, "", false, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support large blobs"}
		}
	}

	return backend, support, legacyKeyRequested, nil
}

func createLargeBlobOutput(
	backend largeBlobBackend,
	support extension.LargeBlobSupport,
	legacyKeyRequested bool,
	response protocol.AuthenticatorMakeCredentialResponse,
) (*webauthn.LargeBlobOutputs, error) {
	directOutput, err := response.LargeBlobUnsignedExtensionOutput()
	if err != nil {
		return nil, err
	}

	if support == "" {
		if directOutput != nil {
			return nil, unexpectedExtensionOutput("largeBlob")
		}

		if len(response.LargeBlobKey) != 0 {
			return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned an unsolicited largeBlobKey"}
		}

		return nil, nil
	}

	if backend != largeBlobBackendDirect && directOutput != nil {
		return nil, unexpectedExtensionOutput("largeBlob")
	}

	if !legacyKeyRequested && len(response.LargeBlobKey) != 0 {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned an unsolicited largeBlobKey"}
	}

	supported := false

	switch backend {
	case largeBlobBackendDirect:
		if directOutput != nil {
			if !directOutput.Supported {
				return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned an invalid largeBlob MakeCredential output"}
			}

			supported = true
		}
	case largeBlobBackendLegacy:
		if !legacyKeyRequested {
			break
		}

		switch len(response.LargeBlobKey) {
		case 0:
			return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device omitted the requested largeBlobKey"}
		case 32:
			supported = true
		default:
			return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned a largeBlobKey with an invalid length"}
		}
	}

	if support == extension.LargeBlobSupportRequired && !supported {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device created a credential without required large-blob support"}
	}

	return &webauthn.LargeBlobOutputs{
		LargeBlob: webauthn.AuthenticationExtensionsLargeBlobOutputs{Supported: &supported},
	}, nil
}

func validateGetLargeBlob(
	info protocol.AuthenticatorGetInfoResponse,
	inputs *webauthn.LargeBlobInputs,
	allowList []credential.PublicKeyCredentialDescriptor,
) (largeBlobBackend, bool, []byte, error) {
	// CTAP 2.3 PS §§ 12.3-12.4 (largeBlobKey and largeBlob inputs for
	// authenticatorGetAssertion):
	// https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-largeBlobKey-extension
	// https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-largeBlob-extension
	if inputs == nil {
		return largeBlobBackendNone, false, nil, nil
	}

	if inputs.LargeBlob.Support != "" {
		return largeBlobBackendNone, false, nil, &ErrorWithMessage{Err: SyntaxError, Message: "largeBlob support is only valid for MakeCredential"}
	}

	if inputs.LargeBlob.Read != nil && inputs.LargeBlob.Write != nil {
		return largeBlobBackendNone, false, nil, &ErrorWithMessage{Err: SyntaxError, Message: "largeBlob read and write cannot be requested together"}
	}

	if inputs.LargeBlob.Read == nil && inputs.LargeBlob.Write == nil {
		return largeBlobBackendNone, false, nil, nil
	}

	if inputs.LargeBlob.Read != nil && !*inputs.LargeBlob.Read {
		return largeBlobBackendNone, false, nil, nil
	}

	if inputs.LargeBlob.Write != nil && len(allowList) != 1 {
		return largeBlobBackendNone, false, nil, &ErrorWithMessage{Err: SyntaxError, Message: "largeBlob write requires exactly one allowed credential"}
	}

	backend, err := largeBlobBackendForInfo(info)
	if err != nil {
		return largeBlobBackendNone, false, nil, err
	}

	if backend == largeBlobBackendNone {
		return largeBlobBackendNone, false, nil, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support large blobs"}
	}

	return backend, inputs.LargeBlob.Read != nil, inputs.LargeBlob.Write, nil
}

func getLargeBlobOutput(
	backend largeBlobBackend,
	read bool,
	write []byte,
	response protocol.AuthenticatorGetAssertionResponse,
) (*webauthn.LargeBlobOutputs, error) {
	authenticatorOutput, err := response.LargeBlobUnsignedExtensionOutput()
	if err != nil {
		return nil, err
	}

	requested := read || write != nil
	if authenticatorOutput != nil && (!requested || backend != largeBlobBackendDirect) {
		return nil, unexpectedExtensionOutput("largeBlob")
	}

	if len(response.LargeBlobKey) != 0 && (!requested || backend != largeBlobBackendLegacy) {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned an unsolicited largeBlobKey"}
	}

	if backend == largeBlobBackendLegacy && len(response.LargeBlobKey) != 0 && len(response.LargeBlobKey) != 32 {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned a largeBlobKey with an invalid length"}
	}

	if !requested || backend != largeBlobBackendDirect {
		return nil, nil
	}

	output := &webauthn.LargeBlobOutputs{}
	clientOutput := &output.LargeBlob

	if read {
		if authenticatorOutput == nil {
			return output, nil
		}

		if authenticatorOutput.Written != nil {
			return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned written for a largeBlob read"}
		}

		if authenticatorOutput.Blob == nil {
			if authenticatorOutput.OriginalSize != nil {
				return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned largeBlob originalSize without blob"}
			}

			return output, nil
		}

		if authenticatorOutput.OriginalSize == nil {
			return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned a largeBlob without originalSize"}
		}

		blob, err := crypto.DecompressLargeBlobData(
			authenticatorOutput.Blob,
			*authenticatorOutput.OriginalSize,
		)
		if err != nil {
			return nil, err
		}

		clientOutput.Blob = blob

		return output, nil
	}

	if authenticatorOutput == nil || authenticatorOutput.Written == nil {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device omitted written from a largeBlob write output"}
	}

	if authenticatorOutput.Blob != nil || authenticatorOutput.OriginalSize != nil {
		return nil, &ErrorWithMessage{Err: ErrSpecViolation, Message: "device returned blob data for a largeBlob write"}
	}

	clientOutput.Written = authenticatorOutput.Written

	return output, nil
}
