package protocol

import (
	"bytes"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/webauthn"
)

type AuthenticatorGetAssertionRequest struct {
	RPID              string                                     `cbor:"1,keyasint" ctapdiag:"rpId"`
	ClientDataHash    []byte                                     `cbor:"2,keyasint"`
	AllowList         []credential.PublicKeyCredentialDescriptor `cbor:"3,keyasint,omitempty"`
	Extensions        GetExtensionInputs                         `cbor:"4,keyasint,omitzero"`
	Options           map[Option]bool                            `cbor:"5,keyasint,omitempty"`
	PinUvAuthParam    []byte                                     `cbor:"6,keyasint,omitzero" ctapdiag:"-,redact"`
	PinUvAuthProtocol PinUvAuthProtocol                          `cbor:"7,keyasint,omitempty"`
}

type AuthenticatorGetAssertionResponse struct {
	Credential               credential.PublicKeyCredentialDescriptor           `cbor:"1,keyasint,omitzero"`
	AuthDataRaw              []byte                                             `cbor:"2,keyasint" ctapdiag:"authData,redact"`
	AuthData                 *GetAssertionAuthData                              `cbor:"-"`
	Signature                []byte                                             `cbor:"3,keyasint"`
	User                     *credential.PublicKeyCredentialUserEntity          `cbor:"4,keyasint,omitempty"`
	NumberOfCredentials      uint                                               `cbor:"5,keyasint,omitzero"`
	UserSelected             bool                                               `cbor:"6,keyasint,omitzero"`
	LargeBlobKey             []byte                                             `cbor:"7,keyasint,omitempty" ctapdiag:"-,redact"`
	UnsignedExtensionOutputs map[extension.ExtensionIdentifier]any              `cbor:"8,keyasint,omitempty"`
	ExtensionOutputs         *webauthn.GetAuthenticationExtensionsClientOutputs `cbor:"-"`
}

func (r *AuthenticatorGetAssertionResponse) LargeBlobUnsignedExtensionOutput() (*GetLargeBlobOutput, error) {
	return decodeUnsignedExtensionOutput[GetLargeBlobOutput](
		r.UnsignedExtensionOutputs,
		extension.ExtensionIdentifierLargeBlob,
	)
}

type GetAssertionAuthData struct {
	RPIDHash               []byte
	Flags                  AuthDataFlag
	SignCount              uint32
	AttestedCredentialData *AttestedCredentialData
	Extensions             *GetExtensionOutputs
}

func ParseGetAssertionAuthData(data []byte) (GetAssertionAuthData, error) {
	d, err := parseAuthData(data)
	if err != nil {
		return GetAssertionAuthData{}, err
	}

	getAssertionAuthData := GetAssertionAuthData{
		RPIDHash:               d.RPIDHash,
		Flags:                  d.Flags,
		SignCount:              d.SignCount,
		AttestedCredentialData: d.AttestedCredentialData,
	}

	if d.Extensions != nil {
		var extensions GetExtensionOutputs
		if err := cbor.NewDecoder(bytes.NewReader(d.Extensions)).
			Decode(&extensions); err != nil {
			return GetAssertionAuthData{}, err
		}

		getAssertionAuthData.Extensions = &extensions
	}

	return getAssertionAuthData, nil
}
