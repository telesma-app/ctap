package protocol

import (
	"bytes"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/webauthn"
)

type AuthenticatorMakeCredentialRequest struct {
	ClientDataHash               []byte                                             `cbor:"1,keyasint"`
	RP                           credential.PublicKeyCredentialRpEntity             `cbor:"2,keyasint"`
	User                         credential.PublicKeyCredentialUserEntity           `cbor:"3,keyasint"`
	PubKeyCredParams             []credential.PublicKeyCredentialParameters         `cbor:"4,keyasint"`
	ExcludeList                  []credential.PublicKeyCredentialDescriptor         `cbor:"5,keyasint,omitempty"`
	Extensions                   CreateExtensionInputs                              `cbor:"6,keyasint,omitzero"`
	Options                      map[Option]bool                                    `cbor:"7,keyasint,omitempty"`
	PinUvAuthParam               []byte                                             `cbor:"8,keyasint,omitzero" ctapdiag:"-,redact"`
	PinUvAuthProtocol            PinUvAuthProtocol                                  `cbor:"9,keyasint,omitempty"`
	EnterpriseAttestation        uint                                               `cbor:"10,keyasint,omitempty"`
	AttestationFormatsPreference []attestation.AttestationStatementFormatIdentifier `cbor:"11,keyasint,omitempty"`
}

type AuthenticatorMakeCredentialResponse struct {
	Format                   attestation.AttestationStatementFormatIdentifier      `cbor:"1,keyasint" ctapdiag:"fmt"`
	AuthDataRaw              []byte                                                `cbor:"2,keyasint" ctapdiag:"authData,redact"`
	AuthData                 *MakeCredentialAuthData                               `cbor:"-"`
	AttestationStatement     map[string]any                                        `cbor:"3,keyasint,omitzero" ctapdiag:"attStmt"`
	EnterpriseAttestation    bool                                                  `cbor:"4,keyasint,omitzero" ctapdiag:"epAtt"`
	LargeBlobKey             []byte                                                `cbor:"5,keyasint,omitempty" ctapdiag:"-,redact"`
	UnsignedExtensionOutputs map[extension.ExtensionIdentifier]any                 `cbor:"6,keyasint,omitempty"`
	ExtensionOutputs         *webauthn.CreateAuthenticationExtensionsClientOutputs `cbor:"-"`
}

func (r *AuthenticatorMakeCredentialResponse) LargeBlobUnsignedExtensionOutput() (*CreateLargeBlobOutput, error) {
	return decodeUnsignedExtensionOutput[CreateLargeBlobOutput](
		r.UnsignedExtensionOutputs,
		extension.ExtensionIdentifierLargeBlob,
	)
}

func (r *AuthenticatorMakeCredentialResponse) PreviewSignUnsignedExtensionOutput() (*PreviewSignUnsignedOutput, error) {
	return decodeUnsignedExtensionOutput[PreviewSignUnsignedOutput](
		r.UnsignedExtensionOutputs,
		extension.ExtensionIdentifierPreviewSign,
	)
}

type MakeCredentialAuthData struct {
	RPIDHash               []byte
	Flags                  AuthDataFlag
	SignCount              uint32
	AttestedCredentialData *AttestedCredentialData
	Extensions             *CreateExtensionOutputs
}

func ParseMakeCredentialAuthData(data []byte) (MakeCredentialAuthData, error) {
	d, err := parseAuthData(data)
	if err != nil {
		return MakeCredentialAuthData{}, err
	}

	makeCredentialAuthData := MakeCredentialAuthData{
		RPIDHash:               d.RPIDHash,
		Flags:                  d.Flags,
		SignCount:              d.SignCount,
		AttestedCredentialData: d.AttestedCredentialData,
	}

	if d.Extensions != nil {
		var extensions CreateExtensionOutputs
		if err := cbor.NewDecoder(bytes.NewReader(d.Extensions)).
			Decode(&extensions); err != nil {
			return MakeCredentialAuthData{}, err
		}

		makeCredentialAuthData.Extensions = &extensions
	}

	return makeCredentialAuthData, nil
}
