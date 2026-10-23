package protocol

import (
	"fmt"
	"strings"
	"uuid"

	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
)

type (
	Version           string
	Versions          []Version
	PinUvAuthProtocol uint
	UserVerify        uint
)

const (
	FIDO_2_0     Version = "FIDO_2_0"
	FIDO_2_1_PRE Version = "FIDO_2_1_PRE"
	FIDO_2_1     Version = "FIDO_2_1"
	FIDO_2_3     Version = "FIDO_2_3"
	U2F_V2       Version = "U2F_V2"
)

const (
	PinUvAuthProtocolOne PinUvAuthProtocol = iota + 1
	PinUvAuthProtocolTwo
)

// FIDO Registry of Predefined Values 2.3 §3.1 User Verification Methods:
// https://fidoalliance.org/specs/common-specs/fido-registry-v2.3-ps-20260105.html#user-verification-methods
const (
	UserVerifyPresenceInternal    UserVerify = 0x00000001
	UserVerifyFingerprintInternal UserVerify = 0x00000002
	UserVerifyPasscodeInternal    UserVerify = 0x00000004
	UserVerifyVoiceprintInternal  UserVerify = 0x00000008
	UserVerifyFaceprintInternal   UserVerify = 0x00000010
	UserVerifyLocationInternal    UserVerify = 0x00000020
	UserVerifyEyeprintInternal    UserVerify = 0x00000040
	UserVerifyPatternInternal     UserVerify = 0x00000080
	UserVerifyHandprintInternal   UserVerify = 0x00000100
	UserVerifyNone                UserVerify = 0x00000200
	UserVerifyAll                 UserVerify = 0x00000400
	UserVerifyPasscodeExternal    UserVerify = 0x00000800
	UserVerifyPatternExternal     UserVerify = 0x00001000
)

type namedUserVerification struct {
	value UserVerify
	name  string
}

var namedUserVerifications = [...]namedUserVerification{
	{UserVerifyPresenceInternal, "presence_internal"},
	{UserVerifyFingerprintInternal, "fingerprint_internal"},
	{UserVerifyPasscodeInternal, "passcode_internal"},
	{UserVerifyVoiceprintInternal, "voiceprint_internal"},
	{UserVerifyFaceprintInternal, "faceprint_internal"},
	{UserVerifyLocationInternal, "location_internal"},
	{UserVerifyEyeprintInternal, "eyeprint_internal"},
	{UserVerifyPatternInternal, "pattern_internal"},
	{UserVerifyHandprintInternal, "handprint_internal"},
	{UserVerifyNone, "none"},
	{UserVerifyAll, "all"},
	{UserVerifyPasscodeExternal, "passcode_external"},
	{UserVerifyPatternExternal, "pattern_external"},
}

// String returns the symbolic FIDO Registry names of the user verification
// methods in uv. Multiple methods are returned in ascending bit order,
// separated by commas. Undefined method bits are preserved as a hexadecimal
// suffix.
func (uv UserVerify) String() string {
	if uv == 0 {
		return ""
	}

	parts := make([]string, 0, len(namedUserVerifications)+1)

	known := UserVerify(0)
	for _, named := range namedUserVerifications {
		known |= named.value
		if uv&named.value != 0 {
			parts = append(parts, named.name)
		}
	}

	if unknown := uv &^ known; unknown != 0 {
		parts = append(parts, fmt.Sprintf("unknown(0x%x)", uint(unknown)))
	}

	return strings.Join(parts, ",")
}

const (
	DefaultMaxMsgSize       uint = 1024
	DefaultMinPINCodePoints uint = 4
	DefaultMaxPINCodePoints uint = 63
)

// AuthenticatorGetInfoResponse is used in Metadata Statement specification as well, so json notation added.
type AuthenticatorGetInfoResponse struct {
	Versions                         Versions                                           `cbor:"1,keyasint" json:"versions"`
	Extensions                       []extension.ExtensionIdentifier                    `cbor:"2,keyasint,omitempty" json:"extensions,omitempty"`
	AAGUID                           uuid.UUID                                          `cbor:"3,keyasint" json:"aaguid"`
	Options                          map[Option]bool                                    `cbor:"4,keyasint,omitempty" json:"options,omitempty"`
	MaxMsgSize                       uint                                               `cbor:"5,keyasint,omitzero" json:"maxMsgSize,omitempty"`
	PinUvAuthProtocols               []PinUvAuthProtocol                                `cbor:"6,keyasint,omitempty" json:"pinUvAuthProtocols,omitempty"`
	MaxCredentialCountInList         uint                                               `cbor:"7,keyasint,omitzero" json:"maxCredentialCountInList,omitempty"`
	MaxCredentialIdLength            uint                                               `cbor:"8,keyasint,omitzero" json:"maxCredentialIdLength,omitempty"`
	Transports                       []credential.AuthenticatorTransport                `cbor:"9,keyasint,omitempty" json:"transports,omitempty"`
	Algorithms                       []credential.PublicKeyCredentialParameters         `cbor:"10,keyasint,omitempty" json:"algorithms,omitempty"`
	MaxSerializedLargeBlobArray      uint                                               `cbor:"11,keyasint,omitzero" json:"maxSerializedLargeBlobArray,omitempty"`
	ForcePINChange                   bool                                               `cbor:"12,keyasint,omitzero" json:"forcePINChange,omitempty"`
	MinPINLength                     uint                                               `cbor:"13,keyasint,omitzero" json:"minPINLength,omitempty"`
	FirmwareVersion                  *uint                                              `cbor:"14,keyasint,omitzero" json:"firmwareVersion,omitempty"`
	MaxCredBlobLength                uint                                               `cbor:"15,keyasint,omitzero" json:"maxCredBlobLength,omitempty"`
	MaxRPIDsForSetMinPINLength       *uint                                              `cbor:"16,keyasint,omitzero" json:"maxRPIDsForSetMinPINLength,omitempty"`
	PreferredPlatformUvAttempts      uint                                               `cbor:"17,keyasint,omitzero" json:"preferredPlatformUvAttempts,omitempty"`
	UvModality                       *UserVerify                                        `cbor:"18,keyasint,omitzero" json:"uvModality,omitempty"`
	Certifications                   map[string]uint64                                  `cbor:"19,keyasint,omitempty" json:"certifications,omitempty"`
	RemainingDiscoverableCredentials *uint                                              `cbor:"20,keyasint,omitzero" json:"remainingDiscoverableCredentials,omitempty"`
	VendorPrototypeConfigCommands    []VendorCommandID                                  `cbor:"21,keyasint,omitzero" json:"vendorPrototypeConfigCommands,omitempty"`
	AttestationFormats               []attestation.AttestationStatementFormatIdentifier `cbor:"22,keyasint,omitempty" json:"attestationFormats,omitempty"`
	UvCountSinceLastPinEntry         *uint                                              `cbor:"23,keyasint,omitzero" json:"uvCountSinceLastPinEntry,omitempty"`
	LongTouchForReset                *bool                                              `cbor:"24,keyasint,omitzero" json:"longTouchForReset,omitempty"`
	EncIdentifier                    []byte                                             `cbor:"25,keyasint,omitempty" json:"encIdentifier,omitempty"`
	TransportsForReset               []credential.AuthenticatorTransport                `cbor:"26,keyasint,omitempty" json:"transportsForReset,omitempty"`
	PinComplexityPolicy              *bool                                              `cbor:"27,keyasint,omitzero" json:"pinComplexityPolicy,omitempty"`
	PinComplexityPolicyURL           []byte                                             `cbor:"28,keyasint,omitempty" json:"pinComplexityPolicyURL,omitempty"`
	MaxPINLength                     uint                                               `cbor:"29,keyasint,omitzero" json:"maxPINLength,omitempty"`
	EncCredStoreState                []byte                                             `cbor:"30,keyasint,omitempty" json:"encCredStoreState,omitempty"`
	AuthenticatorConfigCommands      []ConfigSubCommand                                 `cbor:"31,keyasint,omitzero" json:"authenticatorConfigCommands,omitempty"`
}

func (r *AuthenticatorGetInfoResponse) EffectiveMaxMsgSize() uint {
	if r.MaxMsgSize != 0 {
		return r.MaxMsgSize
	}

	return DefaultMaxMsgSize
}

func (r *AuthenticatorGetInfoResponse) EffectiveMinPINLength() uint {
	if r.MinPINLength > DefaultMinPINCodePoints {
		return r.MinPINLength
	}

	return DefaultMinPINCodePoints
}

// EffectiveMaxPINLength returns the authenticator's maximum PIN length in
// Unicode code points. CTAP defines 63 code points as the effective value when
// maxPINLength is absent.
func (r *AuthenticatorGetInfoResponse) EffectiveMaxPINLength() uint {
	if r.MaxPINLength != 0 {
		return r.MaxPINLength
	}

	return DefaultMaxPINCodePoints
}

// PinComplexityPolicyURLString returns pinComplexityPolicyURL as a string.
// The field is a CBOR byte string on the wire.
func (r *AuthenticatorGetInfoResponse) PinComplexityPolicyURLString() string {
	return string(r.PinComplexityPolicyURL)
}

func (r *AuthenticatorGetInfoResponse) MaxCredBlobLengthValue() (uint, bool) {
	if r.MaxCredBlobLength == 0 {
		return 0, false
	}

	return r.MaxCredBlobLength, true
}

func (r *AuthenticatorGetInfoResponse) MaxSerializedLargeBlobArrayValue() (uint, bool) {
	if r.MaxSerializedLargeBlobArray == 0 {
		return 0, false
	}

	return r.MaxSerializedLargeBlobArray, true
}
