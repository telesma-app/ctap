package authenticator

import (
	"fmt"
	"slices"

	"github.com/telesma-app/ctap/internal/pin"
	"github.com/telesma-app/ctap/protocol"
)

func validateUserVerificationRequest(
	info protocol.AuthenticatorGetInfoResponse,
	pinUvAuthToken []byte,
	options map[protocol.Option]bool,
) error {
	// CTAP 2.1 PS §§ 6.1, 6.2 (pinUvAuthParam and the uv option):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorMakeCredential
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetAssertion
	if pinUvAuthToken != nil && len(pinUvAuthToken) == 0 {
		return &ErrorWithMessage{Err: SyntaxError, Message: "pinUvAuthToken must not be empty"}
	}

	hasToken := pinUvAuthToken != nil

	builtInUVRequested := options[protocol.OptionUserVerification]
	if hasToken && builtInUVRequested {
		return &ErrorWithMessage{Err: SyntaxError, Message: "pinUvAuthToken and built-in user verification are mutually exclusive"}
	}

	// CTAP 2.1 PS § 6.4 (uv option ID states):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#getinfo-uv
	if builtInUVRequested {
		builtInUVConfigured, ok := info.Options[protocol.OptionUserVerification]
		if !ok {
			return &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support built-in user verification"}
		}

		if !builtInUVConfigured {
			return &ErrorWithMessage{Err: ErrUvNotConfigured, Message: "please configure UV first (e.g. enroll biometry)"}
		}
	}

	return nil
}

func isFIDO20Only(versions protocol.Versions) bool {
	// CTAP 2.0 PS § 5.4 (versions member):
	// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo
	fido20Only := versions.Supports(protocol.FIDO_2_0)
	for _, version := range versions {
		if version != protocol.FIDO_2_0 && version != protocol.U2F_V2 {
			return false
		}
	}

	return fido20Only
}

func hasConfiguredUserVerification(info protocol.AuthenticatorGetInfoResponse) bool {
	// CTAP 2.1 PS §§ 6.4, 9 (clientPin/uv states and the mandatory
	// pinUvAuthToken relationship for conforming CTAP 2.1 authenticators):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#getinfo-options
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#mandatory-features
	return info.Options[protocol.OptionClientPIN] || info.Options[protocol.OptionUserVerification]
}

func alwaysUVEnabled(info protocol.AuthenticatorGetInfoResponse) bool {
	// CTAP 2.1 PS § 7.2.1 (alwaysUv feature detection):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-feature-descriptions-alwaysUv-feature-detection
	return !isFIDO20Only(info.Versions) && info.Options[protocol.OptionAlwaysUv]
}

func (d *Device) pinUvAuthProtocolForRequest(
	pinUvAuthToken []byte,
	required bool,
) (protocol.PinUvAuthProtocol, error) {
	if pinUvAuthToken == nil {
		if required {
			return 0, ErrPinUvAuthTokenRequired
		}

		return 0, nil
	}

	pinUvAuthProtocol, err := d.requirePinUvAuthProtocol()
	if err != nil {
		return 0, err
	}

	// CTAP 2.0 PS § 5.5.7 allowed a pinToken whose length was any
	// positive multiple of 16 bytes:
	// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#clientPin-getPinToken
	// CTAP 2.1 PS §§ 6.5.6, 6.5.7 narrowed token lengths to 16 or 32
	// bytes for protocol 1 and exactly 32 bytes for protocol 2:
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pin-uv-auth-protocol-one
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pin-uv-auth-protocol-two
	if !isFIDO20Only(d.info.Versions) && !d.info.Versions.IsPreviewOnly() &&
		pinUvAuthProtocol == protocol.PinUvAuthProtocolOne &&
		len(pinUvAuthToken) != 16 && len(pinUvAuthToken) != 32 {
		return 0, &ErrorWithMessage{Err: SyntaxError, Message: "pinUvAuthToken must be 16 or 32 bytes for PIN/UV auth protocol 1 on CTAP 2.1 or later"}
	}

	if err := pin.ValidateUvAuthToken(pinUvAuthProtocol, pinUvAuthToken); err != nil {
		return 0, &ErrorWithMessage{Err: SyntaxError, Message: err.Error()}
	}

	return pinUvAuthProtocol, nil
}

func validateMakeCredentialAuthorization(
	info protocol.AuthenticatorGetInfoResponse,
	pinUvAuthToken []byte,
	options map[protocol.Option]bool,
) error {
	if err := validateUserVerificationRequest(info, pinUvAuthToken, options); err != nil {
		return err
	}

	hasToken := pinUvAuthToken != nil
	builtInUVRequested := options[protocol.OptionUserVerification]
	userVerificationConfigured := hasConfiguredUserVerification(info)
	fido20Only := isFIDO20Only(info.Versions)

	// CTAP 2.0 PS § 5.1 and CTAP 2.1 PS § 6.1.2:
	// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-makeCred-authnr-alg
	// CTAP 2.0 authenticators protected by any form of UV always require it
	// for MakeCredential. makeCredUvNotRqd and alwaysUv were added in CTAP 2.1.
	requiresUV := userVerificationConfigured
	if !fido20Only {
		requiresUV = alwaysUVEnabled(info) || userVerificationConfigured && (!info.Options[protocol.OptionMakeCredentialUvNotRequired] ||
			options[protocol.OptionResidentKeys])
	}

	if !requiresUV {
		return nil
	}

	// CTAP 2.1 PS § 6.1.2 (alwaysUv compatibility processing):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#op-makecred-step-options
	// With alwaysUv enabled, an authenticator with configured built-in UV
	// implicitly treats the request as if the uv option were true.
	if hasToken || builtInUVRequested ||
		alwaysUVEnabled(info) && info.Options[protocol.OptionUserVerification] {
		return nil
	}

	return ErrPinUvAuthTokenRequired
}

func validateGetAssertionAuthorization(
	info protocol.AuthenticatorGetInfoResponse,
	pinUvAuthToken []byte,
	options map[protocol.Option]bool,
) error {
	if err := validateUserVerificationRequest(info, pinUvAuthToken, options); err != nil {
		return err
	}

	// CTAP 2.1 PS § 6.2 (GetAssertion options; rk is not defined):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetAssertion
	if _, ok := options[protocol.OptionResidentKeys]; ok {
		return &ErrorWithMessage{Err: ErrNotSupported, Message: "rk option is not supported by GetAssertion"}
	}

	userPresence, ok := options[protocol.OptionUserPresence]
	userPresenceRequested := !ok || userPresence
	// CTAP 2.1 PS §§ 6.2.2, 7.2.3 (GetAssertion with alwaysUv):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-getAssert-authnr-alg
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-feature-descriptions-alwaysUv-authnr-actions
	if isFIDO20Only(info.Versions) || !alwaysUVEnabled(info) || !userPresenceRequested {
		return nil
	}

	if pinUvAuthToken != nil || options[protocol.OptionUserVerification] ||
		info.Options[protocol.OptionUserVerification] {
		return nil
	}

	if info.Options[protocol.OptionClientPIN] &&
		!info.Options[protocol.OptionNoMcGaPermissionsWithClientPin] {
		return ErrPinUvAuthTokenRequired
	}

	if builtInUVConfigured, ok := info.Options[protocol.OptionUserVerification]; ok && !builtInUVConfigured {
		return &ErrorWithMessage{Err: ErrUvNotConfigured, Message: "please configure UV first (e.g. enroll biometry)"}
	}

	return &ErrorWithMessage{Err: ErrBuiltInUVRequired, Message: "alwaysUv requires user verification for GetAssertion"}
}

func validatePinUvAuthTokenPermissionSet(permission protocol.Permission) error {
	// CTAP 2.3 PS § 6.5.5 (permissions request member):
	// https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authnrClientPin-cmd-dfn
	if permission == protocol.PermissionNone {
		return &ErrorWithMessage{Err: SyntaxError, Message: "pinUvAuthToken permission must not be zero"}
	}

	// CTAP 2.3 PS § 6.5.5.7 (pcmr is assigned as a standalone persistent-token permission):
	// https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#gettingPinUvAuthToken
	if permission&protocol.PermissionPersistentCredentialManagementReadOnly != 0 &&
		permission != protocol.PermissionPersistentCredentialManagementReadOnly {
		return &ErrorWithMessage{Err: SyntaxError, Message: "pcmr permission cannot be combined with other permissions"}
	}

	return nil
}

func validatePinUvAuthTokenPermissionRPID(permission protocol.Permission, rpID string) error {
	// CTAP 2.1 PS § 6.5.5.7 (permissions RP ID requirements):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#gettingPinUvAuthToken
	if permission&(protocol.PermissionMakeCredential|protocol.PermissionGetAssertion) != 0 && rpID == "" {
		return &ErrorWithMessage{Err: SyntaxError, Message: "rpID is required for MakeCredential and GetAssertion permissions"}
	}

	return nil
}

func permissionedPinUvAuthTokensSupported(info protocol.AuthenticatorGetInfoResponse) bool {
	// CTAP 2.1 PS § 6.4 (pinUvAuthToken option ID):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#getinfo-pinuvauthtoken
	return !isFIDO20Only(info.Versions) && info.Options[protocol.OptionPinUvAuthToken]
}

type pinTokenFlow uint8

const (
	pinTokenFlowLegacy pinTokenFlow = iota + 1
	pinTokenFlowWithPermissions
)

func selectPinTokenFlowUsingPIN(
	info protocol.AuthenticatorGetInfoResponse,
	permission protocol.Permission,
	rpID string,
) (pinTokenFlow, error) {
	// CTAP 2.0 PS § 5.5.7 (legacy getPinToken) has no permissions parameter
	// and grants the default mc|ga permissions. CTAP 2.1 PS § 6.5.5.7.2
	// (getPinUvAuthTokenUsingPinWithPermissions) requires a nonzero permissions
	// value.
	// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#clientPin-getPinToken
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#getPinUvAuthTokenUsingPinWithPermissions
	if !isFIDO20Only(info.Versions) || permission != protocol.PermissionNone {
		if err := validatePinUvAuthTokenPermissionSet(permission); err != nil {
			return 0, err
		}
	}

	// CTAP 2.1 PS § 6.5.5.7.2 (getPinUvAuthTokenUsingPinWithPermissions):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#getPinUvAuthTokenUsingPinWithPermissions
	clientPIN, ok := info.Options[protocol.OptionClientPIN]
	if !ok {
		return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support clientPin"}
	}

	if !clientPIN {
		return 0, &ErrorWithMessage{Err: ErrPinNotSet, Message: "please set PIN first"}
	}

	// CTAP 2.1 PS § 6.4 (noMcGaPermissionsWithClientPin):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#getinfo-nomcgapermissionswithclientpin
	if info.Options[protocol.OptionNoMcGaPermissionsWithClientPin] &&
		permission&(protocol.PermissionMakeCredential|protocol.PermissionGetAssertion) != 0 {
		return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't allow PIN-obtained tokens with MakeCredential or GetAssertion permissions"}
	}

	// CTAP 2.1 PS §§ 6.5.5.7.2, 6.12, 6.13 (permission feature detection and preview compatibility):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#getPinUvAuthTokenUsingPinWithPermissions
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#prototypeAuthenticatorBioEnrollment
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#prototypeAuthenticatorCredentialManagement
	previewPermissions := protocol.PermissionNone

	if permission&protocol.PermissionCredentialManagement != 0 {
		if info.Versions.IsPreviewOnly() {
			if _, err := credentialManagementMode(info); err != nil {
				return 0, err
			}

			previewPermissions |= protocol.PermissionCredentialManagement
		} else if !info.Options[protocol.OptionCredentialManagement] {
			return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support CredentialManagement permission"}
		}
	}

	if permission&protocol.PermissionBioEnrollment != 0 {
		if info.Versions.IsPreviewOnly() {
			if _, err := bioEnrollmentMode(info); err != nil {
				return 0, err
			}

			previewPermissions |= protocol.PermissionBioEnrollment
		} else if _, ok := info.Options[protocol.OptionBioEnroll]; !ok {
			return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support BioEnrollment permission"}
		}
	}

	// CTAP 2.3 PS § 6.5.5.7.2 (lbw, acfg, and pcmr permission prerequisites):
	// https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#getPinUvAuthTokenUsingPinWithPermissions
	if permission&protocol.PermissionLargeBlobWrite != 0 && !info.Options[protocol.OptionLargeBlobs] {
		return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support LargeBlobWrite permission"}
	}

	if permission&protocol.PermissionAuthenticatorConfiguration != 0 &&
		!info.Options[protocol.OptionAuthenticatorConfig] {
		return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support AuthenticatorConfiguration permission"}
	}

	if permission&protocol.PermissionPersistentCredentialManagementReadOnly != 0 &&
		!info.Options[protocol.OptionPersistentCredentialManagementReadOnly] {
		return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support PersistentCredentialManagementReadOnly permission"}
	}

	permissionedTokens := permissionedPinUvAuthTokensSupported(info)
	// CTAP 2.1 PS §§ 1.1, 6.5.5.7.1 (superseded getPinToken compatibility):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#relationship-to-other-specifications
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#getPinToken
	if !permissionedTokens || previewPermissions != protocol.PermissionNone {
		legacyPermissions := protocol.PermissionMakeCredential |
			protocol.PermissionGetAssertion |
			previewPermissions
		if permission&^legacyPermissions != 0 {
			return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "legacy getPinToken cannot grant the requested permissions"}
		}

		// Legacy getPinToken grants mc|ga without binding the token to an RP ID.
		// The authenticator associates one on first use, so rpID is not required here.
		return pinTokenFlowLegacy, nil
	}

	// CTAP 2.1 PS § 6.5.5.7.2 (rpId is required for mc and ga):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#getPinUvAuthTokenUsingPinWithPermissions
	if err := validatePinUvAuthTokenPermissionRPID(permission, rpID); err != nil {
		return 0, err
	}

	return pinTokenFlowWithPermissions, nil
}

type uvTokenFlow uint8

const (
	uvTokenFlowPreview uvTokenFlow = iota + 1
	uvTokenFlowWithPermissions
)

func selectPinUvAuthTokenFlowUsingUV(
	info protocol.AuthenticatorGetInfoResponse,
	permission protocol.Permission,
	rpID string,
) (uvTokenFlow, error) {
	if err := validatePinUvAuthTokenPermissionSet(permission); err != nil {
		return 0, err
	}

	uv, ok := info.Options[protocol.OptionUserVerification]
	if !ok {
		return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support user verification"}
	}

	if !uv {
		return 0, &ErrorWithMessage{Err: ErrUvNotConfigured, Message: "please configure UV first (e.g. enroll biometry)"}
	}

	// FIDO_2_1_PRE RD 2019 § 5.5.8 (getUvToken) defines a legacy UV-token
	// flow gated by the uvToken option. It uses pinUvAuthProtocol 1 and carries
	// neither permissions nor rpId. Preview biometric and credential-management
	// commands are authorized with that legacy token.
	// https://fidoalliance.org/specs/fido-v2.1-rd-20191217/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html#getUvToken
	if info.Versions.IsPreviewOnly() && info.Options[protocol.OptionUvToken] {
		if len(info.PinUvAuthProtocols) != 0 &&
			!slices.Contains(info.PinUvAuthProtocols, protocol.PinUvAuthProtocolOne) {
			return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "device advertises uvToken without pinUvAuthProtocol 1"}
		}

		legacyPermissions := protocol.PermissionMakeCredential | protocol.PermissionGetAssertion

		if permission&protocol.PermissionCredentialManagement != 0 {
			if _, err := credentialManagementMode(info); err != nil {
				return 0, err
			}

			legacyPermissions |= protocol.PermissionCredentialManagement
		}

		if permission&protocol.PermissionBioEnrollment != 0 {
			if _, err := bioEnrollmentMode(info); err != nil {
				return 0, err
			}

			legacyPermissions |= protocol.PermissionBioEnrollment
		}

		if permission&^legacyPermissions != 0 {
			return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "preview getUvToken cannot grant the requested permissions"}
		}

		return uvTokenFlowPreview, nil
	}

	// CTAP 2.1 PS § 6.5.5.7.3 (getPinUvAuthTokenUsingUvWithPermissions):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#getPinUvAuthTokenUsingUvWithPermissions
	if !permissionedPinUvAuthTokensSupported(info) {
		return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support pinUvAuthToken"}
	}

	// CTAP 2.3 PS § 6.5.5.7.3 (cm, be, lbw, acfg, and pcmr permission prerequisites):
	// https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#getPinUvAuthTokenUsingUvWithPermissions
	if permission&protocol.PermissionCredentialManagement != 0 &&
		!info.Options[protocol.OptionCredentialManagement] {
		return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support CredentialManagement permission"}
	}

	if permission&protocol.PermissionBioEnrollment != 0 {
		if _, ok := info.Options[protocol.OptionBioEnroll]; !ok || !info.Options[protocol.OptionUvBioEnroll] {
			return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support obtaining BioEnrollment permission using built-in UV"}
		}
	}

	if permission&protocol.PermissionLargeBlobWrite != 0 && !info.Options[protocol.OptionLargeBlobs] {
		return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support LargeBlobWrite permission"}
	}

	if permission&protocol.PermissionAuthenticatorConfiguration != 0 {
		if !info.Options[protocol.OptionAuthenticatorConfig] || !info.Options[protocol.OptionUvAcfg] {
			return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support obtaining AuthenticatorConfiguration permission using built-in UV"}
		}
	}

	if permission&protocol.PermissionPersistentCredentialManagementReadOnly != 0 &&
		!info.Options[protocol.OptionPersistentCredentialManagementReadOnly] {
		return 0, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support PersistentCredentialManagementReadOnly permission"}
	}

	if err := validatePinUvAuthTokenPermissionRPID(permission, rpID); err != nil {
		return 0, err
	}

	return uvTokenFlowWithPermissions, nil
}

func bioEnrollmentMode(info protocol.AuthenticatorGetInfoResponse) (preview bool, err error) {
	// CTAP 2.1 PS §§ 6.7.1, 6.12 (bioEnroll feature detection and preview compatibility):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorBioEnrollmentFeatureDetection
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#prototypeAuthenticatorBioEnrollment
	preview = info.Versions.IsPreviewOnly()
	if preview {
		// Like bioEnroll, this option's value reports whether an enrollment
		// exists. Presence of the option reports support, so false still permits
		// preview enrollment commands.
		if _, ok := info.Options[protocol.OptionUserVerificationMgmtPreview]; !ok {
			return false, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support preview biometric enrollment"}
		}

		return true, nil
	}

	// CTAP 2.1 PS § 6.4 (bioEnroll option ID states):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#getinfo-bioenroll
	// bioEnroll's value reports whether an enrollment exists. Presence of the
	// option reports support, so false still permits enrollment commands.
	if _, ok := info.Options[protocol.OptionBioEnroll]; !ok {
		return false, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support biometric enrollment"}
	}

	return preview, nil
}

func credentialManagementMode(info protocol.AuthenticatorGetInfoResponse) (preview bool, err error) {
	// CTAP 2.1 PS §§ 6.8.1, 6.13 (credMgmt feature detection and preview compatibility):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorCredMgmtFeatureDetection
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#prototypeAuthenticatorCredentialManagement
	preview = info.Versions.IsPreviewOnly()

	option := protocol.OptionCredentialManagement
	if preview {
		option = protocol.OptionCredentialManagementPreview
	}

	if supported, ok := info.Options[option]; !ok || !supported {
		return false, &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support credential management"}
	}

	return preview, nil
}

func largeBlobsAuthorizationRequired(info protocol.AuthenticatorGetInfoResponse) bool {
	// CTAP 2.1 PS § 6.10.2 (authorization for large-blob writes):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#largeBlobsRW
	return hasConfiguredUserVerification(info) || alwaysUVEnabled(info)
}

func configAuthorizationRequired(
	info protocol.AuthenticatorGetInfoResponse,
	subCommand protocol.ConfigSubCommand,
) bool {
	// CTAP 2.1 PS § 6.11 (authenticatorConfig authorization):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorConfig
	userVerificationConfigured := hasConfiguredUserVerification(info)
	alwaysUV := alwaysUVEnabled(info)

	// CTAP 2.1 PS § 6.11.2 (unauthenticated initial toggleAlwaysUv exception):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#toggle-alwaysUv
	// An unprotected authenticator with alwaysUv enabled may accept this one
	// unauthenticated command so the initial configuration can disable alwaysUv.
	if subCommand == protocol.ConfigSubCommandToggleAlwaysUv && !userVerificationConfigured && alwaysUV {
		return false
	}

	return userVerificationConfigured || alwaysUV
}

func validateAuthenticatorConfigCommand(
	info protocol.AuthenticatorGetInfoResponse,
	subCommand protocol.ConfigSubCommand,
) error {
	// CTAP 2.1 PS § 6.4 (authnrCfg option ID):
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#getinfo-authnrcfg
	if !info.Options[protocol.OptionAuthenticatorConfig] {
		return &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support authnrCfg"}
	}

	// CTAP 2.3 PS §§ 6.4, 6.11 (authenticatorConfigCommands):
	// https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#getinfo-authenticatorconfigcommands
	// https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorConfig
	// CTAP 2.3 exposes exact subcommand support. A missing or empty list does
	// not advertise support for any standard authenticatorConfig subcommand.
	if info.Versions.Supports(protocol.FIDO_2_3) &&
		!slices.Contains(info.AuthenticatorConfigCommands, subCommand) {
		return &ErrorWithMessage{Err: ErrNotSupported, Message: fmt.Sprintf("device doesn't support authenticatorConfig subcommand %s", subCommand)}
	}

	return nil
}
