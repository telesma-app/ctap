package protocol

import "testing"

func TestProtocolNames(t *testing.T) {
	commands := []struct {
		value Command
		name  string
	}{
		{AuthenticatorMakeCredential, "authenticatorMakeCredential"},
		{AuthenticatorGetAssertion, "authenticatorGetAssertion"},
		{AuthenticatorGetNextAssertion, "authenticatorGetNextAssertion"},
		{AuthenticatorGetInfo, "authenticatorGetInfo"},
		{AuthenticatorClientPIN, "authenticatorClientPIN"},
		{AuthenticatorReset, "authenticatorReset"},
		{AuthenticatorBioEnrollment, "authenticatorBioEnrollment"},
		{AuthenticatorCredentialManagement, "authenticatorCredentialManagement"},
		{AuthenticatorSelection, "authenticatorSelection"},
		{AuthenticatorLargeBlobs, "authenticatorLargeBlobs"},
		{AuthenticatorConfig, "authenticatorConfig"},
		{PrototypeAuthenticatorBioEnrollment, "prototypeAuthenticatorBioEnrollment"},
		{PrototypeAuthenticatorCredentialManagement, "prototypeAuthenticatorCredentialManagement"},
	}
	for _, tt := range commands {
		if got, ok := tt.value.Name(); !ok || got != tt.name {
			t.Errorf("Command(%d).Name() = %q, %v, want %q, true", tt.value, got, ok, tt.name)
		}
	}

	if got, ok := Command(0x7e).Name(); ok || got != "" {
		t.Errorf("unknown Command.Name() = %q, %v, want empty, false", got, ok)
	}

	assertNames(t, "ClientPIN", []namedValue[ClientPINSubCommand]{
		{ClientPINSubCommandGetPINRetries, "getPINRetries"},
		{ClientPINSubCommandGetKeyAgreement, "getKeyAgreement"},
		{ClientPINSubCommandSetPIN, "setPIN"},
		{ClientPINSubCommandChangePIN, "changePIN"},
		{ClientPINSubCommandGetPinToken, "getPinToken"},
		{ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions, "getPinUvAuthTokenUsingUvWithPermissions"},
		{ClientPINSubCommandGetUVRetries, "getUVRetries"},
		{ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions, "getPinUvAuthTokenUsingPinWithPermissions"},
	}, ClientPINSubCommand.Name)
	assertNames(t, "BioEnrollment", []namedValue[BioEnrollmentSubCommand]{
		{BioEnrollmentSubCommandEnrollBegin, "enrollBegin"},
		{BioEnrollmentSubCommandEnrollCaptureNextSample, "enrollCaptureNextSample"},
		{BioEnrollmentSubCommandCancelCurrentEnrollment, "cancelCurrentEnrollment"},
		{BioEnrollmentSubCommandEnumerateEnrollments, "enumerateEnrollments"},
		{BioEnrollmentSubCommandSetFriendlyName, "setFriendlyName"},
		{BioEnrollmentSubCommandRemoveEnrollment, "removeEnrollment"},
		{BioEnrollmentSubCommandGetFingerprintSensorInfo, "getFingerprintSensorInfo"},
	}, BioEnrollmentSubCommand.Name)
	assertNames(t, "CredentialManagement", []namedValue[CredentialManagementSubCommand]{
		{CredentialManagementSubCommandGetCredsMetadata, "getCredsMetadata"},
		{CredentialManagementSubCommandEnumerateRPsBegin, "enumerateRPsBegin"},
		{CredentialManagementSubCommandEnumerateRPsGetNextRP, "enumerateRPsGetNextRP"},
		{CredentialManagementSubCommandEnumerateCredentialsBegin, "enumerateCredentialsBegin"},
		{CredentialManagementSubCommandEnumerateCredentialsGetNextCredential, "enumerateCredentialsGetNextCredential"},
		{CredentialManagementSubCommandDeleteCredential, "deleteCredential"},
		{CredentialManagementSubCommandUpdateUserInformation, "updateUserInformation"},
	}, CredentialManagementSubCommand.Name)
	assertNames(t, "Config", []namedValue[ConfigSubCommand]{
		{ConfigSubCommandEnableEnterpriseAttestation, "enableEnterpriseAttestation"},
		{ConfigSubCommandToggleAlwaysUv, "toggleAlwaysUv"},
		{ConfigSubCommandSetMinPINLength, "setMinPINLength"},
		{ConfigSubCommandEnableLongTouchForReset, "enableLongTouchForReset"},
		{ConfigSubCommandVendorPrototype, "vendorPrototype"},
	}, ConfigSubCommand.Name)
}

type namedUnsigned interface {
	~uint8 | ~uint
}

type namedValue[T namedUnsigned] struct {
	value T
	name  string
}

func assertNames[T namedUnsigned](
	t *testing.T,
	typeName string,
	values []namedValue[T],
	name func(T) (string, bool),
) {
	t.Helper()

	for _, tt := range values {
		if got, ok := name(tt.value); !ok || got != tt.name {
			t.Errorf("%s(%d).Name() = %q, %v, want %q, true", typeName, tt.value, got, ok, tt.name)
		}
	}

	if got, ok := name(T(0xfe)); ok || got != "" {
		t.Errorf("unknown %s.Name() = %q, %v, want empty, false", typeName, got, ok)
	}
}

func TestPermissionString(t *testing.T) {
	tests := []struct {
		permission Permission
		want       string
	}{
		{PermissionNone, "none"},
		{PermissionMakeCredential, "mc"},
		{PermissionGetAssertion, "ga"},
		{PermissionCredentialManagement, "cm"},
		{PermissionBioEnrollment, "be"},
		{PermissionLargeBlobWrite, "lbw"},
		{PermissionAuthenticatorConfiguration, "acfg"},
		{PermissionPersistentCredentialManagementReadOnly, "pcmr"},
		{PermissionMakeCredential | PermissionGetAssertion | PermissionCredentialManagement |
			PermissionBioEnrollment | PermissionLargeBlobWrite | PermissionAuthenticatorConfiguration,
			"mc,ga,cm,be,lbw,acfg"},
		{PermissionCredentialManagement | PermissionLargeBlobWrite, "cm,lbw"},
		{Permission(0x80), "unknown(0x80)"},
		{PermissionCredentialManagement | Permission(0x80), "cm,unknown(0x80)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.permission.String(); got != tt.want {
				t.Errorf("Permission(%#02x).String() = %q, want %q", tt.permission, got, tt.want)
			}
		})
	}
}

func TestUserVerifyValuesMatchFIDORegistry(t *testing.T) {
	tests := []struct {
		name   string
		method UserVerify
		want   UserVerify
	}{
		{"presence internal", UserVerifyPresenceInternal, 0x00000001},
		{"fingerprint internal", UserVerifyFingerprintInternal, 0x00000002},
		{"passcode internal", UserVerifyPasscodeInternal, 0x00000004},
		{"voiceprint internal", UserVerifyVoiceprintInternal, 0x00000008},
		{"faceprint internal", UserVerifyFaceprintInternal, 0x00000010},
		{"location internal", UserVerifyLocationInternal, 0x00000020},
		{"eyeprint internal", UserVerifyEyeprintInternal, 0x00000040},
		{"pattern internal", UserVerifyPatternInternal, 0x00000080},
		{"handprint internal", UserVerifyHandprintInternal, 0x00000100},
		{"none", UserVerifyNone, 0x00000200},
		{"all", UserVerifyAll, 0x00000400},
		{"passcode external", UserVerifyPasscodeExternal, 0x00000800},
		{"pattern external", UserVerifyPatternExternal, 0x00001000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.method != tt.want {
				t.Errorf("UserVerify value = %#08x, want %#08x", tt.method, tt.want)
			}
		})
	}
}

func TestUserVerifyString(t *testing.T) {
	tests := []struct {
		name     string
		modality UserVerify
		want     string
	}{
		{"zero", 0, ""},
		{"presence internal", UserVerifyPresenceInternal, "presence_internal"},
		{"fingerprint internal", UserVerifyFingerprintInternal, "fingerprint_internal"},
		{"passcode internal", UserVerifyPasscodeInternal, "passcode_internal"},
		{"voiceprint internal", UserVerifyVoiceprintInternal, "voiceprint_internal"},
		{"faceprint internal", UserVerifyFaceprintInternal, "faceprint_internal"},
		{"location internal", UserVerifyLocationInternal, "location_internal"},
		{"eyeprint internal", UserVerifyEyeprintInternal, "eyeprint_internal"},
		{"pattern internal", UserVerifyPatternInternal, "pattern_internal"},
		{"handprint internal", UserVerifyHandprintInternal, "handprint_internal"},
		{"passcode external", UserVerifyPasscodeExternal, "passcode_external"},
		{"pattern external", UserVerifyPatternExternal, "pattern_external"},
		{"none", UserVerifyNone, "none"},
		{"all", UserVerifyAll, "all"},
		{"combined", UserVerifyPresenceInternal | UserVerifyFingerprintInternal | UserVerifyPasscodeExternal,
			"presence_internal,fingerprint_internal,passcode_external"},
		{"unknown", UserVerify(0x2000), "unknown(0x2000)"},
		{"known and unknown", UserVerifyFingerprintInternal | UserVerify(0x2000),
			"fingerprint_internal,unknown(0x2000)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.modality.String(); got != tt.want {
				t.Errorf("UserVerify(%#x).String() = %q, want %q", tt.modality, got, tt.want)
			}
		})
	}
}

func TestLastEnrollSampleStatusValuesMatchCTAP23(t *testing.T) {
	tests := []struct {
		name   string
		status LastEnrollSampleStatus
		want   LastEnrollSampleStatus
	}{
		{"fingerprint good", LastEnrollSampleStatusFingerprintGood, 0x00},
		{"fingerprint too high", LastEnrollSampleStatusFingerprintTooHigh, 0x01},
		{"fingerprint too low", LastEnrollSampleStatusFingerprintTooLow, 0x02},
		{"fingerprint too left", LastEnrollSampleStatusFingerprintTooLeft, 0x03},
		{"fingerprint too right", LastEnrollSampleStatusFingerprintTooRight, 0x04},
		{"fingerprint too fast", LastEnrollSampleStatusFingerprintTooFast, 0x05},
		{"fingerprint too slow", LastEnrollSampleStatusFingerprintTooSlow, 0x06},
		{"fingerprint poor quality", LastEnrollSampleStatusFingerprintPoorQuality, 0x07},
		{"fingerprint too skewed", LastEnrollSampleStatusFingerprintTooSkewed, 0x08},
		{"fingerprint too short", LastEnrollSampleStatusFingerprintTooShort, 0x09},
		{"fingerprint merge failure", LastEnrollSampleStatusFingerprintMergeFailure, 0x0a},
		{"fingerprint exists", LastEnrollSampleStatusFingerprintExists, 0x0b},
		{"no user activity", LastEnrollSampleStatusNoUserActivity, 0x0d},
		{"no user presence transition", LastEnrollSampleStatusNoUserPresenceTransition, 0x0e},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.status != tt.want {
				t.Errorf("LastEnrollSampleStatus value = %#02x, want %#02x", tt.status, tt.want)
			}
		})
	}
}

func TestLastEnrollSampleStatusString(t *testing.T) {
	tests := []struct {
		status LastEnrollSampleStatus
		want   string
	}{
		{LastEnrollSampleStatusFingerprintGood, "CTAP2_ENROLL_FEEDBACK_FP_GOOD"},
		{LastEnrollSampleStatusFingerprintTooHigh, "CTAP2_ENROLL_FEEDBACK_FP_TOO_HIGH"},
		{LastEnrollSampleStatusFingerprintTooLow, "CTAP2_ENROLL_FEEDBACK_FP_TOO_LOW"},
		{LastEnrollSampleStatusFingerprintTooLeft, "CTAP2_ENROLL_FEEDBACK_FP_TOO_LEFT"},
		{LastEnrollSampleStatusFingerprintTooRight, "CTAP2_ENROLL_FEEDBACK_FP_TOO_RIGHT"},
		{LastEnrollSampleStatusFingerprintTooFast, "CTAP2_ENROLL_FEEDBACK_FP_TOO_FAST"},
		{LastEnrollSampleStatusFingerprintTooSlow, "CTAP2_ENROLL_FEEDBACK_FP_TOO_SLOW"},
		{LastEnrollSampleStatusFingerprintPoorQuality, "CTAP2_ENROLL_FEEDBACK_FP_POOR_QUALITY"},
		{LastEnrollSampleStatusFingerprintTooSkewed, "CTAP2_ENROLL_FEEDBACK_FP_TOO_SKEWED"},
		{LastEnrollSampleStatusFingerprintTooShort, "CTAP2_ENROLL_FEEDBACK_FP_TOO_SHORT"},
		{LastEnrollSampleStatusFingerprintMergeFailure, "CTAP2_ENROLL_FEEDBACK_FP_MERGE_FAILURE"},
		{LastEnrollSampleStatusFingerprintExists, "CTAP2_ENROLL_FEEDBACK_FP_EXISTS"},
		{LastEnrollSampleStatusNoUserActivity, "CTAP2_ENROLL_FEEDBACK_NO_USER_ACTIVITY"},
		{LastEnrollSampleStatusNoUserPresenceTransition, "CTAP2_ENROLL_FEEDBACK_NO_USER_PRESENCE_TRANSITION"},
		{LastEnrollSampleStatus(0x0c), "unknown(0x0c)"},
		{LastEnrollSampleStatus(0xff), "unknown(0xff)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.status.String(); got != tt.want {
				t.Errorf("LastEnrollSampleStatus(%#02x).String() = %q, want %q", tt.status, got, tt.want)
			}
		})
	}
}
