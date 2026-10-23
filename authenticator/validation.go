package authenticator

import (
	"errors"
	"fmt"
	"slices"
	"unicode/utf8"

	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/internal/pin"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/webauthn"
)

func validateHMACGetSecretSalts(input webauthn.HMACGetSecretInput) error {
	if len(input.Salt1) != 32 {
		return &ErrorWithMessage{Err: ErrInvalidSaltSize, Message: "salt1 must be exactly 32 bytes"}
	}

	if input.Salt2 != nil && len(input.Salt2) != 32 {
		return &ErrorWithMessage{Err: ErrInvalidSaltSize, Message: "salt2 must be exactly 32 bytes when present"}
	}

	return nil
}

func (d *Device) normalizeAndValidateCurrentPIN(value string) (string, error) {
	return pin.NormalizeAndValidate(value, protocol.DefaultMinPINCodePoints)
}

func (d *Device) normalizeAndValidateNewPIN(value string) (string, error) {
	minPINLength := d.info.EffectiveMinPINLength()

	maxPINLength := d.info.EffectiveMaxPINLength()
	if maxPINLength < minPINLength {
		return "", &ErrorWithMessage{Err: ErrSpecViolation, Message: fmt.Sprintf("maximum PIN length %d is less than minimum PIN length %d", maxPINLength, minPINLength)}
	}

	value, err := pin.NormalizeAndValidate(value, minPINLength)
	if err != nil {
		return "", err
	}

	if uint(utf8.RuneCountInString(value)) > maxPINLength {
		return "", fmt.Errorf("pin must contain at most %d Unicode code points", maxPINLength)
	}

	return value, nil
}

func (d *Device) pinPolicyError(err error) error {
	if err == nil || len(d.info.PinComplexityPolicyURL) == 0 {
		return err
	}

	if ctapErr, ok := errors.AsType[*ctaptransport.CTAPError](err); !ok || ctapErr.StatusCode != ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION {
		return err
	}

	return &ErrorWithMessage{Err: err, Message: "PIN policy details: " + d.info.PinComplexityPolicyURLString()}
}

func validateSetMinPINLength(
	info protocol.AuthenticatorGetInfoResponse,
	params protocol.SetMinPINLengthConfigSubCommandParams,
) error {
	if params.NewMinPINLength != nil {
		if *params.NewMinPINLength < info.EffectiveMinPINLength() {
			return &ErrorWithMessage{Err: SyntaxError, Message: "new minimum PIN length cannot decrease the current minimum"}
		}

		if *params.NewMinPINLength > info.EffectiveMaxPINLength() {
			return &ErrorWithMessage{Err: SyntaxError, Message: "new minimum PIN length exceeds the maximum PIN length"}
		}
	}

	if len(params.MinPINLengthRPIDs) != 0 {
		if info.MaxRPIDsForSetMinPINLength != nil &&
			uint(len(params.MinPINLengthRPIDs)) > *info.MaxRPIDsForSetMinPINLength {
			return &ErrorWithMessage{Err: SyntaxError, Message: "too many RP IDs for setMinPINLength"}
		}

		if !slices.Contains(info.Extensions, extension.ExtensionIdentifierMinPinLength) &&
			!slices.Contains(info.Extensions, extension.ExtensionIdentifierPinComplexityPolicy) {
			return &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support PIN policy RP IDs"}
		}
	}

	if params.PINComplexityPolicy && info.PinComplexityPolicy == nil {
		return &ErrorWithMessage{Err: ErrNotSupported, Message: "device doesn't support pinComplexityPolicy"}
	}

	if params.ForceChangePIN &&
		!info.Options[protocol.OptionClientPIN] {
		return &ErrorWithMessage{Err: ErrPinNotSet, Message: "cannot force a PIN change before a PIN is set"}
	}

	return nil
}
