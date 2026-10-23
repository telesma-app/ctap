package authenticator

import (
	"errors"
)

var (
	ErrPingPongMismatch         = errors.New("device: ping/pong mismatch")
	ErrPinUvAuthTokenRequired   = errors.New("device: pinUvAuthToken required")
	ErrBuiltInUVRequired        = errors.New("device: built-in user verification required")
	ErrNotSupported             = errors.New("device: not supported")
	SyntaxError                 = errors.New("device: syntax error") //nolint:staticcheck // Preserve the established public API.
	ErrBadType                  = errors.New("device: bad type")
	ErrInvalidSaltSize          = errors.New("device: invalid salt size")
	ErrPinNotSet                = errors.New("device: pin not set")
	ErrPinAlreadySet            = errors.New("device: pin already set")
	ErrPinChangeRequired        = errors.New("device: pin change required")
	ErrUvNotConfigured          = errors.New("device: UV not configured")
	ErrLargeBlobsIntegrityCheck = errors.New("device: large blobs integrity check failed")
	ErrLargeBlobsTooBig         = errors.New("device: size of serialized large blobs is too big that token")
	ErrSpecViolation            = errors.New("device: spec violation")
)

type ErrorWithMessage struct {
	Message string
	Err     error
}

func (m *ErrorWithMessage) Error() string {
	if m.Message != "" {
		return m.Err.Error() + " (" + m.Message + ")"
	}

	return m.Err.Error()
}

func (m *ErrorWithMessage) Unwrap() error {
	return m.Err
}
