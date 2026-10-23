package pin

import (
	cryptofips140 "crypto/fips140"
	"fmt"
	"unicode/utf8"

	ctapfips140 "github.com/telesma-app/ctap/fips140"
	"github.com/telesma-app/ctap/protocol"
	"golang.org/x/text/unicode/norm"
)

const maxUTF8Bytes = 63

// ValidateFIPS140UvAuthProtocol rejects PIN/UV auth protocols outside the
// CTAP FIPS 140-3 policy. The rule covers the platform's own cryptography, not
// the authenticator's: protocol 1 derives its shared secret with a bare
// SHA-256 rather than an approved KDF, and encrypts with unauthenticated
// AES-CBC under a fixed zero IV. Protocol 2 replaces both.
func ValidateFIPS140UvAuthProtocol(pinUvAuthProtocol protocol.PinUvAuthProtocol) error {
	if !cryptofips140.Enabled() || pinUvAuthProtocol == protocol.PinUvAuthProtocolTwo {
		return nil
	}

	return &ctapfips140.PolicyError{
		Operation: fmt.Sprintf("PIN/UV auth protocol %d", pinUvAuthProtocol),
	}
}

// ValidateUvAuthToken validates the token length accepted by the selected
// PIN/UV auth protocol. Callers with authenticator version information may
// apply stricter version-specific requirements.
func ValidateUvAuthToken(pinUvAuthProtocol protocol.PinUvAuthProtocol, pinUvAuthToken []byte) error {
	if err := ValidateFIPS140UvAuthProtocol(pinUvAuthProtocol); err != nil {
		return err
	}

	switch pinUvAuthProtocol {
	case protocol.PinUvAuthProtocolOne:
		// CTAP 2.0 allowed any positive multiple of the AES block size. CTAP
		// 2.1 narrowed this to 16 or 32 bytes; callers with authenticator
		// version information enforce that stricter requirement.
		if len(pinUvAuthToken) == 0 || len(pinUvAuthToken)%16 != 0 {
			return fmt.Errorf("pinUvAuthToken must be a positive multiple of 16 bytes for PIN/UV auth protocol 1")
		}
	case protocol.PinUvAuthProtocolTwo:
		if len(pinUvAuthToken) != 32 {
			return fmt.Errorf("pinUvAuthToken must be 32 bytes for PIN/UV auth protocol 2")
		}
	default:
		return fmt.Errorf("unsupported PIN/UV auth protocol %d", pinUvAuthProtocol)
	}

	return nil
}

// NormalizeAndValidate normalizes a PIN to NFC and validates the minimum code
// point count and CTAP UTF-8 representation limit.
func NormalizeAndValidate(value string, minCodePoints uint) (string, error) {
	if minCodePoints < protocol.DefaultMinPINCodePoints {
		minCodePoints = protocol.DefaultMinPINCodePoints
	}

	value = norm.NFC.String(value)
	if uint(utf8.RuneCountInString(value)) < minCodePoints {
		return "", fmt.Errorf("pin must contain at least %d Unicode code points", minCodePoints)
	}

	if len([]byte(value)) > maxUTF8Bytes {
		return "", fmt.Errorf("pin must be at most %d UTF-8 bytes", maxUTF8Bytes)
	}

	if value[len(value)-1] == 0x00 {
		return "", fmt.Errorf("pin must not end in a 0x00 byte")
	}

	return value, nil
}
