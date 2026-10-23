package pin

import (
	cryptofips140 "crypto/fips140"
	"errors"
	"strings"
	"testing"

	ctapfips140 "github.com/telesma-app/ctap/fips140"
	"github.com/telesma-app/ctap/protocol"
)

func TestValidateUvAuthToken(t *testing.T) {
	tests := []struct {
		name     string
		protocol protocol.PinUvAuthProtocol
		length   int
		wantErr  bool
	}{
		{name: "protocol 1 16 bytes", protocol: protocol.PinUvAuthProtocolOne, length: 16},
		{name: "protocol 1 32 bytes", protocol: protocol.PinUvAuthProtocolOne, length: 32},
		{name: "protocol 1 CTAP 2.0 compatible length", protocol: protocol.PinUvAuthProtocolOne, length: 48},
		{name: "protocol 1 empty", protocol: protocol.PinUvAuthProtocolOne, wantErr: true},
		{name: "protocol 1 wrong length", protocol: protocol.PinUvAuthProtocolOne, length: 31, wantErr: true},
		{name: "protocol 2 32 bytes", protocol: protocol.PinUvAuthProtocolTwo, length: 32},
		{name: "protocol 2 16 bytes", protocol: protocol.PinUvAuthProtocolTwo, length: 16, wantErr: true},
		{name: "unknown protocol", protocol: 99, length: 32, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUvAuthToken(tt.protocol, make([]byte, tt.length))

			fipsRejected := cryptofips140.Enabled() && tt.protocol != protocol.PinUvAuthProtocolTwo
			if tt.wantErr || fipsRejected {
				if err == nil {
					t.Fatalf("expected an error")
				}

				if fipsRejected && !errors.Is(err, ctapfips140.ErrNotAllowed) {
					t.Fatalf("error = %v, want errors.Is(error, %v)", err, ctapfips140.ErrNotAllowed)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateFIPS140UvAuthProtocol(t *testing.T) {
	if !cryptofips140.Enabled() {
		t.Skip("requires Go FIPS 140-3 mode")
	}

	err := ValidateFIPS140UvAuthProtocol(protocol.PinUvAuthProtocolOne)
	if !errors.Is(err, ctapfips140.ErrNotAllowed) {
		t.Fatalf("error = %v, want errors.Is(error, %v)", err, ctapfips140.ErrNotAllowed)
	}

	if err := ValidateFIPS140UvAuthProtocol(protocol.PinUvAuthProtocolTwo); err != nil {
		t.Fatalf("protocol 2 rejected: %v", err)
	}
}

func TestNormalizeAndValidate(t *testing.T) {
	t.Run("rejects PIN below explicit minimum", func(t *testing.T) {
		_, err := NormalizeAndValidate("12345", 6)
		if err == nil {
			t.Fatalf("expected an error")
		}

		if container, element := err.Error(), "at least 6"; !strings.Contains(container, element) {
			t.Errorf("value does not contain %#v", element)
		}
	})

	t.Run("rejects PIN over UTF-8 limit", func(t *testing.T) {
		_, err := NormalizeAndValidate(strings.Repeat("a", 64), protocol.DefaultMinPINCodePoints)
		if err == nil {
			t.Fatalf("expected an error")
		}

		if container, element := err.Error(), "63 UTF-8 bytes"; !strings.Contains(container, element) {
			t.Errorf("value does not contain %#v", element)
		}
	})

	t.Run("normalizes PIN to NFC", func(t *testing.T) {
		value, err := NormalizeAndValidate("Cafe\u0301123", protocol.DefaultMinPINCodePoints)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := value, "Caf\u00e9123"; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})

	t.Run("rejects PIN ending in NUL byte", func(t *testing.T) {
		_, err := NormalizeAndValidate("1234\x00", protocol.DefaultMinPINCodePoints)
		if err == nil {
			t.Fatalf("expected an error")
		}

		if container, element := err.Error(), "0x00"; !strings.Contains(container, element) {
			t.Errorf("value does not contain %#v", element)
		}
	})
}
