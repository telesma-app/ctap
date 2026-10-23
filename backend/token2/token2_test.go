package token2

import (
	"errors"
	"fmt"
	"testing"

	token2transport "github.com/telesma-app/ctap/transport/token2"
)

func TestUnsupportedCardClassification(t *testing.T) {
	if got := isUnsupportedCard(&token2transport.APDUError{SW1: 0x6a, SW2: 0x82}); !got {
		t.Errorf("got false, want true")
	}

	if got := isUnsupportedCard(fmt.Errorf("select applet: %w", token2transport.ErrInvalidResponse)); !got {
		t.Errorf("got false, want true")
	}

	if got := isUnsupportedCard(errors.New("PC/SC service unavailable")); got {
		t.Errorf("got true, want false")
	}
}
