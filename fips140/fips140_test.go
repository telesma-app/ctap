package fips140_test

import (
	"errors"
	"strings"
	"testing"

	ctapfips140 "github.com/telesma-app/ctap/fips140"
)

func TestPolicyError(t *testing.T) {
	err := &ctapfips140.PolicyError{Operation: "verify COSE algorithm -47"}

	if !strings.Contains(err.Error(), "verify COSE algorithm -47") {
		t.Fatalf("Error() = %q, want operation", err.Error())
	}

	if !strings.Contains(err.Error(), "FIPS 140-3 mode") {
		t.Fatalf("Error() = %q, want FIPS 140-3 mode", err.Error())
	}

	if !errors.Is(err, ctapfips140.ErrNotAllowed) {
		t.Fatal("errors.Is did not match ErrNotAllowed")
	}

	var target *ctapfips140.PolicyError
	if !errors.As(err, &target) {
		t.Fatal("errors.As did not match PolicyError")
	}

	if target.Operation != err.Operation {
		t.Fatalf("errors.As operation = %q, want %q", target.Operation, err.Operation)
	}
}

func TestPolicyErrorWithoutOperation(t *testing.T) {
	err := &ctapfips140.PolicyError{}
	if got, want := err.Error(), ctapfips140.ErrNotAllowed.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}
