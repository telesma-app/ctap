// Package fips140 exposes errors from the CTAP FIPS 140-3 policy.
package fips140

import "errors"

// ErrNotAllowed identifies an operation rejected by the CTAP FIPS 140-3
// policy.
var ErrNotAllowed = errors.New("fips140: operation is not allowed in FIPS 140-3 mode")

// PolicyError reports a CTAP operation rejected by the FIPS 140-3 policy.
type PolicyError struct {
	Operation string
}

// Error implements error.
func (e *PolicyError) Error() string {
	if e.Operation == "" {
		return ErrNotAllowed.Error()
	}

	return "fips140: " + e.Operation + " is not allowed in FIPS 140-3 mode"
}

// Unwrap makes ErrNotAllowed available through errors.Is.
func (e *PolicyError) Unwrap() error {
	return ErrNotAllowed
}
