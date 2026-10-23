// Package fips140policy applies CTAP request policy when Go's FIPS 140-3 mode
// is enabled.
package fips140policy

import (
	cryptofips140 "crypto/fips140"
	"fmt"
	"slices"

	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapfips140 "github.com/telesma-app/ctap/fips140"
)

// FilterCredentialParameters removes algorithms that cannot be requested for
// credential generation under the active FIPS 140-3 policy.
func FilterCredentialParameters(
	parameters []credential.PublicKeyCredentialParameters,
) ([]credential.PublicKeyCredentialParameters, error) {
	if !cryptofips140.Enabled() || len(parameters) == 0 {
		return parameters, nil
	}

	parameters = slices.DeleteFunc(slices.Clone(parameters), func(parameter credential.PublicKeyCredentialParameters) bool {
		return !parameter.Algorithm.FIPS140Approved()
	})
	if len(parameters) == 0 {
		return nil, &ctapfips140.PolicyError{
			Operation: "MakeCredential without an approved credential algorithm",
		}
	}

	return parameters, nil
}

// FilterPreviewSignAlgorithms removes algorithms that cannot be requested for
// previewSign key generation under the active FIPS 140-3 policy.
func FilterPreviewSignAlgorithms(algorithms []cose.Algorithm) ([]cose.Algorithm, error) {
	if !cryptofips140.Enabled() || len(algorithms) == 0 {
		return algorithms, nil
	}

	algorithms = slices.DeleteFunc(slices.Clone(algorithms), func(algorithm cose.Algorithm) bool {
		return !algorithm.FIPS140Approved()
	})
	if len(algorithms) == 0 {
		return nil, &ctapfips140.PolicyError{
			Operation: "previewSign credential generation without an approved algorithm",
		}
	}

	return algorithms, nil
}

// ValidateCredentialKey rejects a generated credential whose algorithm is
// outside the active FIPS 140-3 policy, which an authenticator can return by
// ignoring the algorithms [FilterCredentialParameters] left in the request.
func ValidateCredentialKey(key cose.Key) error {
	if !cryptofips140.Enabled() {
		return nil
	}

	algorithm, err := key.Algorithm()
	if err != nil {
		return err
	}

	if !algorithm.FIPS140Approved() {
		return &ctapfips140.PolicyError{
			Operation: fmt.Sprintf("credential algorithm %d returned by MakeCredential", algorithm),
		}
	}

	return nil
}
