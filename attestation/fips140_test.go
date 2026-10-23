package attestation

import (
	cryptofips140 "crypto/fips140"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/telesma-app/ctap/cose"
	ctapfips140 "github.com/telesma-app/ctap/fips140"
)

func TestFIPS140SignatureRejectionIsReportedAsUnsupported(t *testing.T) {
	if !cryptofips140.Enabled() {
		t.Skip("requires Go FIPS 140-3 mode")
	}

	valid, err := verifySignature(&rsa.PublicKey{}, cose.AlgorithmRS1, nil, nil)
	if valid != nil {
		t.Fatalf("valid = %v, want nil", valid)
	}

	if !errors.Is(err, ErrAlgorithmUnsupported) {
		t.Fatalf("error = %v, want errors.Is(error, %v)", err, ErrAlgorithmUnsupported)
	}

	if !errors.Is(err, ctapfips140.ErrNotAllowed) {
		t.Fatalf("error = %v, want errors.Is(error, %v)", err, ctapfips140.ErrNotAllowed)
	}
}
