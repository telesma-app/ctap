package fips140policy

import (
	cryptofips140 "crypto/fips140"
	"errors"
	"slices"
	"testing"

	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapfips140 "github.com/telesma-app/ctap/fips140"
)

func TestFilterCredentialParametersPassesEmptyInputThrough(t *testing.T) {
	filtered, err := FilterCredentialParameters(nil)
	if err != nil {
		t.Fatalf("FilterCredentialParameters: %v", err)
	}

	if filtered != nil {
		t.Fatalf("filtered = %v, want nil", filtered)
	}
}

func TestFilterCredentialParameters(t *testing.T) {
	if !cryptofips140.Enabled() {
		t.Skip("requires Go FIPS 140-3 mode")
	}

	parameters := []credential.PublicKeyCredentialParameters{
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmES256},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmESP256},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmES384},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmESP384},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmES512},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmESP512},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmEd25519},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmEdDSA},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmRS256},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmRS384},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmRS512},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmPS256},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmPS384},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmPS512},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmES256K},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmRS1},
		{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.Algorithm(12345)},
	}
	original := slices.Clone(parameters)

	filtered, err := FilterCredentialParameters(parameters)
	if err != nil {
		t.Fatalf("FilterCredentialParameters: %v", err)
	}

	if !slices.Equal(parameters, original) {
		t.Fatalf("input parameters changed: got %v, want %v", parameters, original)
	}

	got := make([]cose.Algorithm, 0, len(filtered))
	for _, parameter := range filtered {
		got = append(got, parameter.Algorithm)
	}
	// AlgorithmEdDSA is absent: it does not name a curve.
	want := []cose.Algorithm{
		cose.AlgorithmES256,
		cose.AlgorithmESP256,
		cose.AlgorithmES384,
		cose.AlgorithmESP384,
		cose.AlgorithmES512,
		cose.AlgorithmESP512,
		cose.AlgorithmEd25519,
		cose.AlgorithmRS256,
		cose.AlgorithmRS384,
		cose.AlgorithmRS512,
		cose.AlgorithmPS256,
		cose.AlgorithmPS384,
		cose.AlgorithmPS512,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("filtered algorithms = %v, want %v", got, want)
	}
}

func TestFilterPreviewSignAlgorithms(t *testing.T) {
	if !cryptofips140.Enabled() {
		t.Skip("requires Go FIPS 140-3 mode")
	}

	algorithms := []cose.Algorithm{
		cose.AlgorithmES256K,
		cose.AlgorithmES256,
		cose.AlgorithmRS1,
		cose.AlgorithmEd25519,
	}
	original := slices.Clone(algorithms)

	filtered, err := FilterPreviewSignAlgorithms(algorithms)
	if err != nil {
		t.Fatalf("FilterPreviewSignAlgorithms: %v", err)
	}

	if !slices.Equal(algorithms, original) {
		t.Fatalf("input algorithms changed: got %v, want %v", algorithms, original)
	}

	if got, want := filtered, []cose.Algorithm{cose.AlgorithmES256, cose.AlgorithmEd25519}; !slices.Equal(got, want) {
		t.Fatalf("filtered algorithms = %v, want %v", got, want)
	}

	_, err = FilterPreviewSignAlgorithms([]cose.Algorithm{cose.AlgorithmES256K, cose.AlgorithmRS1})
	if !errors.Is(err, ctapfips140.ErrNotAllowed) {
		t.Fatalf("error = %v, want errors.Is(error, %v)", err, ctapfips140.ErrNotAllowed)
	}
}
