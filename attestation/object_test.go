package attestation

import (
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/cose"
)

func TestParseObjectAndExtractCertificateChain(t *testing.T) {
	raw, err := cbor.Marshal(Object{
		Format:   AttestationStatementFormatIdentifierPacked,
		AuthData: []byte{1, 2, 3},
		Statement: map[string]any{
			"alg": int64(cose.AlgorithmES256),
			"sig": []byte{4, 5, 6},
			"x5c": []any{[]byte{7, 8, 9}},
		},
	})
	if err != nil {
		t.Fatalf("marshal object: %v", err)
	}

	object, err := ParseObject(raw)
	if err != nil {
		t.Fatalf("ParseObject() error = %v", err)
	}

	attestationType, chain, err := object.TypeAndCertificateChain()
	if err != nil {
		t.Fatalf("TypeAndCertificateChain() error = %v", err)
	}

	if attestationType != TypeBasic {
		t.Fatalf("attestation type = %q, want %q", attestationType, TypeBasic)
	}

	if len(chain) != 1 || len(chain[0]) != 3 {
		t.Fatalf("certificate chain = %#v, want one certificate", chain)
	}
}

func TestParseObjectRejectsTrailingData(t *testing.T) {
	raw, err := cbor.Marshal(Object{
		Format:    AttestationStatementFormatIdentifierNone,
		AuthData:  []byte{1},
		Statement: map[string]any{},
	})
	if err != nil {
		t.Fatalf("marshal object: %v", err)
	}

	raw = append(raw, 0)

	_, err = ParseObject(raw)
	if !errors.Is(err, ErrStatementMalformed) {
		t.Fatalf("ParseObject() error = %v, want %v", err, ErrStatementMalformed)
	}
}
