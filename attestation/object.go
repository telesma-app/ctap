package attestation

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/cose"
)

// Object is the WebAuthn attestation object returned by a create ceremony.
type Object struct {
	Format    AttestationStatementFormatIdentifier `cbor:"fmt"`
	AuthData  []byte                               `cbor:"authData"`
	Statement map[string]any                       `cbor:"attStmt"`
}

// ParseObject decodes exactly one CBOR-encoded WebAuthn attestation object.
func ParseObject(raw []byte) (Object, error) {
	var object Object
	if err := cbor.Unmarshal(raw, &object); err != nil {
		return Object{}, fmt.Errorf("%w: decode object: %v", ErrStatementMalformed, err)
	}

	if object.Format == "" || object.AuthData == nil || object.Statement == nil {
		return Object{}, fmt.Errorf("%w: incomplete object", ErrStatementMalformed)
	}

	return object, nil
}

// TypeAndCertificateChain extracts the attestation type and untrusted x5c
// values without performing signature or trust verification.
func (o Object) TypeAndCertificateChain() (Type, [][]byte, error) {
	switch o.Format {
	case AttestationStatementFormatIdentifierNone:
		if len(o.Statement) != 0 {
			return TypeNone, nil, fmt.Errorf("%w: none statement is not empty", ErrStatementMalformed)
		}

		return TypeNone, nil, nil
	case AttestationStatementFormatIdentifierPacked:
		statement, ok := ParsePackedStatement(o.Statement)
		if !ok {
			return TypeUnsupported, nil, ErrStatementMalformed
		}

		if _, present := o.Statement["ecdaaKeyId"]; present {
			return TypeUnsupported, nil, ErrFormatUnsupported
		}

		if len(statement.X509Chain) == 0 {
			return TypeSelf, nil, nil
		}

		return TypeBasic, statement.X509Chain, nil
	case AttestationStatementFormatIdentifierFIDOU2F:
		statement, ok := ParseFIDOU2FStatement(o.Statement)
		if !ok || len(statement.X509Chain) == 0 {
			return TypeBasic, nil, ErrStatementMalformed
		}

		return TypeBasic, statement.X509Chain, nil
	default:
		return TypeUnsupported, nil, ErrFormatUnsupported
	}
}

// ParsePackedStatement decodes a packed attestation statement map.
func ParsePackedStatement(values map[string]any) (PackedAttestationStatementFormat, bool) {
	algorithm, ok := integer(values["alg"])
	if !ok {
		return PackedAttestationStatementFormat{}, false
	}

	signature, ok := values["sig"].([]byte)
	if !ok {
		return PackedAttestationStatementFormat{}, false
	}

	var chain [][]byte
	if raw, present := values["x5c"]; present {
		chain, ok = x509Chain(raw)
		if !ok {
			return PackedAttestationStatementFormat{}, false
		}
	}

	return PackedAttestationStatementFormat{
		Algorithm: cose.Algorithm(algorithm),
		Signature: signature,
		X509Chain: chain,
	}, true
}

// ParseFIDOU2FStatement decodes a FIDO U2F attestation statement map.
func ParseFIDOU2FStatement(values map[string]any) (FIDOU2FAttestationStatementFormat, bool) {
	chain, ok := x509Chain(values["x5c"])
	if !ok {
		return FIDOU2FAttestationStatementFormat{}, false
	}

	signature, ok := values["sig"].([]byte)
	if !ok {
		return FIDOU2FAttestationStatementFormat{}, false
	}

	return FIDOU2FAttestationStatementFormat{
		X509Chain: chain,
		Signature: signature,
	}, true
}

// ParseTPMStatement decodes a TPM attestation statement map.
func ParseTPMStatement(values map[string]any) (TPMAttestationStatementFormat, bool) {
	version, ok := values["ver"].(string)
	if !ok {
		return TPMAttestationStatementFormat{}, false
	}

	algorithm, ok := integer(values["alg"])
	if !ok {
		return TPMAttestationStatementFormat{}, false
	}

	chain, ok := x509Chain(values["x5c"])
	if !ok {
		return TPMAttestationStatementFormat{}, false
	}

	signature, ok := values["sig"].([]byte)
	if !ok {
		return TPMAttestationStatementFormat{}, false
	}

	certInfo, ok := values["certInfo"].([]byte)
	if !ok {
		return TPMAttestationStatementFormat{}, false
	}

	publicArea, ok := values["pubArea"].([]byte)
	if !ok {
		return TPMAttestationStatementFormat{}, false
	}

	return TPMAttestationStatementFormat{
		Version:   version,
		Algorithm: cose.Algorithm(algorithm),
		X509Chain: chain,
		Signature: signature,
		CertInfo:  certInfo,
		PubArea:   publicArea,
	}, true
}

func integer(value any) (int64, bool) {
	switch value := value.(type) {
	case int:
		return int64(value), true
	case int8:
		return int64(value), true
	case int16:
		return int64(value), true
	case int32:
		return int64(value), true
	case int64:
		return value, true
	case uint:
		if uint64(value) <= uint64(^uint64(0)>>1) {
			return int64(value), true
		}
	case uint8:
		return int64(value), true
	case uint16:
		return int64(value), true
	case uint32:
		return int64(value), true
	case uint64:
		if value <= uint64(^uint64(0)>>1) {
			return int64(value), true
		}
	}

	return 0, false
}

func x509Chain(raw any) ([][]byte, bool) {
	if chain, ok := raw.([][]byte); ok {
		return chain, true
	}

	items, ok := raw.([]any)
	if !ok {
		return nil, false
	}

	chain := make([][]byte, 0, len(items))
	for _, item := range items {
		certificate, ok := item.([]byte)
		if !ok {
			return nil, false
		}

		chain = append(chain, certificate)
	}

	return chain, true
}
