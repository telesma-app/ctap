package attestation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/telesma-app/ctap/cose"
	ctapfips140 "github.com/telesma-app/ctap/fips140"
)

var (
	ErrStatementMalformed     = errors.New("attestation: malformed statement")
	ErrFormatUnsupported      = errors.New("attestation: format unsupported")
	ErrAlgorithmUnsupported   = errors.New("attestation: algorithm unsupported")
	ErrCredentialKeyMalformed = errors.New("attestation: malformed credential key")
	ErrSignatureInvalid       = errors.New("attestation: invalid signature")
)

// Type describes the attestation evidence established by statement verification.
type Type string

const (
	TypeNone        Type = "none"
	TypeSelf        Type = "self"
	TypeBasic       Type = "basic"
	TypeUnsupported Type = "unsupported"
)

// Verification is the format-level cryptographic result for an attestation statement.
// CertificateChain contains the statement's untrusted x5c values. Trust evaluation is
// a separate relying-party concern.
type Verification struct {
	Type             Type
	SignatureValid   *bool
	CertificateChain [][]byte
}

// VerifyPacked verifies a packed attestation statement. It does not establish
// trust in the statement certificate chain.
func VerifyPacked(
	statement PackedAttestationStatementFormat,
	ecdaaPresent bool,
	credentialPublicKey crypto.PublicKey,
	credentialAlgorithm cose.Algorithm,
	signedData []byte,
) (Verification, error) {
	if ecdaaPresent {
		return Verification{Type: TypeUnsupported}, ErrFormatUnsupported
	}

	if len(statement.X509Chain) == 0 {
		verification := Verification{Type: TypeSelf}
		if statement.Algorithm != credentialAlgorithm {
			return verification, fmt.Errorf(
				"%w: self attestation algorithm %d does not match credential algorithm %d",
				ErrStatementMalformed,
				statement.Algorithm,
				credentialAlgorithm,
			)
		}

		var err error

		verification.SignatureValid, err = verifySignature(
			credentialPublicKey,
			statement.Algorithm,
			signedData,
			statement.Signature,
		)

		return verification, err
	}

	verification := Verification{
		Type:             TypeBasic,
		CertificateChain: statement.X509Chain,
	}

	leaf, err := x509.ParseCertificate(statement.X509Chain[0])
	if err != nil {
		return verification, fmt.Errorf("%w: parse leaf certificate: %v", ErrStatementMalformed, err)
	}

	verification.SignatureValid, err = verifySignature(
		leaf.PublicKey,
		statement.Algorithm,
		signedData,
		statement.Signature,
	)

	return verification, err
}

// VerifyFIDOU2F verifies a FIDO U2F attestation statement. It does not
// establish trust in the statement certificate chain.
func VerifyFIDOU2F(
	statement FIDOU2FAttestationStatementFormat,
	credentialPublicKey crypto.PublicKey,
	credentialAlgorithm cose.Algorithm,
	rpIDHash []byte,
	clientDataHash []byte,
	credentialID []byte,
) (Verification, error) {
	verification := Verification{
		Type:             TypeBasic,
		CertificateChain: statement.X509Chain,
	}
	if len(statement.X509Chain) == 0 {
		return verification, fmt.Errorf("%w: missing certificate chain", ErrStatementMalformed)
	}

	key, ok := credentialPublicKey.(*ecdsa.PublicKey)
	if !ok || credentialAlgorithm != cose.AlgorithmES256 {
		return verification, fmt.Errorf("%w: FIDO U2F requires an ES256 credential key", ErrStatementMalformed)
	}

	encodedKey, err := key.Bytes()
	if err != nil {
		return verification, fmt.Errorf("%w: %v", ErrCredentialKeyMalformed, err)
	}

	signedData := make([]byte, 0, 1+len(rpIDHash)+len(clientDataHash)+len(credentialID)+len(encodedKey))
	signedData = append(signedData, 0)
	signedData = append(signedData, rpIDHash...)
	signedData = append(signedData, clientDataHash...)
	signedData = append(signedData, credentialID...)
	signedData = append(signedData, encodedKey...)

	leaf, err := x509.ParseCertificate(statement.X509Chain[0])
	if err != nil {
		return verification, fmt.Errorf("%w: parse leaf certificate: %v", ErrStatementMalformed, err)
	}

	verification.SignatureValid, err = verifySignature(
		leaf.PublicKey,
		cose.AlgorithmES256,
		signedData,
		statement.Signature,
	)

	return verification, err
}

func verifySignature(
	publicKey crypto.PublicKey,
	algorithm cose.Algorithm,
	message []byte,
	signature []byte,
) (*bool, error) {
	err := cose.VerifySignature(publicKey, algorithm, message, signature)
	if errors.Is(err, cose.ErrUnsupportedAlgorithm) ||
		errors.Is(err, cose.ErrUnsupportedKey) ||
		errors.Is(err, ctapfips140.ErrNotAllowed) {
		return nil, fmt.Errorf("%w: %w", ErrAlgorithmUnsupported, err)
	}

	valid := err == nil
	if err != nil {
		return &valid, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}

	return &valid, nil
}
