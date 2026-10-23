package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/telesma-app/ctap/cose"
)

func TestVerifyPacked(t *testing.T) {
	credentialKey := generateP256Key(t)
	message := []byte("packed attestation")
	signature := signES256(t, credentialKey, message)

	t.Run("self", func(t *testing.T) {
		verification, err := VerifyPacked(
			PackedAttestationStatementFormat{
				Algorithm: cose.AlgorithmES256,
				Signature: signature,
			},
			false,
			&credentialKey.PublicKey,
			cose.AlgorithmES256,
			message,
		)
		if err != nil {
			t.Fatalf("VerifyPacked() error = %v", err)
		}

		if verification.Type != TypeSelf || verification.SignatureValid == nil || !*verification.SignatureValid {
			t.Fatalf("VerifyPacked() = %#v, want valid self attestation", verification)
		}
	})

	t.Run("basic", func(t *testing.T) {
		attestationKey := generateP256Key(t)
		certificate := certificateDER(t, attestationKey)

		verification, err := VerifyPacked(
			PackedAttestationStatementFormat{
				Algorithm: cose.AlgorithmES256,
				Signature: signES256(t, attestationKey, message),
				X509Chain: [][]byte{certificate},
			},
			false,
			&credentialKey.PublicKey,
			cose.AlgorithmES256,
			message,
		)
		if err != nil {
			t.Fatalf("VerifyPacked() error = %v", err)
		}

		if verification.Type != TypeBasic || verification.SignatureValid == nil || !*verification.SignatureValid {
			t.Fatalf("VerifyPacked() = %#v, want valid basic attestation", verification)
		}

		if len(verification.CertificateChain) != 1 {
			t.Fatalf("certificate chain length = %d, want 1", len(verification.CertificateChain))
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		corrupt := append([]byte(nil), signature...)
		corrupt[len(corrupt)-1] ^= 0xff

		verification, err := VerifyPacked(
			PackedAttestationStatementFormat{
				Algorithm: cose.AlgorithmES256,
				Signature: corrupt,
			},
			false,
			&credentialKey.PublicKey,
			cose.AlgorithmES256,
			message,
		)
		if !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("VerifyPacked() error = %v, want %v", err, ErrSignatureInvalid)
		}

		if verification.SignatureValid == nil || *verification.SignatureValid {
			t.Fatalf("signature valid = %v, want false", verification.SignatureValid)
		}
	})

	t.Run("ECDAA unsupported", func(t *testing.T) {
		verification, err := VerifyPacked(
			PackedAttestationStatementFormat{},
			true,
			&credentialKey.PublicKey,
			cose.AlgorithmES256,
			message,
		)
		if !errors.Is(err, ErrFormatUnsupported) {
			t.Fatalf("VerifyPacked() error = %v, want %v", err, ErrFormatUnsupported)
		}

		if verification.Type != TypeUnsupported {
			t.Fatalf("attestation type = %q, want %q", verification.Type, TypeUnsupported)
		}
	})
}

func TestVerifyFIDOU2F(t *testing.T) {
	credentialKey := generateP256Key(t)
	attestationKey := generateP256Key(t)
	rpIDHash := sha256.Sum256([]byte("example.test"))
	clientDataHash := sha256.Sum256([]byte("client data"))
	credentialID := []byte("credential")

	publicKey, err := credentialKey.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("credential public key bytes: %v", err)
	}

	signedData := make([]byte, 0, 1+len(rpIDHash)+len(clientDataHash)+len(credentialID)+len(publicKey))
	signedData = append(signedData, 0)
	signedData = append(signedData, rpIDHash[:]...)
	signedData = append(signedData, clientDataHash[:]...)
	signedData = append(signedData, credentialID...)
	signedData = append(signedData, publicKey...)

	verification, err := VerifyFIDOU2F(
		FIDOU2FAttestationStatementFormat{
			X509Chain: [][]byte{certificateDER(t, attestationKey)},
			Signature: signES256(t, attestationKey, signedData),
		},
		&credentialKey.PublicKey,
		cose.AlgorithmES256,
		rpIDHash[:],
		clientDataHash[:],
		credentialID,
	)
	if err != nil {
		t.Fatalf("VerifyFIDOU2F() error = %v", err)
	}

	if verification.Type != TypeBasic || verification.SignatureValid == nil || !*verification.SignatureValid {
		t.Fatalf("VerifyFIDOU2F() = %#v, want valid basic attestation", verification)
	}
}

func generateP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}

	return key
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, message []byte) []byte {
	t.Helper()

	digest := sha256.Sum256(message)

	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}

	return signature
}

func certificateDER(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test attestation"},
		NotBefore:             time.Unix(1, 0),
		NotAfter:              time.Unix(2, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return certificate
}
