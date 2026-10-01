package cose

import (
	"crypto/ed25519"
	cryptofips140 "crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math"
	"math/big"
	"strconv"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	ctapfips140 "github.com/telesma-app/ctap/fips140"
)

func TestFIPS140SignatureGate(t *testing.T) {
	if !cryptofips140.Enabled() {
		t.Skip("requires Go FIPS 140-3 mode")
	}

	t.Run("blocked verification algorithms", func(t *testing.T) {
		tests := []struct {
			name      string
			publicKey any
			algorithm Algorithm
		}{
			{name: "RS1", publicKey: &rsa.PublicKey{}, algorithm: AlgorithmRS1},
			{name: "ES256K", publicKey: new(secp256k1.PublicKey), algorithm: AlgorithmES256K},
			{name: "Ed448", publicKey: ed448.PublicKey(make([]byte, ed448.PublicKeySize)), algorithm: AlgorithmEdDSA},
			{
				name:      "small RSA modulus",
				publicKey: &rsa.PublicKey{N: fips140TestRSAModulus(1024), E: 65537},
				algorithm: AlgorithmRS256,
			},
			{
				name:      "negative RSA modulus",
				publicKey: &rsa.PublicKey{N: new(big.Int).Neg(fips140TestRSAModulus(2048)), E: 65537},
				algorithm: AlgorithmRS256,
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				err := VerifySignature(test.publicKey, test.algorithm, nil, nil)
				assertFIPS140NotAllowed(t, err)
			})
		}
		t.Run("large RSA exponent", func(t *testing.T) {
			if strconv.IntSize == 32 {
				t.Skip("requires a 64-bit int")
			}
			exponent := int64(math.MaxInt32) + 2
			publicKey := &rsa.PublicKey{N: fips140TestRSAModulus(2048), E: int(exponent)}
			err := VerifySignature(publicKey, AlgorithmRS256, nil, nil)
			assertFIPS140NotAllowed(t, err)
		})
	})

	t.Run("blocked credential keys", func(t *testing.T) {
		tests := []struct {
			name string
			key  Key
		}{
			{
				name: "RS1",
				key: Key{
					KeyParameterKty:  KeyTypeRSA,
					KeyParameterAlg:  AlgorithmRS1,
					RSAKeyParameterN: fips140TestRSAModulus(2048).Bytes(),
					RSAKeyParameterE: []byte{0x01, 0x00, 0x01},
				},
			},
			{
				name: "secp256k1 curve with ES256",
				key: Key{
					KeyParameterKty:    KeyTypeEC2,
					KeyParameterAlg:    AlgorithmES256,
					EC2KeyParameterCrv: EllipticCurveSecp256k1,
				},
			},
			{
				name: "Ed448 curve with generic EdDSA",
				key: Key{
					KeyParameterKty:    KeyTypeOKP,
					KeyParameterAlg:    AlgorithmEdDSA,
					OKPKeyParameterCrv: EllipticCurveEd448,
					OKPKeyParameterX:   make([]byte, ed448.PublicKeySize),
				},
			},
			{
				name: "odd RSA modulus bit length and small exponent",
				key: Key{
					KeyParameterKty:  KeyTypeRSA,
					KeyParameterAlg:  AlgorithmRS256,
					RSAKeyParameterN: fips140TestRSAModulus(2049).Bytes(),
					RSAKeyParameterE: []byte{0x03},
				},
			},
			{
				name: "large RSA exponent",
				key: Key{
					KeyParameterKty:  KeyTypeRSA,
					KeyParameterAlg:  AlgorithmRS256,
					RSAKeyParameterN: fips140TestRSAModulus(2048).Bytes(),
					RSAKeyParameterE: big.NewInt(math.MaxInt32 + 2).Bytes(),
				},
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				_, err := test.key.PublicKey()
				assertFIPS140NotAllowed(t, err)
			})
		}
	})

	t.Run("unknown algorithm remains unsupported", func(t *testing.T) {
		err := VerifySignature(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)), Algorithm(12345), nil, nil)
		if !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Fatalf("VerifySignature error = %v, want %v", err, ErrUnsupportedAlgorithm)
		}
		if errors.Is(err, ctapfips140.ErrNotAllowed) {
			t.Fatalf("VerifySignature error = %v, must not be a FIPS policy rejection", err)
		}
	})

	t.Run("unhandled classifications fail closed", func(t *testing.T) {
		publicKey := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
		for _, test := range []struct {
			name      string
			algorithm Algorithm
			approval  fips140Approval
		}{
			{name: "verify-only algorithm without key policy", algorithm: AlgorithmEd25519, approval: fips140VerifyOnly},
			{name: "unknown approval", algorithm: AlgorithmEd25519, approval: fips140Approval(255)},
		} {
			t.Run(test.name, func(t *testing.T) {
				err := enforceFIPS140SignaturePolicy(publicKey, test.algorithm, signatureAlgorithm{
					kind: signatureEdDSA,
					fips: test.approval,
				})
				assertFIPS140NotAllowed(t, err)
			})
		}
	})

	t.Run("Ed25519 remains available", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate Ed25519 key: %v", err)
		}
		message := []byte("FIPS 140-3 Ed25519 verification")
		signature := ed25519.Sign(privateKey, message)
		key := credentialKey(privateKey, AlgorithmEdDSA)
		publicKey, err := key.PublicKey()
		if err != nil {
			t.Fatalf("PublicKey: %v", err)
		}
		if err := VerifySignature(publicKey, AlgorithmEdDSA, message, signature); err != nil {
			t.Fatalf("VerifySignature: %v", err)
		}
	})
}

func assertFIPS140NotAllowed(t testing.TB, err error) {
	t.Helper()
	if !errors.Is(err, ctapfips140.ErrNotAllowed) {
		t.Fatalf("error = %v, want errors.Is(error, %v)", err, ctapfips140.ErrNotAllowed)
	}
	var notAllowed *ctapfips140.PolicyError
	if !errors.As(err, &notAllowed) {
		t.Fatalf("error type = %T, want *fips140.PolicyError", err)
	}
}

func fips140TestRSAModulus(bits int) *big.Int {
	modulus := new(big.Int).SetBit(new(big.Int), bits-1, 1)
	return modulus.SetBit(modulus, 0, 1)
}

// TestFIPS140AlgorithmClassification pins every algorithm's classification, so
// an entry added without one fails here rather than at runtime.
func TestFIPS140AlgorithmClassification(t *testing.T) {
	want := map[Algorithm]fips140Approval{
		AlgorithmES256:   fips140Approved,
		AlgorithmESP256:  fips140Approved,
		AlgorithmES384:   fips140Approved,
		AlgorithmESP384:  fips140Approved,
		AlgorithmES512:   fips140Approved,
		AlgorithmESP512:  fips140Approved,
		AlgorithmEd25519: fips140Approved,
		AlgorithmRS256:   fips140Approved,
		AlgorithmRS384:   fips140Approved,
		AlgorithmRS512:   fips140Approved,
		AlgorithmPS256:   fips140Approved,
		AlgorithmPS384:   fips140Approved,
		AlgorithmPS512:   fips140Approved,
		AlgorithmEdDSA:   fips140VerifyOnly,
		AlgorithmES256K:  fips140NotApproved,
		AlgorithmRS1:     fips140NotApproved,
	}

	for algorithm, spec := range signatureAlgorithms {
		expected, listed := want[algorithm]
		if !listed {
			t.Errorf("algorithm %d is not classified by this test; classify it and update want", algorithm)
			continue
		}
		if spec.fips != expected {
			t.Errorf("algorithm %d classification = %d, want %d", algorithm, spec.fips, expected)
		}
	}
	for algorithm := range want {
		if _, registered := signatureAlgorithms[algorithm]; !registered {
			t.Errorf("algorithm %d is classified by this test but not registered", algorithm)
		}
	}

	for algorithm, expected := range want {
		if got := algorithm.FIPS140Approved(); got != (expected == fips140Approved) {
			t.Errorf(
				"Algorithm(%d).FIPS140Approved() = %v, want %v",
				algorithm, got, expected == fips140Approved,
			)
		}
	}

	if Algorithm(12345).FIPS140Approved() {
		t.Error("unregistered algorithm reported as approved")
	}
}
