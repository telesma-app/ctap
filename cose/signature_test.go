package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func TestCredentialKeyAndSignatureAlgorithms(t *testing.T) {
	p256 := generateECDSAKey(t, elliptic.P256())
	p384 := generateECDSAKey(t, elliptic.P384())
	p521 := generateECDSAKey(t, elliptic.P521())

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}

	var (
		ed448Key     ed448.PrivateKey
		secp256k1Key *secp256k1.PrivateKey
	)
	if !fips140.Enabled() {
		_, ed448Key, err = ed448.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate Ed448 key: %v", err)
		}

		secp256k1Key, err = secp256k1.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("generate secp256k1 key: %v", err)
		}
	}

	tests := []struct {
		name      string
		algorithm Algorithm
		key       any
		fipsBlock bool
	}{
		{name: "ES256", algorithm: AlgorithmES256, key: p256},
		{name: "ESP256", algorithm: AlgorithmESP256, key: p256},
		{name: "ES384", algorithm: AlgorithmES384, key: p384},
		{name: "ESP384", algorithm: AlgorithmESP384, key: p384},
		{name: "ES512", algorithm: AlgorithmES512, key: p521},
		{name: "ESP512", algorithm: AlgorithmESP512, key: p521},
		{name: "EdDSA", algorithm: AlgorithmEdDSA, key: ed25519Key},
		{name: "EdDSA Ed448", algorithm: AlgorithmEdDSA, key: ed448Key, fipsBlock: true},
		{name: "Ed25519", algorithm: AlgorithmEd25519, key: ed25519Key},
		{name: "ES256K", algorithm: AlgorithmES256K, key: secp256k1Key, fipsBlock: true},
		{name: "RS256", algorithm: AlgorithmRS256, key: rsaKey},
		{name: "RS384", algorithm: AlgorithmRS384, key: rsaKey},
		{name: "RS512", algorithm: AlgorithmRS512, key: rsaKey},
		{name: "RS1", algorithm: AlgorithmRS1, key: rsaKey, fipsBlock: true},
		{name: "PS256", algorithm: AlgorithmPS256, key: rsaKey},
		{name: "PS384", algorithm: AlgorithmPS384, key: rsaKey},
		{name: "PS512", algorithm: AlgorithmPS512, key: rsaKey},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if fips140.Enabled() && test.fipsBlock {
				t.Skip("algorithm is intentionally unavailable in FIPS 140-3 mode")
			}

			message := []byte("credential signature message")
			key := credentialKey(test.key, test.algorithm)
			key[2] = []byte("optional key ID")

			algorithm, err := key.Algorithm()
			if err != nil {
				t.Fatalf("read algorithm: %v", err)
			}

			if algorithm != test.algorithm {
				t.Fatalf("algorithm = %d, want %d", algorithm, test.algorithm)
			}

			publicKey, err := key.PublicKey()
			if err != nil {
				t.Fatalf("convert public key: %v", err)
			}

			signature := signTestMessage(t, test.key, test.algorithm, message)
			if err := VerifySignature(publicKey, test.algorithm, message, signature); err != nil {
				t.Fatalf("verify signature: %v", err)
			}

			corrupt := append([]byte(nil), signature...)

			corrupt[len(corrupt)-1] ^= 0x01
			if err := VerifySignature(publicKey, test.algorithm, message, corrupt); !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("corrupt signature error = %v, want %v", err, ErrInvalidSignature)
			}
		})
	}
}

func TestVerifySignatureRejectsUnsupportedAndMismatchedAlgorithms(t *testing.T) {
	p256 := generateECDSAKey(t, elliptic.P256())
	p384 := generateECDSAKey(t, elliptic.P384())
	message := []byte("message")
	signature := signTestMessage(t, p256, AlgorithmES256, message)

	if err := VerifySignature(&p384.PublicKey, AlgorithmES256, message, signature); !errors.Is(
		err,
		ErrKeyAlgorithmMismatch,
	) {
		t.Fatalf("curve mismatch error = %v, want %v", err, ErrKeyAlgorithmMismatch)
	}

	if err := VerifySignature(&p256.PublicKey, Algorithm(12345), message, signature); !errors.Is(
		err,
		ErrUnsupportedAlgorithm,
	) {
		t.Fatalf("unsupported algorithm error = %v, want %v", err, ErrUnsupportedAlgorithm)
	}
}

func TestCredentialPublicKeyValidation(t *testing.T) {
	valid := credentialKey(generateECDSAKey(t, elliptic.P256()), AlgorithmES256)
	tests := []struct {
		name string
		key  Key
		want error
	}{
		{name: "nil", key: nil},
		{name: "missing key type", key: Key{KeyParameterAlg: AlgorithmES256}},
		{name: "unsupported key type", key: Key{KeyParameterKty: 99}, want: ErrUnsupportedKey},
		{
			name: "algorithm curve mismatch",
			key:  credentialKey(generateECDSAKey(t, elliptic.P384()), AlgorithmES256),
			want: ErrKeyAlgorithmMismatch,
		},
		{
			name: "unsupported algorithm",
			key:  credentialKey(generateECDSAKey(t, elliptic.P256()), Algorithm(12345)),
			want: ErrUnsupportedAlgorithm,
		},
		{
			name: "unsupported curve",
			key: Key{
				KeyParameterKty:    KeyTypeEC2,
				KeyParameterAlg:    AlgorithmES256,
				EC2KeyParameterCrv: 99,
				EC2KeyParameterX:   make([]byte, 32),
				EC2KeyParameterY:   make([]byte, 32),
			},
			want: ErrUnsupportedKey,
		},
		{
			name: "short coordinate",
			key: Key{
				KeyParameterKty:    KeyTypeEC2,
				KeyParameterAlg:    AlgorithmES256,
				EC2KeyParameterCrv: EllipticCurveP256,
				EC2KeyParameterX:   make([]byte, 31),
				EC2KeyParameterY:   make([]byte, 32),
			},
		},
		{
			name: "short Ed25519 key",
			key: Key{
				KeyParameterKty:    KeyTypeOKP,
				KeyParameterAlg:    AlgorithmEd25519,
				OKPKeyParameterCrv: EllipticCurveEd25519,
				OKPKeyParameterX:   make([]byte, 31),
			},
		},
		{
			name: "small RSA modulus",
			key: Key{
				KeyParameterKty:  KeyTypeRSA,
				KeyParameterAlg:  AlgorithmRS256,
				RSAKeyParameterN: []byte{0x03},
				RSAKeyParameterE: []byte{0x03},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.key.PublicKey()
			if err == nil {
				t.Fatal("PublicKey succeeded")
			}

			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("PublicKey error = %v, want %v", err, test.want)
			}
		})
	}

	valid[KeyParameterAlg] = uint64(math.MaxInt64) + 1
	if _, err := valid.Algorithm(); err == nil {
		t.Fatal("Algorithm accepted overflowing unsigned value")
	}
}

func credentialKey(key any, algorithm Algorithm) Key {
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		size := (key.Curve.Params().BitSize + 7) / 8

		encoded, err := key.PublicKey.Bytes()
		if err != nil {
			panic(err)
		}

		curve := EllipticCurveP256

		switch key.Curve {
		case elliptic.P384():
			curve = EllipticCurveP384
		case elliptic.P521():
			curve = EllipticCurveP521
		}

		return Key{
			KeyParameterKty:    KeyTypeEC2,
			KeyParameterAlg:    algorithm,
			EC2KeyParameterCrv: curve,
			EC2KeyParameterX:   append([]byte(nil), encoded[1:1+size]...),
			EC2KeyParameterY:   append([]byte(nil), encoded[1+size:]...),
		}
	case ed25519.PrivateKey:
		return Key{
			KeyParameterKty:    KeyTypeOKP,
			KeyParameterAlg:    algorithm,
			OKPKeyParameterCrv: EllipticCurveEd25519,
			OKPKeyParameterX:   []byte(key.Public().(ed25519.PublicKey)),
		}
	case ed448.PrivateKey:
		return Key{
			KeyParameterKty:    KeyTypeOKP,
			KeyParameterAlg:    algorithm,
			OKPKeyParameterCrv: EllipticCurveEd448,
			OKPKeyParameterX:   []byte(key.Public().(ed448.PublicKey)),
		}
	case *secp256k1.PrivateKey:
		encoded := key.PubKey().SerializeUncompressed()

		return Key{
			KeyParameterKty:    KeyTypeEC2,
			KeyParameterAlg:    algorithm,
			EC2KeyParameterCrv: EllipticCurveSecp256k1,
			EC2KeyParameterX:   append([]byte(nil), encoded[1:33]...),
			EC2KeyParameterY:   append([]byte(nil), encoded[33:]...),
		}
	case *rsa.PrivateKey:
		return Key{
			KeyParameterKty:  KeyTypeRSA,
			KeyParameterAlg:  algorithm,
			RSAKeyParameterN: key.N.Bytes(),
			RSAKeyParameterE: big.NewInt(int64(key.E)).Bytes(),
		}
	default:
		panic("unsupported test credential key")
	}
}

func signTestMessage(t *testing.T, key any, algorithm Algorithm, message []byte) []byte {
	t.Helper()

	var hash crypto.Hash

	switch algorithm {
	case AlgorithmES256, AlgorithmESP256, AlgorithmES256K, AlgorithmRS256, AlgorithmPS256:
		hash = crypto.SHA256
	case AlgorithmES384, AlgorithmESP384, AlgorithmRS384, AlgorithmPS384:
		hash = crypto.SHA384
	case AlgorithmES512, AlgorithmESP512, AlgorithmRS512, AlgorithmPS512:
		hash = crypto.SHA512
	case AlgorithmRS1:
		hash = crypto.SHA1
	case AlgorithmEdDSA, AlgorithmEd25519:
		switch key := key.(type) {
		case ed25519.PrivateKey:
			return ed25519.Sign(key, message)
		case ed448.PrivateKey:
			return ed448.Sign(key, message, "")
		default:
			t.Fatalf("unsupported EdDSA test signing key %T", key)
		}
	default:
		t.Fatalf("unsupported test algorithm %d", algorithm)
	}

	hasher := hash.New()
	_, _ = hasher.Write(message)
	digest := hasher.Sum(nil)

	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		signature, err := ecdsa.SignASN1(rand.Reader, key, digest)
		if err != nil {
			t.Fatalf("sign ECDSA: %v", err)
		}

		return signature
	case *secp256k1.PrivateKey:
		return secp256k1ecdsa.Sign(key, digest).Serialize()
	case *rsa.PrivateKey:
		if algorithm == AlgorithmPS256 || algorithm == AlgorithmPS384 || algorithm == AlgorithmPS512 {
			signature, err := rsa.SignPSS(rand.Reader, key, hash, digest, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hash,
			})
			if err != nil {
				t.Fatalf("sign RSA-PSS: %v", err)
			}

			return signature
		}

		signature, err := rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
		if err != nil {
			t.Fatalf("sign RSA: %v", err)
		}

		return signature
	default:
		t.Fatalf("unsupported test signing key %T", key)
		return nil
	}
}

func generateECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	return key
}
