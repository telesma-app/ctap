package cose

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/fxamacker/cbor/v2"
)

func TestRegistryIdentifiers(t *testing.T) {
	tests := []struct {
		name string
		got  int
		want int
	}{
		{name: "ES256K", got: int(AlgorithmES256K), want: -47},
		{name: "EdDSA", got: int(AlgorithmEdDSA), want: -8},
		{name: "RS1", got: int(AlgorithmRS1), want: -65535},
		{name: "Ed448", got: EllipticCurveEd448, want: 7},
		{name: "secp256k1", got: EllipticCurveSecp256k1, want: 8},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("identifier = %d, want %d", test.got, test.want)
			}
		})
	}
}

func TestRegistryCredentialKeysCBORRoundTrip(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("registry algorithms in this test are intentionally unavailable in FIPS 140-3 mode")
	}

	secp256k1Key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate secp256k1 key: %v", err)
	}

	_, ed448Key, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed448 key: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("create CTAP2 encoding mode: %v", err)
	}

	message := []byte("registry CBOR round trip")

	tests := []struct {
		name      string
		algorithm Algorithm
		key       any
	}{
		{name: "ES256K", algorithm: AlgorithmES256K, key: secp256k1Key},
		{name: "Ed448", algorithm: AlgorithmEdDSA, key: ed448Key},
		{name: "RS1", algorithm: AlgorithmRS1, key: rsaKey},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := encMode.Marshal(credentialKey(test.key, test.algorithm))
			if err != nil {
				t.Fatalf("encode credential key: %v", err)
			}

			var decoded Key
			if err := cbor.Unmarshal(encoded, &decoded); err != nil {
				t.Fatalf("decode credential key: %v", err)
			}

			publicKey, err := decoded.PublicKey()
			if err != nil {
				t.Fatalf("convert public key: %v", err)
			}

			signature := signTestMessage(t, test.key, test.algorithm, message)
			if err := VerifySignature(publicKey, test.algorithm, message, signature); err != nil {
				t.Fatalf("verify signature: %v", err)
			}
		})
	}
}

func TestRegistryCredentialKeyAlgorithmMismatch(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("blocked algorithms take precedence over mismatch validation in FIPS 140-3 mode")
	}

	p256 := generateECDSAKey(t, elliptic.P256())

	secp256k1Key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate secp256k1 key: %v", err)
	}

	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}

	_, ed448Key, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed448 key: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	tests := []struct {
		name string
		key  Key
	}{
		{name: "ES256K with P-256 key", key: credentialKey(p256, AlgorithmES256K)},
		{name: "ES256 with secp256k1 key", key: credentialKey(secp256k1Key, AlgorithmES256)},
		{name: "Ed25519 with Ed448 key", key: credentialKey(ed448Key, AlgorithmEd25519)},
		{name: "RS1 with EC2 key", key: credentialKey(p256, AlgorithmRS1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.key.PublicKey(); !errors.Is(err, ErrKeyAlgorithmMismatch) {
				t.Fatalf("PublicKey error = %v, want %v", err, ErrKeyAlgorithmMismatch)
			}
		})
	}

	message := []byte("algorithm mismatch")
	if err := VerifySignature(secp256k1Key.PubKey(), AlgorithmES256, message, nil); !errors.Is(err, ErrKeyAlgorithmMismatch) {
		t.Fatalf("secp256k1/ES256 error = %v, want %v", err, ErrKeyAlgorithmMismatch)
	}

	if err := VerifySignature(&p256.PublicKey, AlgorithmES256K, message, nil); !errors.Is(err, ErrKeyAlgorithmMismatch) {
		t.Fatalf("P-256/ES256K error = %v, want %v", err, ErrKeyAlgorithmMismatch)
	}

	if err := VerifySignature(ed448Key.Public(), AlgorithmEd25519, message, nil); !errors.Is(err, ErrKeyAlgorithmMismatch) {
		t.Fatalf("Ed448/Ed25519 error = %v, want %v", err, ErrKeyAlgorithmMismatch)
	}

	if err := VerifySignature(ed25519Key.Public(), AlgorithmEdDSA, message, []byte("invalid")); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Ed25519/EdDSA error = %v, want %v", err, ErrInvalidSignature)
	}

	if err := VerifySignature(&rsaKey.PublicKey, AlgorithmES256K, message, nil); !errors.Is(err, ErrKeyAlgorithmMismatch) {
		t.Fatalf("RSA/ES256K error = %v, want %v", err, ErrKeyAlgorithmMismatch)
	}
}

func TestRegistryCredentialPublicKeyValidation(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("registry algorithms in this test are intentionally unavailable in FIPS 140-3 mode")
	}

	_, ed448Key, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed448 key: %v", err)
	}

	secp256k1Key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate secp256k1 key: %v", err)
	}

	ed448Credential := credentialKey(ed448Key, AlgorithmEdDSA)
	secp256k1Credential := credentialKey(secp256k1Key, AlgorithmES256K)

	tests := []struct {
		name   string
		key    Key
		mutate func(Key)
	}{
		{name: "Ed448 missing x", key: ed448Credential, mutate: func(key Key) { delete(key, OKPKeyParameterX) }},
		{name: "Ed448 invalid x type", key: ed448Credential, mutate: func(key Key) { key[OKPKeyParameterX] = "x" }},
		{name: "Ed448 short x", key: ed448Credential, mutate: func(key Key) { key[OKPKeyParameterX] = make([]byte, ed448.PublicKeySize-1) }},
		{name: "Ed448 long x", key: ed448Credential, mutate: func(key Key) { key[OKPKeyParameterX] = make([]byte, ed448.PublicKeySize+1) }},
		{name: "Ed448 invalid point", key: ed448Credential, mutate: func(key Key) {
			encoded := make([]byte, ed448.PublicKeySize)
			encoded[ed448.PublicKeySize-1] = 1
			key[OKPKeyParameterX] = encoded
		}},
		{name: "Ed448 identity", key: ed448Credential, mutate: func(key Key) {
			encoded := make([]byte, ed448.PublicKeySize)
			encoded[0] = 1
			key[OKPKeyParameterX] = encoded
		}},
		{name: "secp256k1 missing x", key: secp256k1Credential, mutate: func(key Key) { delete(key, EC2KeyParameterX) }},
		{name: "secp256k1 invalid x type", key: secp256k1Credential, mutate: func(key Key) { key[EC2KeyParameterX] = "x" }},
		{name: "secp256k1 short x", key: secp256k1Credential, mutate: func(key Key) { key[EC2KeyParameterX] = make([]byte, 31) }},
		{name: "secp256k1 long x", key: secp256k1Credential, mutate: func(key Key) { key[EC2KeyParameterX] = make([]byte, 33) }},
		{name: "secp256k1 missing y", key: secp256k1Credential, mutate: func(key Key) { delete(key, EC2KeyParameterY) }},
		{name: "secp256k1 invalid y type", key: secp256k1Credential, mutate: func(key Key) { key[EC2KeyParameterY] = false }},
		{name: "secp256k1 short y", key: secp256k1Credential, mutate: func(key Key) { key[EC2KeyParameterY] = make([]byte, 31) }},
		{name: "secp256k1 long y", key: secp256k1Credential, mutate: func(key Key) { key[EC2KeyParameterY] = make([]byte, 33) }},
		{name: "secp256k1 point outside curve", key: secp256k1Credential, mutate: func(key Key) {
			key[EC2KeyParameterX] = make([]byte, 32)
			key[EC2KeyParameterY] = make([]byte, 32)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := cloneKey(test.key)
			test.mutate(key)

			if _, err := key.PublicKey(); err == nil {
				t.Fatal("PublicKey succeeded")
			}
		})
	}
}

func TestRegistryVerifySignatureRejectsMalformedSignatures(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("blocked algorithms take precedence over signature validation in FIPS 140-3 mode")
	}

	secp256k1Key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate secp256k1 key: %v", err)
	}

	_, ed448Key, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed448 key: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	message := []byte("malformed registry signature")

	tests := []struct {
		name      string
		publicKey any
		algorithm Algorithm
		signature []byte
	}{
		{name: "ES256K empty", publicKey: secp256k1Key.PubKey(), algorithm: AlgorithmES256K},
		{name: "ES256K malformed DER", publicKey: secp256k1Key.PubKey(), algorithm: AlgorithmES256K, signature: []byte{0x30, 0x01, 0x00}},
		{name: "Ed448 short", publicKey: ed448Key.Public(), algorithm: AlgorithmEdDSA, signature: make([]byte, ed448.SignatureSize-1)},
		{name: "Ed448 long", publicKey: ed448Key.Public(), algorithm: AlgorithmEdDSA, signature: make([]byte, ed448.SignatureSize+1)},
		{name: "RS1 empty", publicKey: &rsaKey.PublicKey, algorithm: AlgorithmRS1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := VerifySignature(test.publicKey, test.algorithm, message, test.signature); !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("VerifySignature error = %v, want %v", err, ErrInvalidSignature)
			}
		})
	}
}
