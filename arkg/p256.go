package arkg

import (
	"crypto"
	"crypto/ecdh"
	cryptofips140 "crypto/fips140"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"math/big"

	"filippo.io/nistec"
	"github.com/cloudflare/circl/expander"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/fips140"
)

const p256ContextLimit = 64

var p256ScalarOrder = new(big.Int).SetBytes([]byte{
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
	0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
})

// DeriveP256 derives a P-256 public key and its key handle from an ARKG-P256
// public seed. inputKeyMaterial should contain at least 256 bits of entropy.
// It returns [fips140.ErrNotAllowed] when FIPS 140-3 mode is enabled because
// the implementation uses cryptography outside the Go Cryptographic Module.
func DeriveP256(publicSeed cose.Key, inputKeyMaterial, context []byte) (cose.Key, []byte, error) {
	if cryptofips140.Enabled() {
		return nil, nil, &fips140.PolicyError{Operation: "ARKG-P256"}
	}

	// Validate the ARKG-P256 inputs and COSE binding.
	if len(context) > p256ContextLimit {
		return nil, nil, fmt.Errorf("arkg: P-256 context is %d bytes, maximum is %d", len(context), p256ContextLimit)
	}

	if err := requireInteger(publicSeed, cose.KeyParameterKty, cose.KeyTypeARKGPublicSeedPlaceholder, "kty"); err != nil {
		return nil, nil, err
	}

	if _, found := publicSeed[cose.KeyParameterAlg]; found {
		if err := requireInteger(publicSeed, cose.KeyParameterAlg, int64(cose.AlgorithmARKGP256Placeholder), "alg"); err != nil {
			return nil, nil, err
		}
	}

	derivedAlgorithm, hasDerivedAlgorithm := publicSeed[-3]
	if hasDerivedAlgorithm && !isAlgorithmIdentifier(derivedAlgorithm) {
		return nil, nil, fmt.Errorf("arkg: P-256 public seed has invalid dkalg type %T", derivedAlgorithm)
	}

	// Decode (pk_bl, pk_kem) from the public seed.
	blindingKey, err := nestedKey(publicSeed, -1, "blinding public key")
	if err != nil {
		return nil, nil, err
	}

	blindingPoint, err := p256PublicKey(blindingKey, cose.AlgorithmES256, "blinding public key")
	if err != nil {
		return nil, nil, err
	}

	kemKey, err := nestedKey(publicSeed, -2, "KEM public key")
	if err != nil {
		return nil, nil, err
	}

	kemCurvePoint, err := p256PublicKey(kemKey, cose.AlgorithmECDHESHKDF256, "KEM public key")
	if err != nil {
		return nil, nil, err
	}

	kemPoint, err := ecdh.P256().NewPublicKey(kemCurvePoint.Bytes())
	if err != nil {
		return nil, nil, fmt.Errorf("arkg: invalid P-256 KEM public key: %w", err)
	}

	// Derive ctx_bl and ctx_kem from the application context.
	contextWithLength := make([]byte, 1, 1+len(context))
	contextWithLength[0] = byte(len(context))
	contextWithLength = append(contextWithLength, context...)

	blindingContext := append([]byte("ARKG-Derive-Key-BL."), contextWithLength...)
	kemContext := append([]byte("ARKG-Derive-Key-KEM."), contextWithLength...)

	// (ikm_tau, c) = KEM-Encaps(pk_kem, ikm, ctx_kem).
	sharedSecret, keyHandle, err := p256Encapsulate(kemPoint, inputKeyMaterial, kemContext)
	if err != nil {
		return nil, nil, err
	}
	defer clear(sharedSecret)

	// tau = BL-PRF(ikm_tau, ctx_bl); pk' = pk_bl + tau * G.
	blindingDST := append([]byte("ARKG-BL-EC.ARKG-P256"), blindingContext...)

	blindingFactor := p256Scalar(sharedSecret, blindingDST)
	defer clear(blindingFactor)

	blindingFactorPoint, err := nistec.NewP256Point().ScalarBaseMult(blindingFactor)
	if err != nil {
		return nil, nil, fmt.Errorf("arkg: derive P-256 blinding factor point: %w", err)
	}

	derivedPoint := nistec.NewP256Point().Add(blindingPoint, blindingFactorPoint)
	if derivedPoint.IsInfinity() == 1 {
		return nil, nil, errors.New("arkg: P-256 derived public key is the identity point")
	}

	encodedPoint := derivedPoint.Bytes()

	// Encode pk' as a COSE key and propagate the optional dkalg identifier.
	derivedKey := cose.Key{
		cose.KeyParameterKty:    cose.KeyTypeEC2,
		cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
		cose.EC2KeyParameterX:   encodedPoint[1:33:33],
		cose.EC2KeyParameterY:   encodedPoint[33:65:65],
	}
	if hasDerivedAlgorithm {
		derivedKey[cose.KeyParameterAlg] = derivedAlgorithm
	}

	return derivedKey, keyHandle, nil
}

func p256Encapsulate(publicKey *ecdh.PublicKey, inputKeyMaterial, context []byte) ([]byte, []byte, error) {
	const kemDST = "ARKG-ECDH.ARKG-P256"

	// (pk', sk') = Sub-KEM-Derive-Key-Pair(ikm).
	privateKeyBytes := p256Scalar(inputKeyMaterial, []byte("ARKG-KEM-ECDH-KG."+kemDST))
	defer clear(privateKeyBytes)

	privateKey, err := ecdh.P256().NewPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("arkg: create P-256 KEM private key: %w", err)
	}

	// k' = ECDH(pk, sk'); prk = HKDF-Extract(k').
	secret, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("arkg: derive P-256 KEM secret: %w", err)
	}
	defer clear(secret)

	prk, err := hkdf.Extract(sha256.New, secret, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("arkg: extract P-256 KEM secret: %w", err)
	}
	defer clear(prk)

	// mk = HKDF-Expand(prk); t = HMAC(mk, c'); c = t || c'.
	macInfo := append([]byte("ARKG-KEM-HMAC-mac."+kemDST), context...)

	macKey, err := hkdf.Expand(sha256.New, prk, string(macInfo), sha256.Size)
	if err != nil {
		return nil, nil, fmt.Errorf("arkg: expand P-256 KEM MAC key: %w", err)
	}
	defer clear(macKey)

	encapsulation := privateKey.PublicKey().Bytes()

	mac := hmac.New(sha256.New, macKey)
	_, _ = mac.Write(encapsulation)

	tag := mac.Sum(nil)
	defer clear(tag)

	keyHandle := make([]byte, 16+len(encapsulation))
	copy(keyHandle, tag[:16])
	copy(keyHandle[16:], encapsulation)

	// k = HKDF-Expand(prk).
	sharedInfo := append([]byte("ARKG-KEM-HMAC-shared."+kemDST), context...)

	sharedSecret, err := hkdf.Expand(sha256.New, prk, string(sharedInfo), len(secret))
	if err != nil {
		return nil, nil, fmt.Errorf("arkg: expand P-256 shared secret: %w", err)
	}

	return sharedSecret, keyHandle, nil
}

func p256PublicKey(k cose.Key, algorithm cose.Algorithm, name string) (*nistec.P256Point, error) {
	// Validate the COSE parameters required by ARKG-P256.
	if err := requireInteger(k, cose.KeyParameterKty, cose.KeyTypeEC2, name+" kty"); err != nil {
		return nil, err
	}

	if _, found := k[cose.KeyParameterAlg]; found {
		if err := requireInteger(k, cose.KeyParameterAlg, int64(algorithm), name+" alg"); err != nil {
			return nil, err
		}
	}

	if err := requireInteger(k, cose.EC2KeyParameterCrv, cose.EllipticCurveP256, name+" crv"); err != nil {
		return nil, err
	}

	// Decode the COSE coordinates as an SEC 1 public point.
	x, err := keyBytes(k, cose.EC2KeyParameterX, name+" x")
	if err != nil {
		return nil, err
	}

	y, err := keyBytes(k, cose.EC2KeyParameterY, name+" y")
	if err != nil {
		return nil, err
	}

	if len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("arkg: P-256 %s has invalid coordinate lengths x=%d y=%d", name, len(x), len(y))
	}

	encoded := make([]byte, 65)
	encoded[0] = 4
	copy(encoded[1:33], x)
	copy(encoded[33:], y)

	point, err := nistec.NewP256Point().SetBytes(encoded)
	if err != nil {
		return nil, fmt.Errorf("arkg: invalid P-256 %s: %w", name, err)
	}

	return point, nil
}

func isAlgorithmIdentifier(value any) bool {
	switch value.(type) {
	case string, cose.Algorithm,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return true
	}

	return false
}

func p256Scalar(input, dst []byte) []byte {
	// Hash to the P-256 scalar field using expand_message_xmd with SHA-256.
	uniform := expander.NewExpanderMD(crypto.SHA256, dst).Expand(input, 48)

	scalar := new(big.Int).SetBytes(uniform)
	scalar.Mod(scalar, p256ScalarOrder)

	clear(uniform)

	return scalar.FillBytes(make([]byte, 32))
}

func requireInteger(k cose.Key, label int, want int64, name string) error {
	value, found := k[label]
	if !found {
		return fmt.Errorf("arkg: P-256 public seed is missing %s", name)
	}

	parsed, ok := integer(value)
	if !ok {
		return fmt.Errorf("arkg: P-256 public seed has invalid %s type %T", name, value)
	}

	if parsed != want {
		return fmt.Errorf("arkg: P-256 public seed has invalid %s %d, want %d", name, parsed, want)
	}

	return nil
}

func nestedKey(k cose.Key, label int, name string) (cose.Key, error) {
	value, found := k[label]
	if !found {
		return nil, fmt.Errorf("arkg: P-256 public seed is missing %s", name)
	}

	switch value := value.(type) {
	case cose.Key:
		return value, nil
	case map[int]any:
		return value, nil
	case map[any]any:
		result := make(cose.Key, len(value))
		for rawLabel, parameter := range value {
			label, ok := mapLabel(rawLabel)
			if !ok {
				return nil, fmt.Errorf("arkg: P-256 %s has invalid parameter label type %T", name, rawLabel)
			}

			result[label] = parameter
		}

		return result, nil
	default:
		return nil, fmt.Errorf("arkg: P-256 %s has invalid type %T", name, value)
	}
}

func keyBytes(k cose.Key, label int, name string) ([]byte, error) {
	value, found := k[label]
	if !found {
		return nil, fmt.Errorf("arkg: P-256 public seed is missing %s", name)
	}

	bytes, ok := value.([]byte)
	if !ok {
		return nil, fmt.Errorf("arkg: P-256 public seed has invalid %s type %T", name, value)
	}

	return bytes, nil
}

func mapLabel(value any) (int, bool) {
	parsed, ok := integer(value)
	if !ok || int64(int(parsed)) != parsed {
		return 0, false
	}

	return int(parsed), true
}

func integer(value any) (int64, bool) {
	switch value := value.(type) {
	case cose.Algorithm:
		return int64(value), true
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
		if uint64(value) <= math.MaxInt64 {
			return int64(value), true
		}
	case uint8:
		return int64(value), true
	case uint16:
		return int64(value), true
	case uint32:
		return int64(value), true
	case uint64:
		if value <= math.MaxInt64 {
			return int64(value), true
		}
	}

	return 0, false
}
