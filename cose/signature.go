package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	cryptofips140 "crypto/fips140"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/cloudflare/circl/ecc/goldilocks"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	ctapfips140 "github.com/telesma-app/ctap/fips140"
)

var (
	ErrUnsupportedAlgorithm = errors.New("cose: unsupported signature algorithm")
	ErrUnsupportedKey       = errors.New("cose: unsupported public key")
	ErrKeyAlgorithmMismatch = errors.New("cose: public key and signature algorithm mismatch")
	ErrInvalidSignature     = errors.New("cose: invalid signature")
)

// Algorithm returns the signature algorithm declared by the COSE key.
func (k Key) Algorithm() (Algorithm, error) {
	value, err := keyInteger(k, KeyParameterAlg, "alg")
	if err != nil {
		return 0, err
	}
	algorithm := Algorithm(value)
	if int64(algorithm) != value {
		return 0, fmt.Errorf("cose: algorithm %d overflows int", value)
	}

	return algorithm, nil
}

// PublicKey validates a credential COSE key and converts it to a supported public key type.
// Additional COSE key parameters are ignored.
func (k Key) PublicKey() (crypto.PublicKey, error) {
	if k == nil {
		return nil, errors.New("cose: nil credential key")
	}
	keyType, err := keyInteger(k, KeyParameterKty, "kty")
	if err != nil {
		return nil, err
	}

	var publicKey crypto.PublicKey
	switch keyType {
	case KeyTypeOKP:
		publicKey, err = k.okpPublicKey()
	case KeyTypeEC2:
		publicKey, err = k.ec2PublicKey()
	case KeyTypeRSA:
		publicKey, err = k.rsaPublicKey()
	default:
		return nil, fmt.Errorf("%w: key type %d", ErrUnsupportedKey, keyType)
	}
	if err != nil {
		return nil, err
	}
	algorithm, err := k.Algorithm()
	if err != nil {
		return nil, err
	}
	spec, found := signatureAlgorithms[algorithm]
	if !found {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, algorithm)
	}
	if err := enforceFIPS140SignaturePolicy(publicKey, algorithm, spec); err != nil {
		return nil, err
	}
	if err := validatePublicKeyAlgorithm(publicKey, spec); err != nil {
		return nil, err
	}

	return publicKey, nil
}

// VerifySignature verifies one COSE signature using a supported public key type.
func VerifySignature(publicKey crypto.PublicKey, algorithm Algorithm, message, signature []byte) error {
	spec, found := signatureAlgorithms[algorithm]
	if !found {
		return fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, algorithm)
	}
	if publicKey == nil {
		return ErrKeyAlgorithmMismatch
	}
	if err := enforceFIPS140SignaturePolicy(publicKey, algorithm, spec); err != nil {
		return err
	}
	if err := validatePublicKeyAlgorithm(publicKey, spec); err != nil {
		return err
	}

	switch spec.kind {
	case signatureEdDSA:
		switch key := publicKey.(type) {
		case ed25519.PublicKey:
			if spec.curve != 0 && spec.curve != EllipticCurveEd25519 {
				return ErrKeyAlgorithmMismatch
			}
			if !ed25519.Verify(key, message, signature) {
				return ErrInvalidSignature
			}
		case ed448.PublicKey:
			if spec.curve != 0 && spec.curve != EllipticCurveEd448 {
				return ErrKeyAlgorithmMismatch
			}
			if !ed448.Verify(key, message, signature, "") {
				return ErrInvalidSignature
			}
		default:
			return ErrKeyAlgorithmMismatch
		}

		return nil
	case signatureECDSA:
		key, ok := publicKey.(*ecdsa.PublicKey)
		if !ok || curveID(key.Curve) != spec.curve {
			return ErrKeyAlgorithmMismatch
		}
		digest := signatureDigest(spec.hash, message)
		if !ecdsa.VerifyASN1(key, digest, signature) {
			return ErrInvalidSignature
		}

		return nil
	case signatureECDSASecp256k1:
		key, ok := publicKey.(*secp256k1.PublicKey)
		if !ok {
			return ErrKeyAlgorithmMismatch
		}
		digest := signatureDigest(spec.hash, message)
		parsed, err := secp256k1ecdsa.ParseDERSignature(signature)
		if err != nil || !parsed.Verify(digest, key) {
			return ErrInvalidSignature
		}

		return nil
	case signatureRSA:
		key, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return ErrKeyAlgorithmMismatch
		}
		digest := signatureDigest(spec.hash, message)
		if err := rsa.VerifyPKCS1v15(key, spec.hash, digest, signature); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
		}

		return nil
	case signatureRSAPSS:
		key, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return ErrKeyAlgorithmMismatch
		}
		digest := signatureDigest(spec.hash, message)
		if err := rsa.VerifyPSS(key, spec.hash, digest, signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       spec.hash,
		}); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
		}

		return nil
	default:
		panic("unreachable COSE signature kind")
	}
}

func enforceFIPS140SignaturePolicy(
	publicKey crypto.PublicKey,
	algorithm Algorithm,
	spec signatureAlgorithm,
) error {
	if !cryptofips140.Enabled() {
		return nil
	}
	switch spec.fips {
	case fips140Approved:
	case fips140VerifyOnly:
		if algorithm != AlgorithmEdDSA {
			return &ctapfips140.PolicyError{
				Operation: fmt.Sprintf("COSE signature algorithm %d", algorithm),
			}
		}
		if _, ok := publicKey.(ed25519.PublicKey); !ok {
			return &ctapfips140.PolicyError{
				Operation: fmt.Sprintf("COSE signature algorithm %d with a non-Ed25519 key", algorithm),
			}
		}
	default:
		return &ctapfips140.PolicyError{
			Operation: fmt.Sprintf("COSE signature algorithm %d", algorithm),
		}
	}
	if spec.kind == signatureRSA || spec.kind == signatureRSAPSS {
		if key, ok := publicKey.(*rsa.PublicKey); ok {
			if key == nil || key.N == nil {
				return &ctapfips140.PolicyError{
					Operation: fmt.Sprintf("COSE RSA public key parameters for algorithm %d", algorithm),
				}
			}
			bits := key.N.BitLen()
			if key.N.Sign() <= 0 || key.N.Bit(0) != 1 || bits < 2048 || bits%2 != 0 ||
				key.E <= 1<<16 || key.E > math.MaxInt32 || key.E&1 != 1 {
				return &ctapfips140.PolicyError{
					Operation: fmt.Sprintf("COSE RSA public key parameters for algorithm %d", algorithm),
				}
			}
		}
	}
	return nil
}

func validatePublicKeyAlgorithm(
	publicKey crypto.PublicKey,
	spec signatureAlgorithm,
) error {
	switch spec.kind {
	case signatureEdDSA:
		switch key := publicKey.(type) {
		case ed25519.PublicKey:
			if len(key) != ed25519.PublicKeySize || spec.curve != 0 && spec.curve != EllipticCurveEd25519 {
				return ErrKeyAlgorithmMismatch
			}
		case ed448.PublicKey:
			if len(key) != ed448.PublicKeySize || spec.curve != 0 && spec.curve != EllipticCurveEd448 {
				return ErrKeyAlgorithmMismatch
			}
		default:
			return ErrKeyAlgorithmMismatch
		}
	case signatureECDSA:
		key, ok := publicKey.(*ecdsa.PublicKey)
		if !ok || curveID(key.Curve) != spec.curve {
			return ErrKeyAlgorithmMismatch
		}
	case signatureECDSASecp256k1:
		if _, ok := publicKey.(*secp256k1.PublicKey); !ok {
			return ErrKeyAlgorithmMismatch
		}
	case signatureRSA, signatureRSAPSS:
		if _, ok := publicKey.(*rsa.PublicKey); !ok {
			return ErrKeyAlgorithmMismatch
		}
	default:
		panic("unreachable COSE signature kind")
	}

	return nil
}

type signatureKind uint8

const (
	signatureEdDSA signatureKind = iota + 1
	signatureECDSA
	signatureECDSASecp256k1
	signatureRSA
	signatureRSAPSS
)

// fips140Approval classifies an algorithm under the CTAP FIPS 140-3 policy.
// The zero value denies it, so an unclassified entry fails closed.
type fips140Approval uint8

const (
	fips140NotApproved fips140Approval = iota
	fips140Approved
	// fips140VerifyOnly covers algorithms whose approved parameters are only
	// known from a concrete public key.
	fips140VerifyOnly
)

type signatureAlgorithm struct {
	kind  signatureKind
	hash  crypto.Hash
	curve int64
	fips  fips140Approval
}

var signatureAlgorithms = map[Algorithm]signatureAlgorithm{
	AlgorithmES256:  {kind: signatureECDSA, hash: crypto.SHA256, curve: EllipticCurveP256, fips: fips140Approved},
	AlgorithmESP256: {kind: signatureECDSA, hash: crypto.SHA256, curve: EllipticCurveP256, fips: fips140Approved},
	AlgorithmES384:  {kind: signatureECDSA, hash: crypto.SHA384, curve: EllipticCurveP384, fips: fips140Approved},
	AlgorithmESP384: {kind: signatureECDSA, hash: crypto.SHA384, curve: EllipticCurveP384, fips: fips140Approved},
	AlgorithmES512:  {kind: signatureECDSA, hash: crypto.SHA512, curve: EllipticCurveP521, fips: fips140Approved},
	AlgorithmESP512: {kind: signatureECDSA, hash: crypto.SHA512, curve: EllipticCurveP521, fips: fips140Approved},
	// AlgorithmEdDSA does not name a curve, so creation cannot rule out Ed448.
	AlgorithmEdDSA:   {kind: signatureEdDSA, fips: fips140VerifyOnly},
	AlgorithmEd25519: {kind: signatureEdDSA, curve: EllipticCurveEd25519, fips: fips140Approved},
	AlgorithmES256K:  {kind: signatureECDSASecp256k1, hash: crypto.SHA256, curve: EllipticCurveSecp256k1},
	AlgorithmRS256:   {kind: signatureRSA, hash: crypto.SHA256, fips: fips140Approved},
	AlgorithmRS384:   {kind: signatureRSA, hash: crypto.SHA384, fips: fips140Approved},
	AlgorithmRS512:   {kind: signatureRSA, hash: crypto.SHA512, fips: fips140Approved},
	AlgorithmRS1:     {kind: signatureRSA, hash: crypto.SHA1},
	AlgorithmPS256:   {kind: signatureRSAPSS, hash: crypto.SHA256, fips: fips140Approved},
	AlgorithmPS384:   {kind: signatureRSAPSS, hash: crypto.SHA384, fips: fips140Approved},
	AlgorithmPS512:   {kind: signatureRSAPSS, hash: crypto.SHA512, fips: fips140Approved},
}

// FIPS140Approved reports whether a may be requested for credential generation
// under the CTAP FIPS 140-3 policy. Verification is looser: it also accepts
// [AlgorithmEdDSA] with an Ed25519 key.
func (a Algorithm) FIPS140Approved() bool {
	return signatureAlgorithms[a].fips == fips140Approved
}

func (k Key) okpPublicKey() (crypto.PublicKey, error) {
	curve, err := keyInteger(k, OKPKeyParameterCrv, "crv")
	if err != nil {
		return nil, err
	}

	x, err := keyBytes(k, OKPKeyParameterX, "x")
	if err != nil {
		return nil, err
	}
	switch curve {
	case EllipticCurveEd25519:
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("cose: invalid Ed25519 public key length %d", len(x))
		}

		return ed25519.PublicKey(append([]byte(nil), x...)), nil
	case EllipticCurveEd448:
		if cryptofips140.Enabled() {
			return nil, &ctapfips140.PolicyError{Operation: "COSE Ed448 public key"}
		}
		if len(x) != ed448.PublicKeySize {
			return nil, fmt.Errorf("cose: invalid Ed448 public key length %d", len(x))
		}
		point, err := goldilocks.FromBytes(x)
		if err != nil || point.IsIdentity() {
			return nil, errors.New("cose: invalid Ed448 public key")
		}

		return ed448.PublicKey(append([]byte(nil), x...)), nil
	default:
		return nil, fmt.Errorf("%w: OKP curve %d", ErrUnsupportedKey, curve)
	}
}

func (k Key) ec2PublicKey() (crypto.PublicKey, error) {
	curveValue, err := keyInteger(k, EC2KeyParameterCrv, "crv")
	if err != nil {
		return nil, err
	}

	var curve elliptic.Curve
	var size int
	switch curveValue {
	case EllipticCurveP256:
		curve = elliptic.P256()
	case EllipticCurveP384:
		curve = elliptic.P384()
	case EllipticCurveP521:
		curve = elliptic.P521()
	case EllipticCurveSecp256k1:
		if cryptofips140.Enabled() {
			return nil, &ctapfips140.PolicyError{Operation: "COSE secp256k1 public key"}
		}
		size = 32
	default:
		return nil, fmt.Errorf("%w: EC2 curve %d", ErrUnsupportedKey, curveValue)
	}

	xBytes, err := keyBytes(k, EC2KeyParameterX, "x")
	if err != nil {
		return nil, err
	}
	yBytes, err := keyBytes(k, EC2KeyParameterY, "y")
	if err != nil {
		return nil, err
	}
	if size == 0 {
		size = (curve.Params().BitSize + 7) / 8
	}
	if len(xBytes) != size || len(yBytes) != size {
		return nil, fmt.Errorf(
			"cose: invalid EC2 coordinate lengths x=%d y=%d, want %d",
			len(xBytes),
			len(yBytes),
			size,
		)
	}

	encoded := make([]byte, 1+2*size)
	encoded[0] = 4
	copy(encoded[1:1+size], xBytes)
	copy(encoded[1+size:], yBytes)
	if curveValue == EllipticCurveSecp256k1 {
		publicKey, err := secp256k1.ParsePubKey(encoded)
		if err != nil {
			return nil, fmt.Errorf("cose: invalid secp256k1 public key: %w", err)
		}

		return publicKey, nil
	}
	publicKey, err := ecdsa.ParseUncompressedPublicKey(curve, encoded)
	if err != nil {
		return nil, fmt.Errorf("cose: invalid EC2 public key: %w", err)
	}

	return publicKey, nil
}

func (k Key) rsaPublicKey() (crypto.PublicKey, error) {
	modulus, err := keyBytes(k, RSAKeyParameterN, "n")
	if err != nil {
		return nil, err
	}
	if len(modulus) == 0 || modulus[0] == 0 {
		return nil, errors.New("cose: invalid RSA modulus encoding")
	}
	n := new(big.Int).SetBytes(modulus)
	if n.BitLen() < 2048 || n.Bit(0) == 0 {
		return nil, errors.New("cose: RSA modulus must be an odd integer of at least 2048 bits")
	}

	exponentBytes, err := keyBytes(k, RSAKeyParameterE, "e")
	if err != nil {
		return nil, err
	}
	if len(exponentBytes) == 0 || len(exponentBytes) > 8 || exponentBytes[0] == 0 {
		return nil, errors.New("cose: invalid RSA exponent encoding")
	}
	exponent := new(big.Int).SetBytes(exponentBytes)
	if !exponent.IsInt64() {
		return nil, errors.New("cose: RSA exponent is too large")
	}
	e := exponent.Int64()
	if e < 3 || e%2 == 0 || int64(int(e)) != e {
		return nil, errors.New("cose: RSA exponent must be an odd integer representable as int")
	}

	return &rsa.PublicKey{N: n, E: int(e)}, nil
}

func keyInteger(k Key, label int, name string) (int64, error) {
	value, found := k[label]
	if !found {
		return 0, fmt.Errorf("cose: credential key is missing %s", name)
	}

	switch value := value.(type) {
	case Algorithm:
		return int64(value), nil
	case int:
		return int64(value), nil
	case int8:
		return int64(value), nil
	case int16:
		return int64(value), nil
	case int32:
		return int64(value), nil
	case int64:
		return value, nil
	case uint:
		// uint is 32 bits wide on 32-bit platforms; widen before comparing
		// so the constant does not overflow.
		if uint64(value) > math.MaxInt64 {
			break
		}
		return int64(value), nil
	case uint8:
		return int64(value), nil
	case uint16:
		return int64(value), nil
	case uint32:
		return int64(value), nil
	case uint64:
		if value <= math.MaxInt64 {
			return int64(value), nil
		}
	}

	return 0, fmt.Errorf("cose: credential key has invalid %s type %T", name, value)
}

func keyBytes(k Key, label int, name string) ([]byte, error) {
	value, found := k[label]
	if !found {
		return nil, fmt.Errorf("cose: credential key is missing %s", name)
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil, fmt.Errorf("cose: credential key has invalid %s type %T", name, value)
	}

	return bytes, nil
}

func curveID(curve elliptic.Curve) int64 {
	switch curve {
	case elliptic.P256():
		return EllipticCurveP256
	case elliptic.P384():
		return EllipticCurveP384
	case elliptic.P521():
		return EllipticCurveP521
	default:
		return 0
	}
}

func signatureDigest(hash crypto.Hash, message []byte) []byte {
	switch hash {
	case crypto.SHA1:
		digest := sha1.Sum(message)
		return digest[:]
	case crypto.SHA256:
		digest := sha256.Sum256(message)
		return digest[:]
	case crypto.SHA384:
		digest := sha512.Sum384(message)
		return digest[:]
	case crypto.SHA512:
		digest := sha512.Sum512(message)
		return digest[:]
	default:
		panic("unreachable COSE signature hash")
	}
}
