package cose

import (
	"crypto/ecdh"
	"errors"
	"fmt"
)

// Key represents a COSE_Key map.
//
// CTAP can return credential public keys of different key types, so the wire
// representation remains a map. Cryptographic operations should convert a Key
// to a concrete supported key type and validate it first.
type Key map[int]any

// KeyFromP256PublicKey converts a P-256 public key to the COSE key agreement
// representation required by CTAP. The result contains only required fields.
func KeyFromP256PublicKey(publicKey *ecdh.PublicKey) (Key, error) {
	if publicKey.Curve() != ecdh.P256() {
		return nil, fmt.Errorf("cose: unsupported key agreement curve %q", publicKey.Curve())
	}

	encoded := publicKey.Bytes()

	return Key{
		KeyParameterKty:    KeyTypeEC2,
		KeyParameterAlg:    AlgorithmECDHESHKDF256,
		EC2KeyParameterCrv: EllipticCurveP256,
		EC2KeyParameterX:   encoded[1:33:33],
		EC2KeyParameterY:   encoded[33:65:65],
	}, nil
}

// P256PublicKey validates a CTAP key agreement key and converts it to a
// standard-library P-256 public key.
func (k Key) P256PublicKey() (*ecdh.PublicKey, error) {
	if k == nil {
		return nil, errors.New("cose: nil key agreement key")
	}

	if len(k) != 5 {
		return nil, fmt.Errorf("cose: key agreement key has %d parameters, want 5", len(k))
	}

	if err := requireInteger(k, KeyParameterKty, KeyTypeEC2, "kty"); err != nil {
		return nil, err
	}

	if err := requireInteger(k, KeyParameterAlg, int(AlgorithmECDHESHKDF256), "alg"); err != nil {
		return nil, err
	}

	if err := requireInteger(k, EC2KeyParameterCrv, EllipticCurveP256, "crv"); err != nil {
		return nil, err
	}

	x, err := coordinate(k, EC2KeyParameterX, "x")
	if err != nil {
		return nil, err
	}

	y, err := coordinate(k, EC2KeyParameterY, "y")
	if err != nil {
		return nil, err
	}

	encoded := make([]byte, 65)
	encoded[0] = 0x04
	copy(encoded[1:33], x)
	copy(encoded[33:65], y)

	publicKey, err := ecdh.P256().NewPublicKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("cose: invalid P-256 public key: %w", err)
	}

	return publicKey, nil
}

func requireInteger(k Key, label, want int, name string) error {
	value, ok := k[label]
	if !ok {
		return fmt.Errorf("cose: key agreement key is missing %s", name)
	}

	valid := false

	switch value := value.(type) {
	case Algorithm:
		valid = int(value) == want
	case int:
		valid = value == want
	case int64:
		valid = value == int64(want)
	case uint64:
		valid = want >= 0 && value == uint64(want)
	default:
		return fmt.Errorf("cose: key agreement key has invalid %s type %T", name, value)
	}

	if !valid {
		return fmt.Errorf("cose: key agreement key has invalid %s %v, want %d", name, value, want)
	}

	return nil
}

func coordinate(k Key, label int, name string) ([]byte, error) {
	value, ok := k[label]
	if !ok {
		return nil, fmt.Errorf("cose: key agreement key is missing %s coordinate", name)
	}

	coordinate, ok := value.([]byte)
	if !ok {
		return nil, fmt.Errorf("cose: key agreement key has invalid %s coordinate type %T", name, value)
	}

	if len(coordinate) != 32 {
		return nil, fmt.Errorf("cose: key agreement key has invalid %s coordinate length %d", name, len(coordinate))
	}

	return coordinate, nil
}
