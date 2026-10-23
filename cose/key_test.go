package cose

import (
	"bytes"
	"crypto/ecdh"
	"crypto/fips140"
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestP256PublicKeyCOSECBORRoundTrip(t *testing.T) {
	privateKeyBytes := make([]byte, 32)
	privateKeyBytes[31] = 1

	privateKey, err := ecdh.P256().NewPrivateKey(privateKeyBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	key, err := KeyFromP256PublicKey(privateKey.PublicKey())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := len(key), 5; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}

	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	encoded, err := encMode.Marshal(key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := mustDecodeHex(t,
		"a501020338182001215820"+
			"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"+
			"225820"+
			"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
	)
	if got, want := encoded, want; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	var decoded Key
	if err := cbor.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	publicKey, err := decoded.P256PublicKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := publicKey.Bytes(), privateKey.PublicKey().Bytes(); (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestKeyFromP256PublicKeyRejectsUnsupportedKeys(t *testing.T) {
	if fips140.Enabled() {
		return
	}

	x25519PrivateKey, err := ecdh.X25519().NewPrivateKey(make([]byte, 32))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = KeyFromP256PublicKey(x25519PrivateKey.PublicKey())
	if err == nil {
		t.Fatalf("expected an error")
	}
}

func TestP256KeyCoordinateAppendPreservesOtherCoordinate(t *testing.T) {
	key := validP256Key(t)
	x := key[EC2KeyParameterX].([]byte)
	y := key[EC2KeyParameterY].([]byte)
	wantY := bytes.Clone(y)

	_ = append(x, y[0]^0xff)

	if !bytes.Equal(y, wantY) {
		t.Errorf("appending to x changed y: got %x, want %x", y, wantY)
	}
}

func TestP256PublicKeyRejectsMalformedKeys(t *testing.T) {
	valid := validP256Key(t)

	tests := []struct {
		name   string
		mutate func(Key)
	}{
		{name: "unexpected parameter", mutate: func(k Key) { k[-4] = make([]byte, 32) }},
		{name: "missing kty", mutate: func(k Key) { delete(k, KeyParameterKty) }},
		{name: "invalid kty type", mutate: func(k Key) { k[KeyParameterKty] = "EC2" }},
		{name: "wrong kty", mutate: func(k Key) { k[KeyParameterKty] = 1 }},
		{name: "missing alg", mutate: func(k Key) { delete(k, KeyParameterAlg) }},
		{name: "wrong alg", mutate: func(k Key) { k[KeyParameterAlg] = -7 }},
		{name: "missing crv", mutate: func(k Key) { delete(k, EC2KeyParameterCrv) }},
		{name: "wrong crv", mutate: func(k Key) { k[EC2KeyParameterCrv] = 2 }},
		{name: "missing x", mutate: func(k Key) { delete(k, EC2KeyParameterX) }},
		{name: "invalid x type", mutate: func(k Key) { k[EC2KeyParameterX] = "x" }},
		{name: "empty x", mutate: func(k Key) { k[EC2KeyParameterX] = []byte{} }},
		{name: "short x", mutate: func(k Key) { k[EC2KeyParameterX] = make([]byte, 31) }},
		{name: "long x", mutate: func(k Key) { k[EC2KeyParameterX] = make([]byte, 33) }},
		{name: "missing y", mutate: func(k Key) { delete(k, EC2KeyParameterY) }},
		{name: "invalid y type", mutate: func(k Key) { k[EC2KeyParameterY] = false }},
		{name: "empty y", mutate: func(k Key) { k[EC2KeyParameterY] = []byte{} }},
		{name: "short y", mutate: func(k Key) { k[EC2KeyParameterY] = make([]byte, 31) }},
		{name: "long y", mutate: func(k Key) { k[EC2KeyParameterY] = make([]byte, 33) }},
		{name: "point outside curve", mutate: func(k Key) {
			k[EC2KeyParameterX] = make([]byte, 32)
			k[EC2KeyParameterY] = make([]byte, 32)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := cloneKey(valid)
			tt.mutate(key)

			_, err := key.P256PublicKey()
			if err == nil {
				t.Fatalf("expected an error")
			}
		})
	}

	_, err := (Key)(nil).P256PublicKey()
	if err == nil {
		t.Fatalf("expected an error")
	}
}

func TestP256PublicKeyAcceptsUnsignedDecodedIntegers(t *testing.T) {
	key := validP256Key(t)
	key[KeyParameterKty] = uint64(KeyTypeEC2)
	key[KeyParameterAlg] = int64(AlgorithmECDHESHKDF256)
	key[EC2KeyParameterCrv] = uint64(EllipticCurveP256)

	_, err := key.P256PublicKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func validP256Key(t *testing.T) Key {
	t.Helper()

	privateKeyBytes := make([]byte, 32)
	privateKeyBytes[31] = 1

	privateKey, err := ecdh.P256().NewPrivateKey(privateKeyBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	key, err := KeyFromP256PublicKey(privateKey.PublicKey())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return key
}

func cloneKey(key Key) Key {
	cloned := make(Key, len(key))
	for label, value := range key {
		if bytes, ok := value.([]byte); ok {
			cloned[label] = append([]byte(nil), bytes...)
			continue
		}

		cloned[label] = value
	}

	return cloned
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return decoded
}
