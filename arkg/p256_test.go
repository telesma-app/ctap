package arkg

import (
	"bytes"
	"crypto/ecdh"
	cryptofips140 "crypto/fips140"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/fips140"
)

func TestDeriveP256DraftVectors(t *testing.T) {
	skipWhenFIPS140Required(t)

	tests := []struct {
		name         string
		input        string
		context      string
		sharedSecret string
		keyHandle    string
		derivedX     string
		derivedY     string
	}{
		{
			name:         "vector 1",
			input:        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
			context:      "ARKG-P256.test vectors",
			sharedSecret: "cf5e8ddbb8078a6a0144d4412f22f89407ecee30ec128ce07836af9fc51c05d0",
			keyHandle:    "27987995f184a44cfa548d104b0a461d0487fc739dbcdabc293ac5469221da91b220e04c681074ec4692a76ffacb9043dec2847ea9060fd42da267f66852e63589f0c00dc88f290d660c65a65a50c86361",
			derivedX:     "572a111ce5cfd2a67d56a0f7c684184b16ccd212490dc9c5b579df749647d107",
			derivedY:     "dac2a1b197cc10d2376559ad6df6bc107318d5cfb90def9f4a1f5347e086c2cd",
		},
		{
			name:         "vector 2",
			input:        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
			context:      "ARKG-P256.test vectors",
			sharedSecret: "dcdd95c742ddf25b8a95f3d76326cb3593b7860bb3e04c5e5b25cc15ce1e5c84",
			keyHandle:    "b7507a82771776fbac41a18d94e19a7e0457fd1e438280c127dd55a6138d1baf0a35e3e9671f7e42d8345f47374afa83247a078fa2196cd69497aed59ef92c05cb6b03d306ec24f2f4ff2db09cd95d1b11",
			derivedX:     "ea7d962c9f44ffe8b18f1058a471f394ef81b674948eefc1865b5c021cf858f5",
			derivedY:     "77f9632b84220e4a1444a20b9430b86731c37e4dcb285eda38d76bf758918d86",
		},
		{
			name:         "vector 3",
			input:        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
			context:      "ARKG-P256.test vectors.0",
			sharedSecret: "cde7e271f8da72e5fd2557de362420ddb170dce520362131670eb1080823a113",
			keyHandle:    "81c4e65b552e52350b49864b98b87d510487fc739dbcdabc293ac5469221da91b220e04c681074ec4692a76ffacb9043dec2847ea9060fd42da267f66852e63589f0c00dc88f290d660c65a65a50c86361",
			derivedX:     "b79b65d6bbb419ff97006a1bd52e3f4ad53042173992423e06e52987a037cb61",
			derivedY:     "dd82b126b162e4e7e8dc5c9fd86e82769d402a1968c7c547ef53ae4f96e10b0e",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := decodedP256Seed(t)
			input := hexBytes(t, test.input)
			context := []byte(test.context)

			derived, keyHandle, err := DeriveP256(seed, input, context)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			algorithm, err := derived.Algorithm()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got, want := algorithm, cose.AlgorithmESP256; got != want {
				t.Fatalf("got %#v, want %#v", got, want)
			}
			{
				want, got := hexBytes(t, test.derivedX), derived[cose.EC2KeyParameterX]
				gotValue, ok := got.([]byte)

				if !ok || ((gotValue == nil) != (want == nil) || !bytes.Equal(gotValue, want)) {
					t.Fatalf("got %#v, want %#v", got, want)
				}
			}
			{
				want, got := hexBytes(t, test.derivedY), derived[cose.EC2KeyParameterY]
				gotValue, ok := got.([]byte)

				if !ok || ((gotValue == nil) != (want == nil) || !bytes.Equal(gotValue, want)) {
					t.Fatalf("got %#v, want %#v", got, want)
				}
			}

			if got, want := keyHandle, hexBytes(t, test.keyHandle); (got == nil) != (want == nil) || !bytes.Equal(got, want) {
				t.Fatalf("got %#v, want %#v", got, want)
			}

			kemKey, err := nestedKey(seed, -2, "KEM public key")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			kemCurvePoint, err := p256PublicKey(kemKey, cose.AlgorithmECDHESHKDF256, "KEM public key")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			kemPoint, err := ecdh.P256().NewPublicKey(kemCurvePoint.Bytes())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			contextWithLength := append([]byte{byte(len(context))}, context...)
			kemContext := append([]byte("ARKG-Derive-Key-KEM."), contextWithLength...)

			sharedSecret, encapsulatedHandle, err := p256Encapsulate(kemPoint, input, kemContext)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got, want := sharedSecret, hexBytes(t, test.sharedSecret); (got == nil) != (want == nil) || !bytes.Equal(got, want) {
				t.Fatalf("got %#v, want %#v", got, want)
			}

			if got, want := encapsulatedHandle, keyHandle; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
				t.Fatalf("got %#v, want %#v", got, want)
			}
		})
	}
}

func TestDeriveP256AcceptsOptionalCOSEParameters(t *testing.T) {
	skipWhenFIPS140Required(t)

	seed := p256Seed(t)
	delete(seed, cose.KeyParameterAlg)
	delete(seed, -3)
	delete(seed[-1].(cose.Key), cose.KeyParameterAlg)
	delete(seed[-2].(cose.Key), cose.KeyParameterAlg)

	derived, _, err := DeriveP256(seed, make([]byte, 32), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, hasAlgorithm := derived[cose.KeyParameterAlg]
	if got := hasAlgorithm; got {
		t.Fatalf("got true, want false")
	}

	seed[-3] = "example.org/algorithm"

	derived, _, err = DeriveP256(seed, make([]byte, 32), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := "example.org/algorithm", derived[cose.KeyParameterAlg]
		gotValue, ok := got.(string)

		if !ok || gotValue != want {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}

	seed[-3] = ^uint64(0)

	derived, _, err = DeriveP256(seed, make([]byte, 32), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := ^uint64(0), derived[cose.KeyParameterAlg]
		gotValue, ok := got.(uint64)

		if !ok || gotValue != want {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
}

func TestDerivedP256CoordinateAppendPreservesOtherCoordinate(t *testing.T) {
	skipWhenFIPS140Required(t)

	key, _, err := DeriveP256(p256Seed(t), make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}

	x := key[cose.EC2KeyParameterX].([]byte)
	y := key[cose.EC2KeyParameterY].([]byte)
	wantY := bytes.Clone(y)

	_ = append(x, y[0]^0xff)

	if !bytes.Equal(y, wantY) {
		t.Errorf("appending to x changed y: got %x, want %x", y, wantY)
	}
}

func TestDeriveP256RejectsInvalidPublicSeed(t *testing.T) {
	skipWhenFIPS140Required(t)

	tests := []struct {
		name   string
		mutate func(cose.Key)
		want   string
	}{
		{
			name: "missing kty",
			mutate: func(seed cose.Key) {
				delete(seed, cose.KeyParameterKty)
			},
			want: "missing kty",
		},
		{
			name: "wrong kty",
			mutate: func(seed cose.Key) {
				seed[cose.KeyParameterKty] = cose.KeyTypeEC2
			},
			want: "invalid kty 2",
		},
		{
			name: "wrong outer algorithm",
			mutate: func(seed cose.Key) {
				seed[cose.KeyParameterAlg] = cose.AlgorithmES256
			},
			want: "invalid alg -7",
		},
		{
			name: "invalid derived algorithm",
			mutate: func(seed cose.Key) {
				seed[-3] = []byte("not an algorithm identifier")
			},
			want: "invalid dkalg type []uint8",
		},
		{
			name: "missing blinding key",
			mutate: func(seed cose.Key) {
				delete(seed, -1)
			},
			want: "missing blinding public key",
		},
		{
			name: "invalid nested key type",
			mutate: func(seed cose.Key) {
				seed[-1] = []byte("not a key")
			},
			want: "blinding public key has invalid type []uint8",
		},
		{
			name: "wrong blinding algorithm",
			mutate: func(seed cose.Key) {
				seed[-1].(cose.Key)[cose.KeyParameterAlg] = cose.AlgorithmECDHESHKDF256
			},
			want: "invalid blinding public key alg -25",
		},
		{
			name: "wrong KEM algorithm",
			mutate: func(seed cose.Key) {
				seed[-2].(cose.Key)[cose.KeyParameterAlg] = cose.AlgorithmES256
			},
			want: "invalid KEM public key alg -7",
		},
		{
			name: "missing coordinate",
			mutate: func(seed cose.Key) {
				delete(seed[-1].(cose.Key), cose.EC2KeyParameterX)
			},
			want: "missing blinding public key x",
		},
		{
			name: "wrong coordinate length",
			mutate: func(seed cose.Key) {
				seed[-2].(cose.Key)[cose.EC2KeyParameterY] = make([]byte, 31)
			},
			want: "invalid coordinate lengths x=32 y=31",
		},
		{
			name: "point off curve",
			mutate: func(seed cose.Key) {
				seed[-1].(cose.Key)[cose.EC2KeyParameterX] = make([]byte, 32)
				seed[-1].(cose.Key)[cose.EC2KeyParameterY] = make([]byte, 32)
			},
			want: "invalid P-256 blinding public key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := p256Seed(t)
			test.mutate(seed)
			_, _, err := DeriveP256(seed, make([]byte, 32), nil)
			{
				err, substring := err, test.want
				if err == nil || !strings.Contains(err.Error(), substring) {
					t.Fatalf("error %v does not contain %q", err, substring)
				}
			}
		})
	}
}

func TestDeriveP256RejectsLongContext(t *testing.T) {
	skipWhenFIPS140Required(t)

	_, _, err := DeriveP256(p256Seed(t), make([]byte, 32), make([]byte, p256ContextLimit))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, _, err = DeriveP256(p256Seed(t), make([]byte, 32), make([]byte, p256ContextLimit+1))
	{
		err, want := err, "arkg: P-256 context is 65 bytes, maximum is 64"
		if err == nil || err.Error() != want {
			t.Fatalf("got error %v, want %q", err, want)
		}
	}
}

func TestDeriveP256RejectsFIPS140Mode(t *testing.T) {
	if !cryptofips140.Enabled() {
		t.Skip("FIPS 140-3 mode is not enabled")
	}

	derived, keyHandle, err := DeriveP256(nil, nil, nil)
	if !errors.Is(err, fips140.ErrNotAllowed) {
		t.Fatalf("got error %v, want %v", err, fips140.ErrNotAllowed)
	}

	var notAllowed *fips140.PolicyError
	if !errors.As(err, &notAllowed) {
		t.Fatalf("got error type %T, want *fips140.PolicyError", err)
	}

	if got, want := notAllowed.Operation, "ARKG-P256"; got != want {
		t.Fatalf("got operation %q, want %q", got, want)
	}

	if derived != nil {
		t.Fatalf("got derived key %#v, want nil", derived)
	}

	if keyHandle != nil {
		t.Fatalf("got key handle %#v, want nil", keyHandle)
	}
}

func FuzzDeriveP256(f *testing.F) {
	if cryptofips140.Enabled() {
		f.Skip("FIPS 140-3 mode is enabled")
	}

	encoded, err := cbor.Marshal(p256Seed(f))
	if err != nil {
		f.Fatalf("unexpected error: %v", err)
	}

	f.Add(encoded, make([]byte, 32), []byte("context"))
	f.Add([]byte{0xa0}, []byte{}, make([]byte, p256ContextLimit+1))

	f.Fuzz(func(t *testing.T, encoded, inputKeyMaterial, context []byte) {
		var seed cose.Key
		if cbor.Unmarshal(encoded, &seed) != nil {
			return
		}

		_, _, _ = DeriveP256(seed, inputKeyMaterial, context)
	})
}

func skipWhenFIPS140Required(t *testing.T) {
	t.Helper()

	if cryptofips140.Enabled() {
		t.Skip("FIPS 140-3 mode is enabled")
	}
}

func decodedP256Seed(t *testing.T) cose.Key {
	t.Helper()

	encoded, err := cbor.Marshal(p256Seed(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var seed cose.Key
	if err := cbor.Unmarshal(encoded, &seed); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return seed
}

func p256Seed(t testReporter) cose.Key {
	t.Helper()

	return cose.Key{
		cose.KeyParameterKty: cose.KeyTypeARKGPublicSeedPlaceholder,
		cose.KeyParameterAlg: cose.AlgorithmARKGP256Placeholder,
		-1: cose.Key{
			cose.KeyParameterKty:    cose.KeyTypeEC2,
			cose.KeyParameterAlg:    cose.AlgorithmES256,
			cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
			cose.EC2KeyParameterX:   hexBytes(t, "6d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df"),
			cose.EC2KeyParameterY:   hexBytes(t, "65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7"),
		},
		-2: cose.Key{
			cose.KeyParameterKty:    cose.KeyTypeEC2,
			cose.KeyParameterAlg:    cose.AlgorithmECDHESHKDF256,
			cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
			cose.EC2KeyParameterX:   hexBytes(t, "c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5"),
			cose.EC2KeyParameterY:   hexBytes(t, "dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35"),
		},
		-3: cose.AlgorithmESP256,
	}
}

type testReporter interface {
	Helper()
	Fatalf(string, ...any)
}

func hexBytes(t testReporter, value string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}

	return decoded
}
