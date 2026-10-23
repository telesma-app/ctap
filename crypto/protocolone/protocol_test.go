package protocolone

import (
	"bytes"
	"encoding/base64"
	"math/rand"
	"slices"
	"testing"
)

const (
	derivedSecret             = "iGCxsjN/EAIMuVwL2bvpKnuIB/+eJT84b+sAvyD80zI="
	messageAuthenticationCode = "mCElssa3wFoz1+hjKAG/jg=="
)

func TestKDF(t *testing.T) {
	// Create derived with zero material
	key1 := KDF(nil)

	// Create a deterministic shared secret
	sharedSecret := make([]byte, 32)
	r := rand.New(rand.NewSource(0))

	_, err := r.Read(sharedSecret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantSharedSecret := slices.Clone(sharedSecret)

	// Create derived with a shared secret
	key2 := KDF(sharedSecret)
	if got, want := sharedSecret, wantSharedSecret; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	// Ensure key1 and key2 are different
	if got, want := key2, key1; (got == nil) == (want == nil) && bytes.Equal(got, want) {
		t.Errorf("got %#v, want a value different from %#v", got, want)
	}

	// Compare it with reference
	savedKey, _ := base64.StdEncoding.DecodeString(derivedSecret)
	if got, want := savedKey, key2; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key, _ := base64.StdEncoding.DecodeString(derivedSecret)
	badKey := append(key, 0)

	plaintext := []byte("16-byte block...")
	badPlaintext := []byte("17-byte block...!")
	longPlaintext := slices.Concat(plaintext, plaintext, plaintext, plaintext)

	// Encrypt with a 65-byte key
	_, err := Encrypt(badKey, plaintext)
	if err == nil {
		t.Errorf("expected an error")
	}

	// Encrypt with a 17-byte block
	_, err = Encrypt(key, badPlaintext)
	if err == nil {
		t.Errorf("expected an error")
	}

	// Test encrypt-decrypt with one block
	{
		ciphertext, err := Encrypt(key, plaintext)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		decrypted, err := Decrypt(key, ciphertext)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := decrypted, plaintext; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	// Test encrypt-decrypt with multiple blocks
	{
		ciphertext, err := Encrypt(key, longPlaintext)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		decrypted, err := Decrypt(key, ciphertext)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := decrypted, longPlaintext; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestDecryptRejectsInvalidInputs(t *testing.T) {
	key, _ := base64.StdEncoding.DecodeString(derivedSecret)
	badKey := append(key, 0)

	_, err := Decrypt(badKey, []byte("16-byte block..."))
	if err == nil {
		t.Errorf("expected an error")
	}

	_, err = Decrypt(key, nil)
	if err == nil {
		t.Errorf("expected an error")
	}

	_, err = Decrypt(key, []byte("not block aligned"))
	if err == nil {
		t.Errorf("expected an error")
	}
}

func TestAuthenticate(t *testing.T) {
	key, _ := base64.StdEncoding.DecodeString(derivedSecret)
	message := []byte("hello world!")

	mac := Authenticate(key, message)
	if got, want := len(mac), 16; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := base64.StdEncoding.EncodeToString(mac), messageAuthenticationCode; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}
