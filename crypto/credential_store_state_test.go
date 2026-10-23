package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"strings"
	"testing"
)

func encryptGetInfoMember(
	t *testing.T,
	persistentPinUvAuthToken,
	iv,
	plaintext []byte,
	info string,
) []byte {
	t.Helper()

	key, err := hkdf.Key(
		sha256.New,
		persistentPinUvAuthToken,
		make([]byte, sha256.Size),
		info,
		aes.BlockSize,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ciphertext := make([]byte, aes.BlockSize)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)

	return append(bytes.Clone(iv), ciphertext...)
}

func TestDecryptDeviceIdentifierAndCredentialStoreState(t *testing.T) {
	persistentPinUvAuthToken := bytes.Repeat([]byte{0x11}, 32)
	deviceIdentifier := []byte("identifier-12345")
	credentialStoreState := []byte("store-state-1234")

	encIdentifier := encryptGetInfoMember(
		t,
		persistentPinUvAuthToken,
		bytes.Repeat([]byte{0x22}, aes.BlockSize),
		deviceIdentifier,
		"encIdentifier",
	)
	encCredStoreState := encryptGetInfoMember(
		t,
		persistentPinUvAuthToken,
		bytes.Repeat([]byte{0x33}, aes.BlockSize),
		credentialStoreState,
		"encCredStoreState",
	)

	gotDeviceIdentifier, err := DecryptDeviceIdentifier(
		persistentPinUvAuthToken,
		encIdentifier,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := gotDeviceIdentifier[:], deviceIdentifier; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	gotCredentialStoreState, err := DecryptCredentialStoreState(
		persistentPinUvAuthToken,
		encCredStoreState,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := gotCredentialStoreState[:], credentialStoreState; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	wrongLabel, err := DecryptCredentialStoreState(persistentPinUvAuthToken, encIdentifier)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := wrongLabel[:], deviceIdentifier; (got == nil) == (want == nil) && bytes.Equal(got, want) {
		t.Errorf("got %#v, want a value different from %#v", got, want)
	}
}

func TestDecryptCredentialStoreStateAcceptsRegeneratedIV(t *testing.T) {
	persistentPinUvAuthToken := bytes.Repeat([]byte{0x44}, 32)
	credentialStoreState := []byte("store-state-1234")

	first, err := DecryptCredentialStoreState(
		persistentPinUvAuthToken,
		encryptGetInfoMember(
			t,
			persistentPinUvAuthToken,
			bytes.Repeat([]byte{0x55}, aes.BlockSize),
			credentialStoreState,
			"encCredStoreState",
		),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	second, err := DecryptCredentialStoreState(
		persistentPinUvAuthToken,
		encryptGetInfoMember(
			t,
			persistentPinUvAuthToken,
			bytes.Repeat([]byte{0x66}, aes.BlockSize),
			credentialStoreState,
			"encCredStoreState",
		),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := second, first; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestDecryptGetInfoMembersValidateInput(t *testing.T) {
	_, err := DecryptDeviceIdentifier(nil, make([]byte, 32))
	if err == nil {
		t.Fatalf("expected an error")
	}

	if container, element := err.Error(), "persistentPinUvAuthToken must not be empty"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	_, err = DecryptDeviceIdentifier(make([]byte, 15), make([]byte, 32))
	if err == nil {
		t.Fatalf("expected an error")
	}

	if container, element := err.Error(), "persistentPinUvAuthToken must be a positive multiple of 16 bytes"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	_, err = DecryptDeviceIdentifier(make([]byte, 32), make([]byte, 31))
	if err == nil {
		t.Fatalf("expected an error")
	}

	if container, element := err.Error(), "encIdentifier must be exactly 32 bytes"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	_, err = DecryptCredentialStoreState(make([]byte, 32), make([]byte, 31))
	if err == nil {
		t.Fatalf("expected an error")
	}

	if container, element := err.Error(), "encCredStoreState must be exactly 32 bytes"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}
}
