package protocoltwo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
)

func KDF(z []byte) ([]byte, error) {
	if len(z) != 32 {
		return nil, fmt.Errorf("invalid P-256 shared secret length: got %d, want 32", len(z))
	}

	// Zero bytes for salt
	salt := make([]byte, 32)

	prk, err := hkdf.Extract(sha256.New, z, salt)
	if err != nil {
		return nil, fmt.Errorf("extracting CTAP2 HKDF key failed: %w", err)
	}
	defer clear(prk)

	hmacKey, err := hkdf.Expand(sha256.New, prk, "CTAP2 HMAC key", 32)
	if err != nil {
		return nil, fmt.Errorf("calculating CTAP2 HMAC key using HKDF failed: %w", err)
	}
	defer clear(hmacKey)

	aesKey, err := hkdf.Expand(sha256.New, prk, "CTAP2 AES key", 32)
	if err != nil {
		return nil, fmt.Errorf("calculating CTAP2 AES key using HKDF failed: %w", err)
	}
	defer clear(aesKey)

	return slices.Concat(hmacKey, aesKey), nil
}

func Encrypt(sharedSecret []byte, demPlaintext []byte) ([]byte, error) {
	if len(sharedSecret) != 64 {
		return nil, fmt.Errorf("invalid shared secret length")
	}

	if len(demPlaintext)%16 != 0 {
		return nil, fmt.Errorf("invalid plaintext length")
	}

	// Discard the first 32 bytes of the key.
	// (This selects the AES-key portion of the shared secret.)
	key := sharedSecret[32:]

	// Encrypt PIN using AES-CBC using random IV
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cannot create new AES cipher: %w", err)
	}

	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("cannot generate random iv: %w", err)
	}

	ciphertext := make([]byte, len(demPlaintext))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, demPlaintext)

	return slices.Concat(iv, ciphertext), nil
}

func Decrypt(sharedSecret []byte, demCiphertext []byte) ([]byte, error) {
	if len(sharedSecret) != 64 {
		return nil, fmt.Errorf("invalid shared secret length")
	}

	// Discard the first 32 bytes of the key.
	// (This selects the AES-key portion of the shared secret.)
	key := sharedSecret[32:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cannot create new AES cipher: %w", err)
	}

	if len(demCiphertext) < block.BlockSize() {
		return nil, errors.New("invalid ciphertext")
	}

	iv := demCiphertext[:16]

	ciphertext := demCiphertext[16:]
	if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
		return nil, errors.New("invalid ciphertext")
	}

	plaintext := make([]byte, len(ciphertext))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}

// Authenticate calculates a protocol-two authentication parameter.
// sharedSecret must contain at least the 32-byte HMAC key produced by the
// protocol-two KDF, or be a 32-byte pinUvAuthToken.
func Authenticate(sharedSecret []byte, message []byte) []byte {
	// If the key is longer than 32 bytes, discard the excess.
	// (This selects the HMAC-key portion of the shared secret.
	// When the key is the pinUvAuthToken, it is exactly 32 bytes long, and thus this step has no effect.)
	key := sharedSecret[:32]

	hasher := hmac.New(sha256.New, key)
	hasher.Write(message)

	return hasher.Sum(nil)
}
