package protocolone

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

func KDF(z []byte) []byte {
	sharedSecret := sha256.Sum256(z)
	return sharedSecret[:]
}

func Encrypt(sharedSecret []byte, demPlaintext []byte) ([]byte, error) {
	if len(sharedSecret) != 32 {
		return nil, fmt.Errorf("invalid shared secret length")
	}

	if len(demPlaintext)%16 != 0 {
		return nil, fmt.Errorf("invalid plaintext length")
	}

	// Encrypt PIN using AES-CBC using null IV
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("cannot create new AES cipher: %w", err)
	}

	iv := make([]byte, block.BlockSize())
	ciphertext := make([]byte, len(demPlaintext))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, demPlaintext)

	return ciphertext, nil
}

func Decrypt(sharedSecret []byte, demCiphertext []byte) ([]byte, error) {
	if len(sharedSecret) != 32 {
		return nil, fmt.Errorf("invalid shared secret length")
	}

	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("cannot create new AES cipher: %w", err)
	}

	if len(demCiphertext) == 0 || len(demCiphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("invalid ciphertext length")
	}

	iv := make([]byte, block.BlockSize())
	plaintext := make([]byte, len(demCiphertext))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, demCiphertext)

	return plaintext, nil
}

// Authenticate calculates a protocol-one authentication parameter.
// sharedSecret must be a CTAP-valid protocol-one shared secret or token: a
// positive multiple of 16 bytes.
func Authenticate(sharedSecret []byte, message []byte) []byte {
	hasher := hmac.New(sha256.New, sharedSecret)
	hasher.Write(message)

	return hasher.Sum(nil)[:16]
}
