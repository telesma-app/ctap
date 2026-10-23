package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

const getInfoEncryptedMemberPlaintextSize = aes.BlockSize

// DecryptDeviceIdentifier decrypts the device identifier returned in
// authenticatorGetInfo's encIdentifier member.
func DecryptDeviceIdentifier(
	persistentPinUvAuthToken,
	encIdentifier []byte,
) ([getInfoEncryptedMemberPlaintextSize]byte, error) {
	return decryptGetInfoMember(persistentPinUvAuthToken, encIdentifier, "encIdentifier")
}

// DecryptCredentialStoreState decrypts the credential store state returned in
// authenticatorGetInfo's encCredStoreState member.
func DecryptCredentialStoreState(
	persistentPinUvAuthToken,
	encCredStoreState []byte,
) ([getInfoEncryptedMemberPlaintextSize]byte, error) {
	return decryptGetInfoMember(persistentPinUvAuthToken, encCredStoreState, "encCredStoreState")
}

func decryptGetInfoMember(
	persistentPinUvAuthToken,
	encrypted []byte,
	info string,
) ([getInfoEncryptedMemberPlaintextSize]byte, error) {
	var plaintext [getInfoEncryptedMemberPlaintextSize]byte
	if len(persistentPinUvAuthToken) == 0 {
		return plaintext, fmt.Errorf("persistentPinUvAuthToken must not be empty")
	}

	if len(persistentPinUvAuthToken)%aes.BlockSize != 0 {
		return plaintext, fmt.Errorf(
			"persistentPinUvAuthToken must be a positive multiple of %d bytes",
			aes.BlockSize,
		)
	}

	if len(encrypted) != 2*getInfoEncryptedMemberPlaintextSize {
		return plaintext, fmt.Errorf(
			"%s must be exactly %d bytes",
			info,
			2*getInfoEncryptedMemberPlaintextSize,
		)
	}

	key, err := hkdf.Key(
		sha256.New,
		persistentPinUvAuthToken,
		make([]byte, sha256.Size),
		info,
		getInfoEncryptedMemberPlaintextSize,
	)
	if err != nil {
		return plaintext, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return plaintext, err
	}

	iv := encrypted[:getInfoEncryptedMemberPlaintextSize]
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(
		plaintext[:],
		encrypted[getInfoEncryptedMemberPlaintextSize:],
	)

	return plaintext, nil
}
