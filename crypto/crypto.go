package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/crypto/protocolone"
	"github.com/telesma-app/ctap/crypto/protocoltwo"
	pinvalidation "github.com/telesma-app/ctap/internal/pin"
	"github.com/telesma-app/ctap/protocol"
)

const largeBlobNonceSize = 12

type PinUvAuthProtocol struct {
	Number             protocol.PinUvAuthProtocol
	platformPrivateKey *ecdh.PrivateKey
	platformCoseKey    cose.Key
}

func NewPinUvAuthProtocol(number protocol.PinUvAuthProtocol) (*PinUvAuthProtocol, error) {
	if err := pinvalidation.ValidateFIPS140UvAuthProtocol(number); err != nil {
		return nil, err
	}

	platformPrivkey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cannot generate platform P-256 keypair: %w", err)
	}

	platformPubkey, err := cose.KeyFromP256PublicKey(platformPrivkey.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("cannot convert platform public key to COSE_Key: %w", err)
	}

	return &PinUvAuthProtocol{
		Number:             number,
		platformPrivateKey: platformPrivkey,
		platformCoseKey:    platformPubkey,
	}, nil
}

// ECDH returns a caller-owned derived shared secret.
func (p *PinUvAuthProtocol) ECDH(peerCoseKey cose.Key) ([]byte, error) {
	peerPubkey, err := peerCoseKey.P256PublicKey()
	if err != nil {
		return nil, fmt.Errorf("cannot convert peer public key to Go *ecdh.PublicKey: %w", err)
	}

	z, err := p.platformPrivateKey.ECDH(peerPubkey)
	if err != nil {
		return nil, fmt.Errorf("cannot derive shared secret: %w", err)
	}
	defer clear(z)

	return p.KDF(z)
}

func (p *PinUvAuthProtocol) KDF(z []byte) ([]byte, error) {
	switch p.Number {
	case protocol.PinUvAuthProtocolOne:
		return protocolone.KDF(z), nil
	case protocol.PinUvAuthProtocolTwo:
		return protocoltwo.KDF(z)
	default:
		return nil, ErrInvalidAuthProtocol
	}
}

func (p *PinUvAuthProtocol) Encrypt(sharedSecret []byte, demPlaintext []byte) ([]byte, error) {
	switch p.Number {
	case protocol.PinUvAuthProtocolOne:
		return protocolone.Encrypt(sharedSecret, demPlaintext)
	case protocol.PinUvAuthProtocolTwo:
		return protocoltwo.Encrypt(sharedSecret, demPlaintext)
	default:
		return nil, ErrInvalidAuthProtocol
	}
}

func (p *PinUvAuthProtocol) Decrypt(sharedSecret []byte, demCiphertext []byte) ([]byte, error) {
	switch p.Number {
	case protocol.PinUvAuthProtocolOne:
		return protocolone.Decrypt(sharedSecret, demCiphertext)
	case protocol.PinUvAuthProtocolTwo:
		return protocoltwo.Decrypt(sharedSecret, demCiphertext)
	default:
		return nil, ErrInvalidAuthProtocol
	}
}

// Encapsulate returns the platform public key and a caller-owned derived shared secret.
func (p *PinUvAuthProtocol) Encapsulate(peerCoseKey cose.Key) (cose.Key, []byte, error) {
	sharedSecret, err := p.ECDH(peerCoseKey)
	if err != nil {
		return nil, nil, err
	}

	return p.platformCoseKey, sharedSecret, nil
}

// Authenticate calculates a PIN/UV authentication parameter. sharedSecret
// must already satisfy the selected CTAP protocol's shared-secret or token
// length rules.
//
// It applies no FIPS 140-3 policy and panics on an unknown protocol. Callers
// that need the policy go through [NewPinUvAuthProtocol].
func Authenticate(number protocol.PinUvAuthProtocol, sharedSecret []byte, message []byte) []byte {
	switch number {
	case protocol.PinUvAuthProtocolOne:
		return protocolone.Authenticate(sharedSecret, message)
	case protocol.PinUvAuthProtocolTwo:
		return protocoltwo.Authenticate(sharedSecret, message)
	default:
		panic("invalid auth protocol")
	}
}

func DecryptLargeBlob(key []byte, blob protocol.LargeBlob) ([]byte, error) {
	plaintext, err := OpenLargeBlob(key, blob)
	if err != nil {
		return nil, err
	}

	return DecompressLargeBlobData(plaintext, blob.OrigSize)
}

// OpenLargeBlob authenticates and decrypts a large-blob array element without
// decompressing its plaintext. Callers that scan an array can use a successful
// return to distinguish an AEAD key match from a malformed DEFLATE stream.
func OpenLargeBlob(key []byte, blob protocol.LargeBlob) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid large blob key length: got %d, want 32", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}

	if len(blob.Nonce) != largeBlobNonceSize {
		return nil, fmt.Errorf("invalid large blob nonce length: got %d, want %d", len(blob.Nonce), largeBlobNonceSize)
	}

	origSizeBin := make([]byte, 8)
	binary.LittleEndian.PutUint64(origSizeBin, uint64(blob.OrigSize))

	sealed := slices.Concat(blob.Nonce, blob.Ciphertext)

	return gcm.Open(nil, nil, sealed, slices.Concat([]byte("blob"), origSizeBin))
}

func EncryptLargeBlob(key []byte, origData []byte) (protocol.LargeBlob, error) {
	if len(key) != 32 {
		return protocol.LargeBlob{}, fmt.Errorf("invalid large blob key length: got %d, want 32", len(key))
	}

	plaintext, err := CompressLargeBlobData(origData)
	if err != nil {
		return protocol.LargeBlob{}, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return protocol.LargeBlob{}, err
	}

	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return protocol.LargeBlob{}, err
	}

	origSize := len(origData)
	origSizeBin := make([]byte, 8)
	binary.LittleEndian.PutUint64(origSizeBin, uint64(origSize))

	sealed := gcm.Seal(nil, nil, plaintext, slices.Concat([]byte("blob"), origSizeBin))

	return protocol.LargeBlob{
		Ciphertext: sealed[largeBlobNonceSize:len(sealed):len(sealed)],
		Nonce:      sealed[:largeBlobNonceSize:largeBlobNonceSize],
		OrigSize:   uint(origSize),
	}, nil
}
