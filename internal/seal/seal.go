// Package seal encrypts env values and registry tokens at rest.
// Plaintext, keys, and nonces are never logged.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// KeyVersion is the only key version this process writes.
const KeyVersion = 1

// Box is an AES-256-GCM key. A nil Box means the key is not configured.
type Box struct {
	key []byte
}

// New rejects a key that is not 32 bytes.
func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid secrets key")
	}
	cp := make([]byte, 32)
	copy(cp, key)
	return &Box{key: cp}, nil
}

// EnvAAD binds a ciphertext to one env value.
func EnvAAD(projectID, setName, key string) string {
	return projectID + "|" + setName + "|" + key
}

// RegistryAAD binds a ciphertext to one registry host.
func RegistryAAD(projectID, host string) string {
	return projectID + "|registry|" + host
}

// Seal returns a fresh 12-byte nonce and the ciphertext. The nonce is not
// inside the ciphertext.
func (b *Box) Seal(aad string, plain []byte) (nonce, ciphertext []byte, err error) {
	if b == nil {
		return nil, nil, errors.New("secrets key not configured")
	}
	block, err := aes.NewCipher(b.key)
	if err != nil {
		return nil, nil, errors.New("encrypt failed")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, errors.New("encrypt failed")
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, errors.New("encrypt failed")
	}
	ciphertext = gcm.Seal(nil, nonce, plain, []byte(aad))
	return nonce, ciphertext, nil
}

// Open fails closed. The error does not include plaintext or the AAD.
func (b *Box) Open(aad string, nonce, ciphertext []byte) ([]byte, error) {
	if b == nil {
		return nil, errors.New("secrets key not configured")
	}
	block, err := aes.NewCipher(b.key)
	if err != nil {
		return nil, errors.New("decrypt failed")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("decrypt failed")
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("decrypt failed")
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(aad))
	if err != nil {
		return nil, errors.New("decrypt failed")
	}
	return plain, nil
}
