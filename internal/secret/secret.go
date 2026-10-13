// Package secret mints high-entropy tokens and compares only their SHA-256.
// Plaintext tokens are never stored.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

const tokenBytes = 32

// NewToken returns a 32-byte token as unpadded base64url (43 characters)
// and the SHA-256 of that string.
func NewToken() (plain string, hash []byte, err error) {
	buf := make([]byte, tokenBytes)
	if _, err = rand.Read(buf); err != nil {
		return "", nil, err
	}
	plain = base64.RawURLEncoding.EncodeToString(buf)
	return plain, Hash(plain), nil
}

// Hash is the SHA-256 of the plaintext token string the client presents.
func Hash(plain string) []byte {
	sum := sha256.Sum256([]byte(plain))
	return append([]byte(nil), sum[:]...)
}

// Equal compares two digests in constant time. Length mismatches fail.
func Equal(a, b []byte) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// UserCodeAlphabet is the device-flow alphabet from the REST contract.
const UserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// NewUserCode returns an 8-character code from UserCodeAlphabet, displayed
// as XXXX-XXXX. Selection uses rejection sampling so the modulo is unbiased.
func NewUserCode() (string, error) {
	const alphabet = UserCodeAlphabet
	out := make([]byte, 8)
	buf := make([]byte, 1)
	// 20 * 12 = 240. Bytes in [240, 255] are discarded.
	const limit = 240
	for i := 0; i < len(out); {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		if int(buf[0]) >= limit {
			continue
		}
		out[i] = alphabet[int(buf[0])%len(alphabet)]
		i++
	}
	return string(out[:4]) + "-" + string(out[4:]), nil
}
