package store

import (
	"time"

	"github.com/google/uuid"
)

// ImageDeploy is one finished or in-flight image deploy.
// InFlight is not part of the HTTP object.
type ImageDeploy struct {
	ID            uuid.UUID  `json:"id"`
	EntryID       uuid.UUID  `json:"entry_id"`
	HostID        uuid.UUID  `json:"host_id"`
	Digest        *string    `json:"digest"`
	SpecHash      string     `json:"spec_hash"`
	Outcome       string     `json:"outcome"`
	ExitCode      *int       `json:"exit_code"`
	StartedAt     time.Time  `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at"`
	By            uuid.UUID  `json:"by"`
	Via           string     `json:"via"`
	InFlight      bool       `json:"-"`
	InFlightUntil time.Time  `json:"-"`
}

// EnvKey is one env-set key in an HTTP body. Value is null when the key is secret.
// Preview is the v1.13 preview of a secret and null for a plain key.
// The store leaves Preview nil. The HTTP handler fills it and never puts the secret in Value.
type EnvKey struct {
	Key      string  `json:"key"`
	IsSecret bool    `json:"is_secret"`
	Value    *string `json:"value"`
	Preview  *string `json:"preview"`
}

// EnvKeyPut is one key for PutEnvKey.
// Secret nil stores a new key as secret and leaves an existing flag unchanged.
// Nonce and Ciphertext seal Plain when the stored flag is secret.
type EnvKeyPut struct {
	Key        string
	Plain      string
	Secret     *bool
	Nonce      []byte
	Ciphertext []byte
	KeyVersion int
}

// EnvSet is one project env set.
type EnvSet struct {
	Name      string    `json:"name"`
	Keys      []EnvKey  `json:"keys"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy uuid.UUID `json:"updated_by"`
}

// EnvSecret is one env value prepared for PutEnvSet.
// Nonce, Ciphertext, and KeyVersion seal Plain (AAD project_id|set|key).
// PutEnvSet stores Plain only when that key already exists and is not secret.
// A new key, and a key that stays secret, store the seal and not Plain.
type EnvSecret struct {
	Key        string
	Plain      string
	Nonce      []byte
	Ciphertext []byte
	KeyVersion int
}

// EnvMaterial is a stored env value, including ciphertext. It is not returned over HTTP.
type EnvMaterial struct {
	Key        string
	IsSecret   bool
	Plain      string
	Nonce      []byte
	Ciphertext []byte
	KeyVersion int
}

// Registry is a registry credential without the token.
type Registry struct {
	Host      string    `json:"host"`
	Username  string    `json:"username"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy uuid.UUID `json:"updated_by"`
}

// RegistryWrite is an encrypted registry token.
type RegistryWrite struct {
	Username   string
	Nonce      []byte
	Ciphertext []byte
	KeyVersion int
}

// RegistryMaterial is one stored registry token. It is not returned over HTTP.
type RegistryMaterial struct {
	Host       string
	Username   string
	Nonce      []byte
	Ciphertext []byte
	KeyVersion int
}

// DefaultGrantActions is the grant inserted for a new entry.
// Program owners do not receive deploy. Image owners and admins do.
func DefaultGrantActions(kind string) (admin, viewer []string) {
	if kind == "image" {
		return []string{"run", "stop", "restart", "logs", "deploy"}, []string{"logs"}
	}
	return []string{"run", "stop", "restart", "logs"}, []string{"logs"}
}
