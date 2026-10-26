package store

import (
	"encoding/json"
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
	By            *uuid.UUID `json:"by"`
	Via           string     `json:"via"`
	InFlight      bool       `json:"-"`
	InFlightUntil time.Time  `json:"-"`
}

// AutoActionsPerHour is the rev 2 cap on stored auto_action rows per
// (entry, host) in a rolling hour.
const AutoActionsPerHour = 20

// AutoTarget is the entry an auto_action names, as one host sees it.
// Deployed is true when the entry has a succeeded or unchanged deploy row
// on that host.
type AutoTarget struct {
	ProjectID uuid.UUID
	EntryID   uuid.UUID
	ImageRaw  json.RawMessage
	Deployed  bool
}

// AutoAction is one checked agent auto_action to store (api-v1 v1.15 item 3).
// Outcome is auto_restarted, auto_rolled_back, auto_gave_up, or auto_failed.
// Digest is nil when the frame sent null or the outcome is auto_failed.
// At is server time.
type AutoAction struct {
	ID      uuid.UUID
	EntryID uuid.UUID
	HostID  uuid.UUID
	Outcome string
	Digest  *string
	At      time.Time
}

// IsAutoOutcome reports the automatic deploy-row outcomes.
func IsAutoOutcome(outcome string) bool {
	switch outcome {
	case "auto_restarted", "auto_rolled_back", "auto_gave_up", "auto_failed":
		return true
	}
	return false
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

// EnvSecret is one env value prepared for PutEnvSet, CreateEnvSet, and MergeEnvSet.
// Nonce, Ciphertext, and KeyVersion seal Plain (AAD project_id|set|key).
// The store keeps Plain for a key that is plain (an existing plain key, or a
// new key when newKeysSecret is false) and the seal for a key that is secret.
type EnvSecret struct {
	Key        string
	Plain      string
	Nonce      []byte
	Ciphertext []byte
	KeyVersion int
}

// EnvSealer seals one stored plain value for MakeEnvKeysSecret, which calls
// it while holding the set's locks. It must be pure CPU work and must not
// call the Store. Only Nonce, Ciphertext, and KeyVersion of its result are read.
type EnvSealer func(key, plain string) (EnvSecret, error)

// MissingEnvKeyError is a MakeEnvKeysSecret key that is not in the set.
// It matches ErrNotFound. The message names the key, never a value.
type MissingEnvKeyError struct {
	Key string
}

func (e *MissingEnvKeyError) Error() string { return "key " + e.Key + " not found" }

func (e *MissingEnvKeyError) Is(target error) bool { return target == ErrNotFound }

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
