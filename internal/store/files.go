package store

import (
	"time"

	"github.com/google/uuid"
)

// MaxProjectFiles is the number of files one project may store.
const MaxProjectFiles = 64

// ProjectFile is one file in an HTTP list or PUT response.
// SHA256 is null when the file is secret. Content is never on this object.
type ProjectFile struct {
	Name      string    `json:"name"`
	IsSecret  bool      `json:"is_secret"`
	Size      int       `json:"size"`
	SHA256    *string   `json:"sha256"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy uuid.UUID `json:"updated_by"`
	Plain     string    `json:"-"`
}

// FileWrite is one sealed or plain file body. Plain is empty when IsSecret.
type FileWrite struct {
	IsSecret   bool
	Plain      string
	Nonce      []byte
	Ciphertext []byte
	KeyVersion int
	SHA256     string
	Size       int
}

// FileMaterial is a stored file, including ciphertext. It is not an HTTP body.
type FileMaterial struct {
	Name       string
	IsSecret   bool
	Plain      string
	Nonce      []byte
	Ciphertext []byte
	KeyVersion int
	SHA256     string
	Size       int
	UpdatedAt  time.Time
	UpdatedBy  uuid.UUID
}

// FileInUse is a delete refused because image entries still name the file.
// Entries is sorted. Error text is "conflict"; the HTTP layer lists Entries.
type FileInUse struct {
	Entries []string
}

func (e *FileInUse) Error() string { return "conflict" }

func (e *FileInUse) Unwrap() error { return ErrConflict }
