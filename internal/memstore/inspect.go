package memstore

import (
	"bytes"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// AllAudits returns a copy of every audit row, including sign-in rows that
// have no project id and so are omitted from ListAudit.
func (m *Mem) AllAudits() []store.AuditEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.AuditEntry, len(m.audits))
	copy(out, m.audits)
	return out
}

// DropProjectFile removes a file without the reference check. Tests use it
// to build the deleted-since-save state the API refuses to create.
func (m *Mem) DropProjectFile(projectID uuid.UUID, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.projectFiles, envKey(projectID, name))
}

// TamperProjectFile flips the last ciphertext byte. Tests use it to prove a
// deploy fails closed. It does not log the bytes.
func (m *Mem) TamperProjectFile(projectID uuid.UUID, name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := envKey(projectID, name)
	rec, ok := m.projectFiles[key]
	if !ok || len(rec.Ciphertext) == 0 {
		return false
	}
	ct := append([]byte(nil), rec.Ciphertext...)
	ct[len(ct)-1] ^= 0xff
	rec.Ciphertext = ct
	m.projectFiles[key] = rec
	return true
}

// HoldsPlaintext reports whether a session, join token, invite, device code,
// or host credential is stored as the plaintext bytes. User codes are
// plaintext on purpose and are not checked here.
func (m *Mem) HoldsPlaintext(plain string) bool {
	if plain == "" {
		return false
	}
	raw := []byte(plain)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, rec := range m.sessions {
		if bytes.Contains(rec.hash, raw) {
			return true
		}
	}
	for _, rec := range m.tokens {
		if bytes.Contains(rec.hash, raw) {
			return true
		}
	}
	for _, rec := range m.invites {
		if bytes.Contains(rec.hash, raw) {
			return true
		}
	}
	for _, d := range m.devices {
		if bytes.Contains(d.Hash, raw) {
			return true
		}
	}
	for _, c := range m.creds {
		if bytes.Contains(c.Hash, raw) {
			return true
		}
	}
	for _, code := range m.oauthCodes {
		if bytes.Contains(code.hash, raw) {
			return true
		}
	}
	for _, client := range m.oauthClients {
		if bytes.Contains(client.SecretHash, raw) {
			return true
		}
	}
	return false
}

// DeviceCount is the number of device-code rows.
func (m *Mem) DeviceCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.devices)
}
