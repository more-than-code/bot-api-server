package memstore

import (
	"bytes"

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
