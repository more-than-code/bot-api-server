package memstore

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (m *Mem) CreateJoinToken(_ context.Context, projectID uuid.UUID, hash []byte, hint *string, createdBy uuid.UUID, expiresAt, at time.Time) (store.JoinToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.projects[projectID]; !ok || p.DeletedAt != nil {
		return store.JoinToken{}, store.ErrNotFound
	}
	tok := store.JoinToken{
		ID:           uuid.New(),
		ProjectID:    projectID,
		HostNameHint: hint,
		CreatedBy:    createdBy,
		CreatedAt:    at,
		ExpiresAt:    expiresAt,
	}
	m.tokens[tok.ID] = tokenRec{JoinToken: tok, hash: cloneBytes(hash)}
	m.tokenByHash[hashKey(hash)] = tok.ID
	return tok, nil
}

func (m *Mem) ListJoinTokens(_ context.Context, projectID uuid.UUID, limit int, cursor *store.Cursor) ([]store.JoinToken, *store.Cursor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var items []store.JoinToken
	for _, tok := range m.tokens {
		if tok.ProjectID == projectID {
			items = append(items, tok.JoinToken)
		}
	}
	out, next := pageBy(items, limit, cursor, func(t store.JoinToken) time.Time { return t.CreatedAt }, func(t store.JoinToken) string { return t.ID.String() }, false)
	return out, next, nil
}

func (m *Mem) RevokeJoinToken(_ context.Context, projectID, tokenID uuid.UUID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tok, ok := m.tokens[tokenID]
	if !ok || tok.ProjectID != projectID {
		return store.ErrNotFound
	}
	if tok.RevokedAt == nil {
		tok.RevokedAt = &at
		m.tokens[tokenID] = tok
	}
	return nil
}

func (m *Mem) ConsumeJoinToken(_ context.Context, tokenHash []byte, in store.EnrollInput, credentialID uuid.UUID, credentialHash []byte, at time.Time) (store.Host, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.tokenByHash[hashKey(tokenHash)]
	if !ok || !secret.Equal(tokenHash, m.tokens[id].hash) {
		secret.Equal(tokenHash, dummyHash)
		return store.Host{}, store.ErrUnauthorized
	}
	tok := m.tokens[id]
	if tok.UsedAt != nil || tok.RevokedAt != nil || !at.Before(tok.ExpiresAt) {
		return store.Host{}, store.ErrUnauthorized
	}
	p, ok := m.projects[tok.ProjectID]
	if !ok || p.DeletedAt != nil {
		return store.Host{}, store.ErrUnauthorized
	}
	name, err := store.Unique(in.Name, 63, func(candidate string) bool {
		for _, h := range m.hosts {
			if h.ProjectID == tok.ProjectID && h.Name == candidate {
				return true
			}
		}
		return false
	})
	if err != nil {
		return store.Host{}, err
	}
	host := store.Host{
		ID:           uuid.New(),
		ProjectID:    tok.ProjectID,
		Name:         name,
		NodeType:     in.NodeType,
		OS:           in.OS,
		Arch:         in.Arch,
		AlwaysOn:     in.AlwaysOn,
		AgentVersion: in.AgentVersion,
		LastSeenAt:   &at,
		EnrolledAt:   at,
	}
	m.hosts[host.ID] = host
	m.creds[credentialID] = credRec{Credential: store.Credential{
		ID:     credentialID,
		HostID: host.ID,
		Hash:   cloneBytes(credentialHash),
	}}
	m.credByHash[hashKey(credentialHash)] = credentialID
	tok.UsedAt = &at
	tok.UsedByHostID = &host.ID
	m.tokens[id] = tok
	return host, nil
}

func (m *Mem) GetHost(_ context.Context, id uuid.UUID) (store.Host, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[id]
	if !ok {
		return store.Host{}, store.ErrNotFound
	}
	return cloneHost(h), nil
}

func (m *Mem) ListHosts(_ context.Context, projectID uuid.UUID, limit int, cursor *store.Cursor) ([]store.Host, *store.Cursor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	all := m.visibleHostsLocked(projectID)
	items := make([]store.Host, 0, len(all))
	for _, h := range all {
		if hostAfter(h, cursor) {
			items = append(items, h)
		}
	}
	if limit <= 0 {
		limit = 50
	}
	var next *store.Cursor
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		rank := 0
		if last.Relation == "shared" {
			rank = 1
		}
		next = &store.Cursor{Rank: &rank, Name: last.Name, ID: last.ID.String()}
	}
	if items == nil {
		items = []store.Host{}
	}
	return items, next, nil
}

func (m *Mem) visibleHostsLocked(projectID uuid.UUID) []store.Host {
	var items []store.Host
	for _, h := range m.hosts {
		if h.ProjectID != projectID {
			continue
		}
		h.Relation = "owner"
		h.ShareLevel = nil
		items = append(items, cloneHost(h))
	}
	for _, sh := range m.shares {
		if sh.ProjectID != projectID {
			continue
		}
		h, ok := m.hosts[sh.HostID]
		if !ok || h.ProjectID == projectID {
			continue
		}
		h.Relation = "shared"
		level := sh.Level
		h.ShareLevel = &level
		items = append(items, cloneHost(h))
	}
	sort.Slice(items, func(i, j int) bool {
		ri, rj := 0, 0
		if items[i].Relation == "shared" {
			ri = 1
		}
		if items[j].Relation == "shared" {
			rj = 1
		}
		if ri != rj {
			return ri < rj
		}
		if items[i].Name != items[j].Name {
			return items[i].Name < items[j].Name
		}
		return items[i].ID.String() < items[j].ID.String()
	})
	return items
}

// hostAfter reports whether h is strictly after the host-list cursor.
// A nil cursor, or one without a rank, starts at the beginning. The cursor
// host does not have to still be in the list.
func hostAfter(h store.Host, cursor *store.Cursor) bool {
	if cursor == nil || cursor.Rank == nil {
		return true
	}
	rank := 0
	if h.Relation == "shared" {
		rank = 1
	}
	if rank != *cursor.Rank {
		return rank > *cursor.Rank
	}
	if h.Name != cursor.Name {
		return h.Name > cursor.Name
	}
	return h.ID.String() > cursor.ID
}

func (m *Mem) RevokeHost(_ context.Context, hostID uuid.UUID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[hostID]
	if !ok {
		return store.ErrNotFound
	}
	if h.RevokedAt == nil {
		h.RevokedAt = &at
		m.hosts[hostID] = h
	}
	m.revokeCredsLocked(hostID, at)
	m.markHostServicesGoneLocked(hostID)
	return nil
}

func (m *Mem) TouchHost(_ context.Context, hostID uuid.UUID, at time.Time, version, osName, arch string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[hostID]
	if !ok {
		return store.ErrNotFound
	}
	h.LastSeenAt = &at
	if version != "" {
		h.AgentVersion = version
	}
	if osName != "" {
		h.OS = osName
	}
	if arch != "" {
		h.Arch = arch
	}
	m.hosts[hostID] = h
	return nil
}

func (m *Mem) LookupCredential(_ context.Context, hash []byte) (store.Credential, store.Host, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.credByHash[hashKey(hash)]
	if !ok {
		secret.Equal(hash, dummyHash)
		return store.Credential{}, store.Host{}, store.ErrUnauthorized
	}
	cred := m.creds[id]
	if !secret.Equal(hash, cred.Hash) {
		return store.Credential{}, store.Host{}, store.ErrUnauthorized
	}
	host, ok := m.hosts[cred.HostID]
	if !ok {
		return store.Credential{}, store.Host{}, store.ErrUnauthorized
	}
	return cred.Credential, cloneHost(host), nil
}
