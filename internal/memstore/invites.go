package memstore

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (m *Mem) CreateInvite(_ context.Context, projectID uuid.UUID, hash []byte, role string, createdBy uuid.UUID, expiresAt, at time.Time, maxUses int) (store.Invite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.projects[projectID]; !ok || p.DeletedAt != nil {
		return store.Invite{}, store.ErrNotFound
	}
	inv := store.Invite{
		ID:        uuid.New(),
		ProjectID: projectID,
		Role:      role,
		CreatedBy: createdBy,
		CreatedAt: at,
		ExpiresAt: expiresAt,
		MaxUses:   maxUses,
	}
	m.invites[inv.ID] = inviteRec{Invite: inv, hash: cloneBytes(hash)}
	m.inviteByHash[hashKey(hash)] = inv.ID
	return inv, nil
}

func (m *Mem) ListInvites(_ context.Context, projectID uuid.UUID, limit int, cursor *store.Cursor) ([]store.Invite, *store.Cursor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.projects[projectID]; !ok || p.DeletedAt != nil {
		return nil, nil, store.ErrNotFound
	}
	var items []store.Invite
	for _, inv := range m.invites {
		if inv.ProjectID == projectID {
			items = append(items, inv.Invite)
		}
	}
	out, next := pageBy(items, limit, cursor, func(inv store.Invite) time.Time { return inv.CreatedAt }, func(inv store.Invite) string { return inv.ID.String() }, true)
	return out, next, nil
}

func (m *Mem) RevokeInvite(_ context.Context, projectID, inviteID uuid.UUID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[inviteID]
	if !ok || inv.ProjectID != projectID {
		return store.ErrNotFound
	}
	if inv.RevokedAt == nil {
		inv.RevokedAt = &at
		m.invites[inviteID] = inv
	}
	return nil
}

func (m *Mem) LookupInvite(_ context.Context, tokenHash []byte, userID uuid.UUID, at time.Time) (store.InviteLookup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.inviteByHashLocked(tokenHash)
	if !ok || !store.InviteUsable(inv.Invite, at) {
		return store.InviteLookup{}, store.ErrNotFound
	}
	p, ok := m.projects[inv.ProjectID]
	if !ok || p.DeletedAt != nil {
		return store.InviteLookup{}, store.ErrNotFound
	}
	_, member := m.members[memberKey(inv.ProjectID, userID)]
	return store.InviteLookup{
		ProjectID:     inv.ProjectID,
		ProjectName:   p.Name,
		Role:          inv.Role,
		AlreadyMember: member,
	}, nil
}

func (m *Mem) AcceptInvite(_ context.Context, tokenHash []byte, userID uuid.UUID, at time.Time) (store.InviteAccept, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.inviteByHashLocked(tokenHash)
	if !ok || !store.InviteUsable(inv.Invite, at) {
		return store.InviteAccept{}, store.ErrNotFound
	}
	p, ok := m.projects[inv.ProjectID]
	if !ok || p.DeletedAt != nil {
		return store.InviteAccept{}, store.ErrNotFound
	}
	if mem, member := m.members[memberKey(inv.ProjectID, userID)]; member {
		return store.InviteAccept{InviteID: inv.ID, ProjectID: inv.ProjectID, Role: mem.Role}, nil
	}
	if _, ok := m.users[userID]; !ok {
		return store.InviteAccept{}, store.ErrNotFound
	}
	inv.Uses++
	m.invites[inv.ID] = inv
	m.members[memberKey(inv.ProjectID, userID)] = memberRec{
		ProjectID: inv.ProjectID,
		UserID:    userID,
		Role:      inv.Role,
		AddedBy:   inv.CreatedBy,
		CreatedAt: at,
	}
	return store.InviteAccept{InviteID: inv.ID, ProjectID: inv.ProjectID, Role: inv.Role}, nil
}

func (m *Mem) inviteByHashLocked(tokenHash []byte) (inviteRec, bool) {
	id, ok := m.inviteByHash[hashKey(tokenHash)]
	if !ok || !secret.Equal(tokenHash, m.invites[id].hash) {
		secret.Equal(tokenHash, dummyHash)
		return inviteRec{}, false
	}
	return m.invites[id], true
}

func (m *Mem) deleteInvitesLocked(projectID uuid.UUID) {
	for id, inv := range m.invites {
		if inv.ProjectID != projectID {
			continue
		}
		delete(m.inviteByHash, hashKey(inv.hash))
		delete(m.invites, id)
	}
}
