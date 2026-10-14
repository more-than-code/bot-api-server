package memstore

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (m *Mem) CreateProject(_ context.Context, ownerID uuid.UUID, name, baseSlug string, at time.Time) (store.Project, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[ownerID]; !ok {
		return store.Project{}, store.ErrNotFound
	}
	slug, err := store.Unique(baseSlug, 80, func(s string) bool {
		_, taken := m.bySlug[s]
		return taken
	})
	if err != nil {
		return store.Project{}, err
	}
	p := store.Project{
		ID:        uuid.New(),
		Name:      name,
		Slug:      slug,
		Role:      storeRoleOwner,
		CreatedBy: ownerID,
		CreatedAt: at,
	}
	m.projects[p.ID] = p
	m.bySlug[slug] = p.ID
	m.members[memberKey(p.ID, ownerID)] = memberRec{
		ProjectID: p.ID,
		UserID:    ownerID,
		Role:      storeRoleOwner,
		AddedBy:   ownerID,
		CreatedAt: at,
	}
	return p, nil
}

const storeRoleOwner = "owner"

func (m *Mem) ListProjects(_ context.Context, userID uuid.UUID, limit int, cursor *store.Cursor) ([]store.Project, *store.Cursor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var items []store.Project
	for _, mem := range m.members {
		if mem.UserID != userID {
			continue
		}
		p, ok := m.projects[mem.ProjectID]
		if !ok || p.DeletedAt != nil {
			continue
		}
		p.Role = mem.Role
		items = append(items, p)
	}
	out, next := pageProjects(items, limit, cursor)
	return out, next, nil
}

func (m *Mem) ListAllProjects(ctx context.Context, userID uuid.UUID) ([]store.Project, error) {
	items, _, err := m.ListProjects(ctx, userID, 10000, nil)
	return items, err
}

func (m *Mem) GetProject(_ context.Context, id uuid.UUID) (store.Project, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.projects[id]
	if !ok || p.DeletedAt != nil {
		return store.Project{}, store.ErrNotFound
	}
	return p, nil
}

func (m *Mem) Role(_ context.Context, projectID, userID uuid.UUID) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.projects[projectID]
	if !ok || p.DeletedAt != nil {
		return "", store.ErrNotFound
	}
	mem, ok := m.members[memberKey(projectID, userID)]
	if !ok {
		return "", store.ErrNotFound
	}
	return mem.Role, nil
}

func (m *Mem) RenameProject(_ context.Context, id uuid.UUID, name string) (store.Project, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.projects[id]
	if !ok || p.DeletedAt != nil {
		return store.Project{}, store.ErrNotFound
	}
	p.Name = name
	m.projects[id] = p
	return p, nil
}

func (m *Mem) DeleteProject(_ context.Context, id uuid.UUID, at time.Time) ([]uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.projects[id]
	if !ok || p.DeletedAt != nil {
		return nil, store.ErrNotFound
	}
	p.DeletedAt = &at
	m.projects[id] = p
	var ids []uuid.UUID
	for hid, h := range m.hosts {
		if h.ProjectID != id {
			continue
		}
		ids = append(ids, hid)
		if h.RevokedAt == nil {
			h.RevokedAt = &at
			m.hosts[hid] = h
		}
		m.revokeCredsLocked(hid, at)
	}
	m.cascadeProjectLocked(id)
	sortUUIDs(ids)
	return ids, nil
}

// cascadeProjectLocked moves this project's services on other hosts back to
// those hosts' owners, and drops shares of this project and of its hosts.
func (m *Mem) cascadeProjectLocked(projectID uuid.UUID) {
	for id, svc := range m.services {
		if svc.ProjectID != projectID {
			continue
		}
		h, ok := m.hosts[svc.HostID]
		if !ok || h.ProjectID == projectID {
			continue
		}
		svc.ProjectID = h.ProjectID
		m.services[id] = svc
	}
	for key, sh := range m.shares {
		h, ok := m.hosts[sh.HostID]
		if sh.ProjectID == projectID || (ok && h.ProjectID == projectID) {
			delete(m.shares, key)
		}
	}
}

func (m *Mem) revokeCredsLocked(hostID uuid.UUID, at time.Time) {
	for id, c := range m.creds {
		if c.HostID == hostID && c.RevokedAt == nil {
			t := at
			c.RevokedAt = &t
			m.creds[id] = c
		}
	}
}

func (m *Mem) ListMembers(_ context.Context, projectID uuid.UUID, limit int, cursor *store.Cursor) ([]store.Member, *store.Cursor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.projects[projectID]; !ok || p.DeletedAt != nil {
		return nil, nil, store.ErrNotFound
	}
	var items []store.Member
	for _, mem := range m.members {
		if mem.ProjectID != projectID {
			continue
		}
		u := m.users[mem.UserID]
		items = append(items, store.Member{
			UserID:    mem.UserID,
			Email:     u.Email,
			Name:      u.Name,
			Role:      mem.Role,
			CreatedAt: mem.CreatedAt,
		})
	}
	out, next := pageBy(items, limit, cursor, func(it store.Member) time.Time { return it.CreatedAt }, func(it store.Member) string { return it.UserID.String() }, false)
	return out, next, nil
}

func (m *Mem) AddMember(_ context.Context, projectID, userID uuid.UUID, role string, addedBy uuid.UUID, at time.Time) (store.Member, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.projects[projectID]; !ok || p.DeletedAt != nil {
		return store.Member{}, store.ErrNotFound
	}
	u, ok := m.users[userID]
	if !ok {
		return store.Member{}, store.ErrNotFound
	}
	key := memberKey(projectID, userID)
	if _, exists := m.members[key]; exists {
		return store.Member{}, store.ErrConflict
	}
	m.members[key] = memberRec{ProjectID: projectID, UserID: userID, Role: role, AddedBy: addedBy, CreatedAt: at}
	return store.Member{UserID: userID, Email: u.Email, Name: u.Name, Role: role, CreatedAt: at}, nil
}

func (m *Mem) UpdateMemberRole(_ context.Context, projectID, userID uuid.UUID, role string) (store.Member, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := memberKey(projectID, userID)
	mem, ok := m.members[key]
	if !ok {
		return store.Member{}, store.ErrNotFound
	}
	if mem.Role == storeRoleOwner {
		return store.Member{}, store.ErrOwner
	}
	mem.Role = role
	m.members[key] = mem
	u := m.users[userID]
	return store.Member{UserID: userID, Email: u.Email, Name: u.Name, Role: role, CreatedAt: mem.CreatedAt}, nil
}

func (m *Mem) RemoveMember(_ context.Context, projectID, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := memberKey(projectID, userID)
	mem, ok := m.members[key]
	if !ok {
		return store.ErrNotFound
	}
	if mem.Role == storeRoleOwner {
		return store.ErrOwner
	}
	delete(m.members, key)
	return nil
}

func (m *Mem) TransferOwnership(_ context.Context, projectID, newOwner uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	targetKey := memberKey(projectID, newOwner)
	target, ok := m.members[targetKey]
	if !ok {
		return store.ErrNotFound
	}
	var ownerKey string
	for k, mem := range m.members {
		if mem.ProjectID == projectID && mem.Role == storeRoleOwner {
			ownerKey = k
			break
		}
	}
	if ownerKey == "" {
		return store.ErrState
	}
	owner := m.members[ownerKey]
	owner.Role = "admin"
	m.members[ownerKey] = owner
	target = m.members[targetKey]
	target.Role = storeRoleOwner
	m.members[targetKey] = target
	return nil
}

func pageProjects(items []store.Project, limit int, cursor *store.Cursor) ([]store.Project, *store.Cursor) {
	return pageBy(items, limit, cursor, func(p store.Project) time.Time { return p.CreatedAt }, func(p store.Project) string { return p.ID.String() }, false)
}
