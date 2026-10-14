package memstore

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func shareKey(hostID, projectID uuid.UUID) string {
	return hostID.String() + "/" + projectID.String()
}

func (m *Mem) HostFacts(_ context.Context, userID, hostID uuid.UUID) (store.HostFacts, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[hostID]
	if !ok {
		return store.HostFacts{}, store.ErrNotFound
	}
	var facts store.HostFacts
	if p, ok := m.projects[h.ProjectID]; ok && p.DeletedAt == nil {
		if mem, ok := m.members[memberKey(h.ProjectID, userID)]; ok {
			facts.OwnerRole = mem.Role
		}
	}
	for _, sh := range m.shares {
		if sh.HostID != hostID {
			continue
		}
		p, ok := m.projects[sh.ProjectID]
		if !ok || p.DeletedAt != nil {
			continue
		}
		mem, ok := m.members[memberKey(sh.ProjectID, userID)]
		if !ok {
			continue
		}
		facts.Shares = append(facts.Shares, store.HostShareAccess{
			ProjectID: sh.ProjectID,
			Level:     sh.Level,
			Role:      mem.Role,
		})
	}
	sort.Slice(facts.Shares, func(i, j int) bool {
		return facts.Shares[i].ProjectID.String() < facts.Shares[j].ProjectID.String()
	})
	return facts, nil
}

func (m *Mem) ListHostShares(_ context.Context, hostID uuid.UUID) ([]store.HostShare, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.hosts[hostID]; !ok {
		return nil, store.ErrNotFound
	}
	out := []store.HostShare{}
	for _, sh := range m.shares {
		if sh.HostID != hostID {
			continue
		}
		if p, ok := m.projects[sh.ProjectID]; ok {
			sh.ProjectName = p.Name
		}
		out = append(out, sh)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ProjectName != out[j].ProjectName {
			return out[i].ProjectName < out[j].ProjectName
		}
		return out[i].ProjectID.String() < out[j].ProjectID.String()
	})
	return out, nil
}

func (m *Mem) PutHostShare(_ context.Context, hostID, projectID uuid.UUID, level string, createdBy uuid.UUID, at time.Time) (store.HostShare, bool, error) {
	if !store.ValidShareLevel(level) {
		return store.HostShare{}, false, store.ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[hostID]
	if !ok {
		return store.HostShare{}, false, store.ErrNotFound
	}
	owner, ok := m.projects[h.ProjectID]
	if !ok || owner.DeletedAt != nil {
		return store.HostShare{}, false, store.ErrNotFound
	}
	if h.ProjectID == projectID {
		return store.HostShare{}, false, store.ErrInvalid
	}
	p, ok := m.projects[projectID]
	if !ok || p.DeletedAt != nil {
		return store.HostShare{}, false, store.ErrNotFound
	}
	key := shareKey(hostID, projectID)
	prev, existed := m.shares[key]
	item := store.HostShare{
		HostID:      hostID,
		ProjectID:   projectID,
		ProjectName: p.Name,
		Level:       level,
		CreatedBy:   createdBy,
		CreatedAt:   at,
	}
	if existed {
		item.CreatedBy = prev.CreatedBy
		item.CreatedAt = prev.CreatedAt
	}
	m.shares[key] = item
	return item, !existed, nil
}

func (m *Mem) DeleteHostShare(_ context.Context, hostID, projectID uuid.UUID, reassignOwner bool) (store.HostShare, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[hostID]
	if !ok {
		return store.HostShare{}, store.ErrNotFound
	}
	key := shareKey(hostID, projectID)
	item, ok := m.shares[key]
	if !ok {
		return store.HostShare{}, store.ErrNotFound
	}
	if p, ok := m.projects[projectID]; ok {
		item.ProjectName = p.Name
	}
	n := 0
	for _, svc := range m.services {
		if svc.HostID == hostID && svc.ProjectID == projectID {
			n++
		}
	}
	if n > 0 && !reassignOwner {
		return store.HostShare{}, store.ErrConflict
	}
	if n > 0 {
		for id, svc := range m.services {
			if svc.HostID == hostID && svc.ProjectID == projectID {
				svc.ProjectID = h.ProjectID
				m.services[id] = svc
			}
		}
	}
	delete(m.shares, key)
	return item, nil
}
