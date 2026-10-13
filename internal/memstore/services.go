package memstore

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (m *Mem) ListServices(_ context.Context, hostID uuid.UUID, now time.Time) ([]store.Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var items []store.Service
	for _, s := range m.services {
		if s.HostID != hostID {
			continue
		}
		s.Health = store.DeriveHealth(m.latestHealthLocked(s.ID), now)
		s.Ports = copyInts(s.Ports)
		items = append(items, s)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	if len(items) > 500 {
		items = items[:500]
	}
	if items == nil {
		items = []store.Service{}
	}
	return items, nil
}

func (m *Mem) GetService(_ context.Context, id uuid.UUID, now time.Time) (store.Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.services[id]
	if !ok {
		return store.Service{}, store.ErrNotFound
	}
	s.Health = store.DeriveHealth(m.latestHealthLocked(s.ID), now)
	s.Ports = copyInts(s.Ports)
	return s, nil
}

func (m *Mem) UpsertDiscovered(_ context.Context, hostID uuid.UUID, items []store.Discovered, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.hosts[hostID]; !ok {
		return store.ErrNotFound
	}
	for _, item := range items {
		var found uuid.UUID
		var existing store.Service
		ok := false
		for id, s := range m.services {
			if s.HostID == hostID && s.Name == item.Name {
				found = id
				existing = s
				ok = true
				break
			}
		}
		if !ok {
			id := uuid.New()
			m.services[id] = store.Service{
				ID:            id,
				HostID:        hostID,
				Name:          item.Name,
				Source:        "discovered",
				Kind:          item.Kind,
				Ports:         copyInts(item.Ports),
				SystemdUnit:   item.SystemdUnit,
				SystemdScope:  item.SystemdScope,
				ContainerName: item.ContainerName,
				ProcessName:   item.ProcessName,
				FirstSeenAt:   at,
				LastSeenAt:    at,
			}
			continue
		}
		existing.LastSeenAt = at
		if existing.Source == "discovered" {
			existing.Kind = item.Kind
			existing.Ports = copyInts(item.Ports)
			existing.SystemdUnit = item.SystemdUnit
			existing.SystemdScope = item.SystemdScope
			existing.ContainerName = item.ContainerName
			existing.ProcessName = item.ProcessName
		}
		m.services[found] = existing
	}
	return nil
}

func (m *Mem) ReplaceHealthChecks(_ context.Context, serviceID uuid.UUID, checks []store.HealthCheckInput) ([]store.HealthCheck, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.services[serviceID]; !ok {
		return nil, store.ErrNotFound
	}
	for id, c := range m.checks {
		if c.ServiceID == serviceID {
			delete(m.checks, id)
		}
	}
	out := make([]store.HealthCheck, 0, len(checks))
	for _, in := range checks {
		c := store.HealthCheck{
			ID:              uuid.New(),
			ServiceID:       serviceID,
			Protocol:        in.Protocol,
			Port:            in.Port,
			Path:            in.Path,
			IntervalSec:     in.IntervalSec,
			ExpectStatusMin: in.ExpectStatusMin,
			ExpectStatusMax: in.ExpectStatusMax,
			Enabled:         in.Enabled,
		}
		m.checks[c.ID] = c
		out = append(out, c)
	}
	return out, nil
}

func (m *Mem) ListHealthChecks(_ context.Context, serviceID uuid.UUID) ([]store.HealthCheck, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.HealthCheck
	for _, c := range m.checks {
		if c.ServiceID == serviceID {
			out = append(out, c)
		}
	}
	if out == nil {
		out = []store.HealthCheck{}
	}
	return out, nil
}

func (m *Mem) HealthChecksForHost(_ context.Context, hostID uuid.UUID) ([]store.AgentCheck, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.AgentCheck
	for _, c := range m.checks {
		if !c.Enabled {
			continue
		}
		svc, ok := m.services[c.ServiceID]
		if !ok || svc.HostID != hostID {
			continue
		}
		out = append(out, store.AgentCheck{
			ID:              c.ID,
			Service:         svc.Name,
			Protocol:        c.Protocol,
			Port:            c.Port,
			Path:            c.Path,
			IntervalSec:     c.IntervalSec,
			ExpectStatusMin: c.ExpectStatusMin,
			ExpectStatusMax: c.ExpectStatusMax,
		})
	}
	if out == nil {
		out = []store.AgentCheck{}
	}
	return out, nil
}

func copyInts(in []int) []int {
	if len(in) == 0 {
		return []int{}
	}
	return append([]int(nil), in...)
}

// PutDeclared seeds a declared service. Tests use it to prove discovery does
// not downgrade manually set fields. It is not part of store.Store.
func (m *Mem) PutDeclared(hostID uuid.UUID, name, kind string, ports []int, at time.Time) store.Service {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := store.Service{
		ID:          uuid.New(),
		HostID:      hostID,
		Name:        name,
		Source:      "declared",
		Kind:        kind,
		Ports:       copyInts(ports),
		FirstSeenAt: at,
		LastSeenAt:  at,
	}
	m.services[s.ID] = s
	return s
}
