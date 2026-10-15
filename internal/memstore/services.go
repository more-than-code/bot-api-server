package memstore

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/authz"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (m *Mem) ListServices(_ context.Context, hostID uuid.UUID, projects []uuid.UUID, now time.Time) ([]store.Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var items []store.Service
	for _, s := range m.services {
		if s.HostID != hostID {
			continue
		}
		if !projectVisible(s.ProjectID, projects) {
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
	hostProject := m.hosts[hostID].ProjectID
	for _, item := range items {
		name, source, projectID, catalogEntry := store.PlaceDiscovered(item, hostProject, m.lookupCatalogLocked)
		var found uuid.UUID
		var existing store.Service
		ok := false
		for id, s := range m.services {
			if s.HostID == hostID && s.Name == name {
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
				ProjectID:     projectID,
				Name:          name,
				Source:        source,
				Kind:          item.Kind,
				Ports:         copyInts(item.Ports),
				SystemdUnit:   cloneString(item.SystemdUnit),
				SystemdScope:  cloneString(item.SystemdScope),
				ContainerName: cloneString(item.ContainerName),
				ProcessName:   cloneString(item.ProcessName),
				OwnerUser:     store.NormalizeOwnerUser(item.OwnerUser),
				CatalogEntry:  cloneString(catalogEntry),
				FirstSeenAt:   at,
				LastSeenAt:    at,
			}
			continue
		}
		existing.LastSeenAt = at
		existing.OwnerUser = store.NormalizeOwnerUser(item.OwnerUser)
		if existing.Source != "declared" && source == "owned" {
			existing.Source = "owned"
			existing.ProjectID = projectID
			existing.CatalogEntry = cloneString(catalogEntry)
		}
		if existing.Source != "declared" {
			existing.Kind = item.Kind
			existing.Ports = copyInts(item.Ports)
			existing.SystemdUnit = cloneString(item.SystemdUnit)
			existing.SystemdScope = cloneString(item.SystemdScope)
			existing.ContainerName = cloneString(item.ContainerName)
			existing.ProcessName = cloneString(item.ProcessName)
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

func (m *Mem) SetServiceDisplayName(_ context.Context, id uuid.UUID, name *string, now time.Time) (store.Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.services[id]
	if !ok {
		return store.Service{}, store.ErrNotFound
	}
	if name != nil {
		want := strings.ToLower(*name)
		for otherID, other := range m.services {
			if otherID == id || other.HostID != s.HostID || other.DisplayName == nil {
				continue
			}
			if strings.ToLower(*other.DisplayName) == want {
				return store.Service{}, store.ErrConflict
			}
		}
		copied := *name
		s.DisplayName = &copied
	} else {
		s.DisplayName = nil
	}
	m.services[id] = s
	return m.serviceCopyLocked(s, now), nil
}

func (m *Mem) ListProjectServices(_ context.Context, projectID uuid.UUID, q store.ServiceListQuery, now time.Time) (store.ServicePage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if q.HostID != nil {
		host, ok := m.hosts[*q.HostID]
		level := ""
		if ok {
			level = m.shareLevelLocked(*q.HostID, projectID)
		}
		if !ok || !authz.ProjectHostReached(host.ProjectID == projectID, level) {
			return store.ServicePage{}, store.ErrInvalid
		}
	}
	var rows []store.ProjectService
	for _, svc := range m.services {
		host, ok := m.hosts[svc.HostID]
		if !ok {
			continue
		}
		level := m.shareLevelLocked(host.ID, projectID)
		if !authz.ProjectServiceVisible(host.ProjectID == projectID, level, svc.ProjectID, projectID) {
			continue
		}
		if q.HostID != nil && svc.HostID != *q.HostID {
			continue
		}
		projectName := ""
		if p, ok := m.projects[svc.ProjectID]; ok {
			projectName = p.Name
		}
		row := m.projectRowLocked(svc, host, projectName, now)
		if !serviceMatches(row, q.Q) {
			continue
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		return store.ServiceBefore(serviceOrder(rows[i]), serviceOrder(rows[j]), q.Sort, q.Dir)
	})
	total := len(rows)
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}
	if offset > len(rows) {
		offset = len(rows)
	}
	rows = rows[offset:]
	limit := q.Limit
	if limit < 1 {
		limit = 50
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	if rows == nil {
		rows = []store.ProjectService{}
	}
	return store.ServicePage{Items: rows, Total: total}, nil
}

func (m *Mem) shareLevelLocked(hostID, projectID uuid.UUID) string {
	sh, ok := m.shares[shareKey(hostID, projectID)]
	if !ok {
		return ""
	}
	return sh.Level
}

func (m *Mem) projectRowLocked(svc store.Service, host store.Host, projectName string, now time.Time) store.ProjectService {
	copied := m.serviceCopyLocked(svc, now)
	var revoked *time.Time
	if host.RevokedAt != nil {
		t := *host.RevokedAt
		revoked = &t
	}
	return store.ProjectService{
		Service:       copied,
		HostName:      host.Name,
		ProjectName:   projectName,
		HostRevokedAt: revoked,
		HostAlwaysOn:  host.AlwaysOn,
	}
}

func (m *Mem) serviceCopyLocked(svc store.Service, now time.Time) store.Service {
	svc.Health = store.DeriveHealth(m.latestHealthLocked(svc.ID), now)
	svc.Ports = copyInts(svc.Ports)
	svc.DisplayName = cloneString(svc.DisplayName)
	svc.OwnerUser = cloneString(svc.OwnerUser)
	svc.SystemdUnit = cloneString(svc.SystemdUnit)
	svc.SystemdScope = cloneString(svc.SystemdScope)
	svc.ContainerName = cloneString(svc.ContainerName)
	svc.ProcessName = cloneString(svc.ProcessName)
	svc.CatalogEntry = cloneString(svc.CatalogEntry)
	return svc
}

func serviceOrder(row store.ProjectService) store.ServiceOrder {
	name := row.Name
	if row.DisplayName != nil {
		name = *row.DisplayName
	}
	return store.ServiceOrder{
		ID:         row.ID,
		NameKey:    strings.ToLower(name),
		Host:       row.HostName,
		Kind:       row.Kind,
		StatusRank: store.HealthRank(row.Health.Status),
		LastSeen:   row.LastSeenAt,
	}
}

func serviceMatches(row store.ProjectService, q string) bool {
	if q == "" {
		return true
	}
	needle := strings.ToLower(q)
	fields := []string{row.Name, row.Kind, row.HostName}
	if row.DisplayName != nil {
		fields = append(fields, *row.DisplayName)
	}
	if row.OwnerUser != nil {
		fields = append(fields, *row.OwnerUser)
	}
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), needle) {
			return true
		}
	}
	for _, port := range row.Ports {
		if strings.Contains(strconv.Itoa(port), needle) {
			return true
		}
	}
	return false
}

func cloneString(in *string) *string {
	if in == nil {
		return nil
	}
	v := *in
	return &v
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
		ProjectID:   m.hosts[hostID].ProjectID,
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

// SetServiceProject assigns a service to a project. Tests use it to place a
// service on a sharing project. It is not part of store.Store.
func (m *Mem) SetServiceProject(id, projectID uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.services[id]
	if !ok {
		return
	}
	s.ProjectID = projectID
	m.services[id] = s
}
