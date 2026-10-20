package memstore

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (m *Mem) InsertBatch(_ context.Context, hostID, batchID uuid.UUID, samples []store.Sample, at time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := hostID.String() + "/" + batchID.String()
	if _, ok := m.batches[key]; ok {
		return false, nil
	}
	m.batches[key] = at
	for _, s := range samples {
		s.HostID = hostID
		if name := s.Tags["service"]; name != "" && (s.M == "process" || s.M == "health") {
			if id, ok := m.serviceIDLocked(hostID, name); ok {
				s.ServiceID = &id
			}
		}
		m.samples = append(m.samples, cloneSample(s))
	}
	return true, nil
}

func (m *Mem) LoadMetric(_ context.Context, hostID uuid.UUID, measurement string, from, to time.Time) ([]store.Sample, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Sample
	for _, s := range m.samples {
		if s.HostID == hostID && s.M == measurement && !s.T.Before(from) && s.T.Before(to) {
			out = append(out, cloneSample(s))
		}
	}
	if out == nil {
		out = []store.Sample{}
	}
	return out, nil
}

func (m *Mem) LatestProcesses(_ context.Context, hostID uuid.UUID, since time.Time, sortKey string, limit int) (*time.Time, []store.ProcessItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var maxT time.Time
	found := false
	for _, s := range m.samples {
		if s.HostID != hostID || s.M != "process" || s.T.Before(since) {
			continue
		}
		if !found || s.T.After(maxT) {
			maxT = s.T
			found = true
		}
	}
	if !found {
		return nil, []store.ProcessItem{}, nil
	}
	window := maxT.Add(-2 * time.Second)
	newest := map[int]store.ProcessItem{}
	newestAt := map[int]time.Time{}
	for _, s := range m.samples {
		if s.HostID != hostID || s.M != "process" {
			continue
		}
		if s.T.Before(window) || s.T.After(maxT) {
			continue
		}
		item := processItem(s)
		if prev, ok := newestAt[item.PID]; ok && !s.T.After(prev) {
			continue
		}
		newest[item.PID] = item
		newestAt[item.PID] = s.T
	}
	items := make([]store.ProcessItem, 0, len(newest))
	for _, item := range newest {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if sortKey == "memory" {
			if items[i].MemoryRSS != items[j].MemoryRSS {
				return items[i].MemoryRSS > items[j].MemoryRSS
			}
		} else if items[i].CPUUsage != items[j].CPUUsage {
			return items[i].CPUUsage > items[j].CPUUsage
		}
		return items[i].PID < items[j].PID
	})
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	if len(items) > limit {
		items = items[:limit]
	}
	t := maxT
	return &t, items, nil
}

func projectVisible(projectID uuid.UUID, projects []uuid.UUID) bool {
	if projects == nil {
		return true
	}
	for _, id := range projects {
		if projectID == id {
			return true
		}
	}
	return false
}

func (m *Mem) HealthHistory(_ context.Context, serviceID uuid.UUID, from, to time.Time, limit int) ([]store.HealthPoint, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var items []store.HealthPoint
	for _, s := range m.samples {
		if s.M != "health" || s.ServiceID == nil || *s.ServiceID != serviceID {
			continue
		}
		if s.T.Before(from) || !s.T.Before(to) {
			continue
		}
		items = append(items, healthPoint(s))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].T.After(items[j].T) })
	if len(items) > limit {
		items = items[:limit]
	}
	if items == nil {
		items = []store.HealthPoint{}
	}
	return items, nil
}

func (m *Mem) latestHealthLocked(serviceID uuid.UUID, now time.Time) *store.HealthPoint {
	var points []store.HealthPoint
	for _, s := range m.samples {
		if s.M != "health" || s.ServiceID == nil || *s.ServiceID != serviceID {
			continue
		}
		points = append(points, healthPoint(s))
	}
	return store.SelectHealth(points, now)
}

func (m *Mem) serviceIDLocked(hostID uuid.UUID, name string) (uuid.UUID, bool) {
	for id, s := range m.services {
		if s.HostID == hostID && s.Name == name {
			return id, true
		}
	}
	return uuid.Nil, false
}

func (m *Mem) InsertAudit(_ context.Context, row store.AuditRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextAudit++
	detail := row.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		raw = []byte(`{}`)
	}
	m.audits = append(m.audits, store.AuditEntry{
		ID:          strconv.FormatInt(m.nextAudit, 10),
		At:          row.At,
		ActorUserID: row.ActorUserID,
		Via:         row.Via,
		ProjectID:   row.ProjectID,
		HostID:      row.HostID,
		ServiceID:   row.ServiceID,
		Action:      row.Action,
		Decision:    row.Decision,
		TaskID:      row.TaskID,
		Result:      row.Result,
		ErrorCode:   row.ErrorCode,
		Detail:      raw,
	})
	return nil
}

func (m *Mem) ListAudit(_ context.Context, projectID uuid.UUID, limit int, cursor *store.Cursor) ([]store.AuditEntry, *store.Cursor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var items []store.AuditEntry
	for _, a := range m.audits {
		if a.ProjectID == nil || *a.ProjectID != projectID {
			continue
		}
		items = append(items, a)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].At.Equal(items[j].At) {
			return auditID(items[i].ID) > auditID(items[j].ID)
		}
		return items[i].At.After(items[j].At)
	})
	var cursorID int64
	if cursor != nil {
		cursorID = auditID(cursor.ID)
	}
	filtered := make([]store.AuditEntry, 0, len(items))
	for _, a := range items {
		if cursor != nil {
			id := auditID(a.ID)
			if a.At.After(cursor.At) || (a.At.Equal(cursor.At) && id >= cursorID) {
				continue
			}
		}
		filtered = append(filtered, a)
	}
	if limit <= 0 {
		limit = 50
	}
	var next *store.Cursor
	if len(filtered) > limit {
		filtered = filtered[:limit]
		last := filtered[len(filtered)-1]
		next = &store.Cursor{At: last.At, ID: last.ID}
	}
	if filtered == nil {
		filtered = []store.AuditEntry{}
	}
	return filtered, next, nil
}

func auditID(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func processItem(s store.Sample) store.ProcessItem {
	pid, _ := strconv.Atoi(s.Tags["pid"])
	item := store.ProcessItem{
		PID:         pid,
		ProcessName: s.Tags["process_name"],
		User:        s.Tags["user"],
		Cmdline:     s.Tags["cmdline"],
		ServiceID:   s.ServiceID,
		CPUUsage:    s.Floats["cpu_usage"],
		MemoryRSS:   s.Ints["memory_rss"],
		MemoryUsage: s.Floats["memory_usage"],
		NumThreads:  int(s.Ints["num_threads"]),
	}
	if raw := s.Strs["started_at"]; raw != "" {
		if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			u := t.UTC()
			item.StartedAt = &u
		}
	}
	return item
}

func healthPoint(s store.Sample) store.HealthPoint {
	p := store.HealthPoint{
		T:        s.T,
		Protocol: s.Tags["protocol"],
		Result:   s.Strs["result"],
	}
	if raw := s.Tags["check_id"]; raw != "" {
		if id, err := uuid.Parse(raw); err == nil {
			p.CheckID = &id
		}
	}
	if raw := s.Tags["port"]; raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			p.Port = &n
		}
	}
	if !s.Nulls["latency_ms"] {
		if v, ok := s.Floats["latency_ms"]; ok {
			p.LatencyMS = &v
		}
	}
	if !s.Nulls["http_status"] {
		if v, ok := s.Ints["http_status"]; ok {
			n := int(v)
			p.HTTPStatus = &n
		}
	}
	return p
}

func cloneSample(s store.Sample) store.Sample {
	out := s
	out.Tags = cloneMap(s.Tags)
	out.Floats = cloneFloats(s.Floats)
	out.Ints = cloneInts(s.Ints)
	out.Strs = cloneMap(s.Strs)
	out.Nulls = cloneBools(s.Nulls)
	if s.ServiceID != nil {
		id := *s.ServiceID
		out.ServiceID = &id
	}
	return out
}

func cloneMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneFloats(in map[string]float64) map[string]float64 {
	out := make(map[string]float64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneInts(in map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneBools(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
