package memstore

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

type confirmationRec struct {
	hash []byte
	row  store.CatalogConfirmation
}

func entryKey(projectID uuid.UUID, name string) string {
	return projectID.String() + "/" + name
}

func approvalKey(entryID, hostID uuid.UUID) string {
	return entryID.String() + "/" + hostID.String()
}

func idemKey(userID uuid.UUID, key string) string {
	return userID.String() + "/" + key
}

func cloneHost(h store.Host) store.Host {
	h.Programs = clonePrograms(h.Programs)
	if h.ShareLevel != nil {
		level := *h.ShareLevel
		h.ShareLevel = &level
	}
	return h
}

func clonePrograms(p *store.HostPrograms) *store.HostPrograms {
	if p == nil {
		return nil
	}
	cp := *p
	cp.RunAs = append([]string(nil), p.RunAs...)
	return &cp
}

func cloneEntry(e store.CatalogEntry) store.CatalogEntry {
	e.Spec.Args = append([]string(nil), e.Spec.Args...)
	env := make(map[string]string, len(e.Spec.Env))
	for k, v := range e.Spec.Env {
		env[k] = v
	}
	e.Spec.Env = env
	if e.MyActions != nil {
		e.MyActions = append([]string(nil), e.MyActions...)
	}
	return e
}

func cloneGrants(in []store.CatalogGrant) []store.CatalogGrant {
	if in == nil {
		return []store.CatalogGrant{}
	}
	out := make([]store.CatalogGrant, len(in))
	for i, g := range in {
		g.Actions = append([]string(nil), g.Actions...)
		out[i] = g
	}
	return out
}

func normWrite(spec store.ProgramSpec) store.ProgramSpec {
	if spec.Args == nil {
		spec.Args = []string{}
	}
	if spec.Env == nil {
		spec.Env = map[string]string{}
	} else {
		env := make(map[string]string, len(spec.Env))
		for k, v := range spec.Env {
			env[k] = v
		}
		spec.Env = env
	}
	spec.Args = append([]string(nil), spec.Args...)
	return spec
}

func (m *Mem) CreateCatalogEntry(_ context.Context, projectID uuid.UUID, in store.CatalogWrite) (store.CatalogEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.projects[projectID]
	if !ok || p.DeletedAt != nil {
		return store.CatalogEntry{}, store.ErrNotFound
	}
	if _, exists := m.entryByName[entryKey(projectID, in.Name)]; exists {
		return store.CatalogEntry{}, store.ErrConflict
	}
	e := store.CatalogEntry{
		ID:             uuid.New(),
		ProjectID:      projectID,
		Name:           in.Name,
		Kind:           "program",
		Spec:           normWrite(in.Spec),
		SpecHash:       in.SpecHash,
		CommandDisplay: in.CommandDisplay,
		CreatedBy:      in.Actor,
		CreatedAt:      in.At,
		UpdatedAt:      in.At,
	}
	m.entries[e.ID] = e
	m.entryByName[entryKey(projectID, in.Name)] = e.ID
	m.grants[e.ID] = []store.CatalogGrant{
		{Subject: "role:admin", Actions: []string{"run", "stop", "restart", "logs"}},
		{Subject: "role:viewer", Actions: []string{"logs"}},
	}
	return cloneEntry(e), nil
}

func (m *Mem) ReplaceCatalogEntry(_ context.Context, projectID uuid.UUID, name string, in store.CatalogWrite) (string, store.CatalogEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.entryByName[entryKey(projectID, name)]
	if !ok {
		return "", store.CatalogEntry{}, store.ErrNotFound
	}
	e := m.entries[id]
	old := e.SpecHash
	if old != in.SpecHash {
		m.deleteApprovalsLocked(id)
	}
	e.Spec = normWrite(in.Spec)
	e.SpecHash = in.SpecHash
	e.CommandDisplay = in.CommandDisplay
	e.UpdatedAt = in.At
	m.entries[id] = e
	return old, cloneEntry(e), nil
}

func (m *Mem) DeleteCatalogEntry(_ context.Context, projectID uuid.UUID, name string) (store.CatalogEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.entryByName[entryKey(projectID, name)]
	if !ok {
		return store.CatalogEntry{}, store.ErrNotFound
	}
	e := cloneEntry(m.entries[id])
	m.deleteEntryLocked(id)
	return e, nil
}

func (m *Mem) GetCatalogEntry(_ context.Context, projectID uuid.UUID, name string) (store.CatalogEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.entryByName[entryKey(projectID, name)]
	if !ok {
		return store.CatalogEntry{}, store.ErrNotFound
	}
	return cloneEntry(m.entries[id]), nil
}

func (m *Mem) ListCatalogEntries(_ context.Context, projectID uuid.UUID) ([]store.CatalogEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []store.CatalogEntry{}
	for _, e := range m.entries {
		if e.ProjectID == projectID {
			out = append(out, cloneEntry(e))
		}
	}
	sortEntries(out)
	return out, nil
}

func sortEntries(out []store.CatalogEntry) {
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && (out[j].Name < out[j-1].Name || (out[j].Name == out[j-1].Name && out[j].ID.String() < out[j-1].ID.String())) {
			out[j], out[j-1] = out[j-1], out[j]
			j--
		}
	}
}

func (m *Mem) ListCatalogGrants(_ context.Context, entryID uuid.UUID) ([]store.CatalogGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[entryID]; !ok {
		return nil, store.ErrNotFound
	}
	return m.grantsLocked(entryID), nil
}

func (m *Mem) grantsLocked(entryID uuid.UUID) []store.CatalogGrant {
	out := cloneGrants(m.grants[entryID])
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && out[j].Subject < out[j-1].Subject {
			out[j], out[j-1] = out[j-1], out[j]
			j--
		}
	}
	return out
}

func (m *Mem) ReplaceCatalogGrants(_ context.Context, projectID uuid.UUID, name string, grants []store.CatalogGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.entryByName[entryKey(projectID, name)]
	if !ok {
		return store.ErrNotFound
	}
	m.grants[id] = cloneGrants(grants)
	return nil
}

func (m *Mem) HostProjectRelation(_ context.Context, projectID, hostID uuid.UUID) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[hostID]
	if !ok {
		return "", store.ErrNotFound
	}
	if h.ProjectID == projectID {
		return "owner", nil
	}
	if sh, ok := m.shares[shareKey(hostID, projectID)]; ok {
		return sh.Level, nil
	}
	return "", nil
}

func (m *Mem) ListCatalogApprovals(_ context.Context, hostID uuid.UUID) ([]store.CatalogApproval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.hosts[hostID]; !ok {
		return nil, store.ErrNotFound
	}
	out := []store.CatalogApproval{}
	for _, a := range m.approvals {
		if a.HostID != hostID {
			continue
		}
		view, ok := m.approvalViewLocked(a)
		if ok {
			out = append(out, view)
		}
	}
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && approvalBefore(out[j], out[j-1]) {
			out[j], out[j-1] = out[j-1], out[j]
			j--
		}
	}
	return out, nil
}

func approvalBefore(a, b store.CatalogApproval) bool {
	if !a.RequestedAt.Equal(b.RequestedAt) {
		return a.RequestedAt.After(b.RequestedAt)
	}
	return a.EntryID.String() < b.EntryID.String()
}

func (m *Mem) approvalViewLocked(a store.CatalogApproval) (store.CatalogApproval, bool) {
	e, ok := m.entries[a.EntryID]
	if !ok {
		return store.CatalogApproval{}, false
	}
	p := m.projects[e.ProjectID]
	a.EntryName = e.Name
	a.ProjectID = e.ProjectID
	a.ProjectName = p.Name
	a.CommandDisplay = e.CommandDisplay
	a.Dir = e.Spec.Dir
	a.Exec = e.Spec.Exec
	a.Args = append([]string{}, e.Spec.Args...)
	if a.Args == nil {
		a.Args = []string{}
	}
	a.Env = make(map[string]string, len(e.Spec.Env))
	for k, v := range e.Spec.Env {
		a.Env[k] = v
	}
	a.RunAs = e.Spec.RunAs
	a.Shell = e.Spec.Shell
	if a.ApprovedBy != nil {
		id := *a.ApprovedBy
		a.ApprovedBy = &id
	}
	if a.ApprovedAt != nil {
		t := *a.ApprovedAt
		a.ApprovedAt = &t
	}
	return a, true
}

func (m *Mem) ApproveCatalog(_ context.Context, hostID, entryID uuid.UUID, specHash string, approver uuid.UUID, at time.Time) (store.CatalogApproval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[entryID]
	if !ok {
		return store.CatalogApproval{}, store.ErrNotFound
	}
	if e.SpecHash != specHash {
		return store.CatalogApproval{}, store.ErrConflict
	}
	if _, ok := m.hosts[hostID]; !ok {
		return store.CatalogApproval{}, store.ErrNotFound
	}
	key := approvalKey(entryID, hostID)
	row, exists := m.approvals[key]
	if !exists {
		row = store.CatalogApproval{
			EntryID:     entryID,
			HostID:      hostID,
			RequestedBy: approver,
			RequestedAt: at,
		}
	}
	row.SpecHash = specHash
	row.Status = "approved"
	who := approver
	when := at
	row.ApprovedBy = &who
	row.ApprovedAt = &when
	m.approvals[key] = row
	view, _ := m.approvalViewLocked(row)
	return view, nil
}

func (m *Mem) DeleteCatalogApproval(_ context.Context, hostID, entryID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := approvalKey(entryID, hostID)
	if _, ok := m.approvals[key]; !ok {
		return store.ErrNotFound
	}
	delete(m.approvals, key)
	return nil
}

func (m *Mem) UpsertPendingApproval(_ context.Context, entryID, hostID uuid.UUID, specHash string, userID uuid.UUID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[entryID]; !ok {
		return store.ErrNotFound
	}
	if _, ok := m.hosts[hostID]; !ok {
		return store.ErrNotFound
	}
	key := approvalKey(entryID, hostID)
	if row, ok := m.approvals[key]; ok && row.Status == "approved" && row.SpecHash == specHash {
		return nil
	}
	m.approvals[key] = store.CatalogApproval{
		EntryID:     entryID,
		HostID:      hostID,
		SpecHash:    specHash,
		Status:      "pending",
		RequestedBy: userID,
		RequestedAt: at,
	}
	return nil
}

func (m *Mem) PutConfirmation(_ context.Context, hash []byte, c store.CatalogConfirmation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := hashKey(hash)
	if _, ok := m.confirmations[key]; ok {
		return store.ErrConflict
	}
	m.confirmations[key] = confirmationRec{hash: cloneBytes(hash), row: c}
	return nil
}

func (m *Mem) GetConfirmation(_ context.Context, hash []byte) (store.CatalogConfirmation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.confirmations[hashKey(hash)]
	if !ok || !secret.Equal(hash, rec.hash) {
		return store.CatalogConfirmation{}, store.ErrNotFound
	}
	return rec.row, nil
}

func (m *Mem) MarkConfirmationUsed(_ context.Context, hash []byte, userID uuid.UUID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := hashKey(hash)
	rec, ok := m.confirmations[key]
	if !ok || !secret.Equal(hash, rec.hash) || rec.row.UserID != userID || rec.row.UsedAt != nil || !rec.row.ExpiresAt.After(at) {
		return store.ErrNotFound
	}
	used := at
	rec.row.UsedAt = &used
	m.confirmations[key] = rec
	return nil
}

func (m *Mem) GetIdempotency(_ context.Context, userID uuid.UUID, key string, at time.Time) (store.IdempotencyRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.idempotency[idemKey(userID, key)]
	if !ok {
		return store.IdempotencyRecord{}, store.ErrNotFound
	}
	if !rec.CreatedAt.After(at.Add(-store.IdempotencyTTL)) {
		delete(m.idempotency, idemKey(userID, key))
		return store.IdempotencyRecord{}, store.ErrNotFound
	}
	return copyIdem(rec), nil
}

func (m *Mem) ClaimIdempotency(_ context.Context, userID uuid.UUID, key string, hash []byte, at time.Time) (store.IdempotencyRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := idemKey(userID, key)
	if rec, ok := m.idempotency[k]; ok {
		if !rec.CreatedAt.After(at.Add(-store.IdempotencyTTL)) {
			delete(m.idempotency, k)
		} else {
			out := copyIdem(rec)
			if rec.Pending {
				return out, false, store.ErrPending
			}
			if !secret.Equal(rec.RequestHash, hash) {
				return out, false, store.ErrConflict
			}
			return out, false, nil
		}
	}
	rec := store.IdempotencyRecord{RequestHash: cloneBytes(hash), Pending: true, CreatedAt: at}
	m.idempotency[k] = rec
	return copyIdem(rec), true, nil
}

func copyIdem(rec store.IdempotencyRecord) store.IdempotencyRecord {
	rec.RequestHash = cloneBytes(rec.RequestHash)
	rec.Body = append([]byte(nil), rec.Body...)
	return rec
}

func (m *Mem) PutIdempotency(_ context.Context, userID uuid.UUID, key string, rec store.IdempotencyRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := idemKey(userID, key)
	if _, ok := m.idempotency[k]; ok {
		return store.ErrConflict
	}
	rec.RequestHash = cloneBytes(rec.RequestHash)
	rec.Body = append([]byte(nil), rec.Body...)
	m.idempotency[k] = rec
	return nil
}

func (m *Mem) ReplaceIdempotencyResponse(_ context.Context, userID uuid.UUID, key string, status int, body []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := idemKey(userID, key)
	rec, ok := m.idempotency[k]
	if !ok {
		return store.ErrNotFound
	}
	rec.Status = status
	rec.Body = append([]byte(nil), body...)
	rec.Pending = false
	m.idempotency[k] = rec
	return nil
}

func (m *Mem) SetHostPrograms(_ context.Context, hostID uuid.UUID, programs *store.HostPrograms) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.hosts[hostID]
	if !ok {
		return store.ErrNotFound
	}
	h.Programs = clonePrograms(programs)
	m.hosts[hostID] = h
	return nil
}

func (m *Mem) lookupCatalogLocked(slug, entry string) (uuid.UUID, bool) {
	id, ok := m.bySlug[slug]
	if !ok {
		return uuid.Nil, false
	}
	p, ok := m.projects[id]
	if !ok || p.DeletedAt != nil {
		return uuid.Nil, false
	}
	if _, ok := m.entryByName[entryKey(id, entry)]; !ok {
		return uuid.Nil, false
	}
	return id, true
}

func (m *Mem) deleteCatalogLocked(projectID uuid.UUID) {
	var ids []uuid.UUID
	for id, e := range m.entries {
		if e.ProjectID == projectID {
			ids = append(ids, id)
		}
	}
	for _, id := range ids {
		m.deleteEntryLocked(id)
	}
}

func (m *Mem) deleteEntryLocked(id uuid.UUID) {
	e, ok := m.entries[id]
	if !ok {
		return
	}
	delete(m.entries, id)
	delete(m.entryByName, entryKey(e.ProjectID, e.Name))
	delete(m.grants, id)
	m.deleteApprovalsLocked(id)
	for key, rec := range m.confirmations {
		if rec.row.EntryID == id {
			delete(m.confirmations, key)
		}
	}
}

func (m *Mem) deleteApprovalsLocked(entryID uuid.UUID) {
	for key, a := range m.approvals {
		if a.EntryID == entryID {
			delete(m.approvals, key)
		}
	}
}
