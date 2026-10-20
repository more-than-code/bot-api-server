package memstore

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

type catalogWriteConfirmationRec struct {
	hash []byte
	row  store.CatalogWriteConfirmation
}

func (m *Mem) PutCatalogWriteConfirmation(_ context.Context, hash []byte, c store.CatalogWriteConfirmation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, rec := range m.catalogWriteConfirmations {
		if rec.row.ExpiresAt.Before(c.CreatedAt) {
			delete(m.catalogWriteConfirmations, key)
		}
	}
	key := hashKey(hash)
	if _, ok := m.catalogWriteConfirmations[key]; ok {
		return store.ErrConflict
	}
	m.catalogWriteConfirmations[key] = catalogWriteConfirmationRec{hash: cloneBytes(hash), row: cloneCatalogWriteConfirmation(c)}
	return nil
}

func (m *Mem) GetCatalogWriteConfirmation(_ context.Context, hash []byte) (store.CatalogWriteConfirmation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.catalogWriteConfirmations[hashKey(hash)]
	if !ok || !secret.Equal(hash, rec.hash) {
		return store.CatalogWriteConfirmation{}, store.ErrNotFound
	}
	return cloneCatalogWriteConfirmation(rec.row), nil
}

func (m *Mem) CountEntryApprovals(_ context.Context, projectID uuid.UUID, name string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.countEntryApprovalsLocked(projectID, name), nil
}

func (m *Mem) countEntryApprovalsLocked(projectID uuid.UUID, name string) int {
	id, ok := m.entryByName[entryKey(projectID, name)]
	if !ok {
		return 0
	}
	n := 0
	for _, a := range m.approvals {
		if a.EntryID == id {
			n++
		}
	}
	return n
}

// CommitCatalogWrite holds the memstore mutex across the re-check, the
// catalog write, and the delete of the plan. A conflict leaves the plan.
func (m *Mem) CommitCatalogWrite(_ context.Context, hash []byte, userID uuid.UUID, at time.Time, in store.CatalogWrite) (string, store.CatalogEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := hashKey(hash)
	rec, ok := m.catalogWriteConfirmations[key]
	if !ok || !secret.Equal(hash, rec.hash) || rec.row.UserID != userID || rec.row.UsedAt != nil || !rec.row.ExpiresAt.After(at) {
		return "", store.CatalogEntry{}, store.ErrNotFound
	}
	c := rec.row
	if in.Name != c.EntryName {
		return "", store.CatalogEntry{}, store.ErrConflict
	}
	var old string
	var entry store.CatalogEntry
	var err error
	switch c.Action {
	case "create":
		if in.Kind != "image" || !store.SameJSON(c.Body, in.ImageRaw) {
			return "", store.CatalogEntry{}, store.ErrConflict
		}
		entry, err = m.createCatalogEntryLocked(c.ProjectID, in)
		if errors.Is(err, store.ErrConflict) {
			return "", store.CatalogEntry{}, store.ErrConflict
		}
	case "update":
		if in.Kind != "image" || !store.SameJSON(c.Body, in.ImageRaw) {
			return "", store.CatalogEntry{}, store.ErrConflict
		}
		id, found := m.entryByName[entryKey(c.ProjectID, c.EntryName)]
		if !found || m.entries[id].SpecHash != c.BaseSpecHash {
			return "", store.CatalogEntry{}, store.ErrConflict
		}
		old, entry, err = m.replaceCatalogEntryLocked(c.ProjectID, c.EntryName, in)
		if errors.Is(err, store.ErrNotFound) {
			return "", store.CatalogEntry{}, store.ErrConflict
		}
	case "delete":
		id, found := m.entryByName[entryKey(c.ProjectID, c.EntryName)]
		if !found || m.entries[id].SpecHash != c.BaseSpecHash {
			return "", store.CatalogEntry{}, store.ErrConflict
		}
		entry, err = m.deleteCatalogEntryLocked(c.ProjectID, c.EntryName)
		if errors.Is(err, store.ErrNotFound) {
			return "", store.CatalogEntry{}, store.ErrConflict
		}
	default:
		return "", store.CatalogEntry{}, errors.New("catalog write action")
	}
	if err != nil {
		return "", store.CatalogEntry{}, err
	}
	delete(m.catalogWriteConfirmations, key)
	return old, entry, nil
}

func cloneCatalogWriteConfirmation(c store.CatalogWriteConfirmation) store.CatalogWriteConfirmation {
	c.RequestHash = cloneBytes(c.RequestHash)
	if c.Body != nil {
		c.Body = append([]byte(nil), c.Body...)
	}
	if c.UsedAt != nil {
		used := *c.UsedAt
		c.UsedAt = &used
	}
	return c
}
