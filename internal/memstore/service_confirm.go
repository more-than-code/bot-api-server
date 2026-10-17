package memstore

import (
	"bytes"
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

type serviceConfirmationRec struct {
	hash []byte
	row  store.ServiceConfirmation
}

func (m *Mem) PutServiceConfirmation(_ context.Context, hash []byte, c store.ServiceConfirmation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := hashKey(hash)
	if _, ok := m.serviceConfirmations[key]; ok {
		return store.ErrConflict
	}
	c.RequestHash = cloneBytes(c.RequestHash)
	c.CurrentHash = cloneBytes(c.CurrentHash)
	c.Checks = cloneChecks(c.Checks)
	if c.UsedAt != nil {
		used := *c.UsedAt
		c.UsedAt = &used
	}
	m.serviceConfirmations[key] = serviceConfirmationRec{hash: cloneBytes(hash), row: c}
	return nil
}

func (m *Mem) GetServiceConfirmation(_ context.Context, hash []byte) (store.ServiceConfirmation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.serviceConfirmations[hashKey(hash)]
	if !ok || !secret.Equal(hash, rec.hash) {
		return store.ServiceConfirmation{}, store.ErrNotFound
	}
	return cloneServiceConfirmation(rec.row), nil
}

// CommitHealthReplacement holds the memstore mutex across the re-read, the
// mark, and the replace. A hash mismatch leaves the plan unused.
func (m *Mem) CommitHealthReplacement(_ context.Context, hash []byte, userID uuid.UUID, at time.Time) ([]store.HealthCheck, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := hashKey(hash)
	rec, ok := m.serviceConfirmations[key]
	if !ok || !secret.Equal(hash, rec.hash) || rec.row.UserID != userID || rec.row.UsedAt != nil || !rec.row.ExpiresAt.After(at) {
		return nil, store.ErrNotFound
	}
	if _, ok := m.services[rec.row.ServiceID]; !ok {
		return nil, store.ErrNotFound
	}
	current := m.listHealthChecksLocked(rec.row.ServiceID)
	if !bytes.Equal(store.HealthSetHash(store.HealthCheckInputs(current)), rec.row.CurrentHash) {
		return nil, store.ErrConflict
	}
	used := at
	rec.row.UsedAt = &used
	m.serviceConfirmations[key] = rec
	return m.replaceHealthChecksLocked(rec.row.ServiceID, rec.row.Checks)
}

func (m *Mem) MarkServiceConfirmationUsed(_ context.Context, hash []byte, userID uuid.UUID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := hashKey(hash)
	rec, ok := m.serviceConfirmations[key]
	if !ok || !secret.Equal(hash, rec.hash) || rec.row.UserID != userID || rec.row.UsedAt != nil || !rec.row.ExpiresAt.After(at) {
		return store.ErrNotFound
	}
	used := at
	rec.row.UsedAt = &used
	m.serviceConfirmations[key] = rec
	return nil
}

func cloneServiceConfirmation(c store.ServiceConfirmation) store.ServiceConfirmation {
	c.RequestHash = cloneBytes(c.RequestHash)
	c.CurrentHash = cloneBytes(c.CurrentHash)
	c.Checks = cloneChecks(c.Checks)
	if c.UsedAt != nil {
		used := *c.UsedAt
		c.UsedAt = &used
	}
	return c
}

func cloneChecks(in []store.HealthCheckInput) []store.HealthCheckInput {
	out := make([]store.HealthCheckInput, len(in))
	for i, c := range in {
		out[i] = c
		if c.Path != nil {
			p := *c.Path
			out[i].Path = &p
		}
	}
	return out
}
