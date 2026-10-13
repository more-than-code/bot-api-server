package memstore

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (m *Mem) CreateDevice(_ context.Context, row store.Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.deviceByCode[row.UserCode]; ok {
		return store.ErrConflict
	}
	if _, ok := m.deviceByHash[hashKey(row.Hash)]; ok {
		return store.ErrConflict
	}
	row.Hash = cloneBytes(row.Hash)
	m.devices[row.ID] = row
	m.deviceByHash[hashKey(row.Hash)] = row.ID
	m.deviceByCode[row.UserCode] = row.ID
	return nil
}

func (m *Mem) DeviceByUserCode(_ context.Context, code string) (store.Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.deviceByCode[code]
	if !ok {
		return store.Device{}, store.ErrNotFound
	}
	return m.devices[id], nil
}

func (m *Mem) DeviceByHash(_ context.Context, hash []byte) (store.Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.deviceByHash[hashKey(hash)]
	if !ok {
		secret.Equal(hash, dummyHash)
		return store.Device{}, store.ErrNotFound
	}
	d := m.devices[id]
	if !secret.Equal(hash, d.Hash) {
		return store.Device{}, store.ErrNotFound
	}
	return d, nil
}

func (m *Mem) ApproveDevice(_ context.Context, code string, userID uuid.UUID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.decideLocked(code, userID, at, true)
}

func (m *Mem) DenyDevice(_ context.Context, code string, userID uuid.UUID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.decideLocked(code, userID, at, false)
}

func (m *Mem) decideLocked(code string, userID uuid.UUID, at time.Time, approve bool) error {
	id, ok := m.deviceByCode[code]
	if !ok {
		return store.ErrNotFound
	}
	d := m.devices[id]
	if !at.Before(d.ExpiresAt) {
		return store.ErrExpired
	}
	if d.ApprovedAt != nil || d.DeniedAt != nil || d.ConsumedAt != nil {
		return store.ErrState
	}
	if approve {
		d.ApprovedAt = &at
		d.ApprovedBy = &userID
	} else {
		d.DeniedAt = &at
	}
	m.devices[id] = d
	return nil
}

func (m *Mem) ConsumeDevice(_ context.Context, hash []byte, at time.Time) (store.Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.deviceByHash[hashKey(hash)]
	if !ok || !secret.Equal(hash, m.devices[id].Hash) {
		secret.Equal(hash, dummyHash)
		return store.Device{}, store.ErrNotFound
	}
	d := m.devices[id]
	if !at.Before(d.ExpiresAt) {
		return store.Device{}, store.ErrExpired
	}
	if d.DeniedAt != nil {
		return store.Device{}, store.ErrState
	}
	if d.ApprovedAt == nil {
		return store.Device{}, store.ErrState
	}
	if d.ConsumedAt != nil {
		return store.Device{}, store.ErrConflict
	}
	d.ConsumedAt = &at
	m.devices[id] = d
	return d, nil
}

// DeleteExpiredDevices removes codes whose expiry is before the cutoff.
func (m *Mem) DeleteExpiredDevices(_ context.Context, before time.Time) ([][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var hashes [][]byte
	for id, d := range m.devices {
		if !d.ExpiresAt.Before(before) {
			continue
		}
		hashes = append(hashes, append([]byte(nil), d.Hash...))
		delete(m.devices, id)
		delete(m.deviceByHash, hashKey(d.Hash))
		delete(m.deviceByCode, d.UserCode)
	}
	return hashes, nil
}
