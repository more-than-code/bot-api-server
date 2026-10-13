package db

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// DeleteExpiredDevices removes device codes that expired before the cutoff.
func (d *DB) DeleteExpiredDevices(ctx context.Context, before time.Time) ([][]byte, error) {
	rows, err := d.pool.Query(ctx, `
DELETE FROM app.device_codes WHERE expires_at < $1 RETURNING device_code_hash
`, before)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var hashes [][]byte
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			return nil, mapErr(err)
		}
		hashes = append(hashes, h)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	if hashes == nil {
		hashes = [][]byte{}
	}
	return hashes, nil
}

func (d *DB) CreateDevice(ctx context.Context, row store.Device) error {
	if err := exec(ctx, d.pool, `
INSERT INTO app.device_codes (id, device_code_hash, user_code, client_name, created_at, expires_at)
VALUES ($1::uuid, $2, $3, $4, $5, $6)
`, row.ID.String(), row.Hash, row.UserCode, row.ClientName, row.CreatedAt, row.ExpiresAt); err != nil {
		return mapErr(err)
	}
	return nil
}

func (d *DB) DeviceByUserCode(ctx context.Context, code string) (store.Device, error) {
	return scanDevice(d.pool.QueryRow(ctx, `
SELECT id::text, device_code_hash, user_code, client_name, created_at, expires_at,
       approved_by_user_id::text, approved_at, denied_at, consumed_at
FROM app.device_codes
WHERE user_code = $1
`, code))
}

func (d *DB) DeviceByHash(ctx context.Context, hash []byte) (store.Device, error) {
	dev, err := scanDevice(d.pool.QueryRow(ctx, `
SELECT id::text, device_code_hash, user_code, client_name, created_at, expires_at,
       approved_by_user_id::text, approved_at, denied_at, consumed_at
FROM app.device_codes
WHERE device_code_hash = $1
`, hash))
	if errors.Is(err, store.ErrNotFound) {
		secret.Equal(hash, missHash)
		return store.Device{}, store.ErrNotFound
	}
	if err != nil {
		return store.Device{}, err
	}
	if !secret.Equal(hash, dev.Hash) {
		return store.Device{}, store.ErrNotFound
	}
	return dev, nil
}

func (d *DB) ApproveDevice(ctx context.Context, code string, userID uuid.UUID, at time.Time) error {
	return d.decideDevice(ctx, code, userID, at, true)
}

func (d *DB) DenyDevice(ctx context.Context, code string, userID uuid.UUID, at time.Time) error {
	return d.decideDevice(ctx, code, userID, at, false)
}

func (d *DB) decideDevice(ctx context.Context, code string, userID uuid.UUID, at time.Time, approve bool) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return mapErr(err)
	}
	defer tx.Rollback(ctx)
	dev, err := scanDevice(tx.QueryRow(ctx, `
SELECT id::text, device_code_hash, user_code, client_name, created_at, expires_at,
       approved_by_user_id::text, approved_at, denied_at, consumed_at
FROM app.device_codes
WHERE user_code = $1
FOR UPDATE
`, code))
	if err != nil {
		return err
	}
	if !at.Before(dev.ExpiresAt) {
		return store.ErrExpired
	}
	if dev.ApprovedAt != nil || dev.DeniedAt != nil || dev.ConsumedAt != nil {
		return store.ErrState
	}
	if approve {
		if err := exec(ctx, tx, `
UPDATE app.device_codes
SET approved_at = $2, approved_by_user_id = $3::uuid
WHERE id = $1::uuid
`, dev.ID.String(), at, userID.String()); err != nil {
			return mapErr(err)
		}
	} else {
		if err := exec(ctx, tx, `
UPDATE app.device_codes
SET denied_at = $2
WHERE id = $1::uuid
`, dev.ID.String(), at); err != nil {
			return mapErr(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return mapErr(err)
	}
	return nil
}

func (d *DB) ConsumeDevice(ctx context.Context, hash []byte, at time.Time) (store.Device, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.Device{}, mapErr(err)
	}
	defer tx.Rollback(ctx)
	dev, err := scanDevice(tx.QueryRow(ctx, `
UPDATE app.device_codes
SET consumed_at = $2
WHERE device_code_hash = $1
  AND consumed_at IS NULL
  AND approved_at IS NOT NULL
  AND denied_at IS NULL
  AND expires_at > $2
RETURNING id::text, device_code_hash, user_code, client_name, created_at, expires_at,
          approved_by_user_id::text, approved_at, denied_at, consumed_at
`, hash, at))
	if err == nil {
		if !secret.Equal(hash, dev.Hash) {
			return store.Device{}, store.ErrNotFound
		}
		if err := tx.Commit(ctx); err != nil {
			return store.Device{}, mapErr(err)
		}
		return dev, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.Device{}, err
	}
	row, rerr := scanDevice(tx.QueryRow(ctx, `
SELECT id::text, device_code_hash, user_code, client_name, created_at, expires_at,
       approved_by_user_id::text, approved_at, denied_at, consumed_at
FROM app.device_codes
WHERE device_code_hash = $1
`, hash))
	if errors.Is(rerr, store.ErrNotFound) {
		secret.Equal(hash, missHash)
		return store.Device{}, store.ErrNotFound
	}
	if rerr != nil {
		return store.Device{}, rerr
	}
	if !secret.Equal(hash, row.Hash) {
		return store.Device{}, store.ErrNotFound
	}
	if !at.Before(row.ExpiresAt) {
		return store.Device{}, store.ErrExpired
	}
	if row.DeniedAt != nil || row.ApprovedAt == nil {
		return store.Device{}, store.ErrState
	}
	return store.Device{}, store.ErrConflict
}

func scanDevice(row pgx.Row) (store.Device, error) {
	var dev store.Device
	var id string
	var approvedBy *string
	if err := row.Scan(
		&id, &dev.Hash, &dev.UserCode, &dev.ClientName, &dev.CreatedAt, &dev.ExpiresAt,
		&approvedBy, &dev.ApprovedAt, &dev.DeniedAt, &dev.ConsumedAt,
	); err != nil {
		return store.Device{}, mapErr(err)
	}
	var err error
	if dev.ID, err = parseID(id); err != nil {
		return store.Device{}, err
	}
	if dev.ApprovedBy, err = parseOptID(approvedBy); err != nil {
		return store.Device{}, err
	}
	return dev, nil
}
