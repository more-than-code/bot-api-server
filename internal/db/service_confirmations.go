package db

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/more-than-code/bot-api-server/internal/store"
)

type serviceCheckWire struct {
	Protocol        string  `json:"protocol"`
	Port            int     `json:"port"`
	Path            *string `json:"path"`
	IntervalSec     int     `json:"interval_sec"`
	ExpectStatusMin int     `json:"expect_status_min"`
	ExpectStatusMax int     `json:"expect_status_max"`
	Enabled         bool    `json:"enabled"`
}

func (d *DB) PutServiceConfirmation(ctx context.Context, hash []byte, c store.ServiceConfirmation) error {
	raw, err := json.Marshal(serviceCheckWires(c.Checks))
	if err != nil {
		return err
	}
	err = exec(ctx, d.pool, `
INSERT INTO app.service_confirmations (
    token_hash, user_id, project_id, service_id, action,
    request_hash, current_hash, checks, idempotency_key, created_at, expires_at
) VALUES ($1, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7, $8::jsonb, $9, $10, $11)
`, hash, c.UserID.String(), c.ProjectID.String(), c.ServiceID.String(), c.Action,
		c.RequestHash, c.CurrentHash, raw, c.IdempotencyKey, c.CreatedAt, c.ExpiresAt)
	return mapErr(err)
}

const serviceConfirmationCols = `
SELECT user_id::text, project_id::text, service_id::text, action,
       request_hash, current_hash, checks, idempotency_key, created_at, expires_at, used_at
FROM app.service_confirmations
WHERE token_hash = $1`

func (d *DB) GetServiceConfirmation(ctx context.Context, hash []byte) (store.ServiceConfirmation, error) {
	return scanServiceConfirmation(d.pool.QueryRow(ctx, serviceConfirmationCols, hash))
}

func scanServiceConfirmation(row pgx.Row) (store.ServiceConfirmation, error) {
	var c store.ServiceConfirmation
	var userID, projectID, serviceID string
	var raw []byte
	err := row.Scan(&userID, &projectID, &serviceID, &c.Action,
		&c.RequestHash, &c.CurrentHash, &raw, &c.IdempotencyKey, &c.CreatedAt, &c.ExpiresAt, &c.UsedAt)
	if err != nil {
		return store.ServiceConfirmation{}, mapErr(err)
	}
	var perr error
	if c.UserID, perr = parseID(userID); perr != nil {
		return store.ServiceConfirmation{}, perr
	}
	if c.ProjectID, perr = parseID(projectID); perr != nil {
		return store.ServiceConfirmation{}, perr
	}
	if c.ServiceID, perr = parseID(serviceID); perr != nil {
		return store.ServiceConfirmation{}, perr
	}
	checks, err := parseServiceChecks(raw)
	if err != nil {
		return store.ServiceConfirmation{}, err
	}
	c.Checks = checks
	return c, nil
}

// CommitHealthReplacement locks the confirmation and the service, re-reads
// the check set, and marks plus replaces only when the hash still matches.
// A mismatch returns ErrConflict with the transaction rolled back.
func (d *DB) CommitHealthReplacement(ctx context.Context, hash []byte, userID uuid.UUID, at time.Time) ([]store.HealthCheck, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	defer tx.Rollback(ctx)
	c, err := scanServiceConfirmation(tx.QueryRow(ctx, serviceConfirmationCols+` FOR UPDATE`, hash))
	if err != nil {
		return nil, err
	}
	if c.UserID != userID || c.UsedAt != nil || !c.ExpiresAt.After(at) {
		return nil, store.ErrNotFound
	}
	if err := lockService(ctx, tx, c.ServiceID); err != nil {
		return nil, err
	}
	current, err := listHealthChecksTx(ctx, tx, c.ServiceID)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(store.HealthSetHash(store.HealthCheckInputs(current)), c.CurrentHash) {
		return nil, store.ErrConflict
	}
	tag, err := tx.Exec(ctx, `
UPDATE app.service_confirmations
SET used_at = $3
WHERE token_hash = $1 AND user_id = $2::uuid AND used_at IS NULL AND expires_at > $3
`, hash, userID.String(), at)
	if err != nil {
		return nil, mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return nil, store.ErrNotFound
	}
	out, err := insertHealthChecks(ctx, tx, c.ServiceID, c.Checks)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (d *DB) MarkServiceConfirmationUsed(ctx context.Context, hash []byte, userID uuid.UUID, at time.Time) error {
	tag, err := d.pool.Exec(ctx, `
UPDATE app.service_confirmations
SET used_at = $3
WHERE token_hash = $1 AND user_id = $2::uuid AND used_at IS NULL AND expires_at > $3
`, hash, userID.String(), at)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func serviceCheckWires(in []store.HealthCheckInput) []serviceCheckWire {
	out := make([]serviceCheckWire, len(in))
	for i, c := range in {
		out[i] = serviceCheckWire{
			Protocol: c.Protocol, Port: c.Port, Path: c.Path, IntervalSec: c.IntervalSec,
			ExpectStatusMin: c.ExpectStatusMin, ExpectStatusMax: c.ExpectStatusMax, Enabled: c.Enabled,
		}
	}
	return out
}

func parseServiceChecks(raw []byte) ([]store.HealthCheckInput, error) {
	var rows []serviceCheckWire
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	out := make([]store.HealthCheckInput, len(rows))
	for i, row := range rows {
		item := store.HealthCheckInput{
			Protocol: row.Protocol, Port: row.Port, IntervalSec: row.IntervalSec,
			ExpectStatusMin: row.ExpectStatusMin, ExpectStatusMax: row.ExpectStatusMax, Enabled: row.Enabled,
		}
		if row.Path != nil {
			p := *row.Path
			item.Path = &p
		}
		out[i] = item
	}
	return out, nil
}
