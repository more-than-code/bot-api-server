package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (d *DB) CreateCatalogEntry(ctx context.Context, projectID uuid.UUID, in store.CatalogWrite) (store.CatalogEntry, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.CatalogEntry{}, mapErr(err)
	}
	defer tx.Rollback(ctx)
	entry, err := insertCatalogEntry(ctx, tx, projectID, in)
	if err != nil {
		return store.CatalogEntry{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return store.CatalogEntry{}, mapErr(err)
	}
	return entry, nil
}

// insertCatalogEntry is the console create path. CommitCatalogWrite uses it
// inside the confirmation transaction.
func insertCatalogEntry(ctx context.Context, tx pgx.Tx, projectID uuid.UUID, in store.CatalogWrite) (store.CatalogEntry, error) {
	kind := in.Kind
	if kind == "" {
		kind = "program"
	}
	spec, err := marshalWrite(in)
	if err != nil {
		return store.CatalogEntry{}, err
	}
	id := uuid.New()
	entry, err := scanCatalog(tx.QueryRow(ctx, `
INSERT INTO app.catalog_entries (
    id, project_id, name, kind, spec, spec_hash, command_display, created_by, created_at, updated_at
)
SELECT $1::uuid, p.id, $2, $3, $4::jsonb, $5, $6, $7::uuid, $8, $8
FROM app.projects p
WHERE p.id = $9::uuid AND p.deleted_at IS NULL
RETURNING id::text, project_id::text, name, kind, spec, spec_hash, command_display,
          created_by::text, created_at, updated_at
`, id.String(), in.Name, kind, spec, in.SpecHash, in.CommandDisplay, in.Actor.String(), in.At, projectID.String()))
	if err != nil {
		return store.CatalogEntry{}, err
	}
	if err := insertDefaultGrants(ctx, tx, entry.ID, kind); err != nil {
		return store.CatalogEntry{}, err
	}
	return entry, nil
}

func insertDefaultGrants(ctx context.Context, tx pgx.Tx, entryID uuid.UUID, kind string) error {
	admin, viewer := store.DefaultGrantActions(kind)
	if err := exec(ctx, tx, `
INSERT INTO app.catalog_grants (entry_id, subject, actions)
VALUES ($1::uuid, 'role:admin', $2::text[]), ($1::uuid, 'role:viewer', $3::text[])
`, entryID.String(), admin, viewer); err != nil {
		return mapErr(err)
	}
	return nil
}

func (d *DB) ReplaceCatalogEntry(ctx context.Context, projectID uuid.UUID, name string, in store.CatalogWrite) (string, store.CatalogEntry, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return "", store.CatalogEntry{}, mapErr(err)
	}
	defer tx.Rollback(ctx)
	old, entry, err := replaceCatalogEntry(ctx, tx, projectID, name, in)
	if err != nil {
		return "", store.CatalogEntry{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", store.CatalogEntry{}, mapErr(err)
	}
	return old, entry, nil
}

// replaceCatalogEntry is the console replace path, including the approval
// void when spec_hash changes. The caller holds the transaction.
func replaceCatalogEntry(ctx context.Context, tx pgx.Tx, projectID uuid.UUID, name string, in store.CatalogWrite) (string, store.CatalogEntry, error) {
	spec, err := marshalWrite(in)
	if err != nil {
		return "", store.CatalogEntry{}, err
	}
	var old string
	var id string
	err = tx.QueryRow(ctx, `
SELECT id::text, spec_hash
FROM app.catalog_entries
WHERE project_id = $1::uuid AND name = $2
FOR UPDATE
`, projectID.String(), name).Scan(&id, &old)
	if err != nil {
		return "", store.CatalogEntry{}, mapErr(err)
	}
	if old != in.SpecHash {
		if err := exec(ctx, tx, `DELETE FROM app.catalog_host_approvals WHERE entry_id = $1::uuid`, id); err != nil {
			return "", store.CatalogEntry{}, mapErr(err)
		}
	}
	entry, err := scanCatalog(tx.QueryRow(ctx, `
UPDATE app.catalog_entries
SET spec = $2::jsonb, spec_hash = $3, command_display = $4, updated_at = $5
WHERE id = $1::uuid
RETURNING id::text, project_id::text, name, kind, spec, spec_hash, command_display,
          created_by::text, created_at, updated_at
`, id, spec, in.SpecHash, in.CommandDisplay, in.At))
	if err != nil {
		return "", store.CatalogEntry{}, err
	}
	return old, entry, nil
}

func (d *DB) DeleteCatalogEntry(ctx context.Context, projectID uuid.UUID, name string) (store.CatalogEntry, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.CatalogEntry{}, mapErr(err)
	}
	defer tx.Rollback(ctx)
	entry, err := deleteCatalogEntry(ctx, tx, projectID, name)
	if err != nil {
		return store.CatalogEntry{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return store.CatalogEntry{}, mapErr(err)
	}
	return entry, nil
}

// deleteCatalogEntry removes the entry. Grants, approvals, and action
// confirmations cascade. Service rows are not touched.
func deleteCatalogEntry(ctx context.Context, tx pgx.Tx, projectID uuid.UUID, name string) (store.CatalogEntry, error) {
	return scanCatalog(tx.QueryRow(ctx, `
DELETE FROM app.catalog_entries
WHERE project_id = $1::uuid AND name = $2
RETURNING id::text, project_id::text, name, kind, spec, spec_hash, command_display,
          created_by::text, created_at, updated_at
`, projectID.String(), name))
}

func (d *DB) GetCatalogEntry(ctx context.Context, projectID uuid.UUID, name string) (store.CatalogEntry, error) {
	return scanCatalog(d.pool.QueryRow(ctx, `
SELECT id::text, project_id::text, name, kind, spec, spec_hash, command_display,
       created_by::text, created_at, updated_at
FROM app.catalog_entries
WHERE project_id = $1::uuid AND name = $2
`, projectID.String(), name))
}

func (d *DB) ListCatalogEntries(ctx context.Context, projectID uuid.UUID) ([]store.CatalogEntry, error) {
	rows, err := d.pool.Query(ctx, `
SELECT id::text, project_id::text, name, kind, spec, spec_hash, command_display,
       created_by::text, created_at, updated_at
FROM app.catalog_entries
WHERE project_id = $1::uuid
ORDER BY name COLLATE "C" ASC, id ASC
`, projectID.String())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.CatalogEntry{}
	for rows.Next() {
		entry, err := scanCatalog(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

// CatalogLastDeployed runs one query for the image entries and one for the
// program entries (api-v1 v1.21). Only rows started via console or mcp count;
// program runs count from the entry's created_at.
func (d *DB) CatalogLastDeployed(ctx context.Context, projectID uuid.UUID, entries []store.CatalogEntry) (map[uuid.UUID]time.Time, error) {
	out := map[uuid.UUID]time.Time{}
	var imageIDs, programIDs []string
	for _, e := range entries {
		if e.Kind == "image" {
			imageIDs = append(imageIDs, e.ID.String())
		} else {
			programIDs = append(programIDs, e.ID.String())
		}
	}
	if len(imageIDs) > 0 {
		rows, err := d.pool.Query(ctx, `
SELECT d.entry_id::text, max(d.started_at)
FROM app.image_deploys d
JOIN app.catalog_entries e ON e.id = d.entry_id
WHERE e.project_id = $1::uuid
  AND d.entry_id = ANY(CAST($2 AS uuid[]))
  AND d.via IN ('console', 'mcp')
GROUP BY d.entry_id
`, projectID.String(), imageIDs)
		if err != nil {
			return nil, mapErr(err)
		}
		if err := collectLastDeployed(rows, out); err != nil {
			return nil, err
		}
	}
	if len(programIDs) > 0 {
		// Runs count from the entry's creation, so a re-created name starts empty.
		rows, err := d.pool.Query(ctx, `
SELECT e.id::text, max(a.at)
FROM app.catalog_entries e
JOIN app.audit_log a
  ON a.project_id = e.project_id
 AND a.action = $3
 AND a.decision = $4
 AND a.via IN ('console', 'mcp')
 AND a.detail->>'entry' = e.name
 AND a.at >= e.created_at
WHERE e.project_id = $1::uuid AND e.id = ANY(CAST($2 AS uuid[]))
GROUP BY e.id
`, projectID.String(), programIDs, audit.ActionProgramRun, audit.DecisionAllowed)
		if err != nil {
			return nil, mapErr(err)
		}
		if err := collectLastDeployed(rows, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func collectLastDeployed(rows pgx.Rows, out map[uuid.UUID]time.Time) error {
	defer rows.Close()
	for rows.Next() {
		var key string
		var at time.Time
		if err := rows.Scan(&key, &at); err != nil {
			return mapErr(err)
		}
		id, err := uuid.Parse(key)
		if err != nil {
			return err
		}
		out[id] = at.UTC()
	}
	if err := rows.Err(); err != nil {
		return mapErr(err)
	}
	return nil
}

func (d *DB) ListCatalogGrants(ctx context.Context, entryID uuid.UUID) ([]store.CatalogGrant, error) {
	rows, err := d.pool.Query(ctx, `
SELECT subject, actions
FROM app.catalog_grants
WHERE entry_id = $1::uuid
ORDER BY subject ASC
`, entryID.String())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	return collectGrants(rows)
}

func (d *DB) ReplaceCatalogGrants(ctx context.Context, projectID uuid.UUID, name string, grants []store.CatalogGrant) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return mapErr(err)
	}
	defer tx.Rollback(ctx)
	var id string
	err = tx.QueryRow(ctx, `
UPDATE app.catalog_entries
SET updated_at = updated_at
WHERE project_id = $1::uuid AND name = $2
RETURNING id::text
`, projectID.String(), name).Scan(&id)
	if err != nil {
		return mapErr(err)
	}
	if err := exec(ctx, tx, `DELETE FROM app.catalog_grants WHERE entry_id = $1::uuid`, id); err != nil {
		return mapErr(err)
	}
	for _, g := range grants {
		actions := append([]string{}, g.Actions...)
		if err := exec(ctx, tx, `
INSERT INTO app.catalog_grants (entry_id, subject, actions) VALUES ($1::uuid, $2, $3::text[])
`, id, g.Subject, actions); err != nil {
			return mapErr(err)
		}
	}
	return mapErr(tx.Commit(ctx))
}

func (d *DB) HostProjectRelation(ctx context.Context, projectID, hostID uuid.UUID) (string, error) {
	var level string
	err := d.pool.QueryRow(ctx, `
SELECT CASE
    WHEN h.project_id = $1::uuid THEN 'owner'
    ELSE COALESCE((
        SELECT s.level FROM app.host_shares s
        WHERE s.host_id = h.id AND s.project_id = $1::uuid
    ), '')
END
FROM app.hosts h
WHERE h.id = $2::uuid
`, projectID.String(), hostID.String()).Scan(&level)
	if err != nil {
		return "", mapErr(err)
	}
	return level, nil
}

func (d *DB) ListCatalogApprovals(ctx context.Context, hostID uuid.UUID) ([]store.CatalogApproval, error) {
	rows, err := d.pool.Query(ctx, approvalSelect+`
WHERE a.host_id = $1::uuid
ORDER BY a.requested_at DESC, a.entry_id ASC
`, hostID.String())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.CatalogApproval{}
	for rows.Next() {
		item, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (d *DB) ApproveCatalog(ctx context.Context, hostID, entryID uuid.UUID, specHash string, approver uuid.UUID, at time.Time) (store.CatalogApproval, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.CatalogApproval{}, mapErr(err)
	}
	defer tx.Rollback(ctx)
	var current string
	err = tx.QueryRow(ctx, `
SELECT spec_hash FROM app.catalog_entries WHERE id = $1::uuid FOR UPDATE
`, entryID.String()).Scan(&current)
	if err != nil {
		return store.CatalogApproval{}, mapErr(err)
	}
	if current != specHash {
		return store.CatalogApproval{}, store.ErrConflict
	}
	var hostOK bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM app.hosts WHERE id = $1::uuid)`, hostID.String()).Scan(&hostOK); err != nil {
		return store.CatalogApproval{}, mapErr(err)
	}
	if !hostOK {
		return store.CatalogApproval{}, store.ErrNotFound
	}
	if err := exec(ctx, tx, `
INSERT INTO app.catalog_host_approvals (
    entry_id, host_id, spec_hash, status, requested_by, requested_at, approved_by, approved_at
) VALUES ($1::uuid, $2::uuid, $3, 'approved', $4::uuid, $5, $4::uuid, $5)
ON CONFLICT (entry_id, host_id) DO UPDATE SET
    spec_hash = EXCLUDED.spec_hash,
    status = 'approved',
    approved_by = EXCLUDED.approved_by,
    approved_at = EXCLUDED.approved_at
`, entryID.String(), hostID.String(), specHash, approver.String(), at); err != nil {
		return store.CatalogApproval{}, mapErr(err)
	}
	item, err := scanApproval(tx.QueryRow(ctx, approvalSelect+`
WHERE a.entry_id = $1::uuid AND a.host_id = $2::uuid
`, entryID.String(), hostID.String()))
	if err != nil {
		return store.CatalogApproval{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return store.CatalogApproval{}, mapErr(err)
	}
	return item, nil
}

func (d *DB) DeleteCatalogApproval(ctx context.Context, hostID, entryID uuid.UUID) error {
	tag, err := d.pool.Exec(ctx, `
DELETE FROM app.catalog_host_approvals WHERE host_id = $1::uuid AND entry_id = $2::uuid
`, hostID.String(), entryID.String())
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (d *DB) UpsertPendingApproval(ctx context.Context, entryID, hostID uuid.UUID, specHash string, userID uuid.UUID, at time.Time) error {
	err := exec(ctx, d.pool, `
INSERT INTO app.catalog_host_approvals (
    entry_id, host_id, spec_hash, status, requested_by, requested_at
) VALUES ($1::uuid, $2::uuid, $3, 'pending', $4::uuid, $5)
ON CONFLICT (entry_id, host_id) DO UPDATE SET
    spec_hash = EXCLUDED.spec_hash,
    status = 'pending',
    requested_by = EXCLUDED.requested_by,
    requested_at = EXCLUDED.requested_at,
    approved_by = NULL,
    approved_at = NULL
WHERE catalog_host_approvals.status = 'pending'
   OR catalog_host_approvals.spec_hash IS DISTINCT FROM EXCLUDED.spec_hash
`, entryID.String(), hostID.String(), specHash, userID.String(), at)
	return mapErr(err)
}

func (d *DB) PutConfirmation(ctx context.Context, hash []byte, c store.CatalogConfirmation) error {
	err := exec(ctx, d.pool, `
INSERT INTO app.catalog_confirmations (
    token_hash, user_id, project_id, entry_id, entry_name, host_id, action, spec_hash,
    idempotency_key, request_hash, created_at, expires_at, image_digest, image_force
) VALUES ($1, $2::uuid, $3::uuid, $4::uuid, $5, $6::uuid, $7, $8, $9, $10, $11, $12, $13, $14)
`, hash, c.UserID.String(), c.ProjectID.String(), c.EntryID.String(), c.EntryName, c.HostID.String(),
		c.Action, c.SpecHash, c.IdempotencyKey, c.RequestHash, c.CreatedAt, c.ExpiresAt, c.ImageDigest, c.ImageForce)
	return mapErr(err)
}

func (d *DB) GetConfirmation(ctx context.Context, hash []byte) (store.CatalogConfirmation, error) {
	var c store.CatalogConfirmation
	var userID, projectID, entryID, hostID string
	err := d.pool.QueryRow(ctx, `
SELECT user_id::text, project_id::text, entry_id::text, entry_name, host_id::text, action, spec_hash,
       idempotency_key, request_hash, created_at, expires_at, used_at, image_digest, image_force
FROM app.catalog_confirmations
WHERE token_hash = $1
`, hash).Scan(&userID, &projectID, &entryID, &c.EntryName, &hostID, &c.Action, &c.SpecHash,
		&c.IdempotencyKey, &c.RequestHash, &c.CreatedAt, &c.ExpiresAt, &c.UsedAt, &c.ImageDigest, &c.ImageForce)
	if err != nil {
		return store.CatalogConfirmation{}, mapErr(err)
	}
	var perr error
	if c.UserID, perr = parseID(userID); perr != nil {
		return store.CatalogConfirmation{}, perr
	}
	if c.ProjectID, perr = parseID(projectID); perr != nil {
		return store.CatalogConfirmation{}, perr
	}
	if c.EntryID, perr = parseID(entryID); perr != nil {
		return store.CatalogConfirmation{}, perr
	}
	if c.HostID, perr = parseID(hostID); perr != nil {
		return store.CatalogConfirmation{}, perr
	}
	return c, nil
}

func (d *DB) MarkConfirmationUsed(ctx context.Context, hash []byte, userID uuid.UUID, at time.Time) error {
	tag, err := d.pool.Exec(ctx, `
UPDATE app.catalog_confirmations
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

func (d *DB) GetIdempotency(ctx context.Context, userID uuid.UUID, key string, at time.Time) (store.IdempotencyRecord, error) {
	rec, err := scanIdempotency(d.pool.QueryRow(ctx, `
SELECT request_hash, status_code, response, created_at
FROM app.idempotency_keys
WHERE user_id = $1::uuid AND idempotency_key = $2
`, userID.String(), key))
	if err != nil {
		return store.IdempotencyRecord{}, err
	}
	if !rec.CreatedAt.After(at.Add(-store.IdempotencyTTL)) {
		if err := exec(ctx, d.pool, `
DELETE FROM app.idempotency_keys WHERE user_id = $1::uuid AND idempotency_key = $2
`, userID.String(), key); err != nil {
			return store.IdempotencyRecord{}, mapErr(err)
		}
		return store.IdempotencyRecord{}, store.ErrNotFound
	}
	return rec, nil
}

func (d *DB) ClaimIdempotency(ctx context.Context, userID uuid.UUID, key string, hash []byte, at time.Time) (store.IdempotencyRecord, bool, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.IdempotencyRecord{}, false, mapErr(err)
	}
	defer tx.Rollback(ctx)
	cutoff := at.Add(-store.IdempotencyTTL)
	if err := exec(ctx, tx, `
DELETE FROM app.idempotency_keys
WHERE user_id = $1::uuid AND idempotency_key = $2 AND created_at <= $3
`, userID.String(), key, cutoff); err != nil {
		return store.IdempotencyRecord{}, false, mapErr(err)
	}
	tag, err := tx.Exec(ctx, `
INSERT INTO app.idempotency_keys (user_id, idempotency_key, request_hash, status_code, response, created_at)
VALUES ($1::uuid, $2, $3, NULL, NULL, $4)
ON CONFLICT (user_id, idempotency_key) DO NOTHING
`, userID.String(), key, hash, at)
	if err != nil {
		return store.IdempotencyRecord{}, false, mapErr(err)
	}
	if tag.RowsAffected() == 1 {
		if err := tx.Commit(ctx); err != nil {
			return store.IdempotencyRecord{}, false, mapErr(err)
		}
		return store.IdempotencyRecord{RequestHash: append([]byte(nil), hash...), Pending: true, CreatedAt: at}, true, nil
	}
	rec, err := scanIdempotency(tx.QueryRow(ctx, `
SELECT request_hash, status_code, response, created_at
FROM app.idempotency_keys
WHERE user_id = $1::uuid AND idempotency_key = $2
FOR UPDATE
`, userID.String(), key))
	if err != nil {
		return store.IdempotencyRecord{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return store.IdempotencyRecord{}, false, mapErr(err)
	}
	if rec.Pending {
		return rec, false, store.ErrPending
	}
	if !secret.Equal(rec.RequestHash, hash) {
		return rec, false, store.ErrConflict
	}
	return rec, false, nil
}

func scanIdempotency(row pgx.Row) (store.IdempotencyRecord, error) {
	var rec store.IdempotencyRecord
	var status *int
	if err := row.Scan(&rec.RequestHash, &status, &rec.Body, &rec.CreatedAt); err != nil {
		return store.IdempotencyRecord{}, mapErr(err)
	}
	if status == nil || rec.Body == nil {
		rec.Pending = true
		rec.Body = nil
		return rec, nil
	}
	rec.Status = *status
	return rec, nil
}

func (d *DB) PutIdempotency(ctx context.Context, userID uuid.UUID, key string, rec store.IdempotencyRecord) error {
	err := exec(ctx, d.pool, `
INSERT INTO app.idempotency_keys (user_id, idempotency_key, request_hash, status_code, response, created_at)
VALUES ($1::uuid, $2, $3, $4, $5::jsonb, $6)
`, userID.String(), key, rec.RequestHash, rec.Status, rec.Body, rec.CreatedAt)
	return mapErr(err)
}

func (d *DB) ReplaceIdempotencyResponse(ctx context.Context, userID uuid.UUID, key string, status int, body []byte) error {
	tag, err := d.pool.Exec(ctx, `
UPDATE app.idempotency_keys
SET status_code = $3, response = $4::jsonb
WHERE user_id = $1::uuid AND idempotency_key = $2
`, userID.String(), key, status, body)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (d *DB) SetHostPrograms(ctx context.Context, hostID uuid.UUID, programs *store.HostPrograms) error {
	raw, err := programsJSON(programs)
	if err != nil {
		return err
	}
	tag, err := d.pool.Exec(ctx, `UPDATE app.hosts SET programs = $2::jsonb WHERE id = $1::uuid`, hostID.String(), raw)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

const approvalSelect = `
SELECT a.entry_id::text, e.name, e.project_id::text, p.name, a.host_id::text, a.spec_hash,
       e.command_display, e.spec, a.status, a.requested_by::text, a.requested_at,
       a.approved_by::text, a.approved_at
FROM app.catalog_host_approvals a
JOIN app.catalog_entries e ON e.id = a.entry_id
JOIN app.projects p ON p.id = e.project_id
`

func scanCatalog(row pgx.Row) (store.CatalogEntry, error) {
	var e store.CatalogEntry
	var id, projectID, createdBy string
	var spec []byte
	if err := row.Scan(&id, &projectID, &e.Name, &e.Kind, &spec, &e.SpecHash, &e.CommandDisplay, &createdBy, &e.CreatedAt, &e.UpdatedAt); err != nil {
		return store.CatalogEntry{}, mapErr(err)
	}
	var err error
	if e.ID, err = parseID(id); err != nil {
		return store.CatalogEntry{}, err
	}
	if e.ProjectID, err = parseID(projectID); err != nil {
		return store.CatalogEntry{}, err
	}
	if e.CreatedBy, err = parseID(createdBy); err != nil {
		return store.CatalogEntry{}, err
	}
	if e.Kind == "image" {
		e.ImageRaw = append([]byte(nil), spec...)
		return e, nil
	}
	if err := json.Unmarshal(spec, &e.Spec); err != nil {
		return store.CatalogEntry{}, err
	}
	normSpec(&e.Spec)
	return e, nil
}

func scanApproval(row pgx.Row) (store.CatalogApproval, error) {
	var a store.CatalogApproval
	var entryID, projectID, hostID, requestedBy string
	var approvedBy *string
	var spec []byte
	if err := row.Scan(
		&entryID, &a.EntryName, &projectID, &a.ProjectName, &hostID, &a.SpecHash,
		&a.CommandDisplay, &spec, &a.Status, &requestedBy, &a.RequestedAt, &approvedBy, &a.ApprovedAt,
	); err != nil {
		return store.CatalogApproval{}, mapErr(err)
	}
	var parsed store.ProgramSpec
	if err := json.Unmarshal(spec, &parsed); err != nil {
		return store.CatalogApproval{}, err
	}
	a.Dir = parsed.Dir
	a.Exec = parsed.Exec
	a.Args = parsed.Args
	if a.Args == nil {
		a.Args = []string{}
	}
	a.Env = parsed.Env
	if a.Env == nil {
		a.Env = map[string]string{}
	}
	a.RunAs = parsed.RunAs
	a.Shell = parsed.Shell
	var err error
	if a.EntryID, err = parseID(entryID); err != nil {
		return store.CatalogApproval{}, err
	}
	if a.ProjectID, err = parseID(projectID); err != nil {
		return store.CatalogApproval{}, err
	}
	if a.HostID, err = parseID(hostID); err != nil {
		return store.CatalogApproval{}, err
	}
	if a.RequestedBy, err = parseID(requestedBy); err != nil {
		return store.CatalogApproval{}, err
	}
	if a.ApprovedBy, err = parseOptID(approvedBy); err != nil {
		return store.CatalogApproval{}, err
	}
	return a, nil
}

func collectGrants(rows pgx.Rows) ([]store.CatalogGrant, error) {
	out := []store.CatalogGrant{}
	for rows.Next() {
		var g store.CatalogGrant
		if err := rows.Scan(&g.Subject, &g.Actions); err != nil {
			return nil, mapErr(err)
		}
		if g.Actions == nil {
			g.Actions = []string{}
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func marshalSpec(spec store.ProgramSpec) ([]byte, error) {
	normSpec(&spec)
	return json.Marshal(spec)
}

func marshalWrite(in store.CatalogWrite) ([]byte, error) {
	if in.Kind == "image" || len(in.ImageRaw) > 0 {
		if len(in.ImageRaw) == 0 {
			return []byte(`{}`), nil
		}
		return in.ImageRaw, nil
	}
	return marshalSpec(in.Spec)
}

func normSpec(spec *store.ProgramSpec) {
	if spec.Args == nil {
		spec.Args = []string{}
	}
	if spec.Env == nil {
		spec.Env = map[string]string{}
	}
}

func programsJSON(p *store.HostPrograms) (any, error) {
	if p == nil {
		return nil, nil
	}
	cp := *p
	if cp.RunAs == nil {
		cp.RunAs = []string{}
	}
	raw, err := json.Marshal(cp)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func applyPrograms(h *store.Host, raw []byte) error {
	p, err := decodePrograms(raw)
	if err != nil {
		return err
	}
	h.Programs = p
	return nil
}

func decodePrograms(raw []byte) (*store.HostPrograms, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var p store.HostPrograms
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p.RunAs == nil {
		p.RunAs = []string{}
	}
	return &p, nil
}

// catalogLookup finds a live project slug that has a catalog entry of that name.
func (d *DB) catalogLookup(ctx context.Context, q queryer, slug, entry, kind string) (uuid.UUID, bool) {
	var id string
	err := q.QueryRow(ctx, `
SELECT p.id::text
FROM app.projects p
JOIN app.catalog_entries e ON e.project_id = p.id AND e.name = $2 AND e.kind = $3
WHERE p.slug = $1 AND p.deleted_at IS NULL
`, slug, entry, kind).Scan(&id)
	if err != nil {
		return uuid.Nil, false
	}
	parsed, err := parseID(id)
	if err != nil {
		return uuid.Nil, false
	}
	return parsed, true
}
