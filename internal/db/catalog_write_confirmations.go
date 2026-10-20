package db

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (d *DB) PutCatalogWriteConfirmation(ctx context.Context, hash []byte, c store.CatalogWriteConfirmation) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return mapErr(err)
	}
	defer tx.Rollback(ctx)
	// A new plan drops rows that are already past their TTL. The body is
	// the image spec, so it should not sit after expiry.
	if err := exec(ctx, tx, `
DELETE FROM app.catalog_write_confirmations WHERE expires_at < $1
`, c.CreatedAt); err != nil {
		return mapErr(err)
	}
	if err := exec(ctx, tx, `
INSERT INTO app.catalog_write_confirmations (
    token_hash, user_id, project_id, action, entry_name, base_spec_hash,
    body, request_hash, idempotency_key, created_at, expires_at
) VALUES ($1, $2::uuid, $3::uuid, $4, $5, $6, $7::jsonb, $8, $9, $10, $11)
`, hash, c.UserID.String(), c.ProjectID.String(), c.Action, c.EntryName,
		nullText(c.BaseSpecHash), nullJSON(c.Body), c.RequestHash, c.IdempotencyKey, c.CreatedAt, c.ExpiresAt); err != nil {
		return mapErr(err)
	}
	return mapErr(tx.Commit(ctx))
}

const catalogWriteConfirmationCols = `
SELECT user_id::text, project_id::text, action, entry_name, base_spec_hash,
       body, request_hash, idempotency_key, created_at, expires_at, used_at
FROM app.catalog_write_confirmations
WHERE token_hash = $1`

func (d *DB) GetCatalogWriteConfirmation(ctx context.Context, hash []byte) (store.CatalogWriteConfirmation, error) {
	return scanCatalogWriteConfirmation(d.pool.QueryRow(ctx, catalogWriteConfirmationCols, hash))
}

func scanCatalogWriteConfirmation(row pgx.Row) (store.CatalogWriteConfirmation, error) {
	var c store.CatalogWriteConfirmation
	var userID, projectID string
	var base *string
	err := row.Scan(&userID, &projectID, &c.Action, &c.EntryName, &base,
		&c.Body, &c.RequestHash, &c.IdempotencyKey, &c.CreatedAt, &c.ExpiresAt, &c.UsedAt)
	if err != nil {
		return store.CatalogWriteConfirmation{}, mapErr(err)
	}
	var perr error
	if c.UserID, perr = parseID(userID); perr != nil {
		return store.CatalogWriteConfirmation{}, perr
	}
	if c.ProjectID, perr = parseID(projectID); perr != nil {
		return store.CatalogWriteConfirmation{}, perr
	}
	if base != nil {
		c.BaseSpecHash = *base
	}
	return c, nil
}

func (d *DB) CountEntryApprovals(ctx context.Context, projectID uuid.UUID, name string) (int, error) {
	var n int
	err := d.pool.QueryRow(ctx, `
SELECT count(*)
FROM app.catalog_host_approvals a
JOIN app.catalog_entries e ON e.id = a.entry_id
WHERE e.project_id = $1::uuid AND e.name = $2
`, projectID.String(), name).Scan(&n)
	if err != nil {
		return 0, mapErr(err)
	}
	return n, nil
}

// CommitCatalogWrite locks the plan and the catalog row, applies the console
// write, and deletes the plan in that same transaction. The idempotency
// record keeps the response. A conflict rolls back, so the plan stays.
func (d *DB) CommitCatalogWrite(ctx context.Context, hash []byte, userID uuid.UUID, at time.Time, in store.CatalogWrite) (string, store.CatalogEntry, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return "", store.CatalogEntry{}, mapErr(err)
	}
	defer tx.Rollback(ctx)
	c, err := scanCatalogWriteConfirmation(tx.QueryRow(ctx, catalogWriteConfirmationCols+` FOR UPDATE`, hash))
	if err != nil {
		return "", store.CatalogEntry{}, err
	}
	if c.UserID != userID || c.UsedAt != nil || !c.ExpiresAt.After(at) {
		return "", store.CatalogEntry{}, store.ErrNotFound
	}
	if in.Name != c.EntryName {
		return "", store.CatalogEntry{}, store.ErrConflict
	}
	var old string
	var entry store.CatalogEntry
	switch c.Action {
	case "create":
		if in.Kind != "image" || !store.SameJSON(c.Body, in.ImageRaw) {
			return "", store.CatalogEntry{}, store.ErrConflict
		}
		entry, err = insertCatalogEntry(ctx, tx, c.ProjectID, in)
		if errors.Is(err, store.ErrConflict) {
			return "", store.CatalogEntry{}, store.ErrConflict
		}
	case "update":
		if in.Kind != "image" || !store.SameJSON(c.Body, in.ImageRaw) {
			return "", store.CatalogEntry{}, store.ErrConflict
		}
		var current string
		err = tx.QueryRow(ctx, `
SELECT spec_hash FROM app.catalog_entries
WHERE project_id = $1::uuid AND name = $2
FOR UPDATE
`, c.ProjectID.String(), c.EntryName).Scan(&current)
		if err != nil {
			if errors.Is(mapErr(err), store.ErrNotFound) {
				return "", store.CatalogEntry{}, store.ErrConflict
			}
			return "", store.CatalogEntry{}, mapErr(err)
		}
		if current != c.BaseSpecHash {
			return "", store.CatalogEntry{}, store.ErrConflict
		}
		old, entry, err = replaceCatalogEntry(ctx, tx, c.ProjectID, c.EntryName, in)
		if errors.Is(err, store.ErrNotFound) {
			return "", store.CatalogEntry{}, store.ErrConflict
		}
	case "delete":
		var current string
		err = tx.QueryRow(ctx, `
SELECT spec_hash FROM app.catalog_entries
WHERE project_id = $1::uuid AND name = $2
FOR UPDATE
`, c.ProjectID.String(), c.EntryName).Scan(&current)
		if err != nil {
			if errors.Is(mapErr(err), store.ErrNotFound) {
				return "", store.CatalogEntry{}, store.ErrConflict
			}
			return "", store.CatalogEntry{}, mapErr(err)
		}
		if current != c.BaseSpecHash {
			return "", store.CatalogEntry{}, store.ErrConflict
		}
		entry, err = deleteCatalogEntry(ctx, tx, c.ProjectID, c.EntryName)
		if errors.Is(err, store.ErrNotFound) {
			return "", store.CatalogEntry{}, store.ErrConflict
		}
	default:
		return "", store.CatalogEntry{}, errors.New("catalog write action")
	}
	if err != nil {
		return "", store.CatalogEntry{}, err
	}
	tag, err := tx.Exec(ctx, `
DELETE FROM app.catalog_write_confirmations
WHERE token_hash = $1 AND user_id = $2::uuid AND used_at IS NULL AND expires_at > $3
`, hash, userID.String(), at)
	if err != nil {
		return "", store.CatalogEntry{}, mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return "", store.CatalogEntry{}, store.ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return "", store.CatalogEntry{}, mapErr(err)
	}
	return old, entry, nil
}

func nullText(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullJSON(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
