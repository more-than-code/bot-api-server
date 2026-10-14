package db

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (d *DB) HostFacts(ctx context.Context, userID, hostID uuid.UUID) (store.HostFacts, error) {
	rows, err := d.pool.Query(ctx, `
SELECT
    COALESCE((
        SELECT m.role
        FROM app.project_members m
        JOIN app.projects p ON p.id = h.project_id AND p.deleted_at IS NULL
        WHERE m.project_id = h.project_id AND m.user_id = $1::uuid
    ), ''),
    COALESCE(sh.project_id::text, ''),
    COALESCE(sh.level, ''),
    COALESCE(sh.role, '')
FROM app.hosts h
LEFT JOIN (
    SELECT s.host_id, s.project_id, s.level, m.role
    FROM app.host_shares s
    JOIN app.projects p ON p.id = s.project_id AND p.deleted_at IS NULL
    JOIN app.project_members m ON m.project_id = s.project_id AND m.user_id = $1::uuid
) sh ON sh.host_id = h.id
WHERE h.id = $2::uuid
ORDER BY sh.project_id
`, userID.String(), hostID.String())
	if err != nil {
		return store.HostFacts{}, mapErr(err)
	}
	defer rows.Close()
	var facts store.HostFacts
	seen := false
	for rows.Next() {
		var projectText, level, role string
		if err := rows.Scan(&facts.OwnerRole, &projectText, &level, &role); err != nil {
			return store.HostFacts{}, mapErr(err)
		}
		seen = true
		if projectText == "" {
			continue
		}
		id, err := parseID(projectText)
		if err != nil {
			return store.HostFacts{}, err
		}
		facts.Shares = append(facts.Shares, store.HostShareAccess{
			ProjectID: id,
			Level:     level,
			Role:      role,
		})
	}
	if err := rows.Err(); err != nil {
		return store.HostFacts{}, mapErr(err)
	}
	if !seen {
		return store.HostFacts{}, store.ErrNotFound
	}
	return facts, nil
}

func (d *DB) ListHostShares(ctx context.Context, hostID uuid.UUID) ([]store.HostShare, error) {
	var exists bool
	if err := d.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM app.hosts WHERE id = $1::uuid)`, hostID.String()).Scan(&exists); err != nil {
		return nil, mapErr(err)
	}
	if !exists {
		return nil, store.ErrNotFound
	}
	rows, err := d.pool.Query(ctx, `
SELECT s.host_id::text, s.project_id::text, p.name, s.level, s.created_by::text, s.created_at
FROM app.host_shares s
JOIN app.projects p ON p.id = s.project_id
WHERE s.host_id = $1::uuid
ORDER BY p.name COLLATE "C" ASC, s.project_id ASC
`, hostID.String())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.HostShare{}
	for rows.Next() {
		item, err := scanShare(rows)
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

func (d *DB) PutHostShare(ctx context.Context, hostID, projectID uuid.UUID, level string, createdBy uuid.UUID, at time.Time) (store.HostShare, bool, error) {
	if !store.ValidShareLevel(level) {
		return store.HostShare{}, false, store.ErrInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.HostShare{}, false, mapErr(err)
	}
	defer tx.Rollback(ctx)

	var ownerID string
	err = tx.QueryRow(ctx, `SELECT project_id::text FROM app.hosts WHERE id = $1::uuid`, hostID.String()).Scan(&ownerID)
	if err != nil {
		return store.HostShare{}, false, mapErr(err)
	}
	// Lock the owning project before the host. DeleteProject locks the
	// project, then its hosts, then deletes shares. The same order lets
	// that delete either wait for this insert or make this insert see
	// the project as gone, so a share cannot be committed afterwards.
	err = tx.QueryRow(ctx, `
SELECT id::text FROM app.projects
WHERE id = $1::uuid AND deleted_at IS NULL
FOR SHARE
`, ownerID).Scan(&ownerID)
	if err != nil {
		return store.HostShare{}, false, mapErr(err)
	}
	var lockedOwner string
	err = tx.QueryRow(ctx, `SELECT project_id::text FROM app.hosts WHERE id = $1::uuid FOR UPDATE`, hostID.String()).Scan(&lockedOwner)
	if err != nil {
		return store.HostShare{}, false, mapErr(err)
	}
	if lockedOwner != ownerID {
		return store.HostShare{}, false, store.ErrNotFound
	}
	if ownerID == projectID.String() {
		return store.HostShare{}, false, store.ErrInvalid
	}
	var alive bool
	if err := tx.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM app.projects WHERE id = $1::uuid AND deleted_at IS NULL)
`, projectID.String()).Scan(&alive); err != nil {
		return store.HostShare{}, false, mapErr(err)
	}
	if !alive {
		return store.HostShare{}, false, store.ErrNotFound
	}
	var existed bool
	if err := tx.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM app.host_shares WHERE host_id = $1::uuid AND project_id = $2::uuid)
`, hostID.String(), projectID.String()).Scan(&existed); err != nil {
		return store.HostShare{}, false, mapErr(err)
	}
	var createdByArg any
	if createdBy != uuid.Nil {
		createdByArg = createdBy.String()
	}
	row := tx.QueryRow(ctx, `
WITH up AS (
    INSERT INTO app.host_shares (host_id, project_id, level, created_by, created_at)
    VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5)
    ON CONFLICT (host_id, project_id) DO UPDATE SET level = EXCLUDED.level
    RETURNING host_id, project_id, level, created_by, created_at
)
SELECT up.host_id::text, up.project_id::text, p.name, up.level, up.created_by::text, up.created_at
FROM up
JOIN app.projects p ON p.id = up.project_id
`, hostID.String(), projectID.String(), level, createdByArg, at)
	item, err := scanShare(row)
	if err != nil {
		return store.HostShare{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return store.HostShare{}, false, mapErr(err)
	}
	return item, !existed, nil
}

func (d *DB) DeleteHostShare(ctx context.Context, hostID, projectID uuid.UUID, reassignOwner bool) (store.HostShare, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.HostShare{}, mapErr(err)
	}
	defer tx.Rollback(ctx)

	row := tx.QueryRow(ctx, `
SELECT s.host_id::text, s.project_id::text, p.name, s.level, s.created_by::text, s.created_at, h.project_id::text
FROM app.host_shares s
JOIN app.hosts h ON h.id = s.host_id
JOIN app.projects p ON p.id = s.project_id
WHERE s.host_id = $1::uuid AND s.project_id = $2::uuid
FOR UPDATE OF s
`, hostID.String(), projectID.String())
	var hostText, projectText, ownerText string
	var createdText *string
	var item store.HostShare
	if err := row.Scan(&hostText, &projectText, &item.ProjectName, &item.Level, &createdText, &item.CreatedAt, &ownerText); err != nil {
		return store.HostShare{}, mapErr(err)
	}
	var parseErr error
	if item.HostID, parseErr = parseID(hostText); parseErr != nil {
		return store.HostShare{}, parseErr
	}
	if item.ProjectID, parseErr = parseID(projectText); parseErr != nil {
		return store.HostShare{}, parseErr
	}
	if createdText != nil && *createdText != "" {
		if item.CreatedBy, parseErr = parseID(*createdText); parseErr != nil {
			return store.HostShare{}, parseErr
		}
	}
	ownerID, parseErr := parseID(ownerText)
	if parseErr != nil {
		return store.HostShare{}, parseErr
	}
	var n int
	if err := tx.QueryRow(ctx, `
SELECT count(*) FROM app.services WHERE host_id = $1::uuid AND project_id = $2::uuid
`, hostID.String(), projectID.String()).Scan(&n); err != nil {
		return store.HostShare{}, mapErr(err)
	}
	if n > 0 && !reassignOwner {
		return store.HostShare{}, store.ErrConflict
	}
	if n > 0 {
		if err := exec(ctx, tx, `
UPDATE app.services SET project_id = $3::uuid
WHERE host_id = $1::uuid AND project_id = $2::uuid
`, hostID.String(), projectID.String(), ownerID.String()); err != nil {
			return store.HostShare{}, mapErr(err)
		}
	}
	if err := exec(ctx, tx, `
DELETE FROM app.host_shares WHERE host_id = $1::uuid AND project_id = $2::uuid
`, hostID.String(), projectID.String()); err != nil {
		return store.HostShare{}, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return store.HostShare{}, mapErr(err)
	}
	return item, nil
}

func scanShare(row pgx.Row) (store.HostShare, error) {
	var item store.HostShare
	var hostText, projectText string
	var createdText *string
	if err := row.Scan(&hostText, &projectText, &item.ProjectName, &item.Level, &createdText, &item.CreatedAt); err != nil {
		return store.HostShare{}, mapErr(err)
	}
	var err error
	if item.HostID, err = parseID(hostText); err != nil {
		return store.HostShare{}, err
	}
	if item.ProjectID, err = parseID(projectText); err != nil {
		return store.HostShare{}, err
	}
	if createdText != nil && *createdText != "" {
		if item.CreatedBy, err = parseID(*createdText); err != nil {
			return store.HostShare{}, err
		}
	}
	return item, nil
}
