package db

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (d *DB) CreateProject(ctx context.Context, ownerID uuid.UUID, name, baseSlug string, at time.Time) (store.Project, error) {
	for n := 1; n < 1000; n++ {
		var slug string
		if n == 1 {
			if len(baseSlug) > 80 {
				continue
			}
			slug = baseSlug
		} else {
			slug = store.WithSuffix(baseSlug, n, 80)
		}
		p, err := d.insertProject(ctx, ownerID, name, slug, at)
		if err == nil {
			return p, nil
		}
		if isUnique(err) {
			continue
		}
		return store.Project{}, mapErr(err)
	}
	return store.Project{}, store.ErrConflict
}

func (d *DB) insertProject(ctx context.Context, ownerID uuid.UUID, name, slug string, at time.Time) (store.Project, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.Project{}, err
	}
	defer tx.Rollback(ctx)
	id := uuid.New()
	if err := exec(ctx, tx, `
INSERT INTO app.projects (id, name, slug, created_by, created_at)
VALUES ($1::uuid, $2, $3, $4::uuid, $5)
`, id.String(), name, slug, ownerID.String(), at); err != nil {
		return store.Project{}, err
	}
	if err := exec(ctx, tx, `
INSERT INTO app.project_members (project_id, user_id, role, added_by, created_at)
VALUES ($1::uuid, $2::uuid, 'owner', $2::uuid, $3)
`, id.String(), ownerID.String(), at); err != nil {
		return store.Project{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return store.Project{}, err
	}
	return store.Project{
		ID:        id,
		Name:      name,
		Slug:      slug,
		Role:      "owner",
		CreatedBy: ownerID,
		CreatedAt: at,
	}, nil
}

func (d *DB) ListProjects(ctx context.Context, userID uuid.UUID, limit int, cursor *store.Cursor) ([]store.Project, *store.Cursor, error) {
	lim := pageLimit(limit)
	var atArg any
	var idArg any
	if cursor != nil {
		atArg = cursor.At
		idArg = cursor.ID
	}
	rows, err := d.pool.Query(ctx, `
SELECT p.id::text, p.name, p.slug, m.role, p.created_by::text, p.created_at
FROM app.projects p
JOIN app.project_members m ON m.project_id = p.id AND m.user_id = $1::uuid
WHERE p.deleted_at IS NULL
  AND (
    CAST($2 AS timestamptz) IS NULL
    OR (p.created_at, p.id) > (CAST($2 AS timestamptz), CAST($3 AS uuid))
  )
ORDER BY p.created_at ASC, p.id ASC
LIMIT $4
`, userID.String(), atArg, idArg, lim+1)
	if err != nil {
		return nil, nil, mapErr(err)
	}
	defer rows.Close()
	items := []store.Project{}
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, p)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, mapErr(err)
	}
	return cutPage(items, lim, func(p store.Project) time.Time { return p.CreatedAt }, func(p store.Project) string { return p.ID.String() })
}

func (d *DB) ListAllProjects(ctx context.Context, userID uuid.UUID) ([]store.Project, error) {
	items, _, err := d.ListProjects(ctx, userID, 10000, nil)
	return items, err
}

func (d *DB) GetProject(ctx context.Context, id uuid.UUID) (store.Project, error) {
	return scanProject(d.pool.QueryRow(ctx, `
SELECT id::text, name, slug, ''::text, created_by::text, created_at
FROM app.projects
WHERE id = $1::uuid AND deleted_at IS NULL
`, id.String()))
}

func (d *DB) Role(ctx context.Context, projectID, userID uuid.UUID) (string, error) {
	var role string
	err := d.pool.QueryRow(ctx, `
SELECT m.role
FROM app.projects p
JOIN app.project_members m ON m.project_id = p.id AND m.user_id = $2::uuid
WHERE p.id = $1::uuid AND p.deleted_at IS NULL
`, projectID.String(), userID.String()).Scan(&role)
	if err != nil {
		return "", mapErr(err)
	}
	return role, nil
}

func (d *DB) RenameProject(ctx context.Context, id uuid.UUID, name string) (store.Project, error) {
	return scanProject(d.pool.QueryRow(ctx, `
UPDATE app.projects
SET name = $2
WHERE id = $1::uuid AND deleted_at IS NULL
RETURNING id::text, name, slug, ''::text, created_by::text, created_at
`, id.String(), name))
}

func (d *DB) DeleteProject(ctx context.Context, id uuid.UUID, at time.Time) ([]uuid.UUID, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `
UPDATE app.projects
SET deleted_at = $2
WHERE id = $1::uuid AND deleted_at IS NULL
`, id.String(), at)
	if err != nil {
		return nil, mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return nil, store.ErrNotFound
	}
	if err := exec(ctx, tx, `
UPDATE app.hosts
SET revoked_at = $2
WHERE project_id = $1::uuid AND revoked_at IS NULL
`, id.String(), at); err != nil {
		return nil, mapErr(err)
	}
	if err := exec(ctx, tx, `
UPDATE app.agent_credentials c
SET revoked_at = $2
FROM app.hosts h
WHERE c.host_id = h.id AND h.project_id = $1::uuid AND c.revoked_at IS NULL
`, id.String(), at); err != nil {
		return nil, mapErr(err)
	}
	// Still-present rows of this project's hosts go gone at the host's
	// revoke time. A row that is already gone keeps its time. Services on
	// another project's host are left for the hand-back below.
	if err := exec(ctx, tx, `
UPDATE app.services AS s
SET gone_at = h.revoked_at
FROM app.hosts AS h
WHERE s.host_id = h.id
  AND h.project_id = $1::uuid
  AND h.revoked_at IS NOT NULL
  AND s.gone_at IS NULL
`, id.String()); err != nil {
		return nil, mapErr(err)
	}
	// Services this project owns on someone else's host go back to that host's owner.
	if err := exec(ctx, tx, `
UPDATE app.services s
SET project_id = h.project_id
FROM app.hosts h
WHERE s.host_id = h.id
  AND s.project_id = $1::uuid
  AND h.project_id <> $1::uuid
`, id.String()); err != nil {
		return nil, mapErr(err)
	}
	if err := exec(ctx, tx, `
DELETE FROM app.host_shares
WHERE project_id = $1::uuid
   OR host_id IN (SELECT id FROM app.hosts WHERE project_id = $1::uuid)
`, id.String()); err != nil {
		return nil, mapErr(err)
	}
	// Soft-delete does not fire ON DELETE CASCADE. The function runs as
	// the table owner so deploybot_api can remove invites without DELETE.
	deleted, err := tx.Query(ctx, `SELECT app.invites_delete_for_project($1::uuid)`, id.String())
	if err != nil {
		return nil, mapErr(err)
	}
	deleted.Close()
	if err := deleted.Err(); err != nil {
		return nil, mapErr(err)
	}
	// Soft-delete does not cascade. Catalog DELETE is granted, and it
	// removes grants, approvals, and confirmations with the entry.
	if err := exec(ctx, tx, `DELETE FROM app.catalog_entries WHERE project_id = $1::uuid`, id.String()); err != nil {
		return nil, mapErr(err)
	}
	if err := exec(ctx, tx, `DELETE FROM app.env_sets WHERE project_id = $1::uuid`, id.String()); err != nil {
		return nil, mapErr(err)
	}
	if err := exec(ctx, tx, `DELETE FROM app.registries WHERE project_id = $1::uuid`, id.String()); err != nil {
		return nil, mapErr(err)
	}
	// Soft-delete does not cascade. Files have no FK from catalog rows.
	if err := exec(ctx, tx, `DELETE FROM app.project_files WHERE project_id = $1::uuid`, id.String()); err != nil {
		return nil, mapErr(err)
	}
	rows, err := tx.Query(ctx, `
SELECT id::text FROM app.hosts WHERE project_id = $1::uuid ORDER BY id::text
`, id.String())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	ids := []uuid.UUID{}
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			return nil, mapErr(err)
		}
		hid, err := parseID(text)
		if err != nil {
			return nil, err
		}
		ids = append(ids, hid)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return ids, nil
}

func (d *DB) ListMembers(ctx context.Context, projectID uuid.UUID, limit int, cursor *store.Cursor) ([]store.Member, *store.Cursor, error) {
	var alive bool
	if err := d.pool.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM app.projects WHERE id = $1::uuid AND deleted_at IS NULL)
`, projectID.String()).Scan(&alive); err != nil {
		return nil, nil, mapErr(err)
	}
	if !alive {
		return nil, nil, store.ErrNotFound
	}
	lim := pageLimit(limit)
	var atArg any
	var idArg any
	if cursor != nil {
		atArg = cursor.At
		idArg = cursor.ID
	}
	rows, err := d.pool.Query(ctx, `
SELECT m.user_id::text, u.email, u.name, m.role, m.created_at
FROM app.project_members m
JOIN app.users u ON u.id = m.user_id
WHERE m.project_id = $1::uuid
  AND (
    CAST($2 AS timestamptz) IS NULL
    OR (m.created_at, m.user_id) > (CAST($2 AS timestamptz), CAST($3 AS uuid))
  )
ORDER BY m.created_at ASC, m.user_id ASC
LIMIT $4
`, projectID.String(), atArg, idArg, lim+1)
	if err != nil {
		return nil, nil, mapErr(err)
	}
	defer rows.Close()
	items := []store.Member{}
	for rows.Next() {
		m, err := scanMember(rows)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, m)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, mapErr(err)
	}
	return cutPage(items, lim, func(m store.Member) time.Time { return m.CreatedAt }, func(m store.Member) string { return m.UserID.String() })
}

func (d *DB) AddMember(ctx context.Context, projectID, userID uuid.UUID, role string, addedBy uuid.UUID, at time.Time) (store.Member, error) {
	var alive bool
	if err := d.pool.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM app.projects WHERE id = $1::uuid AND deleted_at IS NULL)
`, projectID.String()).Scan(&alive); err != nil {
		return store.Member{}, mapErr(err)
	}
	if !alive {
		return store.Member{}, store.ErrNotFound
	}
	var email, name string
	err := d.pool.QueryRow(ctx, `SELECT email, name FROM app.users WHERE id = $1::uuid`, userID.String()).Scan(&email, &name)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Member{}, store.ErrNotFound
	}
	if err != nil {
		return store.Member{}, mapErr(err)
	}
	if err := exec(ctx, d.pool, `
INSERT INTO app.project_members (project_id, user_id, role, added_by, created_at)
VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5)
`, projectID.String(), userID.String(), role, addedBy.String(), at); err != nil {
		return store.Member{}, mapErr(err)
	}
	return store.Member{UserID: userID, Email: email, Name: name, Role: role, CreatedAt: at}, nil
}

func (d *DB) UpdateMemberRole(ctx context.Context, projectID, userID uuid.UUID, role string) (store.Member, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.Member{}, mapErr(err)
	}
	defer tx.Rollback(ctx)
	m, err := scanMember(tx.QueryRow(ctx, `
SELECT m.user_id::text, u.email, u.name, m.role, m.created_at
FROM app.project_members m
JOIN app.users u ON u.id = m.user_id
WHERE m.project_id = $1::uuid AND m.user_id = $2::uuid
FOR UPDATE OF m
`, projectID.String(), userID.String()))
	if err != nil {
		return store.Member{}, err
	}
	if m.Role == "owner" {
		return store.Member{}, store.ErrOwner
	}
	if err := exec(ctx, tx, `
UPDATE app.project_members
SET role = $3
WHERE project_id = $1::uuid AND user_id = $2::uuid
`, projectID.String(), userID.String(), role); err != nil {
		return store.Member{}, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return store.Member{}, mapErr(err)
	}
	m.Role = role
	return m, nil
}

func (d *DB) RemoveMember(ctx context.Context, projectID, userID uuid.UUID) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return mapErr(err)
	}
	defer tx.Rollback(ctx)
	var role string
	err = tx.QueryRow(ctx, `
SELECT role
FROM app.project_members
WHERE project_id = $1::uuid AND user_id = $2::uuid
FOR UPDATE
`, projectID.String(), userID.String()).Scan(&role)
	if err != nil {
		return mapErr(err)
	}
	if role == "owner" {
		return store.ErrOwner
	}
	if err := exec(ctx, tx, `
DELETE FROM app.project_members
WHERE project_id = $1::uuid AND user_id = $2::uuid
`, projectID.String(), userID.String()); err != nil {
		return mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapErr(err)
	}
	return nil
}

func (d *DB) TransferOwnership(ctx context.Context, projectID, newOwner uuid.UUID) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return mapErr(err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
SELECT user_id::text, role
FROM app.project_members
WHERE project_id = $1::uuid AND (user_id = $2::uuid OR role = 'owner')
FOR UPDATE
`, projectID.String(), newOwner.String())
	if err != nil {
		return mapErr(err)
	}
	foundTarget := false
	ownerID := ""
	for rows.Next() {
		var uid, role string
		if err := rows.Scan(&uid, &role); err != nil {
			rows.Close()
			return mapErr(err)
		}
		if uid == newOwner.String() {
			foundTarget = true
		}
		if role == "owner" {
			ownerID = uid
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return mapErr(err)
	}
	rows.Close()
	if !foundTarget {
		return store.ErrNotFound
	}
	if ownerID == "" {
		return store.ErrState
	}
	if err := exec(ctx, tx, `
UPDATE app.project_members
SET role = 'admin'
WHERE project_id = $1::uuid AND user_id = $2::uuid
`, projectID.String(), ownerID); err != nil {
		return mapErr(err)
	}
	if err := exec(ctx, tx, `
UPDATE app.project_members
SET role = 'owner'
WHERE project_id = $1::uuid AND user_id = $2::uuid
`, projectID.String(), newOwner.String()); err != nil {
		return mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapErr(err)
	}
	return nil
}

func scanProject(row pgx.Row) (store.Project, error) {
	var p store.Project
	var id, createdBy string
	if err := row.Scan(&id, &p.Name, &p.Slug, &p.Role, &createdBy, &p.CreatedAt); err != nil {
		return store.Project{}, mapErr(err)
	}
	var err error
	if p.ID, err = parseID(id); err != nil {
		return store.Project{}, err
	}
	if p.CreatedBy, err = parseID(createdBy); err != nil {
		return store.Project{}, err
	}
	return p, nil
}

func scanMember(row pgx.Row) (store.Member, error) {
	var m store.Member
	var id string
	if err := row.Scan(&id, &m.Email, &m.Name, &m.Role, &m.CreatedAt); err != nil {
		return store.Member{}, mapErr(err)
	}
	var err error
	if m.UserID, err = parseID(id); err != nil {
		return store.Member{}, err
	}
	return m, nil
}

func cutPage[T any](items []T, limit int, at func(T) time.Time, id func(T) string) ([]T, *store.Cursor, error) {
	if items == nil {
		items = []T{}
	}
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		c := &store.Cursor{At: at(last), ID: id(last)}
		return items, c, nil
	}
	return items, nil, nil
}
