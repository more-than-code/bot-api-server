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

func (d *DB) CreateInvite(ctx context.Context, projectID uuid.UUID, hash []byte, role string, createdBy uuid.UUID, expiresAt, at time.Time, maxUses int) (store.Invite, error) {
	id := uuid.New()
	inv, err := scanInvite(d.pool.QueryRow(ctx, `
INSERT INTO app.invites (
    id, project_id, token_hash, role, created_by, created_at, expires_at, max_uses
)
SELECT $1::uuid, p.id, $2, $3, $4::uuid, $5, $6, $7
FROM app.projects p
WHERE p.id = $8::uuid AND p.deleted_at IS NULL
RETURNING id::text, project_id::text, role, created_by::text, created_at, expires_at, max_uses, uses, revoked_at
`, id.String(), hash, role, createdBy.String(), at, expiresAt, maxUses, projectID.String()))
	if err != nil {
		return store.Invite{}, err
	}
	return inv, nil
}

func (d *DB) ListInvites(ctx context.Context, projectID uuid.UUID, limit int, cursor *store.Cursor) ([]store.Invite, *store.Cursor, error) {
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
SELECT id::text, project_id::text, role, created_by::text, created_at, expires_at, max_uses, uses, revoked_at
FROM app.invites
WHERE project_id = $1::uuid
  AND (
    CAST($2 AS timestamptz) IS NULL
    OR (created_at, id) < (CAST($2 AS timestamptz), CAST($3 AS uuid))
  )
ORDER BY created_at DESC, id DESC
LIMIT $4
`, projectID.String(), atArg, idArg, lim+1)
	if err != nil {
		return nil, nil, mapErr(err)
	}
	defer rows.Close()
	items := []store.Invite{}
	for rows.Next() {
		inv, err := scanInvite(rows)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, inv)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, mapErr(err)
	}
	return cutPage(items, lim, func(inv store.Invite) time.Time { return inv.CreatedAt }, func(inv store.Invite) string { return inv.ID.String() })
}

func (d *DB) RevokeInvite(ctx context.Context, projectID, inviteID uuid.UUID, at time.Time) error {
	tag, err := d.pool.Exec(ctx, `
UPDATE app.invites
SET revoked_at = COALESCE(revoked_at, $3)
WHERE id = $2::uuid AND project_id = $1::uuid
`, projectID.String(), inviteID.String(), at)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (d *DB) LookupInvite(ctx context.Context, tokenHash []byte, userID uuid.UUID, at time.Time) (store.InviteLookup, error) {
	inv, stored, err := readInvite(ctx, d.pool, tokenHash)
	if err != nil {
		return store.InviteLookup{}, err
	}
	if !secret.Equal(tokenHash, stored) || !store.InviteUsable(inv, at) {
		return store.InviteLookup{}, store.ErrNotFound
	}
	var name string
	err = d.pool.QueryRow(ctx, `
SELECT name FROM app.projects WHERE id = $1::uuid AND deleted_at IS NULL
`, inv.ProjectID.String()).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.InviteLookup{}, store.ErrNotFound
	}
	if err != nil {
		return store.InviteLookup{}, mapErr(err)
	}
	var member bool
	if err := d.pool.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1 FROM app.project_members WHERE project_id = $1::uuid AND user_id = $2::uuid
)
`, inv.ProjectID.String(), userID.String()).Scan(&member); err != nil {
		return store.InviteLookup{}, mapErr(err)
	}
	return store.InviteLookup{
		ProjectID:     inv.ProjectID,
		ProjectName:   name,
		Role:          inv.Role,
		AlreadyMember: member,
	}, nil
}

func (d *DB) AcceptInvite(ctx context.Context, tokenHash []byte, userID uuid.UUID, at time.Time) (store.InviteAccept, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.InviteAccept{}, mapErr(err)
	}
	defer tx.Rollback(ctx)

	// Touch uses, which deploybot_api may update, so the row stays locked
	// until this transaction ends. SELECT FOR UPDATE would also require
	// UPDATE on every column the statement returns.
	inv, stored, err := lockInvite(ctx, tx, tokenHash)
	if err != nil {
		return store.InviteAccept{}, err
	}
	if !secret.Equal(tokenHash, stored) || !store.InviteUsable(inv, at) {
		return store.InviteAccept{}, store.ErrNotFound
	}
	var alive bool
	if err := tx.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM app.projects WHERE id = $1::uuid AND deleted_at IS NULL)
`, inv.ProjectID.String()).Scan(&alive); err != nil {
		return store.InviteAccept{}, mapErr(err)
	}
	if !alive {
		return store.InviteAccept{}, store.ErrNotFound
	}
	var current string
	err = tx.QueryRow(ctx, `
SELECT role FROM app.project_members WHERE project_id = $1::uuid AND user_id = $2::uuid
`, inv.ProjectID.String(), userID.String()).Scan(&current)
	if err == nil {
		return store.InviteAccept{InviteID: inv.ID, ProjectID: inv.ProjectID, Role: current}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return store.InviteAccept{}, mapErr(err)
	}
	var userExists bool
	if err := tx.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM app.users WHERE id = $1::uuid)
`, userID.String()).Scan(&userExists); err != nil {
		return store.InviteAccept{}, mapErr(err)
	}
	if !userExists {
		return store.InviteAccept{}, store.ErrNotFound
	}
	tag, err := tx.Exec(ctx, `
INSERT INTO app.project_members (project_id, user_id, role, added_by, created_at)
VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5)
ON CONFLICT (project_id, user_id) DO NOTHING
`, inv.ProjectID.String(), userID.String(), inv.Role, inv.CreatedBy.String(), at)
	if err != nil {
		return store.InviteAccept{}, mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		if err := tx.QueryRow(ctx, `
SELECT role FROM app.project_members WHERE project_id = $1::uuid AND user_id = $2::uuid
`, inv.ProjectID.String(), userID.String()).Scan(&current); err != nil {
			return store.InviteAccept{}, mapErr(err)
		}
		return store.InviteAccept{InviteID: inv.ID, ProjectID: inv.ProjectID, Role: current}, nil
	}
	tag, err = tx.Exec(ctx, `
UPDATE app.invites
SET uses = uses + 1
WHERE id = $1::uuid AND uses < max_uses
`, inv.ID.String())
	if err != nil {
		return store.InviteAccept{}, mapErr(err)
	}
	if tag.RowsAffected() != 1 {
		return store.InviteAccept{}, store.ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return store.InviteAccept{}, mapErr(err)
	}
	return store.InviteAccept{InviteID: inv.ID, ProjectID: inv.ProjectID, Role: inv.Role}, nil
}

// lockInvite rewrites uses to its current value so the row lock is an
// update of a column the runtime role may write.
func lockInvite(ctx context.Context, tx pgx.Tx, tokenHash []byte) (store.Invite, []byte, error) {
	row := tx.QueryRow(ctx, `
UPDATE app.invites
SET uses = uses
WHERE token_hash = $1
RETURNING id::text, project_id::text, token_hash, role, created_by::text,
          created_at, expires_at, max_uses, uses, revoked_at
`, tokenHash)
	return scanInviteHash(tokenHash, row)
}

func readInvite(ctx context.Context, q queryer, tokenHash []byte) (store.Invite, []byte, error) {
	row := q.QueryRow(ctx, `
SELECT id::text, project_id::text, token_hash, role, created_by::text,
       created_at, expires_at, max_uses, uses, revoked_at
FROM app.invites
WHERE token_hash = $1
`, tokenHash)
	return scanInviteHash(tokenHash, row)
}

func scanInviteHash(tokenHash []byte, row pgx.Row) (store.Invite, []byte, error) {
	var inv store.Invite
	var id, project, createdBy string
	var stored []byte
	err := row.Scan(
		&id, &project, &stored, &inv.Role, &createdBy,
		&inv.CreatedAt, &inv.ExpiresAt, &inv.MaxUses, &inv.Uses, &inv.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		secret.Equal(tokenHash, missHash)
		return store.Invite{}, nil, store.ErrNotFound
	}
	if err != nil {
		return store.Invite{}, nil, mapErr(err)
	}
	if inv.ID, err = parseID(id); err != nil {
		return store.Invite{}, nil, err
	}
	if inv.ProjectID, err = parseID(project); err != nil {
		return store.Invite{}, nil, err
	}
	if inv.CreatedBy, err = parseID(createdBy); err != nil {
		return store.Invite{}, nil, err
	}
	return inv, stored, nil
}

func scanInvite(row pgx.Row) (store.Invite, error) {
	var inv store.Invite
	var id, project, createdBy string
	err := row.Scan(
		&id, &project, &inv.Role, &createdBy,
		&inv.CreatedAt, &inv.ExpiresAt, &inv.MaxUses, &inv.Uses, &inv.RevokedAt,
	)
	if err != nil {
		return store.Invite{}, mapErr(err)
	}
	if inv.ID, err = parseID(id); err != nil {
		return store.Invite{}, err
	}
	if inv.ProjectID, err = parseID(project); err != nil {
		return store.Invite{}, err
	}
	if inv.CreatedBy, err = parseID(createdBy); err != nil {
		return store.Invite{}, err
	}
	return inv, nil
}
