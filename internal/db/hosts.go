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

func (d *DB) CreateJoinToken(ctx context.Context, projectID uuid.UUID, hash []byte, hint *string, createdBy uuid.UUID, expiresAt, at time.Time) (store.JoinToken, error) {
	id := uuid.New()
	tok, err := scanJoin(d.pool.QueryRow(ctx, `
INSERT INTO app.join_tokens (
    id, project_id, token_hash, host_name_hint, created_by, created_at, expires_at
)
SELECT $1::uuid, p.id, $2, $3, $4::uuid, $5, $6
FROM app.projects p
WHERE p.id = $7::uuid AND p.deleted_at IS NULL
RETURNING id::text, project_id::text, host_name_hint, created_by::text, created_at, expires_at,
          used_at, used_by_host_id::text, revoked_at
`, id.String(), hash, optString(hint), createdBy.String(), at, expiresAt, projectID.String()))
	if err != nil {
		return store.JoinToken{}, err
	}
	return tok, nil
}

func (d *DB) ListJoinTokens(ctx context.Context, projectID uuid.UUID, limit int, cursor *store.Cursor) ([]store.JoinToken, *store.Cursor, error) {
	lim := pageLimit(limit)
	var atArg any
	var idArg any
	if cursor != nil {
		atArg = cursor.At
		idArg = cursor.ID
	}
	rows, err := d.pool.Query(ctx, `
SELECT id::text, project_id::text, host_name_hint, created_by::text, created_at, expires_at,
       used_at, used_by_host_id::text, revoked_at
FROM app.join_tokens
WHERE project_id = $1::uuid
  AND (
    CAST($2 AS timestamptz) IS NULL
    OR (created_at, id) > (CAST($2 AS timestamptz), CAST($3 AS uuid))
  )
ORDER BY created_at ASC, id ASC
LIMIT $4
`, projectID.String(), atArg, idArg, lim+1)
	if err != nil {
		return nil, nil, mapErr(err)
	}
	defer rows.Close()
	items := []store.JoinToken{}
	for rows.Next() {
		tok, err := scanJoin(rows)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, tok)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, mapErr(err)
	}
	return cutPage(items, lim, func(t store.JoinToken) time.Time { return t.CreatedAt }, func(t store.JoinToken) string { return t.ID.String() })
}

func (d *DB) RevokeJoinToken(ctx context.Context, projectID, tokenID uuid.UUID, at time.Time) error {
	tag, err := d.pool.Exec(ctx, `
UPDATE app.join_tokens
SET revoked_at = COALESCE(revoked_at, $3)
WHERE id = $2::uuid AND project_id = $1::uuid
`, projectID.String(), tokenID.String(), at)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (d *DB) ConsumeJoinToken(ctx context.Context, tokenHash []byte, in store.EnrollInput, credentialID uuid.UUID, credentialHash []byte, at time.Time) (store.Host, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.Host{}, mapErr(err)
	}
	defer tx.Rollback(ctx)

	var tok store.JoinToken
	var idText, projectText string
	var stored []byte
	err = tx.QueryRow(ctx, `
SELECT id::text, project_id::text, token_hash, used_at, revoked_at, expires_at
FROM app.join_tokens
WHERE token_hash = $1
FOR UPDATE
`, tokenHash).Scan(&idText, &projectText, &stored, &tok.UsedAt, &tok.RevokedAt, &tok.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		secret.Equal(tokenHash, missHash)
		return store.Host{}, store.ErrUnauthorized
	}
	if err != nil {
		return store.Host{}, mapErr(err)
	}
	if !secret.Equal(tokenHash, stored) || tok.UsedAt != nil || tok.RevokedAt != nil || !at.Before(tok.ExpiresAt) {
		return store.Host{}, store.ErrUnauthorized
	}
	if tok.ID, err = parseID(idText); err != nil {
		return store.Host{}, err
	}
	if tok.ProjectID, err = parseID(projectText); err != nil {
		return store.Host{}, err
	}
	var deleted *time.Time
	err = tx.QueryRow(ctx, `SELECT deleted_at FROM app.projects WHERE id = $1::uuid`, tok.ProjectID.String()).Scan(&deleted)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && deleted != nil) {
		return store.Host{}, store.ErrUnauthorized
	}
	if err != nil {
		return store.Host{}, mapErr(err)
	}

	var takenErr error
	name, err := store.Unique(in.Name, 63, func(candidate string) bool {
		if takenErr != nil {
			return true
		}
		var exists bool
		qerr := tx.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM app.hosts WHERE project_id = $1::uuid AND name = $2)
`, tok.ProjectID.String(), candidate).Scan(&exists)
		if qerr != nil {
			takenErr = qerr
			return true
		}
		return exists
	})
	if takenErr != nil {
		return store.Host{}, mapErr(takenErr)
	}
	if err != nil {
		return store.Host{}, err
	}

	hostID := uuid.New()
	if _, err := tx.Exec(ctx, `SAVEPOINT host_name`); err != nil {
		return store.Host{}, mapErr(err)
	}
	n := 2
	for {
		_, err = tx.Exec(ctx, `
INSERT INTO app.hosts (
    id, project_id, name, node_type, os, arch, always_on, agent_version, last_seen_at, enrolled_at
) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $9)
`, hostID.String(), tok.ProjectID.String(), name, in.NodeType, in.OS, in.Arch, in.AlwaysOn, in.AgentVersion, at)
		if err == nil {
			break
		}
		if !isUnique(err) {
			return store.Host{}, mapErr(err)
		}
		if _, rerr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT host_name`); rerr != nil {
			return store.Host{}, mapErr(rerr)
		}
		if n >= 1000 {
			return store.Host{}, store.ErrConflict
		}
		name = store.WithSuffix(in.Name, n, 63)
		n++
	}
	if err := exec(ctx, tx, `
INSERT INTO app.agent_credentials (id, host_id, credential_hash, created_at)
VALUES ($1::uuid, $2::uuid, $3, $4)
`, credentialID.String(), hostID.String(), credentialHash, at); err != nil {
		return store.Host{}, mapErr(err)
	}
	if err := exec(ctx, tx, `
UPDATE app.join_tokens
SET used_at = $2, used_by_host_id = $3::uuid
WHERE id = $1::uuid
`, tok.ID.String(), at, hostID.String()); err != nil {
		return store.Host{}, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return store.Host{}, mapErr(err)
	}
	seen := at
	return store.Host{
		ID:           hostID,
		ProjectID:    tok.ProjectID,
		Name:         name,
		NodeType:     in.NodeType,
		OS:           in.OS,
		Arch:         in.Arch,
		AlwaysOn:     in.AlwaysOn,
		AgentVersion: in.AgentVersion,
		LastSeenAt:   &seen,
		EnrolledAt:   at,
	}, nil
}

func (d *DB) GetHost(ctx context.Context, id uuid.UUID) (store.Host, error) {
	return scanHost(d.pool.QueryRow(ctx, `
SELECT id::text, project_id::text, name, node_type, os, arch, always_on, agent_version,
       last_seen_at, enrolled_at, revoked_at, programs
FROM app.hosts
WHERE id = $1::uuid
`, id.String()))
}

func (d *DB) ListHosts(ctx context.Context, projectID uuid.UUID, limit int, cursor *store.Cursor) ([]store.Host, *store.Cursor, error) {
	lim := pageLimit(limit)
	var rankArg, nameArg, idArg any
	if cursor != nil && cursor.Rank != nil {
		rankArg = *cursor.Rank
		nameArg = cursor.Name
		idArg = cursor.ID
	}
	// Owned hosts (rank 0) come before shares (rank 1). Each group is name, id.
	// Name uses COLLATE "C" (byte order), matching memstore. Resume is the
	// same (rel_rank, name, id) comparison, with that collation on the name,
	// written out so the cursor predicate cannot fall back to the database
	// locale. A host that is no longer visible does not make it fail.
	rows, err := d.pool.Query(ctx, `
WITH visible AS (
    SELECT h.id, h.project_id, h.name, h.node_type, h.os, h.arch, h.always_on,
           h.agent_version, h.last_seen_at, h.enrolled_at, h.revoked_at, h.programs,
           0 AS rel_rank, NULL::text AS share_level
    FROM app.hosts h
    WHERE h.project_id = $1::uuid
    UNION ALL
    SELECT h.id, h.project_id, h.name, h.node_type, h.os, h.arch, h.always_on,
           h.agent_version, h.last_seen_at, h.enrolled_at, h.revoked_at, h.programs,
           1 AS rel_rank, s.level AS share_level
    FROM app.host_shares s
    JOIN app.hosts h ON h.id = s.host_id
    WHERE s.project_id = $1::uuid
      AND h.project_id <> $1::uuid
)
SELECT id::text, project_id::text, name, node_type, os, arch, always_on, agent_version,
       last_seen_at, enrolled_at, revoked_at, programs, rel_rank, share_level
FROM visible v
WHERE (
    CAST($2 AS int) IS NULL
    OR v.rel_rank > CAST($2 AS int)
    OR (
        v.rel_rank = CAST($2 AS int)
        AND (v.name COLLATE "C") > (CAST($3 AS text) COLLATE "C")
    )
    OR (
        v.rel_rank = CAST($2 AS int)
        AND (v.name COLLATE "C") = (CAST($3 AS text) COLLATE "C")
        AND v.id > CAST($4 AS uuid)
    )
)
ORDER BY v.rel_rank ASC, v.name COLLATE "C" ASC, v.id ASC
LIMIT $5
`, projectID.String(), rankArg, nameArg, idArg, lim+1)
	if err != nil {
		return nil, nil, mapErr(err)
	}
	defer rows.Close()
	items := []store.Host{}
	for rows.Next() {
		h, err := scanListedHost(rows)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, h)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, mapErr(err)
	}
	if len(items) > lim {
		items = items[:lim]
		last := items[len(items)-1]
		rank := 1
		if last.Relation == "owner" {
			rank = 0
		}
		return items, &store.Cursor{Rank: &rank, Name: last.Name, ID: last.ID.String()}, nil
	}
	if items == nil {
		items = []store.Host{}
	}
	return items, nil, nil
}

func scanListedHost(row pgx.Row) (store.Host, error) {
	var h store.Host
	var id, projectID string
	var programs []byte
	var rank int
	var level *string
	if err := row.Scan(
		&id, &projectID, &h.Name, &h.NodeType, &h.OS, &h.Arch, &h.AlwaysOn,
		&h.AgentVersion, &h.LastSeenAt, &h.EnrolledAt, &h.RevokedAt, &programs, &rank, &level,
	); err != nil {
		return store.Host{}, mapErr(err)
	}
	if err := applyPrograms(&h, programs); err != nil {
		return store.Host{}, err
	}
	var err error
	if h.ID, err = parseID(id); err != nil {
		return store.Host{}, err
	}
	if h.ProjectID, err = parseID(projectID); err != nil {
		return store.Host{}, err
	}
	if rank == 0 {
		h.Relation = "owner"
		return h, nil
	}
	h.Relation = "shared"
	h.ShareLevel = level
	return h, nil
}

func (d *DB) RevokeHost(ctx context.Context, hostID uuid.UUID, at time.Time) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return mapErr(err)
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `
UPDATE app.hosts
SET revoked_at = COALESCE(revoked_at, $2)
WHERE id = $1::uuid
`, hostID.String(), at)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	if err := exec(ctx, tx, `
UPDATE app.agent_credentials
SET revoked_at = $2
WHERE host_id = $1::uuid AND revoked_at IS NULL
`, hostID.String(), at); err != nil {
		return mapErr(err)
	}
	// Still-present rows go gone at the host's revoke time. A row that is
	// already gone keeps its time. A second revoke does not move it.
	if err := exec(ctx, tx, `
UPDATE app.services AS s
SET gone_at = h.revoked_at
FROM app.hosts AS h
WHERE s.host_id = h.id
  AND h.id = $1::uuid
  AND h.revoked_at IS NOT NULL
  AND s.gone_at IS NULL
`, hostID.String()); err != nil {
		return mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapErr(err)
	}
	return nil
}

func (d *DB) TouchHost(ctx context.Context, hostID uuid.UUID, at time.Time, version, osName, arch string) error {
	tag, err := d.pool.Exec(ctx, `
UPDATE app.hosts
SET last_seen_at = $2,
    agent_version = CASE WHEN $3 <> '' THEN $3 ELSE agent_version END,
    os = CASE WHEN $4 <> '' THEN $4 ELSE os END,
    arch = CASE WHEN $5 <> '' THEN $5 ELSE arch END
WHERE id = $1::uuid
`, hostID.String(), at, version, osName, arch)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (d *DB) LookupCredential(ctx context.Context, hash []byte) (store.Credential, store.Host, error) {
	var cred store.Credential
	var host store.Host
	var credID, hostID, projectID string
	var stored, programs []byte
	err := d.pool.QueryRow(ctx, `
SELECT c.id::text, c.host_id::text, c.credential_hash, c.revoked_at,
       h.project_id::text, h.name, h.node_type, h.os, h.arch, h.always_on,
       h.agent_version, h.last_seen_at, h.enrolled_at, h.revoked_at, h.programs
FROM app.agent_credentials c
JOIN app.hosts h ON h.id = c.host_id
WHERE c.credential_hash = $1
`, hash).Scan(
		&credID, &hostID, &stored, &cred.RevokedAt,
		&projectID, &host.Name, &host.NodeType, &host.OS, &host.Arch, &host.AlwaysOn,
		&host.AgentVersion, &host.LastSeenAt, &host.EnrolledAt, &host.RevokedAt, &programs,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		secret.Equal(hash, missHash)
		return store.Credential{}, store.Host{}, store.ErrUnauthorized
	}
	if err != nil {
		return store.Credential{}, store.Host{}, mapErr(err)
	}
	if !secret.Equal(hash, stored) {
		return store.Credential{}, store.Host{}, store.ErrUnauthorized
	}
	if cred.ID, err = parseID(credID); err != nil {
		return store.Credential{}, store.Host{}, err
	}
	if cred.HostID, err = parseID(hostID); err != nil {
		return store.Credential{}, store.Host{}, err
	}
	if host.ProjectID, err = parseID(projectID); err != nil {
		return store.Credential{}, store.Host{}, err
	}
	cred.Hash = stored
	host.ID = cred.HostID
	if err = applyPrograms(&host, programs); err != nil {
		return store.Credential{}, store.Host{}, err
	}
	return cred, host, nil
}

func scanJoin(row pgx.Row) (store.JoinToken, error) {
	var t store.JoinToken
	var id, projectID, createdBy string
	var usedBy *string
	if err := row.Scan(&id, &projectID, &t.HostNameHint, &createdBy, &t.CreatedAt, &t.ExpiresAt, &t.UsedAt, &usedBy, &t.RevokedAt); err != nil {
		return store.JoinToken{}, mapErr(err)
	}
	var err error
	if t.ID, err = parseID(id); err != nil {
		return store.JoinToken{}, err
	}
	if t.ProjectID, err = parseID(projectID); err != nil {
		return store.JoinToken{}, err
	}
	if t.CreatedBy, err = parseID(createdBy); err != nil {
		return store.JoinToken{}, err
	}
	if t.UsedByHostID, err = parseOptID(usedBy); err != nil {
		return store.JoinToken{}, err
	}
	return t, nil
}

func scanHost(row pgx.Row) (store.Host, error) {
	var h store.Host
	var id, projectID string
	var programs []byte
	if err := row.Scan(
		&id, &projectID, &h.Name, &h.NodeType, &h.OS, &h.Arch, &h.AlwaysOn,
		&h.AgentVersion, &h.LastSeenAt, &h.EnrolledAt, &h.RevokedAt, &programs,
	); err != nil {
		return store.Host{}, mapErr(err)
	}
	if err := applyPrograms(&h, programs); err != nil {
		return store.Host{}, err
	}
	var err error
	if h.ID, err = parseID(id); err != nil {
		return store.Host{}, err
	}
	if h.ProjectID, err = parseID(projectID); err != nil {
		return store.Host{}, err
	}
	return h, nil
}
