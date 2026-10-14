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

func textArray(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func optText(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (d *DB) PutOAuthClient(ctx context.Context, c store.OAuthClient) error {
	uris := textArray(c.RedirectURIs)
	grants := textArray(c.GrantTypes)
	responses := textArray(c.ResponseTypes)
	if c.Kind == store.ClientInternal {
		_, err := d.pool.Exec(ctx, `
INSERT INTO app.oauth_clients (
    id, name, redirect_uris, grant_types, response_types, token_endpoint_auth_method, secret_hash, kind, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, 'internal', $8)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method,
    secret_hash = EXCLUDED.secret_hash
WHERE app.oauth_clients.kind = 'internal'
`, c.ID, c.Name, uris, grants, responses, c.AuthMethod, c.SecretHash, c.CreatedAt)
		return mapErr(err)
	}
	err := exec(ctx, d.pool, `
INSERT INTO app.oauth_clients (
    id, name, redirect_uris, grant_types, response_types, token_endpoint_auth_method, kind, created_at
) VALUES ($1, $2, $3, $4, $5, $6, 'public', $7)
`, c.ID, c.Name, uris, grants, responses, c.AuthMethod, c.CreatedAt)
	return mapErr(err)
}

func (d *DB) GetOAuthClient(ctx context.Context, id string) (store.OAuthClient, error) {
	var c store.OAuthClient
	err := d.pool.QueryRow(ctx, `
SELECT id, name, redirect_uris, grant_types, response_types, token_endpoint_auth_method,
       secret_hash, kind, created_at, last_used_at
FROM app.oauth_clients
WHERE id = $1
`, id).Scan(&c.ID, &c.Name, &c.RedirectURIs, &c.GrantTypes, &c.ResponseTypes, &c.AuthMethod,
		&c.SecretHash, &c.Kind, &c.CreatedAt, &c.LastUsedAt)
	if err != nil {
		return store.OAuthClient{}, mapErr(err)
	}
	return c, nil
}

func (d *DB) TouchOAuthClient(ctx context.Context, id string, at time.Time) error {
	return mapErr(exec(ctx, d.pool, `UPDATE app.oauth_clients SET last_used_at = $2 WHERE id = $1`, id, at))
}

func (d *DB) DeleteStalePublicClients(ctx context.Context, before time.Time) error {
	return mapErr(exec(ctx, d.pool, `
DELETE FROM app.oauth_clients
WHERE kind = 'public' AND COALESCE(last_used_at, created_at) < $1
`, before))
}

func (d *DB) InsertOAuthRequest(ctx context.Context, req store.OAuthRequest) error {
	return mapErr(exec(ctx, d.pool, `
INSERT INTO app.oauth_requests (
    id, client_id, redirect_uri, code_challenge, state, resource, scope, created_at, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
`, req.ID, req.ClientID, req.RedirectURI, req.Challenge, req.State, req.Resource, req.Scope, req.CreatedAt, req.ExpiresAt))
}

func (d *DB) GetOAuthRequest(ctx context.Context, id string) (store.OAuthRequest, error) {
	var req store.OAuthRequest
	var userText *string
	var decision *string
	err := d.pool.QueryRow(ctx, `
SELECT id, client_id, redirect_uri, code_challenge, state, resource, scope, created_at, expires_at,
       decided_at, decision, user_id::text
FROM app.oauth_requests
WHERE id = $1
`, id).Scan(&req.ID, &req.ClientID, &req.RedirectURI, &req.Challenge, &req.State, &req.Resource, &req.Scope,
		&req.CreatedAt, &req.ExpiresAt, &req.DecidedAt, &decision, &userText)
	if err != nil {
		return store.OAuthRequest{}, mapErr(err)
	}
	if decision != nil {
		req.Decision = *decision
	}
	var errID error
	req.UserID, errID = parseOptID(userText)
	if errID != nil {
		return store.OAuthRequest{}, errID
	}
	return req, nil
}

func (d *DB) ApproveOAuth(ctx context.Context, in store.ApproveCode) (store.OAuthGrant, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.OAuthGrant{}, mapErr(err)
	}
	defer tx.Rollback(ctx)
	req, err := lockRequest(ctx, tx, in.RequestID)
	if err != nil {
		return store.OAuthGrant{}, err
	}
	if req.DecidedAt != nil || !in.At.Before(req.ExpiresAt) {
		return store.OAuthGrant{}, store.ErrNotFound
	}
	grant, err := liveOAuthGrant(ctx, tx, in.UserID, req.ClientID, req.Resource)
	if errors.Is(err, store.ErrNotFound) {
		grant, err = insertGrant(ctx, tx, store.OAuthGrant{
			ID:           uuid.New(),
			UserID:       in.UserID,
			ClientID:     req.ClientID,
			Resource:     req.Resource,
			RedirectHost: in.RedirectHost,
			Kind:         store.GrantKindOAuth,
			CreatedAt:    in.At,
		})
	} else if err == nil {
		_, err = tx.Exec(ctx, `
UPDATE app.oauth_grants SET redirect_host = $2, last_used_at = $3 WHERE id = $1::uuid
`, grant.ID.String(), in.RedirectHost, in.At)
		grant.RedirectHost = in.RedirectHost
		grant.LastUsedAt = &in.At
	}
	if err != nil {
		return store.OAuthGrant{}, err
	}
	if err := insertCode(ctx, tx, store.OAuthCode{
		ID:          uuid.New(),
		Hash:        in.CodeHash,
		ClientID:    req.ClientID,
		RedirectURI: req.RedirectURI,
		Challenge:   req.Challenge,
		Resource:    req.Resource,
		UserID:      in.UserID,
		GrantID:     grant.ID,
		CreatedAt:   in.At,
		ExpiresAt:   in.CodeExpires,
	}); err != nil {
		return store.OAuthGrant{}, err
	}
	tag, err := tx.Exec(ctx, `
UPDATE app.oauth_requests
SET decided_at = $2, decision = 'allow', user_id = $3::uuid
WHERE id = $1 AND decided_at IS NULL
`, in.RequestID, in.At, in.UserID.String())
	if err != nil {
		return store.OAuthGrant{}, mapErr(err)
	}
	if tag.RowsAffected() != 1 {
		return store.OAuthGrant{}, store.ErrNotFound
	}
	if err := exec(ctx, tx, `UPDATE app.oauth_clients SET last_used_at = $2 WHERE id = $1`, req.ClientID, in.At); err != nil {
		return store.OAuthGrant{}, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return store.OAuthGrant{}, mapErr(err)
	}
	return grant, nil
}

func (d *DB) DenyOAuth(ctx context.Context, requestID string, userID uuid.UUID, at time.Time) (store.OAuthRequest, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.OAuthRequest{}, mapErr(err)
	}
	defer tx.Rollback(ctx)
	req, err := lockRequest(ctx, tx, requestID)
	if err != nil {
		return store.OAuthRequest{}, err
	}
	if req.DecidedAt != nil || !at.Before(req.ExpiresAt) {
		return store.OAuthRequest{}, store.ErrNotFound
	}
	tag, err := tx.Exec(ctx, `
UPDATE app.oauth_requests
SET decided_at = $2, decision = 'deny', user_id = $3::uuid
WHERE id = $1 AND decided_at IS NULL
`, requestID, at, userID.String())
	if err != nil {
		return store.OAuthRequest{}, mapErr(err)
	}
	if tag.RowsAffected() != 1 {
		return store.OAuthRequest{}, store.ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return store.OAuthRequest{}, mapErr(err)
	}
	req.DecidedAt = &at
	req.Decision = "deny"
	req.UserID = &userID
	return req, nil
}

func lockRequest(ctx context.Context, tx pgx.Tx, id string) (store.OAuthRequest, error) {
	var req store.OAuthRequest
	var userText *string
	var decision *string
	err := tx.QueryRow(ctx, `
SELECT id, client_id, redirect_uri, code_challenge, state, resource, scope, created_at, expires_at,
       decided_at, decision, user_id::text
FROM app.oauth_requests
WHERE id = $1
FOR UPDATE
`, id).Scan(&req.ID, &req.ClientID, &req.RedirectURI, &req.Challenge, &req.State, &req.Resource, &req.Scope,
		&req.CreatedAt, &req.ExpiresAt, &req.DecidedAt, &decision, &userText)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.OAuthRequest{}, store.ErrNotFound
	}
	if err != nil {
		return store.OAuthRequest{}, mapErr(err)
	}
	if decision != nil {
		req.Decision = *decision
	}
	req.UserID, err = parseOptID(userText)
	if err != nil {
		return store.OAuthRequest{}, err
	}
	return req, nil
}

func (d *DB) FindLiveGrant(ctx context.Context, userID uuid.UUID, clientID, resource string) (store.OAuthGrant, error) {
	return liveOAuthGrant(ctx, d.pool, userID, clientID, resource)
}

func liveOAuthGrant(ctx context.Context, q queryer, userID uuid.UUID, clientID, resource string) (store.OAuthGrant, error) {
	row := q.QueryRow(ctx, `
SELECT g.id::text, g.user_id::text, g.client_id, c.name, g.resource, g.redirect_host, g.kind,
       g.created_at, g.last_used_at, g.revoked_at
FROM app.oauth_grants g
JOIN app.oauth_clients c ON c.id = g.client_id
WHERE g.user_id = $1::uuid AND g.client_id = $2 AND g.resource = $3
  AND g.revoked_at IS NULL AND g.kind = 'oauth'
`, userID.String(), clientID, resource)
	return scanGrant(row)
}

func insertGrant(ctx context.Context, q queryer, g store.OAuthGrant) (store.OAuthGrant, error) {
	_, err := q.Exec(ctx, `
INSERT INTO app.oauth_grants (
    id, user_id, client_id, resource, redirect_host, kind, created_at, last_used_at
) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8)
`, g.ID.String(), g.UserID.String(), g.ClientID, g.Resource, g.RedirectHost, g.Kind, g.CreatedAt, optTime(g.LastUsedAt))
	if err != nil {
		if isUnique(err) {
			return liveOAuthGrant(ctx, q, g.UserID, g.ClientID, g.Resource)
		}
		return store.OAuthGrant{}, mapErr(err)
	}
	var name string
	if err := q.QueryRow(ctx, `SELECT name FROM app.oauth_clients WHERE id = $1`, g.ClientID).Scan(&name); err != nil {
		return store.OAuthGrant{}, mapErr(err)
	}
	g.ClientName = name
	return g, nil
}

func scanGrant(row pgx.Row) (store.OAuthGrant, error) {
	var g store.OAuthGrant
	var idText, userText string
	err := row.Scan(&idText, &userText, &g.ClientID, &g.ClientName, &g.Resource, &g.RedirectHost, &g.Kind,
		&g.CreatedAt, &g.LastUsedAt, &g.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.OAuthGrant{}, store.ErrNotFound
	}
	if err != nil {
		return store.OAuthGrant{}, mapErr(err)
	}
	if g.ID, err = parseID(idText); err != nil {
		return store.OAuthGrant{}, err
	}
	if g.UserID, err = parseID(userText); err != nil {
		return store.OAuthGrant{}, err
	}
	return g, nil
}

func (d *DB) ListUserGrants(ctx context.Context, userID uuid.UUID) ([]store.OAuthGrant, error) {
	rows, err := d.pool.Query(ctx, `
SELECT g.id::text, g.user_id::text, g.client_id, c.name, g.resource, g.redirect_host, g.kind,
       g.created_at, g.last_used_at, g.revoked_at
FROM app.oauth_grants g
JOIN app.oauth_clients c ON c.id = g.client_id
WHERE g.user_id = $1::uuid AND g.revoked_at IS NULL
ORDER BY g.created_at DESC, g.id DESC
`, userID.String())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.OAuthGrant{}
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (d *DB) RevokeUserGrant(ctx context.Context, userID, grantID uuid.UUID, at time.Time) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return mapErr(err)
	}
	defer tx.Rollback(ctx)
	var owner string
	var revoked *time.Time
	err = tx.QueryRow(ctx, `
SELECT user_id::text, revoked_at FROM app.oauth_grants WHERE id = $1::uuid FOR UPDATE
`, grantID.String()).Scan(&owner, &revoked)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (owner != userID.String() || revoked != nil)) {
		return store.ErrNotFound
	}
	if err != nil {
		return mapErr(err)
	}
	if err := revokeFamily(ctx, tx, grantID, at); err != nil {
		return err
	}
	return mapErr(tx.Commit(ctx))
}

func revokeFamily(ctx context.Context, q queryer, grantID uuid.UUID, at time.Time) error {
	if err := exec(ctx, q, `
UPDATE app.oauth_grants SET revoked_at = $2 WHERE id = $1::uuid AND revoked_at IS NULL
`, grantID.String(), at); err != nil {
		return mapErr(err)
	}
	return mapErr(exec(ctx, q, `
UPDATE app.sessions SET expires_at = $2 WHERE grant_id = $1::uuid AND expires_at > $2
`, grantID.String(), at))
}

func insertCode(ctx context.Context, q queryer, c store.OAuthCode) error {
	return mapErr(exec(ctx, q, `
INSERT INTO app.oauth_codes (
    id, code_hash, client_id, redirect_uri, code_challenge, resource, user_id, grant_id, created_at, expires_at
) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::uuid, $8::uuid, $9, $10)
`, c.ID.String(), c.Hash, c.ClientID, c.RedirectURI, c.Challenge, c.Resource, c.UserID.String(), c.GrantID.String(), c.CreatedAt, c.ExpiresAt))
}

func (d *DB) PeekOAuthCode(ctx context.Context, hash []byte) (store.OAuthCode, error) {
	code, err := loadCode(ctx, d.pool, hash, false)
	if err != nil {
		return store.OAuthCode{}, err
	}
	if !secret.Equal(hash, code.Hash) {
		return store.OAuthCode{}, store.ErrNotFound
	}
	return code, nil
}

func loadCode(ctx context.Context, q queryer, hash []byte, lock bool) (store.OAuthCode, error) {
	sql := `
SELECT id::text, code_hash, client_id, redirect_uri, code_challenge, resource, user_id::text, grant_id::text,
       created_at, expires_at, used_at
FROM app.oauth_codes
WHERE code_hash = $1`
	if lock {
		sql += ` FOR UPDATE`
	}
	var c store.OAuthCode
	var idText, userText, grantText string
	err := q.QueryRow(ctx, sql, hash).Scan(&idText, &c.Hash, &c.ClientID, &c.RedirectURI, &c.Challenge, &c.Resource,
		&userText, &grantText, &c.CreatedAt, &c.ExpiresAt, &c.UsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		secret.Equal(hash, missHash)
		return store.OAuthCode{}, store.ErrNotFound
	}
	if err != nil {
		return store.OAuthCode{}, mapErr(err)
	}
	if c.ID, err = parseID(idText); err != nil {
		return store.OAuthCode{}, err
	}
	if c.UserID, err = parseID(userText); err != nil {
		return store.OAuthCode{}, err
	}
	if c.GrantID, err = parseID(grantText); err != nil {
		return store.OAuthCode{}, err
	}
	return c, nil
}

func (d *DB) RedeemOAuthCode(ctx context.Context, in store.RedeemCode) (store.Session, store.Session, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.Session{}, store.Session{}, mapErr(err)
	}
	defer tx.Rollback(ctx)
	code, err := loadCode(ctx, tx, in.Hash, true)
	if err != nil {
		return store.Session{}, store.Session{}, err
	}
	if !secret.Equal(in.Hash, code.Hash) {
		return store.Session{}, store.Session{}, store.ErrNotFound
	}
	if code.UsedAt != nil {
		if err := revokeFamily(ctx, tx, code.GrantID, in.At); err != nil {
			return store.Session{}, store.Session{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return store.Session{}, store.Session{}, mapErr(err)
		}
		return store.Session{}, store.Session{}, store.ErrReuse
	}
	if !in.At.Before(code.ExpiresAt) {
		return store.Session{}, store.Session{}, store.ErrExpired
	}
	if code.Resource != in.Resource {
		return store.Session{}, store.Session{}, store.ErrTarget
	}
	if code.ClientID != in.ClientID || code.RedirectURI != in.RedirectURI {
		return store.Session{}, store.Session{}, store.ErrInvalid
	}
	tag, err := tx.Exec(ctx, `UPDATE app.oauth_codes SET used_at = $2 WHERE id = $1::uuid AND used_at IS NULL`, code.ID.String(), in.At)
	if err != nil {
		return store.Session{}, store.Session{}, mapErr(err)
	}
	if tag.RowsAffected() != 1 {
		return store.Session{}, store.Session{}, store.ErrReuse
	}
	codeID := code.ID
	grantID := code.GrantID
	access, err := insertBound(ctx, tx, store.BoundSession{
		UserID: code.UserID, TokenHash: in.AccessHash, Kind: store.KindMCPAccess,
		ExpiresAt: in.AccessExpires, At: in.At, Audience: in.Audience,
		GrantID: &grantID, ClientID: code.ClientID, CodeID: &codeID,
	})
	if err != nil {
		return store.Session{}, store.Session{}, err
	}
	refresh, err := insertBound(ctx, tx, store.BoundSession{
		UserID: code.UserID, TokenHash: in.RefreshHash, Kind: store.KindMCPRefresh,
		ExpiresAt: in.RefreshExpires, At: in.At, Audience: in.Audience,
		GrantID: &grantID, ClientID: code.ClientID, CodeID: &codeID,
	})
	if err != nil {
		return store.Session{}, store.Session{}, err
	}
	if err := touchFamily(ctx, tx, grantID, code.ClientID, in.At); err != nil {
		return store.Session{}, store.Session{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return store.Session{}, store.Session{}, mapErr(err)
	}
	return access, refresh, nil
}

func touchFamily(ctx context.Context, q queryer, grantID uuid.UUID, clientID string, at time.Time) error {
	if err := exec(ctx, q, `UPDATE app.oauth_grants SET last_used_at = $2 WHERE id = $1::uuid`, grantID.String(), at); err != nil {
		return mapErr(err)
	}
	return mapErr(exec(ctx, q, `UPDATE app.oauth_clients SET last_used_at = $2 WHERE id = $1`, clientID, at))
}

func (d *DB) RotateRefresh(ctx context.Context, in store.RotateRefresh) (store.Session, store.Session, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.Session{}, store.Session{}, mapErr(err)
	}
	defer tx.Rollback(ctx)
	var sessID, userID, kind string
	var clientPtr *string
	var grantText *string
	var stored []byte
	var expires time.Time
	var rotated, revoked, disabled *time.Time
	var resource *string
	err = tx.QueryRow(ctx, `
SELECT s.id::text, s.user_id::text, s.kind, s.expires_at, s.client_id, s.grant_id::text, s.rotated_at, s.token_hash,
       g.resource, g.revoked_at, u.disabled_at
FROM app.sessions s
JOIN app.users u ON u.id = s.user_id
LEFT JOIN app.oauth_grants g ON g.id = s.grant_id
WHERE s.token_hash = $1
FOR UPDATE OF s
`, in.Hash).Scan(&sessID, &userID, &kind, &expires, &clientPtr, &grantText, &rotated, &stored, &resource, &revoked, &disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		secret.Equal(in.Hash, missHash)
		return store.Session{}, store.Session{}, store.ErrNotFound
	}
	if err != nil {
		return store.Session{}, store.Session{}, mapErr(err)
	}
	clientID := ""
	if clientPtr != nil {
		clientID = *clientPtr
	}
	if !secret.Equal(in.Hash, stored) || kind != store.KindMCPRefresh || clientID != in.ClientID || disabled != nil {
		return store.Session{}, store.Session{}, store.ErrInvalid
	}
	grantID, err := parseOptID(grantText)
	if err != nil {
		return store.Session{}, store.Session{}, err
	}
	if grantID == nil {
		return store.Session{}, store.Session{}, store.ErrInvalid
	}
	if rotated != nil {
		if err := revokeFamily(ctx, tx, *grantID, in.At); err != nil {
			return store.Session{}, store.Session{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return store.Session{}, store.Session{}, mapErr(err)
		}
		uid, err := parseID(userID)
		if err != nil {
			return store.Session{}, store.Session{}, err
		}
		return store.Session{UserID: uid, GrantID: grantID}, store.Session{}, store.ErrReuse
	}
	if !in.At.Before(expires) || revoked != nil {
		return store.Session{}, store.Session{}, store.ErrInvalid
	}
	if in.ResourceSet && (resource == nil || *resource != in.Resource) {
		return store.Session{}, store.Session{}, store.ErrTarget
	}
	if _, err := tx.Exec(ctx, `
UPDATE app.sessions SET rotated_at = $2, expires_at = $2 WHERE id = $1::uuid
`, sessID, in.At); err != nil {
		return store.Session{}, store.Session{}, mapErr(err)
	}
	uid, err := parseID(userID)
	if err != nil {
		return store.Session{}, store.Session{}, err
	}
	access, err := insertBound(ctx, tx, store.BoundSession{
		UserID: uid, TokenHash: in.AccessHash, Kind: store.KindMCPAccess,
		ExpiresAt: in.AccessExpires, At: in.At, Audience: in.Audience,
		GrantID: grantID, ClientID: clientID,
	})
	if err != nil {
		return store.Session{}, store.Session{}, err
	}
	refresh, err := insertBound(ctx, tx, store.BoundSession{
		UserID: uid, TokenHash: in.RefreshHash, Kind: store.KindMCPRefresh,
		ExpiresAt: in.RefreshExpires, At: in.At, Audience: in.Audience,
		GrantID: grantID, ClientID: clientID,
	})
	if err != nil {
		return store.Session{}, store.Session{}, err
	}
	if err := touchFamily(ctx, tx, *grantID, clientID, in.At); err != nil {
		return store.Session{}, store.Session{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return store.Session{}, store.Session{}, mapErr(err)
	}
	return access, refresh, nil
}

func (d *DB) IssueDelegated(ctx context.Context, in store.IssueDelegated) (store.Session, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.Session{}, mapErr(err)
	}
	defer tx.Rollback(ctx)
	var sessID, userText, kind string
	var clientPtr, audience *string
	var grantText *string
	var stored []byte
	var expires time.Time
	var rotated, revoked, disabled *time.Time
	err = tx.QueryRow(ctx, `
SELECT s.id::text, s.user_id::text, s.kind, s.expires_at, s.audience, s.client_id, s.grant_id::text,
       s.rotated_at, s.token_hash, g.revoked_at, u.disabled_at
FROM app.sessions s
JOIN app.users u ON u.id = s.user_id
LEFT JOIN app.oauth_grants g ON g.id = s.grant_id
WHERE s.token_hash = $1
FOR UPDATE OF s
`, in.SubjectHash).Scan(&sessID, &userText, &kind, &expires, &audience, &clientPtr, &grantText, &rotated, &stored, &revoked, &disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		secret.Equal(in.SubjectHash, missHash)
		return store.Session{}, store.ErrUnauthorized
	}
	if err != nil {
		return store.Session{}, mapErr(err)
	}
	grantID, err := parseOptID(grantText)
	if err != nil {
		return store.Session{}, err
	}
	aud := ""
	if audience != nil {
		aud = *audience
	}
	clientID := ""
	if clientPtr != nil {
		clientID = *clientPtr
	}
	if !secret.Equal(in.SubjectHash, stored) || kind != store.KindMCPAccess || aud != in.SubjectAudience ||
		!in.At.Before(expires) || rotated != nil || revoked != nil || disabled != nil || grantID == nil || clientID == "" {
		return store.Session{}, store.ErrUnauthorized
	}
	uid, err := parseID(userText)
	if err != nil {
		return store.Session{}, err
	}
	sess, err := insertBound(ctx, tx, store.BoundSession{
		UserID: uid, TokenHash: in.TokenHash, Kind: store.KindDelegated,
		ExpiresAt: in.ExpiresAt, At: in.At, Audience: in.Audience,
		GrantID: grantID, ClientID: clientID,
	})
	if err != nil {
		return store.Session{}, err
	}
	if err := touchFamily(ctx, tx, *grantID, clientID, in.At); err != nil {
		return store.Session{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return store.Session{}, mapErr(err)
	}
	return sess, nil
}

func (d *DB) IssueDeviceAccess(ctx context.Context, in store.IssueDevice) (store.Session, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.Session{}, mapErr(err)
	}
	defer tx.Rollback(ctx)
	if err := ensureDeviceClient(ctx, tx, in.At); err != nil {
		return store.Session{}, err
	}
	grantID := uuid.New()
	if _, err := insertGrant(ctx, tx, store.OAuthGrant{
		ID: grantID, UserID: in.UserID, ClientID: store.ClientDevice, Resource: in.Audience,
		Kind: store.GrantKindDevice, CreatedAt: in.At,
	}); err != nil {
		return store.Session{}, err
	}
	sess, err := insertBound(ctx, tx, store.BoundSession{
		UserID: in.UserID, TokenHash: in.TokenHash, Kind: store.KindMCPAccess,
		ExpiresAt: in.ExpiresAt, At: in.At, Audience: in.Audience,
		GrantID: &grantID, ClientID: store.ClientDevice,
	})
	if err != nil {
		return store.Session{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return store.Session{}, mapErr(err)
	}
	return sess, nil
}

func ensureDeviceClient(ctx context.Context, q queryer, at time.Time) error {
	return mapErr(exec(ctx, q, `
INSERT INTO app.oauth_clients (
    id, name, redirect_uris, grant_types, response_types, token_endpoint_auth_method, kind, created_at
) VALUES ('deploybot-cli', 'deploybot-cli', '{}', '{}', '{code}', 'none', 'internal', $1)
ON CONFLICT (id) DO NOTHING
`, at))
}

func (d *DB) RevokeTokenFamily(ctx context.Context, tokenHash []byte, at time.Time, allowClient string, confidential bool) (store.RevokeResult, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.RevokeResult{}, mapErr(err)
	}
	defer tx.Rollback(ctx)
	var kind, userText string
	var clientPtr *string
	var grantText *string
	var stored []byte
	err = tx.QueryRow(ctx, `
SELECT kind, client_id, user_id::text, grant_id::text, token_hash
FROM app.sessions
WHERE token_hash = $1
FOR UPDATE
`, tokenHash).Scan(&kind, &clientPtr, &userText, &grantText, &stored)
	if errors.Is(err, pgx.ErrNoRows) {
		secret.Equal(tokenHash, missHash)
		return store.RevokeResult{}, nil
	}
	if err != nil {
		return store.RevokeResult{}, mapErr(err)
	}
	if !secret.Equal(tokenHash, stored) {
		return store.RevokeResult{}, nil
	}
	uid, err := parseID(userText)
	if err != nil {
		return store.RevokeResult{}, err
	}
	clientID := ""
	if clientPtr != nil {
		clientID = *clientPtr
	}
	res := store.RevokeResult{Found: true, UserID: uid, ClientID: clientID}
	grantID, err := parseOptID(grantText)
	if err != nil {
		return store.RevokeResult{}, err
	}
	if kind != store.KindMCPAccess && kind != store.KindMCPRefresh {
		return res, nil
	}
	if !confidential && clientID != allowClient {
		return res, nil
	}
	if grantID == nil {
		return res, nil
	}
	var revoked *time.Time
	if err := tx.QueryRow(ctx, `SELECT revoked_at FROM app.oauth_grants WHERE id = $1::uuid`, grantID.String()).Scan(&revoked); err != nil {
		return store.RevokeResult{}, mapErr(err)
	}
	if revoked != nil {
		return res, nil
	}
	if err := revokeFamily(ctx, tx, *grantID, at); err != nil {
		return store.RevokeResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return store.RevokeResult{}, mapErr(err)
	}
	res.Revoked = true
	res.GrantID = *grantID
	return res, nil
}

func (d *DB) CreateBoundSession(ctx context.Context, in store.BoundSession) (store.Session, error) {
	return insertBound(ctx, d.pool, in)
}

func insertBound(ctx context.Context, q queryer, in store.BoundSession) (store.Session, error) {
	id := uuid.New()
	var got store.Session
	var idText, userText string
	var audience, clientID, grantText, codeText *string
	err := q.QueryRow(ctx, `
INSERT INTO app.sessions (
    id, user_id, token_hash, kind, created_at, expires_at, last_seen_at,
    audience, grant_id, client_id, code_id
) VALUES (
    $1::uuid, $2::uuid, $3, $4, $5, $6, $5,
    $7, $8::uuid, $9, $10::uuid
)
RETURNING id::text, user_id::text, kind, created_at, expires_at, last_seen_at,
          audience, client_id, grant_id::text, code_id::text
`, id.String(), in.UserID.String(), in.TokenHash, in.Kind, in.At, in.ExpiresAt,
		optText(in.Audience), optUUID(in.GrantID), optText(in.ClientID), optUUID(in.CodeID)).Scan(
		&idText, &userText, &got.Kind, &got.CreatedAt, &got.ExpiresAt, &got.LastSeenAt,
		&audience, &clientID, &grantText, &codeText,
	)
	if err != nil {
		return store.Session{}, mapErr(err)
	}
	if got.ID, err = parseID(idText); err != nil {
		return store.Session{}, err
	}
	if got.UserID, err = parseID(userText); err != nil {
		return store.Session{}, err
	}
	if audience != nil {
		got.Audience = *audience
	}
	if clientID != nil {
		got.ClientID = *clientID
	}
	if got.GrantID, err = parseOptID(grantText); err != nil {
		return store.Session{}, err
	}
	if got.CodeID, err = parseOptID(codeText); err != nil {
		return store.Session{}, err
	}
	return got, nil
}
