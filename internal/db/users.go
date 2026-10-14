package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// missHash is compared when a digest lookup misses so the compare always runs.
var missHash = secret.Hash("deploybot-miss")

func parseID(s string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("database: bad id")
	}
	return id, nil
}

func parseOptID(s *string) (*uuid.UUID, error) {
	if s == nil {
		return nil, nil
	}
	id, err := parseID(*s)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func optUUID(id *uuid.UUID) any {
	if id == nil {
		return nil
	}
	return id.String()
}

func pageLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	return limit
}

func (d *DB) UpsertGoogleUser(ctx context.Context, in store.GoogleSignIn) (store.User, error) {
	in.Email = strings.ToLower(in.Email)
	userID, identID, found, err := d.googleSubject(ctx, in.Subject)
	if err != nil {
		return store.User{}, err
	}
	if found {
		return d.updateGoogle(ctx, identID, userID, in)
	}
	var taken bool
	if err := d.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM app.users WHERE email = $1)`, in.Email).Scan(&taken); err != nil {
		return store.User{}, mapErr(err)
	}
	if taken {
		return store.User{}, store.ErrConflict
	}
	user, err := d.insertGoogle(ctx, in)
	if err == nil {
		return user, nil
	}
	if !isUnique(err) {
		return store.User{}, mapErr(err)
	}
	userID, identID, found, err = d.googleSubject(ctx, in.Subject)
	if err != nil {
		return store.User{}, err
	}
	if found {
		return d.updateGoogle(ctx, identID, userID, in)
	}
	return store.User{}, store.ErrConflict
}

func (d *DB) googleSubject(ctx context.Context, subject string) (uuid.UUID, uuid.UUID, bool, error) {
	var identText, userText string
	err := d.pool.QueryRow(ctx, `
SELECT id::text, user_id::text
FROM app.user_identities
WHERE provider = 'google' AND provider_subject = $1
`, subject).Scan(&identText, &userText)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.UUID{}, uuid.UUID{}, false, nil
	}
	if err != nil {
		return uuid.UUID{}, uuid.UUID{}, false, mapErr(err)
	}
	identID, err := parseID(identText)
	if err != nil {
		return uuid.UUID{}, uuid.UUID{}, false, err
	}
	userID, err := parseID(userText)
	if err != nil {
		return uuid.UUID{}, uuid.UUID{}, false, err
	}
	return userID, identID, true, nil
}

func (d *DB) updateGoogle(ctx context.Context, identID, userID uuid.UUID, in store.GoogleSignIn) (store.User, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.User{}, mapErr(err)
	}
	defer tx.Rollback(ctx)
	if err := exec(ctx, tx, `
UPDATE app.user_identities
SET email = $2, email_verified = true, last_login_at = $3
WHERE id = $1::uuid
`, identID.String(), in.Email, in.At); err != nil {
		return store.User{}, mapErr(err)
	}
	user, err := scanUser(tx.QueryRow(ctx, `
UPDATE app.users
SET name = CASE WHEN $2 <> '' THEN $2 ELSE name END,
    avatar_url = CASE WHEN $3 <> '' THEN $3 ELSE avatar_url END
WHERE id = $1::uuid
RETURNING id::text, email, name, avatar_url, disabled_at, created_at
`, userID.String(), in.Name, in.AvatarURL))
	if err != nil {
		return store.User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return store.User{}, mapErr(err)
	}
	return user, nil
}

func (d *DB) insertGoogle(ctx context.Context, in store.GoogleSignIn) (store.User, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.User{}, err
	}
	defer tx.Rollback(ctx)
	user := store.User{
		ID:        uuid.New(),
		Email:     in.Email,
		Name:      in.Name,
		AvatarURL: in.AvatarURL,
		CreatedAt: in.At,
	}
	if err := exec(ctx, tx, `
INSERT INTO app.users (id, email, name, avatar_url, created_at)
VALUES ($1::uuid, $2, $3, $4, $5)
`, user.ID.String(), user.Email, user.Name, user.AvatarURL, user.CreatedAt); err != nil {
		return store.User{}, err
	}
	if err := exec(ctx, tx, `
INSERT INTO app.user_identities (
    id, user_id, provider, provider_subject, email, email_verified, created_at, last_login_at
) VALUES ($1::uuid, $2::uuid, 'google', $3, $4, true, $5, $5)
`, uuid.New().String(), user.ID.String(), in.Subject, in.Email, in.At); err != nil {
		return store.User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return store.User{}, err
	}
	return user, nil
}

func (d *DB) GetUser(ctx context.Context, id uuid.UUID) (store.User, error) {
	return scanUser(d.pool.QueryRow(ctx, `
SELECT id::text, email, name, avatar_url, disabled_at, created_at
FROM app.users
WHERE id = $1::uuid
`, id.String()))
}

func (d *DB) UserByEmail(ctx context.Context, email string) (store.User, error) {
	return scanUser(d.pool.QueryRow(ctx, `
SELECT id::text, email, name, avatar_url, disabled_at, created_at
FROM app.users
WHERE email = $1
`, email))
}

func scanUser(row pgx.Row) (store.User, error) {
	var u store.User
	var id string
	if err := row.Scan(&id, &u.Email, &u.Name, &u.AvatarURL, &u.DisabledAt, &u.CreatedAt); err != nil {
		return store.User{}, mapErr(err)
	}
	var err error
	if u.ID, err = parseID(id); err != nil {
		return store.User{}, err
	}
	return u, nil
}

func (d *DB) ListIdentities(ctx context.Context, userID uuid.UUID) ([]store.Identity, error) {
	rows, err := d.pool.Query(ctx, `
SELECT id::text, user_id::text, provider, provider_subject, email, email_verified, created_at, last_login_at
FROM app.user_identities
WHERE user_id = $1::uuid
ORDER BY created_at ASC, id ASC
`, userID.String())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.Identity{}
	for rows.Next() {
		var ident store.Identity
		var id, uid string
		if err := rows.Scan(&id, &uid, &ident.Provider, &ident.ProviderSubject, &ident.Email, &ident.EmailVerified, &ident.CreatedAt, &ident.LastLoginAt); err != nil {
			return nil, mapErr(err)
		}
		if ident.ID, err = parseID(id); err != nil {
			return nil, err
		}
		if ident.UserID, err = parseID(uid); err != nil {
			return nil, err
		}
		out = append(out, ident)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (d *DB) CreateSession(ctx context.Context, userID uuid.UUID, tokenHash []byte, kind string, expiresAt, at time.Time) (store.Session, error) {
	id := uuid.New()
	var got store.Session
	var idText, userText string
	err := d.pool.QueryRow(ctx, `
INSERT INTO app.sessions (id, user_id, token_hash, kind, created_at, expires_at, last_seen_at)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $5)
RETURNING id::text, user_id::text, kind, created_at, expires_at, last_seen_at
`, id.String(), userID.String(), tokenHash, kind, at, expiresAt).Scan(
		&idText, &userText, &got.Kind, &got.CreatedAt, &got.ExpiresAt, &got.LastSeenAt,
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
	return got, nil
}

func (d *DB) GetSession(ctx context.Context, tokenHash []byte, now time.Time) (store.Session, store.User, error) {
	var sess store.Session
	var user store.User
	var sessID, userID, userText string
	var stored []byte
	var audience, clientID, grantText, codeText *string
	var grantRevoked *time.Time
	err := d.pool.QueryRow(ctx, `
SELECT s.id::text, s.user_id::text, s.kind, s.created_at, s.expires_at, s.last_seen_at, s.token_hash,
       s.audience, s.client_id, s.grant_id::text, s.code_id::text, s.rotated_at, g.revoked_at,
       u.id::text, u.email, u.name, u.avatar_url, u.disabled_at, u.created_at
FROM app.sessions s
JOIN app.users u ON u.id = s.user_id
LEFT JOIN app.oauth_grants g ON g.id = s.grant_id
WHERE s.token_hash = $1
`, tokenHash).Scan(
		&sessID, &userID, &sess.Kind, &sess.CreatedAt, &sess.ExpiresAt, &sess.LastSeenAt, &stored,
		&audience, &clientID, &grantText, &codeText, &sess.RotatedAt, &grantRevoked,
		&userText, &user.Email, &user.Name, &user.AvatarURL, &user.DisabledAt, &user.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		secret.Equal(tokenHash, missHash)
		return store.Session{}, store.User{}, store.ErrUnauthorized
	}
	if err != nil {
		return store.Session{}, store.User{}, mapErr(err)
	}
	match := secret.Equal(tokenHash, stored)
	if sess.ID, err = parseID(sessID); err != nil {
		return store.Session{}, store.User{}, err
	}
	if sess.UserID, err = parseID(userID); err != nil {
		return store.Session{}, store.User{}, err
	}
	if user.ID, err = parseID(userText); err != nil {
		return store.Session{}, store.User{}, err
	}
	if sess.GrantID, err = parseOptID(grantText); err != nil {
		return store.Session{}, store.User{}, err
	}
	if sess.CodeID, err = parseOptID(codeText); err != nil {
		return store.Session{}, store.User{}, err
	}
	if audience != nil {
		sess.Audience = *audience
	}
	if clientID != nil {
		sess.ClientID = *clientID
	}
	if !match || !now.Before(sess.ExpiresAt) || user.DisabledAt != nil || grantRevoked != nil {
		return store.Session{}, store.User{}, store.ErrUnauthorized
	}
	return sess, user, nil
}

func (d *DB) DeleteSession(ctx context.Context, id uuid.UUID) error {
	if err := exec(ctx, d.pool, `DELETE FROM app.sessions WHERE id = $1::uuid`, id.String()); err != nil {
		return mapErr(err)
	}
	return nil
}

func (d *DB) TouchSession(ctx context.Context, id uuid.UUID, at time.Time) error {
	tag, err := d.pool.Exec(ctx, `
UPDATE app.sessions
SET last_seen_at = $2
WHERE id = $1::uuid AND last_seen_at <= $2 - interval '1 minute'
`, id.String(), at)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	var exists bool
	if err := d.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM app.sessions WHERE id = $1::uuid)`, id.String()).Scan(&exists); err != nil {
		return mapErr(err)
	}
	if !exists {
		return store.ErrNotFound
	}
	return nil
}
