package db

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const deployCols = `id::text, entry_id::text, host_id::text, digest, spec_hash, outcome, exit_code,
          started_at, finished_at, by_user::text, via, in_flight, in_flight_until`

// beginImageOpAfterSelect is nil in production. A test sets it so two
// transactions can both pass the empty in-flight SELECT before either inserts.
var beginImageOpAfterSelect func()

func (d *DB) BeginImageOp(ctx context.Context, entryID, hostID uuid.UUID, specHash string, by uuid.UUID, via string, at, until time.Time) (store.ImageDeploy, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.ImageDeploy{}, mapErr(err)
	}
	defer tx.Rollback(ctx)
	var staleID string
	var staleUntil *time.Time
	err = tx.QueryRow(ctx, `
SELECT id::text, in_flight_until
FROM app.image_deploys
WHERE host_id = $1::uuid AND entry_id = $2::uuid AND in_flight
FOR UPDATE
`, hostID.String(), entryID.String()).Scan(&staleID, &staleUntil)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return store.ImageDeploy{}, mapErr(err)
	}
	if err == nil {
		if staleUntil != nil && staleUntil.After(at) {
			return store.ImageDeploy{}, store.ErrConflict
		}
		if err := exec(ctx, tx, `
UPDATE app.image_deploys
SET outcome = 'timeout', finished_at = $2, in_flight = false
WHERE id = $1::uuid AND in_flight
`, staleID, at); err != nil {
			return store.ImageDeploy{}, mapErr(err)
		}
	} else if beginImageOpAfterSelect != nil {
		beginImageOpAfterSelect()
	}
	id := uuid.New()
	row, err := scanDeploy(tx.QueryRow(ctx, `
INSERT INTO app.image_deploys (
    id, entry_id, host_id, digest, spec_hash, outcome, exit_code,
    started_at, finished_at, by_user, via, in_flight, in_flight_until
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, NULL, $4, 'in_flight', NULL,
    $5, NULL, $6::uuid, $7, true, $8
)
RETURNING `+deployCols, id.String(), entryID.String(), hostID.String(), specHash, at, by.String(), via, until))
	if err != nil {
		return store.ImageDeploy{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return store.ImageDeploy{}, mapErr(err)
	}
	return row, nil
}

func (d *DB) FinishImageDeploy(ctx context.Context, id uuid.UUID, outcome string, digest *string, exitCode *int, at time.Time) (store.ImageDeploy, error) {
	if digest != nil && !catalog.ValidDigest(*digest) {
		digest = nil
	}
	row, err := scanDeploy(d.pool.QueryRow(ctx, `
UPDATE app.image_deploys
SET digest = $2, outcome = $3, exit_code = $4, finished_at = $5, in_flight = false
WHERE id = $1::uuid AND in_flight
RETURNING `+deployCols+`
`, id.String(), digest, outcome, exitCode, at))
	if err != nil {
		return store.ImageDeploy{}, err
	}
	return row, nil
}

func (d *DB) ReleaseImageOp(ctx context.Context, id uuid.UUID) error {
	return mapErr(exec(ctx, d.pool, `DELETE FROM app.image_deploys WHERE id = $1::uuid AND in_flight`, id.String()))
}

func (d *DB) ListImageDeploys(ctx context.Context, entryID, hostID uuid.UUID) ([]store.ImageDeploy, error) {
	var exists bool
	if err := d.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM app.catalog_entries WHERE id = $1::uuid)`, entryID.String()).Scan(&exists); err != nil {
		return nil, mapErr(err)
	}
	if !exists {
		return nil, store.ErrNotFound
	}
	rows, err := d.pool.Query(ctx, `
SELECT `+deployCols+`
FROM app.image_deploys
WHERE entry_id = $1::uuid AND host_id = $2::uuid AND NOT in_flight
ORDER BY finished_at DESC, id DESC
LIMIT 50
`, entryID.String(), hostID.String())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	return collectDeploys(rows)
}

func (d *DB) RollbackDigests(ctx context.Context, entryID, hostID uuid.UUID) ([]string, error) {
	rows, err := d.pool.Query(ctx, `
SELECT digest
FROM app.image_deploys
WHERE entry_id = $1::uuid AND host_id = $2::uuid
  AND NOT in_flight
  AND outcome IN ('succeeded', 'unchanged')
  AND digest IS NOT NULL
ORDER BY finished_at DESC, id DESC
`, entryID.String(), hostID.String())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	out := make([]string, 0, 3)
	for rows.Next() {
		var digest string
		if err := rows.Scan(&digest); err != nil {
			return nil, mapErr(err)
		}
		if seen[digest] {
			continue
		}
		seen[digest] = true
		out = append(out, digest)
		if len(out) == 3 {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func collectDeploys(rows pgx.Rows) ([]store.ImageDeploy, error) {
	out := []store.ImageDeploy{}
	for rows.Next() {
		row, err := scanDeploy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func scanDeploy(row pgx.Row) (store.ImageDeploy, error) {
	var d store.ImageDeploy
	var id, entryID, hostID, by string
	var until *time.Time
	if err := row.Scan(
		&id, &entryID, &hostID, &d.Digest, &d.SpecHash, &d.Outcome, &d.ExitCode,
		&d.StartedAt, &d.FinishedAt, &by, &d.Via, &d.InFlight, &until,
	); err != nil {
		return store.ImageDeploy{}, mapErr(err)
	}
	if until != nil {
		d.InFlightUntil = *until
	}
	var err error
	if d.ID, err = parseID(id); err != nil {
		return store.ImageDeploy{}, err
	}
	if d.EntryID, err = parseID(entryID); err != nil {
		return store.ImageDeploy{}, err
	}
	if d.HostID, err = parseID(hostID); err != nil {
		return store.ImageDeploy{}, err
	}
	if d.By, err = parseID(by); err != nil {
		return store.ImageDeploy{}, err
	}
	return d, nil
}

func (d *DB) ListEnvKeyNames(ctx context.Context, projectID uuid.UUID) (map[string][]string, error) {
	if err := d.requireProject(ctx, projectID); err != nil {
		return nil, err
	}
	return d.envNames(ctx, d.pool, projectID)
}

func (d *DB) envNames(ctx context.Context, q queryer, projectID uuid.UUID) (map[string][]string, error) {
	rows, err := q.Query(ctx, `
SELECT s.name, v.key
FROM app.env_sets s
LEFT JOIN app.env_values v ON v.project_id = s.project_id AND v.set_name = s.name
WHERE s.project_id = $1::uuid
ORDER BY s.name, v.key
`, projectID.String())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var name string
		var key *string
		if err := rows.Scan(&name, &key); err != nil {
			return nil, mapErr(err)
		}
		if _, ok := out[name]; !ok {
			out[name] = []string{}
		}
		if key != nil {
			out[name] = append(out[name], *key)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (d *DB) ListEnvSets(ctx context.Context, projectID uuid.UUID) ([]store.EnvSet, error) {
	if err := d.requireProject(ctx, projectID); err != nil {
		return nil, err
	}
	rows, err := d.pool.Query(ctx, `
SELECT name FROM app.env_sets WHERE project_id = $1::uuid ORDER BY name
`, projectID.String())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	names := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, mapErr(err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	rows.Close()
	out := make([]store.EnvSet, 0, len(names))
	for _, name := range names {
		set, err := d.GetEnvSet(ctx, projectID, name)
		if err != nil {
			return nil, err
		}
		out = append(out, set)
	}
	return out, nil
}

func (d *DB) GetEnvSet(ctx context.Context, projectID uuid.UUID, name string) (store.EnvSet, error) {
	var set store.EnvSet
	var by string
	err := d.pool.QueryRow(ctx, `
SELECT name, updated_at, updated_by::text
FROM app.env_sets
WHERE project_id = $1::uuid AND name = $2
`, projectID.String(), name).Scan(&set.Name, &set.UpdatedAt, &by)
	if err != nil {
		return store.EnvSet{}, mapErr(err)
	}
	if set.UpdatedBy, err = parseID(by); err != nil {
		return store.EnvSet{}, err
	}
	rows, err := d.pool.Query(ctx, `
SELECT key, is_secret, value
FROM app.env_values
WHERE project_id = $1::uuid AND set_name = $2
ORDER BY key
`, projectID.String(), name)
	if err != nil {
		return store.EnvSet{}, mapErr(err)
	}
	defer rows.Close()
	set.Keys = []store.EnvKey{}
	for rows.Next() {
		var item store.EnvKey
		var value *string
		if err := rows.Scan(&item.Key, &item.IsSecret, &value); err != nil {
			return store.EnvSet{}, mapErr(err)
		}
		if !item.IsSecret {
			item.Value = value
		}
		set.Keys = append(set.Keys, item)
	}
	if err := rows.Err(); err != nil {
		return store.EnvSet{}, mapErr(err)
	}
	return set, nil
}

func (d *DB) PutEnvSet(ctx context.Context, projectID uuid.UUID, name string, keys []store.EnvSecret, actor uuid.UUID, at time.Time) (store.EnvSet, error) {
	if !catalog.ValidName(name) {
		return store.EnvSet{}, store.ErrInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.EnvSet{}, mapErr(err)
	}
	defer tx.Rollback(ctx)
	if err := exec(ctx, tx, `
INSERT INTO app.env_sets (project_id, name, updated_at, updated_by)
VALUES ($1::uuid, $2, $3, $4::uuid)
ON CONFLICT (project_id, name) DO UPDATE
SET updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by
`, projectID.String(), name, at, actor.String()); err != nil {
		return store.EnvSet{}, mapErr(err)
	}
	if err := exec(ctx, tx, `DELETE FROM app.env_values WHERE project_id = $1::uuid AND set_name = $2`, projectID.String(), name); err != nil {
		return store.EnvSet{}, mapErr(err)
	}
	for _, key := range keys {
		if err := exec(ctx, tx, `
INSERT INTO app.env_values (project_id, set_name, key, is_secret, value, nonce, ciphertext, key_version)
VALUES ($1::uuid, $2, $3, true, NULL, $4, $5, $6)
`, projectID.String(), name, key.Key, key.Nonce, key.Ciphertext, key.KeyVersion); err != nil {
			return store.EnvSet{}, mapErr(err)
		}
	}
	if err := d.rehashTx(ctx, tx, projectID, name, at); err != nil {
		return store.EnvSet{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return store.EnvSet{}, mapErr(err)
	}
	return d.GetEnvSet(ctx, projectID, name)
}

func (d *DB) PatchEnvKey(ctx context.Context, projectID uuid.UUID, name, key string, in store.EnvKeyPatch, actor uuid.UUID, at time.Time) (store.EnvSet, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.EnvSet{}, mapErr(err)
	}
	defer tx.Rollback(ctx)
	var tag string
	if in.IsSecret {
		tag, err = execTag(ctx, tx, `
UPDATE app.env_values
SET is_secret = true, value = NULL, nonce = $4, ciphertext = $5, key_version = $6
WHERE project_id = $1::uuid AND set_name = $2 AND key = $3
`, projectID.String(), name, key, in.Nonce, in.Ciphertext, in.KeyVersion)
	} else {
		tag, err = execTag(ctx, tx, `
UPDATE app.env_values
SET is_secret = false, value = $4, nonce = NULL, ciphertext = NULL, key_version = NULL
WHERE project_id = $1::uuid AND set_name = $2 AND key = $3
`, projectID.String(), name, key, in.Plain)
	}
	if err != nil {
		return store.EnvSet{}, mapErr(err)
	}
	if tag == "" || tag == "UPDATE 0" {
		return store.EnvSet{}, store.ErrNotFound
	}
	if err := exec(ctx, tx, `
UPDATE app.env_sets SET updated_at = $3, updated_by = $4::uuid
WHERE project_id = $1::uuid AND name = $2
`, projectID.String(), name, at, actor.String()); err != nil {
		return store.EnvSet{}, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return store.EnvSet{}, mapErr(err)
	}
	return d.GetEnvSet(ctx, projectID, name)
}

func execTag(ctx context.Context, q queryer, sql string, args ...any) (string, error) {
	tag, err := q.Exec(ctx, sql, args...)
	if err != nil {
		return "", err
	}
	return tag.String(), nil
}

func (d *DB) DeleteEnvSet(ctx context.Context, projectID uuid.UUID, name string) error {
	var exists bool
	if err := d.pool.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM app.env_sets WHERE project_id = $1::uuid AND name = $2)
`, projectID.String(), name).Scan(&exists); err != nil {
		return mapErr(err)
	}
	if !exists {
		return store.ErrNotFound
	}
	var used bool
	if err := d.pool.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1 FROM app.catalog_entries e
    WHERE e.project_id = $1::uuid AND e.kind = 'image'
      AND (
        COALESCE(e.spec->'env_sets', '[]'::jsonb) ? $2
        OR EXISTS (
            SELECT 1 FROM jsonb_each_text(COALESCE(e.spec->'secret_env', '{}'::jsonb)) kv
            WHERE split_part(kv.value, '.', 1) = $2
        )
      )
)
`, projectID.String(), name).Scan(&used); err != nil {
		return mapErr(err)
	}
	if used {
		return store.ErrConflict
	}
	return mapErr(exec(ctx, d.pool, `DELETE FROM app.env_sets WHERE project_id = $1::uuid AND name = $2`, projectID.String(), name))
}

func (d *DB) rehashTx(ctx context.Context, tx pgx.Tx, projectID uuid.UUID, set string, at time.Time) error {
	names, err := d.envNames(ctx, tx, projectID)
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `
SELECT id::text, spec, spec_hash
FROM app.catalog_entries
WHERE project_id = $1::uuid AND kind = 'image'
`, projectID.String())
	if err != nil {
		return mapErr(err)
	}
	defer rows.Close()
	type hit struct {
		id   string
		next string
	}
	var hits []hit
	for rows.Next() {
		var id, hash string
		var spec []byte
		if err := rows.Scan(&id, &spec, &hash); err != nil {
			return mapErr(err)
		}
		img, err := catalog.ParseStored(spec)
		if err != nil || !catalog.ReferencesSet(img, set) {
			continue
		}
		digests := map[string]string{}
		for _, ref := range catalog.ReferencedSets(img) {
			digests[ref] = catalog.EnvKeyDigest(names[ref])
		}
		next := catalog.ImageHash(img, digests)
		if next == hash {
			continue
		}
		hits = append(hits, hit{id: id, next: next})
	}
	if err := rows.Err(); err != nil {
		return mapErr(err)
	}
	rows.Close()
	for _, h := range hits {
		if err := exec(ctx, tx, `
UPDATE app.catalog_entries SET spec_hash = $2, updated_at = $3 WHERE id = $1::uuid
`, h.id, h.next, at); err != nil {
			return mapErr(err)
		}
		if err := exec(ctx, tx, `DELETE FROM app.catalog_host_approvals WHERE entry_id = $1::uuid`, h.id); err != nil {
			return mapErr(err)
		}
	}
	return nil
}

func (d *DB) ListEnvMaterial(ctx context.Context, projectID uuid.UUID, name string) ([]store.EnvMaterial, error) {
	var exists bool
	if err := d.pool.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM app.env_sets WHERE project_id = $1::uuid AND name = $2)
`, projectID.String(), name).Scan(&exists); err != nil {
		return nil, mapErr(err)
	}
	if !exists {
		return nil, store.ErrNotFound
	}
	rows, err := d.pool.Query(ctx, `
SELECT key, is_secret, value, nonce, ciphertext, key_version
FROM app.env_values
WHERE project_id = $1::uuid AND set_name = $2
ORDER BY key
`, projectID.String(), name)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.EnvMaterial{}
	for rows.Next() {
		var item store.EnvMaterial
		var plain *string
		var version *int
		if err := rows.Scan(&item.Key, &item.IsSecret, &plain, &item.Nonce, &item.Ciphertext, &version); err != nil {
			return nil, mapErr(err)
		}
		if plain != nil {
			item.Plain = *plain
		}
		if version != nil {
			item.KeyVersion = *version
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (d *DB) ListRegistries(ctx context.Context, projectID uuid.UUID) ([]store.Registry, error) {
	if err := d.requireProject(ctx, projectID); err != nil {
		return nil, err
	}
	rows, err := d.pool.Query(ctx, `
SELECT host, username, updated_at, updated_by::text
FROM app.registries
WHERE project_id = $1::uuid
ORDER BY host
`, projectID.String())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.Registry{}
	for rows.Next() {
		item, err := scanRegistry(rows)
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

func (d *DB) PutRegistry(ctx context.Context, projectID uuid.UUID, host string, in store.RegistryWrite, actor uuid.UUID, at time.Time) (store.Registry, error) {
	if !catalog.ValidRegistryHost(host) {
		return store.Registry{}, store.ErrInvalid
	}
	row := d.pool.QueryRow(ctx, `
INSERT INTO app.registries (project_id, host, username, nonce, ciphertext, key_version, updated_at, updated_by)
VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8::uuid)
ON CONFLICT (project_id, host) DO UPDATE SET
    username = EXCLUDED.username,
    nonce = EXCLUDED.nonce,
    ciphertext = EXCLUDED.ciphertext,
    key_version = EXCLUDED.key_version,
    updated_at = EXCLUDED.updated_at,
    updated_by = EXCLUDED.updated_by
RETURNING host, username, updated_at, updated_by::text
`, projectID.String(), host, in.Username, in.Nonce, in.Ciphertext, in.KeyVersion, at, actor.String())
	item, err := scanRegistry(row)
	if err != nil {
		return store.Registry{}, err
	}
	return item, nil
}

func (d *DB) DeleteRegistry(ctx context.Context, projectID uuid.UUID, host string) error {
	tag, err := d.pool.Exec(ctx, `DELETE FROM app.registries WHERE project_id = $1::uuid AND host = $2`, projectID.String(), host)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (d *DB) GetRegistryMaterial(ctx context.Context, projectID uuid.UUID, host string) (store.RegistryMaterial, error) {
	var item store.RegistryMaterial
	err := d.pool.QueryRow(ctx, `
SELECT host, username, nonce, ciphertext, key_version
FROM app.registries
WHERE project_id = $1::uuid AND host = $2
`, projectID.String(), host).Scan(&item.Host, &item.Username, &item.Nonce, &item.Ciphertext, &item.KeyVersion)
	if err != nil {
		return store.RegistryMaterial{}, mapErr(err)
	}
	return item, nil
}

func scanRegistry(row pgx.Row) (store.Registry, error) {
	var item store.Registry
	var by string
	if err := row.Scan(&item.Host, &item.Username, &item.UpdatedAt, &by); err != nil {
		return store.Registry{}, mapErr(err)
	}
	id, err := parseID(by)
	if err != nil {
		return store.Registry{}, err
	}
	item.UpdatedBy = id
	return item, nil
}

func (d *DB) requireProject(ctx context.Context, projectID uuid.UUID) error {
	var exists bool
	if err := d.pool.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM app.projects WHERE id = $1::uuid AND deleted_at IS NULL)
`, projectID.String()).Scan(&exists); err != nil {
		return mapErr(err)
	}
	if !exists {
		return store.ErrNotFound
	}
	return nil
}
