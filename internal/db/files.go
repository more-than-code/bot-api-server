package db

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (d *DB) ListProjectFiles(ctx context.Context, projectID uuid.UUID) ([]store.ProjectFile, error) {
	if err := d.requireProject(ctx, projectID); err != nil {
		return nil, err
	}
	rows, err := d.pool.Query(ctx, `
SELECT name, is_secret, size,
       CASE WHEN is_secret THEN NULL ELSE sha256 END,
       updated_at, updated_by::text
FROM app.project_files
WHERE project_id = $1::uuid
ORDER BY name
`, projectID.String())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.ProjectFile{}
	for rows.Next() {
		item, err := scanProjectFile(rows.Scan, false)
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

func (d *DB) GetProjectFile(ctx context.Context, projectID uuid.UUID, name string) (store.ProjectFile, error) {
	if err := d.requireProject(ctx, projectID); err != nil {
		return store.ProjectFile{}, err
	}
	row := d.pool.QueryRow(ctx, `
SELECT name, is_secret, size,
       CASE WHEN is_secret THEN NULL ELSE sha256 END,
       updated_at, updated_by::text,
       CASE WHEN is_secret THEN NULL ELSE content_plain END
FROM app.project_files
WHERE project_id = $1::uuid AND name = $2
`, projectID.String(), name)
	item, err := scanProjectFile(row.Scan, true)
	if err != nil {
		return store.ProjectFile{}, err
	}
	return item, nil
}

func (d *DB) PutProjectFile(ctx context.Context, projectID uuid.UUID, name string, in store.FileWrite, actor uuid.UUID, at time.Time) (store.ProjectFile, error) {
	if !dbFileWriteOK(name, in) {
		return store.ProjectFile{}, store.ErrInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return store.ProjectFile{}, mapErr(err)
	}
	defer tx.Rollback(ctx)
	var id string
	err = tx.QueryRow(ctx, `
SELECT id::text FROM app.projects
WHERE id = $1::uuid AND deleted_at IS NULL
FOR UPDATE
`, projectID.String()).Scan(&id)
	if err != nil {
		return store.ProjectFile{}, mapErr(err)
	}
	var n int
	var exists bool
	if err := tx.QueryRow(ctx, `
SELECT count(*), COALESCE(bool_or(name = $2), false)
FROM app.project_files
WHERE project_id = $1::uuid
`, projectID.String(), name).Scan(&n, &exists); err != nil {
		return store.ProjectFile{}, mapErr(err)
	}
	if !exists && n >= store.MaxProjectFiles {
		return store.ProjectFile{}, store.ErrTooManyFiles
	}
	var plain any
	var nonce, cipher []byte
	var ver any
	if in.IsSecret {
		nonce = append([]byte(nil), in.Nonce...)
		cipher = append([]byte(nil), in.Ciphertext...)
		ver = in.KeyVersion
	} else {
		plain = in.Plain
	}
	if err := exec(ctx, tx, `
INSERT INTO app.project_files (
    project_id, name, is_secret, content_plain, nonce, content_cipher, key_version,
    sha256, size, updated_by, updated_at
) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10::uuid, $11)
ON CONFLICT (project_id, name) DO UPDATE SET
    is_secret = EXCLUDED.is_secret,
    content_plain = EXCLUDED.content_plain,
    nonce = EXCLUDED.nonce,
    content_cipher = EXCLUDED.content_cipher,
    key_version = EXCLUDED.key_version,
    sha256 = EXCLUDED.sha256,
    size = EXCLUDED.size,
    updated_by = EXCLUDED.updated_by,
    updated_at = EXCLUDED.updated_at
`, projectID.String(), name, in.IsSecret, plain, nonce, cipher, ver, in.SHA256, in.Size, actor.String(), at); err != nil {
		return store.ProjectFile{}, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return store.ProjectFile{}, mapErr(err)
	}
	return d.GetProjectFile(ctx, projectID, name)
}

func (d *DB) DeleteProjectFile(ctx context.Context, projectID uuid.UUID, name string) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return mapErr(err)
	}
	defer tx.Rollback(ctx)
	var id string
	err = tx.QueryRow(ctx, `
SELECT id::text FROM app.projects
WHERE id = $1::uuid AND deleted_at IS NULL
FOR UPDATE
`, projectID.String()).Scan(&id)
	if err != nil {
		return mapErr(err)
	}
	var exists bool
	if err := tx.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1 FROM app.project_files WHERE project_id = $1::uuid AND name = $2
)
`, projectID.String(), name).Scan(&exists); err != nil {
		return mapErr(err)
	}
	if !exists {
		return store.ErrNotFound
	}
	rows, err := tx.Query(ctx, `
SELECT e.name FROM app.catalog_entries e
WHERE e.project_id = $1::uuid AND e.kind = 'image'
  AND EXISTS (
    SELECT 1 FROM jsonb_array_elements(COALESCE(e.spec->'files', '[]'::jsonb)) f
    WHERE f->>'file' = $2
  )
ORDER BY e.name
`, projectID.String(), name)
	if err != nil {
		return mapErr(err)
	}
	var used []string
	for rows.Next() {
		var entry string
		if err := rows.Scan(&entry); err != nil {
			rows.Close()
			return mapErr(err)
		}
		used = append(used, entry)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return mapErr(err)
	}
	rows.Close()
	if len(used) > 0 {
		return &store.FileInUse{Entries: used}
	}
	if err := exec(ctx, tx, `
DELETE FROM app.project_files WHERE project_id = $1::uuid AND name = $2
`, projectID.String(), name); err != nil {
		return mapErr(err)
	}
	return mapErr(tx.Commit(ctx))
}

func (d *DB) ListFileMaterial(ctx context.Context, projectID uuid.UUID) ([]store.FileMaterial, error) {
	if err := d.requireProject(ctx, projectID); err != nil {
		return nil, err
	}
	rows, err := d.pool.Query(ctx, `
SELECT name, is_secret, COALESCE(content_plain, ''), nonce, content_cipher,
       COALESCE(key_version, 0), sha256, size, updated_at, updated_by::text
FROM app.project_files
WHERE project_id = $1::uuid
ORDER BY name
`, projectID.String())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []store.FileMaterial{}
	for rows.Next() {
		var item store.FileMaterial
		var by string
		if err := rows.Scan(&item.Name, &item.IsSecret, &item.Plain, &item.Nonce, &item.Ciphertext, &item.KeyVersion, &item.SHA256, &item.Size, &item.UpdatedAt, &by); err != nil {
			return nil, mapErr(err)
		}
		id, err := parseID(by)
		if err != nil {
			return nil, err
		}
		item.UpdatedBy = id
		if item.IsSecret {
			item.Plain = ""
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

type rowScan func(dest ...any) error

func scanProjectFile(scan rowScan, withPlain bool) (store.ProjectFile, error) {
	var item store.ProjectFile
	var sum *string
	var by string
	var plain *string
	dest := []any{&item.Name, &item.IsSecret, &item.Size, &sum, &item.UpdatedAt, &by}
	if withPlain {
		dest = append(dest, &plain)
	}
	if err := scan(dest...); err != nil {
		return store.ProjectFile{}, mapErr(err)
	}
	id, err := parseID(by)
	if err != nil {
		return store.ProjectFile{}, err
	}
	item.UpdatedBy = id
	if !item.IsSecret {
		item.SHA256 = sum
		if withPlain && plain != nil {
			item.Plain = *plain
		}
	}
	return item, nil
}

func dbFileWriteOK(name string, in store.FileWrite) bool {
	if !catalog.ValidFileName(name) || !dbSHAHex(in.SHA256) {
		return false
	}
	if in.Size < 1 || in.Size > catalog.MaxFileBytes {
		return false
	}
	if in.IsSecret {
		return in.Plain == "" && len(in.Nonce) == 12 && len(in.Ciphertext) == in.Size+16 && in.KeyVersion >= 1
	}
	return catalog.ValidFileContent(in.Plain) && len(in.Plain) == in.Size && len(in.Nonce) == 0 && len(in.Ciphertext) == 0 && in.KeyVersion == 0
}

func dbSHAHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
