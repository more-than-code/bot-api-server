package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/seal"
	"github.com/more-than-code/bot-api-server/internal/store"
	"github.com/more-than-code/bot-api-server/migrations"
)

func TestProjectFilesMigrationText(t *testing.T) {
	body, err := migrations.FS.ReadFile("0010_project_files.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"CREATE TABLE app.project_files",
		"PRIMARY KEY (project_id, name)",
		"REFERENCES app.projects (id) ON DELETE CASCADE",
		"project_files_form_chk",
		"octet_length(nonce) = 12",
		"octet_length(content_cipher) = size + 16",
		"project_files_name_chk",
		"project_files_sha_chk",
		"GRANT UPDATE (is_secret, content_plain, nonce, content_cipher, key_version, sha256, size, updated_by, updated_at)",
		"REVOKE ALL ON TABLE app.project_files FROM deploybot_api",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("0010 missing %s", want)
		}
	}
	for _, stmt := range splitSQL(text) {
		if !meaningfulSQL(stmt) {
			t.Fatalf("comment-only statement: %q", stmt)
		}
	}
	down, err := migrations.FS.ReadFile("0010_project_files.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	downText := string(down)
	if !strings.Contains(downText, "Take a dump first") {
		t.Fatal("down script does not warn that ciphertext is dropped")
	}
	if !strings.Contains(downText, "DELETE FROM app.schema_migrations WHERE name = '0010_project_files.sql'") {
		t.Fatal("down script does not document the schema_migrations delete")
	}
	stmts := splitSQL(downText)
	if len(stmts) != 1 || !strings.HasPrefix(strings.TrimSpace(stmts[0]), "DROP TABLE IF EXISTS app.project_files") {
		t.Fatalf("down statements %#v", stmts)
	}
}

func TestProjectFilesMigration(t *testing.T) {
	url := os.Getenv("DEPLOYBOT_TEST_DATABASE_URL")
	if url == "" {
		t.Skip()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	d, err := Open(ctx, url)
	if err != nil {
		t.Fatal("connect failed")
	}
	defer d.Close()
	var dbName string
	if err := d.pool.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatal("database name lookup failed")
	}
	if dbName != "deploybot_test" {
		t.Fatalf("refusing database %s", dbName)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := Migrate(cctx, url); err != nil {
			t.Errorf("restore schema: %v", err)
		}
	})
	if err := Migrate(ctx, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	assertImageSchema(t, d, ctx)

	at := time.Now().UTC().Truncate(time.Microsecond)
	owner := catalogUser(t, d, ctx, "files0010", at)
	home := catalogProject(t, d, ctx, owner.ID, "Files", "files0010", at)
	box, err := seal.New(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	const secret = "db-secret-file-value"
	putSecret := func(plain string) {
		t.Helper()
		nonce, ciphertext, err := box.Seal(seal.FileAAD(home.ID.String(), "key.json"), []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(plain))
		if _, err := d.PutProjectFile(ctx, home.ID, "key.json", store.FileWrite{
			IsSecret: true, Nonce: nonce, Ciphertext: ciphertext, KeyVersion: seal.KeyVersion,
			SHA256: hex.EncodeToString(sum[:]), Size: len(plain),
		}, owner.ID, at); err != nil {
			t.Fatal(err)
		}
	}
	putSecret(secret)
	firstMats, err := d.ListFileMaterial(ctx, home.ID)
	if err != nil || len(firstMats) != 1 || len(firstMats[0].Nonce) != 12 {
		t.Fatalf("first nonce %#v %v", firstMats, err)
	}
	firstNonce := append([]byte(nil), firstMats[0].Nonce...)
	putSecret(secret + "-next")
	sum := sha256.Sum256([]byte("plain-line"))
	if _, err := d.PutProjectFile(ctx, home.ID, "app.conf", store.FileWrite{
		Plain: "plain-line", SHA256: hex.EncodeToString(sum[:]), Size: len("plain-line"),
	}, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	listed, err := d.ListProjectFiles(ctx, home.ID)
	if err != nil || len(listed) != 2 || listed[0].Name != "app.conf" || listed[1].SHA256 != nil || listed[1].Plain != "" {
		t.Fatalf("list %#v %v", listed, err)
	}
	got, err := d.GetProjectFile(ctx, home.ID, "app.conf")
	if err != nil || got.Plain != "plain-line" || got.SHA256 == nil {
		t.Fatalf("plain %#v %v", got, err)
	}
	hidden, err := d.GetProjectFile(ctx, home.ID, "key.json")
	if err != nil || hidden.Plain != "" || hidden.SHA256 != nil {
		t.Fatalf("secret get %#v %v", hidden, err)
	}
	mats, err := d.ListFileMaterial(ctx, home.ID)
	if err != nil {
		t.Fatal(err)
	}
	var sealed store.FileMaterial
	for _, mat := range mats {
		if mat.Name == "key.json" {
			sealed = mat
		}
	}
	if sealed.Plain != "" || bytes.Contains(sealed.Ciphertext, []byte(secret)) || bytes.Equal(firstNonce, sealed.Nonce) {
		t.Fatal("ciphertext stored the secret in the clear or reused a nonce")
	}
	opened, err := box.Open(seal.FileAAD(home.ID.String(), "key.json"), sealed.Nonce, sealed.Ciphertext)
	if err != nil || string(opened) != secret+"-next" {
		t.Fatalf("open %q %v", opened, err)
	}
	if _, err := box.Open(seal.EnvAAD(home.ID.String(), "services", "key.json"), sealed.Nonce, sealed.Ciphertext); err == nil {
		t.Fatal("wrong AAD opened")
	}
	flipped := append([]byte(nil), sealed.Ciphertext...)
	flipped[len(flipped)-1] ^= 0xff
	if _, err := box.Open(seal.FileAAD(home.ID.String(), "key.json"), sealed.Nonce, flipped); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
	_, err = d.pool.Exec(ctx, `
INSERT INTO app.project_files (
    project_id, name, is_secret, content_plain, sha256, size, updated_by, updated_at
) VALUES ($1::uuid, 'bad', true, 'x', $2, 1, $3::uuid, $4)
`, home.ID.String(), strings.Repeat("ab", 32), owner.ID.String(), at)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("form check insert %v", err)
	}

	known := map[string]struct{}{"app.conf": {}}
	img, err := catalog.BuildImage("web", []byte(`{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/config/app.conf"}]}`), nil, known)
	if err != nil {
		t.Fatal(err)
	}
	hash := catalog.ImageHash(img, nil)
	write := store.CatalogWrite{
		Name: "web", Kind: "image", ImageRaw: []byte(catalog.SpecJSON(img)),
		SpecHash: hash, CommandDisplay: img.Image, Actor: owner.ID, At: at,
	}
	if _, err := d.CreateCatalogEntry(ctx, home.ID, write); err != nil {
		t.Fatal(err)
	}
	write.Name = "api"
	if _, err := d.CreateCatalogEntry(ctx, home.ID, write); err != nil {
		t.Fatal(err)
	}
	err = d.DeleteProjectFile(ctx, home.ID, "app.conf")
	var used *store.FileInUse
	if !errors.As(err, &used) || strings.Join(used.Entries, ",") != "api,web" {
		t.Fatalf("conflict %v", err)
	}
	limit := catalogProject(t, d, ctx, owner.ID, "Limit", "files0010lim", at)
	for i := 0; i < store.MaxProjectFiles; i++ {
		name := "f" + hex.EncodeToString([]byte{byte(i)})
		body := "x"
		sum := sha256.Sum256([]byte(body))
		if _, err := d.PutProjectFile(ctx, limit.ID, name, store.FileWrite{
			Plain: body, SHA256: hex.EncodeToString(sum[:]), Size: len(body),
		}, owner.ID, at); err != nil {
			t.Fatalf("put %s %v", name, err)
		}
	}
	sum = sha256.Sum256([]byte("x"))
	if _, err := d.PutProjectFile(ctx, limit.ID, "extra", store.FileWrite{
		Plain: "x", SHA256: hex.EncodeToString(sum[:]), Size: 1,
	}, owner.ID, at); !errors.Is(err, store.ErrTooManyFiles) {
		t.Fatalf("65th %v", err)
	}
	replaced := sha256.Sum256([]byte("y"))
	if _, err := d.PutProjectFile(ctx, limit.ID, "f00", store.FileWrite{
		Plain: "y", SHA256: hex.EncodeToString(replaced[:]), Size: 1,
	}, owner.ID, at); err != nil {
		t.Fatalf("replace at the limit %v", err)
	}
	if _, err := d.DeleteProject(ctx, home.ID, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.DeleteProject(ctx, limit.ID, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM app.project_files WHERE project_id = $1::uuid`, home.ID.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("files left %d %v", n, err)
	}

	down, err := migrations.FS.ReadFile("0010_project_files.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET ROLE deploybot_owner`); err != nil {
		t.Fatalf("set role: %v", err)
	}
	for _, stmt := range splitSQL(string(down)) {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			t.Fatalf("down %q: %v", stmt, err)
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM app.schema_migrations WHERE name = '0010_project_files.sql'`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var rel *string
	if err := d.pool.QueryRow(ctx, `SELECT to_regclass('app.project_files')`).Scan(&rel); err != nil || rel != nil {
		t.Fatalf("table survived down %v %v", rel, err)
	}
	if err := Migrate(ctx, url); err != nil {
		t.Fatalf("migrate again: %v", err)
	}
	if err := d.pool.QueryRow(ctx, `SELECT to_regclass('app.project_files')`).Scan(&rel); err != nil || rel == nil {
		t.Fatalf("table missing after up %v %v", rel, err)
	}
	assertImageSchema(t, d, ctx)
}
