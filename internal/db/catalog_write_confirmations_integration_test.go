package db

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
	"github.com/more-than-code/bot-api-server/migrations"
)

func TestCatalogWriteConfirmationsMigrationText(t *testing.T) {
	body, err := migrations.FS.ReadFile("0013_catalog_write_confirmations.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"CREATE TABLE app.catalog_write_confirmations",
		"token_hash bytea PRIMARY KEY",
		"user_id uuid NOT NULL",
		"project_id uuid NOT NULL",
		"action text NOT NULL",
		"entry_name text NOT NULL",
		"base_spec_hash text",
		"body jsonb",
		"request_hash bytea NOT NULL",
		"idempotency_key text NOT NULL",
		"created_at timestamptz NOT NULL",
		"expires_at timestamptz NOT NULL",
		"used_at timestamptz",
		"CONSTRAINT catalog_write_confirmations_token_len CHECK (octet_length(token_hash) = 32)",
		"CONSTRAINT catalog_write_confirmations_request_len CHECK (octet_length(request_hash) = 32)",
		"CONSTRAINT catalog_write_confirmations_action_chk CHECK (action IN ('create', 'update', 'delete'))",
		"CONSTRAINT catalog_write_confirmations_name_chk CHECK (entry_name ~ '^[a-z0-9][a-z0-9-]{0,47}$')",
		"CONSTRAINT catalog_write_confirmations_base_chk CHECK (base_spec_hash IS NULL OR base_spec_hash ~ '^[0-9a-f]{64}$')",
		"CONSTRAINT catalog_write_confirmations_key_chk CHECK (idempotency_key ~ '^[A-Za-z0-9._:-]{1,128}$')",
		"CONSTRAINT catalog_write_confirmations_body_chk CHECK (body IS NULL OR jsonb_typeof(body) = 'object')",
		"(action = 'create' AND body IS NOT NULL AND base_spec_hash IS NULL)",
		"(action = 'update' AND body IS NOT NULL AND base_spec_hash IS NOT NULL)",
		"(action = 'delete' AND body IS NULL AND base_spec_hash IS NOT NULL)",
		"CONSTRAINT catalog_write_confirmations_user_fk FOREIGN KEY (user_id) REFERENCES app.users (id) ON DELETE CASCADE",
		"CONSTRAINT catalog_write_confirmations_project_fk FOREIGN KEY (project_id) REFERENCES app.projects (id) ON DELETE CASCADE",
		"REVOKE ALL ON TABLE app.catalog_write_confirmations FROM deploybot_api",
		"GRANT SELECT, INSERT, DELETE ON TABLE app.catalog_write_confirmations TO deploybot_api",
		"GRANT UPDATE (used_at) ON TABLE app.catalog_write_confirmations TO deploybot_api",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("0013 missing %s", want)
		}
	}
	stmts := splitSQL(text)
	if len(stmts) != 4 {
		t.Fatalf("statements %d", len(stmts))
	}
	down, err := migrations.FS.ReadFile("0013_catalog_write_confirmations.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	downText := string(down)
	if !strings.Contains(downText, "DELETE FROM app.schema_migrations WHERE name = '0013_catalog_write_confirmations.sql'") {
		t.Fatal("down script does not document the schema_migrations delete")
	}
	if !strings.Contains(downText, "DROP TABLE IF EXISTS app.catalog_write_confirmations") {
		t.Fatal("down script does not drop the table")
	}
	downStmts := splitSQL(downText)
	if len(downStmts) != 1 || !strings.HasPrefix(strings.TrimSpace(downStmts[0]), "DROP TABLE IF EXISTS app.catalog_write_confirmations") {
		t.Fatalf("down statements %#v", downStmts)
	}
}

func TestCatalogWriteConfirmationsMigration(t *testing.T) {
	url := os.Getenv("DEPLOYBOT_TEST_DATABASE_URL")
	if url == "" {
		t.Skip()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	t.Cleanup(func() {
		restoreCatalogWriteTable(url)
	})
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
	if err := Migrate(ctx, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	var table string
	if err := d.pool.QueryRow(ctx, `SELECT to_regclass('app.catalog_write_confirmations')::text`).Scan(&table); err != nil || table != "app.catalog_write_confirmations" {
		t.Fatalf("table %s %v", table, err)
	}
	assertTablePrivs(t, d, ctx, "catalog_write_confirmations", true, true, false, true, []string{"used_at"})

	at := time.Now().UTC().Truncate(time.Microsecond)
	owner := catalogUser(t, d, ctx, "cw0013-owner", at)
	other := catalogUser(t, d, ctx, "cw0013-other", at)
	project := catalogProject(t, d, ctx, owner.ID, "CatalogWrite", "cw0013", at)
	host := enrollHostDB(t, d, ctx, project.ID, owner.ID, "cw-host", at)
	if err := d.UpsertDiscovered(ctx, host.ID, []store.Discovered{{
		Name: "swag", Kind: "process", Ports: []int{8080},
	}}, at, true, true); err != nil {
		t.Fatal(err)
	}
	svc := catalogService(t, d, ctx, host.ID, "swag", at)

	current := dbImageWrite(t, "web", `{"kind":"service","image":"nginx"}`, owner.ID, at)
	plain, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PutCatalogWriteConfirmation(ctx, hash, store.CatalogWriteConfirmation{
		UserID: owner.ID, ProjectID: project.ID, Action: "create", EntryName: "web",
		Body: current.ImageRaw, RequestHash: bytes.Repeat([]byte{1}, 32), IdempotencyKey: "cw-create",
		CreatedAt: at, ExpiresAt: at.Add(5 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	var blob string
	if err := d.pool.QueryRow(ctx, `
SELECT token_hash, body::text FROM app.catalog_write_confirmations WHERE entry_name = 'web' AND action = 'create'
`).Scan(&stored, &blob); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(stored, []byte(plain)) || !bytes.Equal(stored, hash) || strings.Contains(blob, plain) {
		t.Fatal("plaintext confirmation id was stored")
	}
	got, err := d.GetCatalogWriteConfirmation(ctx, hash)
	if err != nil || got.UserID != owner.ID || got.Action != "create" || got.BaseSpecHash != "" || got.UsedAt != nil {
		t.Fatalf("row %+v %v", got, err)
	}
	if !store.SameJSON(got.Body, current.ImageRaw) {
		t.Fatalf("body %s", got.Body)
	}
	if _, _, err := d.CommitCatalogWrite(ctx, hash, other.ID, at, current); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign commit %v", err)
	}
	if pending, err := d.GetCatalogWriteConfirmation(ctx, hash); err != nil || pending.UsedAt != nil {
		t.Fatal("foreign commit marked the plan")
	}
	_, entry, err := d.CommitCatalogWrite(ctx, hash, owner.ID, at, current)
	if err != nil || entry.Kind != "image" || entry.SpecHash != current.SpecHash {
		t.Fatalf("create %+v %v", entry, err)
	}
	if _, err := d.GetCatalogWriteConfirmation(ctx, hash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("applied create kept the plan %v", err)
	}
	twin, err := d.CreateCatalogEntry(ctx, project.ID, dbImageWrite(t, "twin", `{"kind":"service","image":"nginx"}`, owner.ID, at))
	if err != nil || twin.SpecHash != entry.SpecHash {
		t.Fatalf("twin hash %s %s %v", twin.SpecHash, entry.SpecHash, err)
	}
	if _, _, err := d.CommitCatalogWrite(ctx, hash, owner.ID, at, current); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second create commit %v", err)
	}

	if _, err := d.ApproveCatalog(ctx, host.ID, entry.ID, entry.SpecHash, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if catalogApprovalCount(t, d, ctx, entry.ID) != 1 {
		t.Fatal("approval missing")
	}
	next := dbImageWrite(t, "web", `{"kind":"service","image":"nginx:1.27"}`, owner.ID, at)
	_, staleHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PutCatalogWriteConfirmation(ctx, staleHash, store.CatalogWriteConfirmation{
		UserID: owner.ID, ProjectID: project.ID, Action: "update", EntryName: "web",
		BaseSpecHash: strings.Repeat("ab", 32), Body: next.ImageRaw, RequestHash: bytes.Repeat([]byte{2}, 32),
		IdempotencyKey: "cw-stale", CreatedAt: at, ExpiresAt: at.Add(5 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.CommitCatalogWrite(ctx, staleHash, owner.ID, at, next); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale %v", err)
	}
	if stale, err := d.GetCatalogWriteConfirmation(ctx, staleHash); err != nil || stale.UsedAt != nil {
		t.Fatal("stale commit marked the plan")
	}
	kept, err := d.GetCatalogEntry(ctx, project.ID, "web")
	if err != nil || kept.SpecHash != entry.SpecHash {
		t.Fatal("stale commit changed the entry")
	}
	_, updHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PutCatalogWriteConfirmation(ctx, updHash, store.CatalogWriteConfirmation{
		UserID: owner.ID, ProjectID: project.ID, Action: "update", EntryName: "web",
		BaseSpecHash: entry.SpecHash, Body: next.ImageRaw, RequestHash: bytes.Repeat([]byte{3}, 32),
		IdempotencyKey: "cw-upd", CreatedAt: at, ExpiresAt: at.Add(5 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	old, updated, err := d.CommitCatalogWrite(ctx, updHash, owner.ID, at, next)
	if err != nil || old != entry.SpecHash || updated.SpecHash != next.SpecHash {
		t.Fatalf("update %s %+v %v", old, updated, err)
	}
	if _, err := d.GetCatalogWriteConfirmation(ctx, updHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("applied update kept the plan %v", err)
	}
	if catalogApprovalCount(t, d, ctx, entry.ID) != 0 {
		t.Fatal("update did not void the approval")
	}

	if _, err := d.ApproveCatalog(ctx, host.ID, entry.ID, updated.SpecHash, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	_, delHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PutCatalogWriteConfirmation(ctx, delHash, store.CatalogWriteConfirmation{
		UserID: owner.ID, ProjectID: project.ID, Action: "delete", EntryName: "web",
		BaseSpecHash: updated.SpecHash, RequestHash: bytes.Repeat([]byte{4}, 32),
		IdempotencyKey: "cw-del", CreatedAt: at, ExpiresAt: at.Add(5 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.CommitCatalogWrite(ctx, delHash, owner.ID, at, store.CatalogWrite{Name: "web"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetCatalogWriteConfirmation(ctx, delHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("applied delete kept the plan %v", err)
	}
	if _, err := d.GetCatalogEntry(ctx, project.ID, "web"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted entry %v", err)
	}
	if catalogApprovalCount(t, d, ctx, entry.ID) != 0 {
		t.Fatal("delete left an approval")
	}
	var grants int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM app.catalog_grants WHERE entry_id = $1::uuid`, entry.ID.String()).Scan(&grants); err != nil || grants != 0 {
		t.Fatalf("grants %d %v", grants, err)
	}
	still, err := d.GetService(ctx, svc.ID, at)
	if err != nil || still.Name != "swag" {
		t.Fatalf("service %+v %v", still, err)
	}

	_, expHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	expWrite := dbImageWrite(t, "late", `{"kind":"service","image":"nginx"}`, owner.ID, at)
	if err := d.PutCatalogWriteConfirmation(ctx, expHash, store.CatalogWriteConfirmation{
		UserID: owner.ID, ProjectID: project.ID, Action: "create", EntryName: "late",
		Body: expWrite.ImageRaw, RequestHash: bytes.Repeat([]byte{5}, 32), IdempotencyKey: "cw-expired",
		CreatedAt: at, ExpiresAt: at.Add(-time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.CommitCatalogWrite(ctx, expHash, owner.ID, at, expWrite); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired %v", err)
	}
	if kept, err := d.GetCatalogWriteConfirmation(ctx, expHash); err != nil || kept.UsedAt != nil {
		t.Fatal("expired commit removed the plan")
	}
	_, freshHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	freshWrite := dbImageWrite(t, "kept", `{"kind":"service","image":"nginx"}`, owner.ID, at)
	if err := d.PutCatalogWriteConfirmation(ctx, freshHash, store.CatalogWriteConfirmation{
		UserID: owner.ID, ProjectID: project.ID, Action: "create", EntryName: "kept",
		Body: freshWrite.ImageRaw, RequestHash: bytes.Repeat([]byte{7}, 32), IdempotencyKey: "cw-fresh",
		CreatedAt: at, ExpiresAt: at.Add(5 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetCatalogWriteConfirmation(ctx, expHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("new plan kept an expired row %v", err)
	}
	if _, err := d.GetCatalogWriteConfirmation(ctx, freshHash); err != nil {
		t.Fatalf("new plan %v", err)
	}

	dropProject := catalogProject(t, d, ctx, owner.ID, "CatalogWriteDrop", "cw0013drop", at)
	_, dropHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PutCatalogWriteConfirmation(ctx, dropHash, store.CatalogWriteConfirmation{
		UserID: owner.ID, ProjectID: dropProject.ID, Action: "create", EntryName: "web",
		Body: current.ImageRaw, RequestHash: bytes.Repeat([]byte{8}, 32), IdempotencyKey: "cw-drop",
		CreatedAt: at, ExpiresAt: at.Add(5 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.DeleteProject(ctx, dropProject.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetCatalogWriteConfirmation(ctx, dropHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("project delete kept the plan %v", err)
	}

	bad := store.CatalogWriteConfirmation{
		UserID: owner.ID, ProjectID: project.ID, Action: "nope", EntryName: "web",
		Body: current.ImageRaw, RequestHash: bytes.Repeat([]byte{6}, 32), IdempotencyKey: "cw-bad-action",
		CreatedAt: at, ExpiresAt: at.Add(time.Minute),
	}
	if _, badHash, err := secret.NewToken(); err != nil {
		t.Fatal(err)
	} else if err := d.PutCatalogWriteConfirmation(ctx, badHash, bad); !checkViolation(err) {
		t.Fatalf("bad action %v", err)
	}
	shaped := bad
	shaped.Action = "create"
	shaped.BaseSpecHash = entry.SpecHash
	shaped.IdempotencyKey = "cw-bad-shape"
	if _, shapeHash, err := secret.NewToken(); err != nil {
		t.Fatal(err)
	} else if err := d.PutCatalogWriteConfirmation(ctx, shapeHash, shaped); !checkViolation(err) {
		t.Fatalf("create with base %v", err)
	}

	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal("connect failed")
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `SET ROLE deploybot_owner`); err != nil {
		t.Fatal(err)
	}
	down, err := migrations.FS.ReadFile("0013_catalog_write_confirmations.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	stmts := splitSQL(string(down))
	if len(stmts) != 1 {
		t.Fatalf("down statements %d", len(stmts))
	}
	if _, err := conn.Exec(ctx, stmts[0]); err != nil {
		t.Fatal(err)
	}
	var gone *string
	if err := conn.QueryRow(ctx, `SELECT to_regclass('app.catalog_write_confirmations')::text`).Scan(&gone); err != nil {
		t.Fatal(err)
	}
	if gone != nil {
		t.Fatalf("table remains %s", *gone)
	}
	if _, err := conn.Exec(ctx, `DELETE FROM app.schema_migrations WHERE name = '0013_catalog_write_confirmations.sql'`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, url); err != nil {
		t.Fatalf("restore migrate: %v", err)
	}
	var restored string
	if err := d.pool.QueryRow(ctx, `SELECT to_regclass('app.catalog_write_confirmations')::text`).Scan(&restored); err != nil || restored != "app.catalog_write_confirmations" {
		t.Fatalf("restored %s %v", restored, err)
	}
}

func restoreCatalogWriteTable(url string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	d, err := Open(ctx, url)
	if err != nil {
		return
	}
	defer d.Close()
	var table *string
	if err := d.pool.QueryRow(ctx, `SELECT to_regclass('app.catalog_write_confirmations')::text`).Scan(&table); err != nil {
		return
	}
	if table == nil {
		_ = Migrate(ctx, url)
	}
}

func dbImageWrite(t *testing.T, name, raw string, actor uuid.UUID, at time.Time) store.CatalogWrite {
	t.Helper()
	img, err := catalog.BuildImage(name, []byte(raw), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec := []byte(catalog.SpecJSON(img))
	return store.CatalogWrite{
		Name: name, Kind: "image", ImageRaw: spec,
		SpecHash: catalog.ImageHash(img, nil), CommandDisplay: img.Image,
		Actor: actor, At: at,
	}
}
