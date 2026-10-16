package db

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/seal"
	"github.com/more-than-code/bot-api-server/internal/store"
	"github.com/more-than-code/bot-api-server/migrations"
)

func TestCatalogImagesMigrationText(t *testing.T) {
	body, err := migrations.FS.ReadFile("0009_catalog_images.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"app.image_deploys",
		"app.env_sets",
		"app.env_values",
		"app.registries",
		"image_deploys_in_flight_uidx",
		"'deploy'",
		"image_digest",
		"image_force",
		"in_flight_until",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("0009 missing %s", want)
		}
	}
	down, err := migrations.FS.ReadFile("0009_catalog_images.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(down), "Take a dump first") {
		t.Fatal("down script does not warn that ciphertext is dropped")
	}
	if !strings.Contains(string(down), "DELETE FROM app.schema_migrations WHERE name = '0009_catalog_images.sql'") {
		t.Fatal("down script does not document the schema_migrations delete")
	}
	start := strings.Index(text, "CREATE UNIQUE INDEX image_deploys_in_flight_uidx")
	if start < 0 {
		t.Fatal("missing unique in-flight index")
	}
	stmt := text[start:]
	if end := strings.Index(stmt, ";"); end >= 0 {
		stmt = stmt[:end]
	}
	low := strings.ToLower(stmt)
	if !strings.Contains(low, "unique") || !strings.Contains(low, "where in_flight") || strings.Contains(low, "not in_flight") {
		t.Fatalf("in-flight index %s", stmt)
	}
}

func assertImages(t *testing.T, d *DB, ctx context.Context, at time.Time) {
	t.Helper()
	assertImageSchema(t, d, ctx)
	owner := catalogUser(t, d, ctx, "image-owner", at)
	home := catalogProject(t, d, ctx, owner.ID, "Images", "imgproj", at)
	host := enrollHostDB(t, d, ctx, home.ID, owner.ID, "img-host", at)
	box, err := seal.New(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	img, err := catalog.BuildImage("web", []byte(`{"kind":"service","image":"nginx","env_sets":["svc"]}`), catalog.SetKeys{"svc": {"TOKEN"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash := catalog.ImageHash(img, map[string]string{"svc": catalog.EnvKeyDigest([]string{"TOKEN"})})
	entry, err := d.CreateCatalogEntry(ctx, home.ID, store.CatalogWrite{
		Name: "web", Kind: "image", ImageRaw: []byte(catalog.SpecJSON(img)),
		SpecHash: hash, CommandDisplay: img.Image, Actor: owner.ID, At: at,
	})
	if err != nil || entry.Kind != "image" || entry.CommandDisplay != img.Image {
		t.Fatalf("entry %+v %v", entry, err)
	}
	grants, err := d.ListCatalogGrants(ctx, entry.ID)
	if err != nil || !grantIs(grants, "role:admin", "run", "stop", "restart", "logs", "deploy") || !grantIs(grants, "role:viewer", "logs") {
		t.Fatalf("grants %#v %v", grants, err)
	}
	nonce, ciphertext, err := box.Seal(seal.EnvAAD(home.ID.String(), "svc", "TOKEN"), []byte("db-secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{{
		Key: "TOKEN", Nonce: nonce, Ciphertext: ciphertext, KeyVersion: seal.KeyVersion,
	}}, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	set, err := d.GetEnvSet(ctx, home.ID, "svc")
	if err != nil || len(set.Keys) != 1 || set.Keys[0].Value != nil || !set.Keys[0].IsSecret {
		t.Fatalf("env set returned a value %#v %v", set, err)
	}
	var plain *string
	var stored []byte
	if err := d.pool.QueryRow(ctx, `
SELECT value, ciphertext FROM app.env_values
WHERE project_id = $1::uuid AND set_name = 'svc' AND key = 'TOKEN'
`, home.ID.String()).Scan(&plain, &stored); err != nil {
		t.Fatal(err)
	}
	if plain != nil || bytes.Contains(stored, []byte("db-secret-value")) {
		t.Fatal("env value stored in the clear")
	}
	if _, err := d.ApproveCatalog(ctx, host.ID, entry.ID, hash, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	nonce2, ct2, err := box.Seal(seal.EnvAAD(home.ID.String(), "svc", "TOKEN"), []byte("other-secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{{
		Key: "TOKEN", Nonce: nonce2, Ciphertext: ct2, KeyVersion: seal.KeyVersion,
	}}, owner.ID, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	same, err := d.GetCatalogEntry(ctx, home.ID, "web")
	if err != nil || same.SpecHash != hash || catalogApprovalCount(t, d, ctx, entry.ID) != 1 {
		t.Fatalf("value change hash %s approvals %d %v", same.SpecHash, catalogApprovalCount(t, d, ctx, entry.ID), err)
	}
	nA, cA, err := box.Seal(seal.EnvAAD(home.ID.String(), "svc", "TOKEN"), []byte("db-secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	nB, cB, err := box.Seal(seal.EnvAAD(home.ID.String(), "svc", "ADDED"), []byte("added-secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{
		{Key: "TOKEN", Nonce: nA, Ciphertext: cA, KeyVersion: seal.KeyVersion},
		{Key: "ADDED", Nonce: nB, Ciphertext: cB, KeyVersion: seal.KeyVersion},
	}, owner.ID, at.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	changed, err := d.GetCatalogEntry(ctx, home.ID, "web")
	if err != nil || changed.SpecHash == hash || catalogApprovalCount(t, d, ctx, entry.ID) != 0 {
		t.Fatalf("key add hash %s approvals %d %v", changed.SpecHash, catalogApprovalCount(t, d, ctx, entry.ID), err)
	}
	rn, rc, err := box.Seal(seal.RegistryAAD(home.ID.String(), "ghcr.io"), []byte("registry-token-value"))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := d.PutRegistry(ctx, home.ID, "ghcr.io", store.RegistryWrite{
		Username: "bot", Nonce: rn, Ciphertext: rc, KeyVersion: seal.KeyVersion,
	}, owner.ID, at)
	if err != nil || reg.Username != "bot" || reg.Host != "ghcr.io" {
		t.Fatalf("registry %+v %v", reg, err)
	}
	listed, err := d.ListRegistries(ctx, home.ID)
	raw, mErr := listedJSON(listed)
	if err != nil || mErr != nil || strings.Contains(raw, "registry-token-value") {
		t.Fatalf("registry list leaked %s %v", raw, err)
	}
	row, err := d.BeginImageOp(ctx, entry.ID, host.ID, changed.SpecHash, owner.ID, "console", at, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.BeginImageOp(ctx, entry.ID, host.ID, changed.SpecHash, owner.ID, "console", at, at.Add(time.Hour)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("in flight %v", err)
	}
	digest := "sha256:" + strings.Repeat("ab", 32)
	if _, err := d.FinishImageDeploy(ctx, row.ID, "succeeded", &digest, nil, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	history, err := d.ListImageDeploys(ctx, entry.ID, host.ID)
	if err != nil || len(history) != 1 || history[0].Outcome != "succeeded" || history[0].Digest == nil || *history[0].Digest != digest {
		t.Fatalf("history %#v %v", history, err)
	}
	opened, err := d.BeginImageOp(ctx, entry.ID, host.ID, changed.SpecHash, owner.ID, "console", at.Add(2*time.Second), at.Add(time.Hour))
	if err != nil {
		t.Fatalf("begin after finish %v", err)
	}
	if err := d.ReleaseImageOp(ctx, opened.ID); err != nil {
		t.Fatal(err)
	}
	dB := "sha256:" + strings.Repeat("cd", 32)
	dC := "sha256:" + strings.Repeat("ef", 32)
	dD := "sha256:" + strings.Repeat("11", 32)
	dE := "sha256:" + strings.Repeat("22", 32)
	finishDeploy(t, d, ctx, entry.ID, host.ID, changed.SpecHash, owner.ID, "unchanged", dB, at.Add(3*time.Second))
	finishDeploy(t, d, ctx, entry.ID, host.ID, changed.SpecHash, owner.ID, "succeeded", dC, at.Add(4*time.Second))
	finishDeploy(t, d, ctx, entry.ID, host.ID, changed.SpecHash, owner.ID, "failed", dD, at.Add(5*time.Second))
	finishDeploy(t, d, ctx, entry.ID, host.ID, changed.SpecHash, owner.ID, "succeeded", dE, at.Add(6*time.Second))
	finishDeploy(t, d, ctx, entry.ID, host.ID, changed.SpecHash, owner.ID, "succeeded", dB, at.Add(7*time.Second))
	got, err := d.RollbackDigests(ctx, entry.ID, host.ID)
	if err != nil || len(got) != 3 || got[0] != dB || got[1] != dE || got[2] != dC {
		t.Fatalf("rollback digests %#v %v", got, err)
	}
	stuckAt := at.Add(8 * time.Second)
	stuck, err := d.BeginImageOp(ctx, entry.ID, host.ID, changed.SpecHash, owner.ID, "console", stuckAt, stuckAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	takenAt := stuckAt.Add(2 * time.Minute)
	taken, err := d.BeginImageOp(ctx, entry.ID, host.ID, changed.SpecHash, owner.ID, "console", takenAt, takenAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("stale takeover %v", err)
	}
	if _, err := d.BeginImageOp(ctx, entry.ID, host.ID, changed.SpecHash, owner.ID, "console", takenAt, takenAt.Add(time.Hour)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("fresh row %v", err)
	}
	var stuckOutcome string
	var stuckFlight bool
	if err := d.pool.QueryRow(ctx, `SELECT outcome, in_flight FROM app.image_deploys WHERE id = $1::uuid`, stuck.ID.String()).Scan(&stuckOutcome, &stuckFlight); err != nil || stuckOutcome != "timeout" || stuckFlight {
		t.Fatalf("stale row %s %v %v", stuckOutcome, stuckFlight, err)
	}
	if err := d.ReleaseImageOp(ctx, taken.ID); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	free := func() { releaseOnce.Do(func() { close(release) }) }
	defer free()
	prevHold := beginImageOpAfterSelect
	beginImageOpAfterSelect = func() {
		entered <- struct{}{}
		<-release
	}
	defer func() { beginImageOpAfterSelect = prevHold }()
	type beginResult struct {
		row store.ImageDeploy
		err error
	}
	results := make(chan beginResult, 2)
	raceAt := at.Add(10 * time.Minute)
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			row, err := d.BeginImageOp(ctx, entry.ID, host.ID, changed.SpecHash, owner.ID, "console", raceAt, raceAt.Add(time.Hour))
			results <- beginResult{row, err}
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			free()
			t.Fatal("both begins did not pass the empty in-flight select")
		}
	}
	free()
	wg.Wait()
	okN, conflictN := 0, 0
	var winner uuid.UUID
	for i := 0; i < 2; i++ {
		got := <-results
		if got.err == nil {
			okN++
			winner = got.row.ID
			continue
		}
		if errors.Is(got.err, store.ErrConflict) {
			conflictN++
			continue
		}
		t.Fatalf("race %v", got.err)
	}
	if okN != 1 || conflictN != 1 {
		t.Fatalf("race ok %d conflict %d", okN, conflictN)
	}
	if err := d.ReleaseImageOp(ctx, winner); err != nil {
		t.Fatal(err)
	}
	_, err = d.pool.Exec(ctx, `
INSERT INTO app.env_values (project_id, set_name, key, is_secret, value)
VALUES ($1::uuid, 'svc', 'LEAK', true, 'plain-and-secret')
`, home.ID.String())
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("form check insert %v", err)
	}
	if _, err := d.DeleteProject(ctx, home.ID, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM app.env_sets WHERE project_id = $1::uuid`, home.ID.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("env sets left %d %v", n, err)
	}
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM app.registries WHERE project_id = $1::uuid`, home.ID.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("registries left %d %v", n, err)
	}
}

func assertImageSchema(t *testing.T, d *DB, ctx context.Context) {
	t.Helper()
	for _, table := range []string{"image_deploys", "env_sets", "env_values", "registries", "project_files"} {
		var name *string
		if err := d.pool.QueryRow(ctx, `SELECT to_regclass($1)`, "app."+table).Scan(&name); err != nil || name == nil {
			t.Fatalf("table %s %v", table, err)
		}
	}
	var kindCheck string
	if err := d.pool.QueryRow(ctx, `
SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'catalog_entries_kind_chk'
`).Scan(&kindCheck); err != nil || !strings.Contains(kindCheck, "image") {
		t.Fatalf("kind check %s %v", kindCheck, err)
	}
	var cols int
	if err := d.pool.QueryRow(ctx, `
SELECT count(*) FROM information_schema.columns
WHERE table_schema = 'app' AND table_name = 'catalog_confirmations'
  AND column_name IN ('image_digest', 'image_force')
`).Scan(&cols); err != nil || cols != 2 {
		t.Fatalf("confirmation columns %d %v", cols, err)
	}
	var digest *string
	if err := d.pool.QueryRow(ctx, `
SELECT data_type FROM information_schema.columns
WHERE table_schema = 'app' AND table_name = 'services' AND column_name = 'image_digest'
`).Scan(&digest); err != nil || digest == nil || *digest != "text" {
		t.Fatalf("image_digest %v %v", digest, err)
	}
	assertTablePrivs(t, d, ctx, "image_deploys", true, true, false, true, []string{"digest", "outcome", "exit_code", "finished_at", "in_flight"})
	assertTablePrivs(t, d, ctx, "env_sets", true, true, false, true, []string{"updated_at", "updated_by"})
	assertTablePrivs(t, d, ctx, "env_values", true, true, false, true, []string{"is_secret", "value", "nonce", "ciphertext", "key_version"})
	assertTablePrivs(t, d, ctx, "registries", true, true, false, true, []string{"username", "nonce", "ciphertext", "key_version", "updated_at", "updated_by"})
	assertTablePrivs(t, d, ctx, "project_files", true, true, false, true, []string{"is_secret", "content_plain", "nonce", "content_cipher", "key_version", "sha256", "size", "updated_by", "updated_at"})
	var indexDef string
	if err := d.pool.QueryRow(ctx, `SELECT pg_get_indexdef(to_regclass('app.image_deploys_in_flight_uidx'))`).Scan(&indexDef); err != nil {
		t.Fatal(err)
	}
	low := strings.ToLower(indexDef)
	whereAt := strings.Index(low, "where")
	if !strings.Contains(low, "unique") || whereAt < 0 || strings.Contains(low[whereAt:], "not") || !strings.Contains(low[whereAt:], "in_flight") {
		t.Fatalf("in-flight index %s", indexDef)
	}
	var untilType *string
	if err := d.pool.QueryRow(ctx, `
SELECT data_type FROM information_schema.columns
WHERE table_schema = 'app' AND table_name = 'image_deploys' AND column_name = 'in_flight_until'
`).Scan(&untilType); err != nil || untilType == nil || *untilType != "timestamp with time zone" {
		t.Fatalf("in_flight_until %v %v", untilType, err)
	}
	var form string
	if err := d.pool.QueryRow(ctx, `
SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'env_values_form_chk'
`).Scan(&form); err != nil || !strings.Contains(form, "is_secret") || !strings.Contains(form, "nonce") {
		t.Fatalf("form check %s %v", form, err)
	}
}

func finishDeploy(t *testing.T, d *DB, ctx context.Context, entryID, hostID uuid.UUID, specHash string, by uuid.UUID, outcome, digest string, at time.Time) {
	t.Helper()
	row, err := d.BeginImageOp(ctx, entryID, hostID, specHash, by, "console", at, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.FinishImageDeploy(ctx, row.ID, outcome, &digest, nil, at); err != nil {
		t.Fatal(err)
	}
}

func listedJSON(items []store.Registry) (string, error) {
	raw, err := json.Marshal(items)
	return string(raw), err
}
