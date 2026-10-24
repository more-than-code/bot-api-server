package db

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/seal"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// assertEnvMakeSecret covers MakeEnvKeysSecret (api-v1 v1.17): conversion of
// two keys, the seal round trip, atomic refusal, idempotency, updated_at, the
// stored row form, and an unchanged spec_hash and approval.
func assertEnvMakeSecret(t *testing.T, d *DB, ctx context.Context, at time.Time) {
	t.Helper()
	owner := catalogUser(t, d, ctx, "env-secret", at)
	home := catalogProject(t, d, ctx, owner.ID, "Secret", "envsecret", at)
	host := enrollHostDB(t, d, ctx, home.ID, owner.ID, "secret-host", at)
	box, err := seal.New(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	pid := home.ID.String()
	plainOf := func(key, plain string) store.EnvSecret {
		t.Helper()
		nonce, ciphertext, err := box.Seal(seal.EnvAAD(pid, "svc", key), []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		return store.EnvSecret{Key: key, Plain: plain, Nonce: nonce, Ciphertext: ciphertext, KeyVersion: seal.KeyVersion}
	}
	if _, err := d.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{
		plainOf("A", "alpha"), plainOf("B", "bravo"), plainOf("C", "charlie"),
	}, owner.ID, at, false); err != nil {
		t.Fatal(err)
	}
	img, err := catalog.BuildImage("web", []byte(`{"kind":"service","image":"nginx","env_sets":["svc"]}`), catalog.SetKeys{"svc": {"A", "B", "C"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash := catalog.ImageHash(img, map[string]string{"svc": catalog.EnvKeyDigest([]string{"A", "B", "C"})})
	entry, err := d.CreateCatalogEntry(ctx, home.ID, store.CatalogWrite{
		Name: "web", Kind: "image", ImageRaw: []byte(catalog.SpecJSON(img)),
		SpecHash: hash, CommandDisplay: img.Image, Actor: owner.ID, At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ApproveCatalog(ctx, host.ID, entry.ID, hash, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	sealer := func(key, plain string) (store.EnvSecret, error) {
		nonce, ciphertext, err := box.Seal(seal.EnvAAD(pid, "svc", key), []byte(plain))
		return store.EnvSecret{Key: key, Nonce: nonce, Ciphertext: ciphertext, KeyVersion: seal.KeyVersion}, err
	}
	failSeal := func(string, string) (store.EnvSecret, error) { return store.EnvSecret{}, errors.New("seal failed") }

	// Atomic refusal: B is valid, GONE is not, and B stays plain.
	_, _, err = d.MakeEnvKeysSecret(ctx, home.ID, "svc", []string{"B", "GONE"}, sealer, owner.ID, at.Add(time.Minute))
	var missing *store.MissingEnvKeyError
	if !errors.As(err, &missing) || missing.Key != "GONE" || !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing key %v", err)
	}
	if rows := envRows(t, d, ctx, home.ID, "svc"); rows["B"].IsSecret || rows["B"].Plain != "bravo" {
		t.Fatal("refusal changed B")
	}
	if _, _, err := d.MakeEnvKeysSecret(ctx, home.ID, "nope", []string{"A"}, sealer, owner.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing set %v", err)
	}
	// A seal error after one key was updated rolls the whole call back.
	calls := 0
	secondFails := func(key, plain string) (store.EnvSecret, error) {
		calls++
		if calls == 2 {
			return store.EnvSecret{}, errors.New("seal failed")
		}
		return sealer(key, plain)
	}
	if _, _, err := d.MakeEnvKeysSecret(ctx, home.ID, "svc", []string{"A", "B"}, secondFails, owner.ID, at.Add(30*time.Second)); err == nil || err.Error() != "seal failed" || calls != 2 {
		t.Fatalf("seal error %v", err)
	}
	if rows := envRows(t, d, ctx, home.ID, "svc"); rows["A"].IsSecret || rows["A"].Plain != "alpha" {
		t.Fatal("failed seal left A secret")
	}
	view, err := d.GetEnvSet(ctx, home.ID, "svc")
	if err != nil || !view.UpdatedAt.Equal(at) {
		t.Fatalf("refusals moved updated_at %s %v", view.UpdatedAt, err)
	}

	set, changed, err := d.MakeEnvKeysSecret(ctx, home.ID, "svc", []string{"B", "A"}, sealer, owner.ID, at.Add(time.Minute))
	if err != nil || len(changed) != 2 || changed[0] != "A" || changed[1] != "B" {
		t.Fatalf("convert %v %v", changed, err)
	}
	if !set.UpdatedAt.Equal(at.Add(time.Minute)) || set.UpdatedBy != owner.ID || len(set.Keys) != 3 {
		t.Fatalf("set %#v", set)
	}
	for _, key := range set.Keys {
		wantSecret := key.Key != "C"
		if key.IsSecret != wantSecret || (key.Value == nil) != wantSecret {
			t.Fatalf("view %#v", key)
		}
	}
	rows := envRows(t, d, ctx, home.ID, "svc")
	for key, want := range map[string]string{"A": "alpha", "B": "bravo"} {
		row := rows[key]
		if !row.IsSecret || row.Plain != "" || row.KeyVersion != seal.KeyVersion {
			t.Fatalf("%s stored secret=%v version=%d", key, row.IsSecret, row.KeyVersion)
		}
		opened, err := box.Open(seal.EnvAAD(pid, "svc", key), row.Nonce, row.Ciphertext)
		if err != nil || string(opened) != want {
			t.Fatalf("%s did not open to the original value %v", key, err)
		}
	}
	if rows["C"].IsSecret || rows["C"].Plain != "charlie" {
		t.Fatal("C changed")
	}
	// The stored form satisfies env_values_form_chk: value NULL with a seal.
	var bad int
	if err := d.pool.QueryRow(ctx, `
SELECT count(*) FROM app.env_values
WHERE project_id = $1::uuid AND set_name = 'svc' AND key IN ('A', 'B')
  AND NOT (is_secret AND value IS NULL AND nonce IS NOT NULL AND ciphertext IS NOT NULL AND key_version IS NOT NULL)
`, pid).Scan(&bad); err != nil || bad != 0 {
		t.Fatalf("row form %d %v", bad, err)
	}

	// Duplicate keys at store level: C is sealed once and listed once.
	sealed := 0
	counting := func(key, plain string) (store.EnvSecret, error) {
		sealed++
		return sealer(key, plain)
	}
	_, changed, err = d.MakeEnvKeysSecret(ctx, home.ID, "svc", []string{"C", "C"}, counting, owner.ID, at.Add(time.Minute))
	if err != nil || len(changed) != 1 || changed[0] != "C" || sealed != 1 {
		t.Fatalf("duplicate %v sealed %d %v", changed, sealed, err)
	}
	c := envRows(t, d, ctx, home.ID, "svc")["C"]
	if opened, err := box.Open(seal.EnvAAD(pid, "svc", "C"), c.Nonce, c.Ciphertext); err != nil || string(opened) != "charlie" {
		t.Fatalf("C did not open to the original value %v", err)
	}

	// Idempotent: already-secret keys are skipped and the set is not touched.
	_, changed, err = d.MakeEnvKeysSecret(ctx, home.ID, "svc", []string{"A", "B"}, failSeal, owner.ID, at.Add(2*time.Minute))
	if err != nil || len(changed) != 0 {
		t.Fatalf("repeat %v %v", changed, err)
	}
	view, err = d.GetEnvSet(ctx, home.ID, "svc")
	if err != nil || !view.UpdatedAt.Equal(at.Add(time.Minute)) {
		t.Fatalf("repeat moved updated_at %s %v", view.UpdatedAt, err)
	}

	got, err := d.GetCatalogEntry(ctx, home.ID, "web")
	if err != nil || got.SpecHash != hash || catalogApprovalCount(t, d, ctx, entry.ID) != 1 {
		t.Fatalf("hash %s approvals %d %v", got.SpecHash, catalogApprovalCount(t, d, ctx, entry.ID), err)
	}
	assertEnvMakeSecretGrants(t, d, ctx)
	assertEnvMakeSecretMany(t, d, ctx, home.ID, owner.ID, box, at)

	plainFlag := false
	if _, _, err := d.PutEnvKey(ctx, home.ID, "svc", store.EnvKeyPut{Key: "A", Plain: "x", Secret: &plainFlag}, owner.ID, at); !errors.Is(err, store.ErrSecretFixed) {
		t.Fatalf("flag %v", err)
	}
}

// assertEnvMakeSecretGrants checks the column grants MakeEnvKeysSecret needs.
func assertEnvMakeSecretGrants(t *testing.T, d *DB, ctx context.Context) {
	t.Helper()
	for _, col := range []struct{ table, column string }{
		{"app.env_values", "is_secret"},
		{"app.env_values", "value"},
		{"app.env_values", "nonce"},
		{"app.env_values", "ciphertext"},
		{"app.env_values", "key_version"},
		{"app.env_sets", "updated_at"},
		{"app.env_sets", "updated_by"},
	} {
		var ok bool
		if err := d.pool.QueryRow(ctx, `SELECT has_column_privilege('deploybot_api', $1, $2, 'UPDATE')`, col.table, col.column).Scan(&ok); err != nil || !ok {
			t.Fatalf("deploybot_api UPDATE on %s.%s: %v %v", col.table, col.column, ok, err)
		}
	}
}

// assertEnvMakeSecretMany converts the 200-key maximum in one call.
func assertEnvMakeSecretMany(t *testing.T, d *DB, ctx context.Context, projectID, actor uuid.UUID, box *seal.Box, at time.Time) {
	t.Helper()
	pid := projectID.String()
	keys := make([]string, 200)
	pairs := make([]store.EnvSecret, 200)
	for i := range keys {
		keys[i] = fmt.Sprintf("K%03d", i)
		pairs[i] = store.EnvSecret{Key: keys[i], Plain: "value-" + keys[i]}
	}
	if _, err := d.PutEnvSet(ctx, projectID, "many", pairs, actor, at, false); err != nil {
		t.Fatal(err)
	}
	sealer := func(key, plain string) (store.EnvSecret, error) {
		nonce, ciphertext, err := box.Seal(seal.EnvAAD(pid, "many", key), []byte(plain))
		return store.EnvSecret{Key: key, Nonce: nonce, Ciphertext: ciphertext, KeyVersion: seal.KeyVersion}, err
	}
	_, changed, err := d.MakeEnvKeysSecret(ctx, projectID, "many", keys, sealer, actor, at.Add(time.Minute))
	if err != nil || len(changed) != 200 {
		t.Fatalf("200 keys changed %d %v", len(changed), err)
	}
	rows := envRows(t, d, ctx, projectID, "many")
	for _, key := range keys {
		row := rows[key]
		opened, err := box.Open(seal.EnvAAD(pid, "many", key), row.Nonce, row.Ciphertext)
		if !row.IsSecret || row.Plain != "" || err != nil || string(opened) != "value-"+key {
			t.Fatalf("%s secret=%v %v", key, row.IsSecret, err)
		}
	}
}
