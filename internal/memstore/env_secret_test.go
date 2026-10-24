package memstore

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/seal"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// TestMakeEnvKeysSecret mirrors the db assertion assertEnvMakeSecret (api-v1 v1.17).
func TestMakeEnvKeysSecret(t *testing.T) {
	ctx := context.Background()
	m := New()
	at := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	owner := catalogUser(t, m, "secret-owner")
	home := catalogProject(t, m, owner.ID, "Sec", "sec", at)
	host := catalogHost(t, m, home, owner.ID, "pi", at)
	box, err := seal.New(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	pid := home.ID.String()
	plainOf := func(key, plain string) store.EnvSecret {
		got := sealKey(t, box, pid, "svc", key, plain)
		got.Plain = plain
		return got
	}
	if _, err := m.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{
		plainOf("A", "alpha"), plainOf("B", "bravo"), plainOf("C", "charlie"),
	}, owner.ID, at, false); err != nil {
		t.Fatal(err)
	}
	img, err := catalog.BuildImage("web", []byte(`{"kind":"service","image":"nginx","env_sets":["svc"]}`), catalog.SetKeys{"svc": {"A", "B", "C"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash := catalog.ImageHash(img, map[string]string{"svc": catalog.EnvKeyDigest([]string{"A", "B", "C"})})
	entry, err := m.CreateCatalogEntry(ctx, home.ID, store.CatalogWrite{
		Name: "web", Kind: "image", ImageRaw: []byte(catalog.SpecJSON(img)),
		SpecHash: hash, CommandDisplay: img.Image, Actor: owner.ID, At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApproveCatalog(ctx, host.ID, entry.ID, hash, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	sealer := func(key, plain string) (store.EnvSecret, error) {
		nonce, ciphertext, err := box.Seal(seal.EnvAAD(pid, "svc", key), []byte(plain))
		return store.EnvSecret{Key: key, Nonce: nonce, Ciphertext: ciphertext, KeyVersion: seal.KeyVersion}, err
	}

	// Atomic refusal: B is valid, GONE is not, and B stays plain.
	_, _, err = m.MakeEnvKeysSecret(ctx, home.ID, "svc", []string{"B", "GONE"}, sealer, owner.ID, at.Add(time.Minute))
	var missing *store.MissingEnvKeyError
	if !errors.As(err, &missing) || missing.Key != "GONE" || !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing key %v", err)
	}
	if rows := envMaterialMap(t, m, ctx, home.ID, "svc"); rows["B"].IsSecret || rows["B"].Plain != "bravo" {
		t.Fatalf("refusal changed B %#v", rows["B"])
	}
	if _, _, err := m.MakeEnvKeysSecret(ctx, home.ID, "nope", []string{"A"}, sealer, owner.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing set %v", err)
	}
	failSeal := func(string, string) (store.EnvSecret, error) { return store.EnvSecret{}, errors.New("seal failed") }
	if _, _, err := m.MakeEnvKeysSecret(ctx, home.ID, "svc", []string{"A"}, failSeal, owner.ID, at.Add(30*time.Second)); err == nil || err.Error() != "seal failed" {
		t.Fatalf("seal error %v", err)
	}
	if rows := envMaterialMap(t, m, ctx, home.ID, "svc"); rows["A"].IsSecret {
		t.Fatal("failed seal changed A")
	}
	// A seal error on the second key leaves the first key plain too.
	calls := 0
	secondFails := func(key, plain string) (store.EnvSecret, error) {
		calls++
		if calls == 2 {
			return store.EnvSecret{}, errors.New("seal failed")
		}
		return sealer(key, plain)
	}
	if _, _, err := m.MakeEnvKeysSecret(ctx, home.ID, "svc", []string{"A", "B"}, secondFails, owner.ID, at.Add(30*time.Second)); err == nil || err.Error() != "seal failed" || calls != 2 {
		t.Fatalf("second seal error %v calls %d", err, calls)
	}
	if rows := envMaterialMap(t, m, ctx, home.ID, "svc"); rows["A"].IsSecret || rows["A"].Plain != "alpha" {
		t.Fatalf("failed seal left A changed %#v", rows["A"])
	}
	view, err := m.GetEnvSet(ctx, home.ID, "svc")
	if err != nil || !view.UpdatedAt.Equal(at) {
		t.Fatalf("refusals moved updated_at %s %v", view.UpdatedAt, err)
	}

	set, changed, err := m.MakeEnvKeysSecret(ctx, home.ID, "svc", []string{"B", "A"}, sealer, owner.ID, at.Add(time.Minute))
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
	rows := envMaterialMap(t, m, ctx, home.ID, "svc")
	for key, want := range map[string]string{"A": "alpha", "B": "bravo"} {
		row := rows[key]
		if !row.IsSecret || row.Plain != "" || row.KeyVersion != seal.KeyVersion {
			t.Fatalf("%s stored %#v", key, row)
		}
		opened, err := box.Open(seal.EnvAAD(pid, "svc", key), row.Nonce, row.Ciphertext)
		if err != nil || string(opened) != want {
			t.Fatalf("%s opened %q %v", key, opened, err)
		}
	}
	if rows["C"].IsSecret || rows["C"].Plain != "charlie" {
		t.Fatalf("C changed %#v", rows["C"])
	}

	// Duplicate keys at store level: C is sealed once and listed once.
	sealed := 0
	counting := func(key, plain string) (store.EnvSecret, error) {
		sealed++
		return sealer(key, plain)
	}
	_, changed, err = m.MakeEnvKeysSecret(ctx, home.ID, "svc", []string{"C", "C"}, counting, owner.ID, at.Add(time.Minute))
	if err != nil || len(changed) != 1 || changed[0] != "C" || sealed != 1 {
		t.Fatalf("duplicate %v sealed %d %v", changed, sealed, err)
	}
	rowC := envMaterialMap(t, m, ctx, home.ID, "svc")["C"]
	if opened, err := box.Open(seal.EnvAAD(pid, "svc", "C"), rowC.Nonce, rowC.Ciphertext); err != nil || string(opened) != "charlie" {
		t.Fatalf("C opened %q %v", opened, err)
	}

	// Idempotent: already-secret keys are skipped and the set is not touched.
	_, changed, err = m.MakeEnvKeysSecret(ctx, home.ID, "svc", []string{"A", "B"}, failSeal, owner.ID, at.Add(2*time.Minute))
	if err != nil || len(changed) != 0 {
		t.Fatalf("repeat %v %v", changed, err)
	}
	view, err = m.GetEnvSet(ctx, home.ID, "svc")
	if err != nil || !view.UpdatedAt.Equal(at.Add(time.Minute)) {
		t.Fatalf("repeat moved updated_at %s %v", view.UpdatedAt, err)
	}
	rowA := envMaterialMap(t, m, ctx, home.ID, "svc")["A"]
	if opened, err := box.Open(seal.EnvAAD(pid, "svc", "A"), rowA.Nonce, rowA.Ciphertext); err != nil || string(opened) != "alpha" {
		t.Fatalf("repeat changed A %q %v", opened, err)
	}

	got, err := m.GetCatalogEntry(ctx, home.ID, "web")
	kept, err2 := m.ListCatalogApprovals(ctx, host.ID)
	if err != nil || err2 != nil || got.SpecHash != hash || len(kept) != 1 {
		t.Fatalf("hash %s approvals %d %v %v", got.SpecHash, len(kept), err, err2)
	}
	// The key PUT still refuses a flag change.
	plainFlag := false
	if _, _, err := m.PutEnvKey(ctx, home.ID, "svc", store.EnvKeyPut{Key: "A", Plain: "x", Secret: &plainFlag}, owner.ID, at); !errors.Is(err, store.ErrSecretFixed) {
		t.Fatalf("flag %v", err)
	}
}
