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

func assertEnvReplaceKeepsVisibility(t *testing.T, d *DB, ctx context.Context, at time.Time) {
	t.Helper()
	owner := catalogUser(t, d, ctx, "env-vis", at)
	home := catalogProject(t, d, ctx, owner.ID, "Vis", "envvis", at)
	box, err := seal.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	pid := home.ID.String()
	sealOf := func(key, plain string) store.EnvSecret {
		t.Helper()
		nonce, ciphertext, err := box.Seal(seal.EnvAAD(pid, "svc", key), []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		return store.EnvSecret{Key: key, Plain: plain, Nonce: nonce, Ciphertext: ciphertext, KeyVersion: seal.KeyVersion}
	}
	if _, err := d.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{
		sealOf("A", "alpha-old"),
	}, owner.ID, at, false); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{
		sealOf("A", "alpha-old"),
		sealOf("B", "bravo-old"),
	}, owner.ID, at, true); err != nil {
		t.Fatal(err)
	}
	before := envRows(t, d, ctx, home.ID, "svc")
	if len(before["B"].Nonce) != 12 {
		t.Fatal("missing B nonce")
	}
	if _, err := d.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{
		sealOf("A", "alpha-next"),
		sealOf("B", "bravo-next"),
		sealOf("C", "charlie-new"),
	}, owner.ID, at.Add(time.Second), true); err != nil {
		t.Fatal(err)
	}
	got := envRows(t, d, ctx, home.ID, "svc")
	if len(got) != 3 {
		t.Fatalf("keys %d", len(got))
	}
	a := got["A"]
	if a.IsSecret || a.Plain != "alpha-next" || len(a.Nonce) != 0 || len(a.Ciphertext) != 0 || a.KeyVersion != 0 {
		t.Fatalf("A secret=%v plain=%q nonce=%d", a.IsSecret, a.Plain, len(a.Nonce))
	}
	b := got["B"]
	if !b.IsSecret || b.Plain != "" || bytes.Equal(b.Nonce, before["B"].Nonce) || bytes.Contains(b.Ciphertext, []byte("bravo-next")) {
		t.Fatalf("B secret=%v plain=%q nonce_reused=%v", b.IsSecret, b.Plain, bytes.Equal(b.Nonce, before["B"].Nonce))
	}
	opened, err := box.Open(seal.EnvAAD(pid, "svc", "B"), b.Nonce, b.Ciphertext)
	if err != nil || string(opened) != "bravo-next" {
		t.Fatalf("B opened %q %v", opened, err)
	}
	c := got["C"]
	if !c.IsSecret || c.Plain != "" {
		t.Fatalf("C secret=%v plain=%q", c.IsSecret, c.Plain)
	}
	opened, err = box.Open(seal.EnvAAD(pid, "svc", "C"), c.Nonce, c.Ciphertext)
	if err != nil || string(opened) != "charlie-new" {
		t.Fatalf("C opened %q %v", opened, err)
	}
	set, err := d.GetEnvSet(ctx, home.ID, "svc")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]store.EnvKey{}
	for _, key := range set.Keys {
		seen[key.Key] = key
	}
	if seen["A"].IsSecret || seen["A"].Value == nil || *seen["A"].Value != "alpha-next" || !seen["B"].IsSecret || seen["B"].Value != nil || !seen["C"].IsSecret || seen["C"].Value != nil {
		t.Fatal("get hid a plain value or returned a secret")
	}
	if _, err := d.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{
		sealOf("A", "alpha-next"),
		sealOf("C", "charlie-new"),
	}, owner.ID, at.Add(2*time.Second), true); err != nil {
		t.Fatal(err)
	}
	got = envRows(t, d, ctx, home.ID, "svc")
	if _, ok := got["B"]; ok || len(got) != 2 || got["A"].IsSecret || got["A"].Plain != "alpha-next" || !got["C"].IsSecret {
		t.Fatal("B still stored or A/C visibility changed")
	}
	if _, err := d.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{
		sealOf("A", "alpha-next"),
		sealOf("B", "bravo-back"),
		sealOf("C", "charlie-new"),
	}, owner.ID, at.Add(3*time.Second), true); err != nil {
		t.Fatal(err)
	}
	got = envRows(t, d, ctx, home.ID, "svc")
	if !got["B"].IsSecret || got["B"].Plain != "" {
		t.Fatal("re-added B was not secret")
	}
	opened, err = box.Open(seal.EnvAAD(pid, "svc", "B"), got["B"].Nonce, got["B"].Ciphertext)
	if err != nil || string(opened) != "bravo-back" {
		t.Fatalf("re-added B opened %q %v", opened, err)
	}
	if _, err := d.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{
		sealOf("B", "bravo-back"),
		sealOf("C", "charlie-new"),
	}, owner.ID, at.Add(4*time.Second), true); err != nil {
		t.Fatal(err)
	}
	if _, ok := envRows(t, d, ctx, home.ID, "svc")["A"]; ok {
		t.Fatal("A still stored")
	}
	if _, err := d.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{
		sealOf("A", "alpha-again"),
		sealOf("B", "bravo-back"),
		sealOf("C", "charlie-new"),
	}, owner.ID, at.Add(5*time.Second), true); err != nil {
		t.Fatal(err)
	}
	got = envRows(t, d, ctx, home.ID, "svc")
	if !got["A"].IsSecret || got["A"].Plain != "" {
		t.Fatal("re-added plain key stayed plain")
	}
	opened, err = box.Open(seal.EnvAAD(pid, "svc", "A"), got["A"].Nonce, got["A"].Ciphertext)
	if err != nil || string(opened) != "alpha-again" {
		t.Fatalf("re-added A opened %q %v", opened, err)
	}
}

func assertEnvKeyUpsertDelete(t *testing.T, d *DB, ctx context.Context, at time.Time) {
	t.Helper()
	owner := catalogUser(t, d, ctx, "env-key", at)
	home := catalogProject(t, d, ctx, owner.ID, "Keys", "envkey", at)
	host := enrollHostDB(t, d, ctx, home.ID, owner.ID, "key-host", at)
	box, err := seal.New(bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	pid := home.ID.String()
	sealOf := func(set, key, plain string) store.EnvKeyPut {
		t.Helper()
		nonce, ciphertext, err := box.Seal(seal.EnvAAD(pid, set, key), []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		return store.EnvKeyPut{Key: key, Plain: plain, Nonce: nonce, Ciphertext: ciphertext, KeyVersion: seal.KeyVersion}
	}
	stored, created, err := d.PutEnvKey(ctx, home.ID, "svc", sealOf("svc", "TOKEN", "one"), owner.ID, at)
	if err != nil || !created || !stored.IsSecret || stored.Value != nil {
		t.Fatalf("create %#v %v %v", stored, created, err)
	}
	plainFlag := false
	visible := sealOf("svc", "NOTE", "visible")
	visible.Secret = &plainFlag
	stored, created, err = d.PutEnvKey(ctx, home.ID, "svc", visible, owner.ID, at)
	if err != nil || !created || stored.IsSecret || stored.Value == nil || *stored.Value != "visible" {
		t.Fatalf("plain %#v %v %v", stored, created, err)
	}
	img, err := catalog.BuildImage("web", []byte(`{"kind":"service","image":"nginx","env_sets":["svc"]}`), catalog.SetKeys{"svc": {"NOTE", "TOKEN"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash := catalog.ImageHash(img, map[string]string{"svc": catalog.EnvKeyDigest([]string{"NOTE", "TOKEN"})})
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
	before := envRows(t, d, ctx, home.ID, "svc")
	next := sealOf("svc", "TOKEN", "two")
	stored, created, err = d.PutEnvKey(ctx, home.ID, "svc", next, owner.ID, at.Add(time.Minute))
	if err != nil || created || !stored.IsSecret {
		t.Fatalf("value %#v %v %v", stored, created, err)
	}
	got, err := d.GetCatalogEntry(ctx, home.ID, "web")
	view, err2 := d.GetEnvSet(ctx, home.ID, "svc")
	if err != nil || err2 != nil || got.SpecHash != hash || catalogApprovalCount(t, d, ctx, entry.ID) != 1 || !view.UpdatedAt.Equal(at.Add(time.Minute)) {
		t.Fatalf("value-only hash %s approvals %d at %s %v", got.SpecHash, catalogApprovalCount(t, d, ctx, entry.ID), view.UpdatedAt, err)
	}
	token := envRows(t, d, ctx, home.ID, "svc")["TOKEN"]
	if bytes.Equal(token.Nonce, before["TOKEN"].Nonce) || token.Plain != "" {
		t.Fatal("value update reused the nonce or stored the plain value")
	}
	opened, err := box.Open(seal.EnvAAD(pid, "svc", "TOKEN"), token.Nonce, token.Ciphertext)
	if err != nil || string(opened) != "two" {
		t.Fatalf("opened %q %v", opened, err)
	}
	secretFlag := true
	same := sealOf("svc", "TOKEN", "two")
	same.Secret = &secretFlag
	if _, _, err := d.PutEnvKey(ctx, home.ID, "svc", same, owner.ID, at.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	flipped := sealOf("svc", "TOKEN", "nope")
	flipped.Secret = &plainFlag
	if _, _, err := d.PutEnvKey(ctx, home.ID, "svc", flipped, owner.ID, at.Add(3*time.Minute)); !errors.Is(err, store.ErrSecretFixed) {
		t.Fatalf("flag %v", err)
	}
	view, err = d.GetEnvSet(ctx, home.ID, "svc")
	token = envRows(t, d, ctx, home.ID, "svc")["TOKEN"]
	if err != nil || !view.UpdatedAt.Equal(at.Add(2*time.Minute)) || !token.IsSecret {
		t.Fatalf("flag mismatch wrote the set %#v %v", view.UpdatedAt, err)
	}
	opened, err = box.Open(seal.EnvAAD(pid, "svc", "TOKEN"), token.Nonce, token.Ciphertext)
	if err != nil || string(opened) != "two" {
		t.Fatalf("flag mismatch changed the value %q %v", opened, err)
	}
	if _, _, err := d.PutEnvKey(ctx, home.ID, "svc", sealOf("svc", "TOKEN", ""), owner.ID, at.Add(3*time.Minute)); !errors.Is(err, store.ErrSecretEmpty) {
		t.Fatalf("empty secret %v", err)
	}
	view, err = d.GetEnvSet(ctx, home.ID, "svc")
	token = envRows(t, d, ctx, home.ID, "svc")["TOKEN"]
	if err != nil || !view.UpdatedAt.Equal(at.Add(2*time.Minute)) || !token.IsSecret {
		t.Fatalf("empty secret wrote the set %#v %v", view.UpdatedAt, err)
	}
	opened, err = box.Open(seal.EnvAAD(pid, "svc", "TOKEN"), token.Nonce, token.Ciphertext)
	if err != nil || string(opened) != "two" {
		t.Fatalf("empty secret changed the value %q %v", opened, err)
	}
	stored, created, err = d.PutEnvKey(ctx, home.ID, "svc", sealOf("svc", "NOTE", ""), owner.ID, at.Add(3*time.Minute))
	if err != nil || created || stored.IsSecret || stored.Value == nil || *stored.Value != "" {
		t.Fatalf("empty plain %#v %v %v", stored, created, err)
	}
	// A separate set, so the new key does not rehash "web".
	stored, created, err = d.PutEnvKey(ctx, home.ID, "blank", sealOf("blank", "FRESH", ""), owner.ID, at.Add(3*time.Minute))
	if err != nil || !created || !stored.IsSecret {
		t.Fatalf("empty new secret %#v %v %v", stored, created, err)
	}
	fresh := envRows(t, d, ctx, home.ID, "blank")["FRESH"]
	opened, err = box.Open(seal.EnvAAD(pid, "blank", "FRESH"), fresh.Nonce, fresh.Ciphertext)
	if err != nil || string(opened) != "" || !fresh.IsSecret {
		t.Fatalf("empty new secret opened %q %v", opened, err)
	}
	extra, created, err := d.PutEnvKey(ctx, home.ID, "svc", sealOf("svc", "EXTRA", "three"), owner.ID, at.Add(4*time.Minute))
	if err != nil || !created || !extra.IsSecret {
		t.Fatalf("add %#v %v %v", extra, created, err)
	}
	got, err = d.GetCatalogEntry(ctx, home.ID, "web")
	if err != nil || got.SpecHash == hash || catalogApprovalCount(t, d, ctx, entry.ID) != 0 {
		t.Fatalf("add hash %s approvals %d %v", got.SpecHash, catalogApprovalCount(t, d, ctx, entry.ID), err)
	}
	if _, err := d.ApproveCatalog(ctx, host.ID, entry.ID, got.SpecHash, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteEnvKey(ctx, home.ID, "svc", "EXTRA", owner.ID, at.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, err = d.GetCatalogEntry(ctx, home.ID, "web")
	if err != nil || got.SpecHash != hash || catalogApprovalCount(t, d, ctx, entry.ID) != 0 {
		t.Fatalf("delete hash %s approvals %d %v", got.SpecHash, catalogApprovalCount(t, d, ctx, entry.ID), err)
	}
	if err := d.DeleteEnvKey(ctx, home.ID, "svc", "GONE", owner.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing key %v", err)
	}
	if err := d.DeleteEnvKey(ctx, home.ID, "missing", "TOKEN", owner.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing set %v", err)
	}
	if err := d.DeleteEnvKey(ctx, home.ID, "svc", "TOKEN", owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteEnvKey(ctx, home.ID, "svc", "NOTE", owner.ID, at); err != nil {
		t.Fatal(err)
	}
	view, err = d.GetEnvSet(ctx, home.ID, "svc")
	if err != nil || len(view.Keys) != 0 || view.Name != "svc" {
		t.Fatalf("empty set %#v %v", view, err)
	}
	stored, created, err = d.PutEnvKey(ctx, home.ID, "svc", sealOf("svc", "TOKEN", "again"), owner.ID, at)
	if err != nil || !created || !stored.IsSecret {
		t.Fatalf("re-add %#v %v %v", stored, created, err)
	}
	again := envRows(t, d, ctx, home.ID, "svc")["TOKEN"]
	opened, err = box.Open(seal.EnvAAD(pid, "svc", "TOKEN"), again.Nonce, again.Ciphertext)
	if err != nil || string(opened) != "again" || again.Plain != "" {
		t.Fatalf("re-add opened %q plain %q %v", opened, again.Plain, err)
	}
	plainKey := store.EnvSecret{Key: "A", Plain: "alpha", Nonce: again.Nonce, Ciphertext: again.Ciphertext, KeyVersion: seal.KeyVersion}
	if _, err := d.PutEnvSet(ctx, home.ID, "plain", []store.EnvSecret{plainKey}, owner.ID, at, false); err != nil {
		t.Fatal(err)
	}
	secretKey := store.EnvSecret{Key: "B", Plain: "bravo", Nonce: again.Nonce, Ciphertext: again.Ciphertext, KeyVersion: seal.KeyVersion}
	nonce, ciphertext, err := box.Seal(seal.EnvAAD(pid, "plain", "B"), []byte("bravo"))
	if err != nil {
		t.Fatal(err)
	}
	secretKey.Nonce, secretKey.Ciphertext = nonce, ciphertext
	if _, err := d.PutEnvSet(ctx, home.ID, "plain", []store.EnvSecret{plainKey, secretKey}, owner.ID, at, true); err != nil {
		t.Fatal(err)
	}
	rows := envRows(t, d, ctx, home.ID, "plain")
	if rows["A"].IsSecret || rows["A"].Plain != "alpha" || len(rows["A"].Nonce) != 0 || !rows["B"].IsSecret || rows["B"].Plain != "" {
		t.Fatalf("new_keys_secret A %#v B %#v", rows["A"], rows["B"])
	}
	opened, err = box.Open(seal.EnvAAD(pid, "plain", "B"), rows["B"].Nonce, rows["B"].Ciphertext)
	if err != nil || string(opened) != "bravo" {
		t.Fatalf("B opened %q %v", opened, err)
	}
}

func assertEnvMergeCreate(t *testing.T, d *DB, ctx context.Context, at time.Time) {
	t.Helper()
	owner := catalogUser(t, d, ctx, "env-merge", at)
	home := catalogProject(t, d, ctx, owner.ID, "Merge", "envmerge", at)
	host := enrollHostDB(t, d, ctx, home.ID, owner.ID, "merge-host", at)
	box, err := seal.New(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	pid := home.ID.String()
	sealed := func(set, key, plain string) store.EnvSecret {
		t.Helper()
		nonce, ciphertext, err := box.Seal(seal.EnvAAD(pid, set, key), []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		return store.EnvSecret{Key: key, Plain: plain, Nonce: nonce, Ciphertext: ciphertext, KeyVersion: seal.KeyVersion}
	}
	openKey := func(set, key string) string {
		t.Helper()
		row := envRows(t, d, ctx, home.ID, set)[key]
		opened, err := box.Open(seal.EnvAAD(pid, set, key), row.Nonce, row.Ciphertext)
		if err != nil {
			t.Fatalf("open %s.%s %v", set, key, err)
		}
		return string(opened)
	}

	// create: a new set is created; an existing one is ErrConflict and unchanged.
	if _, err := d.CreateEnvSet(ctx, home.ID, "svc", []store.EnvSecret{sealed("svc", "TOKEN", "one"), sealed("svc", "NOTE", "note")}, owner.ID, at, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.PutEnvKey(ctx, home.ID, "svc", store.EnvKeyPut{Key: "VIS", Plain: "v1", Secret: boolRef(false)}, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateEnvSet(ctx, home.ID, "svc", []store.EnvSecret{sealed("svc", "OTHER", "x")}, owner.ID, at.Add(time.Minute), true); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("create existing %v", err)
	}
	rows := envRows(t, d, ctx, home.ID, "svc")
	if len(rows) != 3 || openKey("svc", "TOKEN") != "one" {
		t.Fatalf("create conflict changed rows %#v", rows)
	}
	view, err := d.GetEnvSet(ctx, home.ID, "svc")
	if err != nil || !view.UpdatedAt.Equal(at) {
		t.Fatalf("create conflict touched the set %#v %v", view, err)
	}
	// create with newKeysSecret false stores plain values.
	if _, err := d.CreateEnvSet(ctx, home.ID, "plainset", []store.EnvSecret{sealed("plainset", "P", "pv")}, owner.ID, at, false); err != nil {
		t.Fatal(err)
	}
	if row := envRows(t, d, ctx, home.ID, "plainset")["P"]; row.IsSecret || row.Plain != "pv" || len(row.Nonce) != 0 {
		t.Fatalf("plain create row %#v", row)
	}

	img, err := catalog.BuildImage("web", []byte(`{"kind":"service","image":"nginx","env_sets":["svc"]}`), catalog.SetKeys{"svc": {"NOTE", "TOKEN", "VIS"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash := catalog.ImageHash(img, map[string]string{"svc": catalog.EnvKeyDigest([]string{"NOTE", "TOKEN", "VIS"})})
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

	// merge on a missing set is ErrNotFound and creates nothing.
	if _, _, err := d.MergeEnvSet(ctx, home.ID, "missing", []store.EnvSecret{sealed("missing", "A", "a")}, owner.ID, at, true); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("merge missing %v", err)
	}
	if _, err := d.GetEnvSet(ctx, home.ID, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("merge created the set %v", err)
	}

	// An empty value for an existing secret key rolls back the whole merge.
	if _, _, err := d.MergeEnvSet(ctx, home.ID, "svc", []store.EnvSecret{sealed("svc", "VIS", "v2"), sealed("svc", "ADDED", "added"), sealed("svc", "TOKEN", "")}, owner.ID, at.Add(time.Minute), true); !errors.Is(err, store.ErrSecretEmpty) {
		t.Fatalf("merge empty secret %v", err)
	}
	rows = envRows(t, d, ctx, home.ID, "svc")
	if len(rows) != 3 || rows["VIS"].Plain != "v1" || openKey("svc", "TOKEN") != "one" {
		t.Fatalf("refused merge wrote rows %#v", rows)
	}

	// A value-only merge keeps flags, other keys, the hash and the approval.
	set, created, err := d.MergeEnvSet(ctx, home.ID, "svc", []store.EnvSecret{sealed("svc", "VIS", "v2"), sealed("svc", "TOKEN", "two")}, owner.ID, at.Add(2*time.Minute), true)
	if err != nil || len(created) != 0 || len(set.Keys) != 3 || !set.UpdatedAt.Equal(at.Add(2*time.Minute)) {
		t.Fatalf("value merge %#v %v %v", set, created, err)
	}
	rows = envRows(t, d, ctx, home.ID, "svc")
	if rows["VIS"].IsSecret || rows["VIS"].Plain != "v2" || len(rows["VIS"].Nonce) != 0 || !rows["TOKEN"].IsSecret || openKey("svc", "TOKEN") != "two" || openKey("svc", "NOTE") != "note" {
		t.Fatalf("value merge rows %#v", rows)
	}
	got, err := d.GetCatalogEntry(ctx, home.ID, "web")
	if err != nil || got.SpecHash != hash || catalogApprovalCount(t, d, ctx, entry.ID) != 1 {
		t.Fatalf("value merge hash %s approvals %d %v", got.SpecHash, catalogApprovalCount(t, d, ctx, entry.ID), err)
	}

	// A merge adding names follows newKeysSecret and voids the approval;
	// an existing secret key stays secret although newKeysSecret is false.
	set, created, err = d.MergeEnvSet(ctx, home.ID, "svc", []store.EnvSecret{sealed("svc", "ZPLAIN", "zp"), sealed("svc", "APLAIN", "ap"), sealed("svc", "TOKEN", "three")}, owner.ID, at.Add(3*time.Minute), false)
	if err != nil || len(created) != 2 || created[0] != "APLAIN" || created[1] != "ZPLAIN" || len(set.Keys) != 5 {
		t.Fatalf("add merge %#v %v %v", set, created, err)
	}
	rows = envRows(t, d, ctx, home.ID, "svc")
	if rows["APLAIN"].IsSecret || rows["APLAIN"].Plain != "ap" || rows["ZPLAIN"].IsSecret || !rows["TOKEN"].IsSecret || openKey("svc", "TOKEN") != "three" {
		t.Fatalf("add merge rows %#v", rows)
	}
	got, err = d.GetCatalogEntry(ctx, home.ID, "web")
	if err != nil || got.SpecHash == hash || catalogApprovalCount(t, d, ctx, entry.ID) != 0 {
		t.Fatalf("add merge hash %s approvals %d %v", got.SpecHash, catalogApprovalCount(t, d, ctx, entry.ID), err)
	}
}

func boolRef(v bool) *bool { return &v }

func envRows(t *testing.T, d *DB, ctx context.Context, projectID uuid.UUID, name string) map[string]store.EnvMaterial {
	t.Helper()
	mats, err := d.ListEnvMaterial(ctx, projectID, name)
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]store.EnvMaterial, len(mats))
	for _, item := range mats {
		out[item.Key] = item
	}
	return out
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
	}}, owner.ID, at, true); err != nil {
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
	}}, owner.ID, at.Add(time.Second), true); err != nil {
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
	}, owner.ID, at.Add(2*time.Second), true); err != nil {
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
