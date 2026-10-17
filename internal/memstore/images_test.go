package memstore

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/seal"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestImageRehashVoidsApproval(t *testing.T) {
	ctx := context.Background()
	m := New()
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	owner := catalogUser(t, m, "image-owner")
	home := catalogProject(t, m, owner.ID, "Home", "home", at)
	host := catalogHost(t, m, home, owner.ID, "pi", at)
	box, err := seal.New(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	img, err := catalog.BuildImage("web", []byte(`{"kind":"service","image":"nginx","env_sets":["svc"]}`), catalog.SetKeys{"svc": {"A"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash := catalog.ImageHash(img, map[string]string{"svc": catalog.EnvKeyDigest([]string{"A"})})
	entry, err := m.CreateCatalogEntry(ctx, home.ID, store.CatalogWrite{
		Name: "web", Kind: "image", ImageRaw: []byte(catalog.SpecJSON(img)),
		SpecHash: hash, CommandDisplay: img.Image, Actor: owner.ID, At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	grants, err := m.ListCatalogGrants(ctx, entry.ID)
	if err != nil {
		t.Fatal(err)
	}
	admin, viewer := store.DefaultGrantActions("image")
	if !grantHas(grants, "role:admin", admin...) || !grantHas(grants, "role:viewer", viewer...) {
		t.Fatalf("grants %#v", grants)
	}
	if _, err := m.ApproveCatalog(ctx, host.ID, entry.ID, hash, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := m.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{sealKey(t, box, home.ID.String(), "svc", "A", "one")}, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	kept, err := m.ListCatalogApprovals(ctx, host.ID)
	if err != nil || len(kept) != 1 || kept[0].Status != "approved" || kept[0].SpecHash != hash {
		t.Fatalf("value change voided approval %#v %v", kept, err)
	}
	got, err := m.GetCatalogEntry(ctx, home.ID, "web")
	if err != nil || got.SpecHash != hash {
		t.Fatalf("hash changed on value write %s %v", got.SpecHash, err)
	}
	if _, err := m.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{
		sealKey(t, box, home.ID.String(), "svc", "A", "two"),
		sealKey(t, box, home.ID.String(), "svc", "B", "three"),
	}, owner.ID, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	next, err := m.GetCatalogEntry(ctx, home.ID, "web")
	if err != nil || next.SpecHash == hash {
		t.Fatalf("added key left hash %s", next.SpecHash)
	}
	left, err := m.ListCatalogApprovals(ctx, host.ID)
	if err != nil || len(left) != 0 {
		t.Fatalf("approvals %#v %v", left, err)
	}
	if _, err := m.ApproveCatalog(ctx, host.ID, entry.ID, next.SpecHash, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := m.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{
		sealKey(t, box, home.ID.String(), "svc", "B", "other"),
		sealKey(t, box, home.ID.String(), "svc", "A", "other"),
	}, owner.ID, at.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	again, err := m.GetCatalogEntry(ctx, home.ID, "web")
	kept, err2 := m.ListCatalogApprovals(ctx, host.ID)
	if err != nil || err2 != nil || again.SpecHash != next.SpecHash || len(kept) != 1 || kept[0].Status != "approved" {
		t.Fatalf("value rewrite hash %s approvals %#v %v %v", again.SpecHash, kept, err, err2)
	}
	view, err := m.GetEnvSet(ctx, home.ID, "svc")
	if err != nil || len(view.Keys) != 2 || view.Keys[0].Value != nil || view.Keys[1].Value != nil {
		t.Fatalf("secret returned %#v %v", view, err)
	}
}

func TestEnvReplaceKeepsWave2aHash(t *testing.T) {
	ctx := context.Background()
	m := New()
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	owner := catalogUser(t, m, "image-2a")
	home := catalogProject(t, m, owner.ID, "Home", "home", at)
	host := catalogHost(t, m, home, owner.ID, "pi", at)
	box, err := seal.New(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	img, err := catalog.BuildImage("web", []byte(`{"kind":"service","image":"nginx","env_sets":["svc"]}`), catalog.SetKeys{"svc": {"A"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash := catalog.ImageHash(img, map[string]string{"svc": catalog.EnvKeyDigest([]string{"A"})})
	raw := bytes.ReplaceAll([]byte(catalog.SpecJSON(img)), []byte(`,"files":[]`), nil)
	if bytes.Contains(raw, []byte(`"files"`)) {
		t.Fatalf("2a spec %s", raw)
	}
	entry, err := m.CreateCatalogEntry(ctx, home.ID, store.CatalogWrite{
		Name: "web", Kind: "image", ImageRaw: raw,
		SpecHash: hash, CommandDisplay: img.Image, Actor: owner.ID, At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApproveCatalog(ctx, host.ID, entry.ID, hash, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := m.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{sealKey(t, box, home.ID.String(), "svc", "A", "other")}, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	got, err := m.GetCatalogEntry(ctx, home.ID, "web")
	kept, err2 := m.ListCatalogApprovals(ctx, host.ID)
	if err != nil || err2 != nil || got.SpecHash != hash || len(kept) != 1 || kept[0].Status != "approved" {
		t.Fatalf("hash %s approvals %#v %v %v", got.SpecHash, kept, err, err2)
	}
}

func TestEnvReplaceKeepsVisibility(t *testing.T) {
	ctx := context.Background()
	m := New()
	at := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	owner := catalogUser(t, m, "env-vis")
	home := catalogProject(t, m, owner.ID, "Home", "home", at)
	box, err := seal.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	pid := home.ID.String()
	sealOf := func(key, plain string) store.EnvSecret {
		t.Helper()
		got := sealKey(t, box, pid, "svc", key, plain)
		got.Plain = plain
		return got
	}
	if _, err := m.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{
		sealOf("A", "alpha-old"),
		sealOf("B", "bravo-old"),
	}, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := m.PatchEnvKey(ctx, home.ID, "svc", "A", store.EnvKeyPatch{IsSecret: false, Plain: "alpha-old"}, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	before, err := m.ListEnvMaterial(ctx, home.ID, "svc")
	if err != nil {
		t.Fatal(err)
	}
	var oldNonce []byte
	for _, item := range before {
		if item.Key == "B" {
			oldNonce = append([]byte(nil), item.Nonce...)
		}
	}
	if len(oldNonce) != 12 {
		t.Fatalf("B nonce %d", len(oldNonce))
	}
	if _, err := m.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{
		sealOf("A", "alpha-next"),
		sealOf("B", "bravo-next"),
		sealOf("C", "charlie-new"),
	}, owner.ID, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := envMaterialMap(t, m, ctx, home.ID, "svc")
	if len(got) != 3 {
		t.Fatalf("keys %d", len(got))
	}
	a := got["A"]
	if a.IsSecret || a.Plain != "alpha-next" || len(a.Nonce) != 0 || len(a.Ciphertext) != 0 || a.KeyVersion != 0 {
		t.Fatalf("A secret=%v plain=%q nonce=%d cipher=%d version=%d", a.IsSecret, a.Plain, len(a.Nonce), len(a.Ciphertext), a.KeyVersion)
	}
	b := got["B"]
	if !b.IsSecret || b.Plain != "" || bytes.Equal(b.Nonce, oldNonce) || bytes.Contains(b.Ciphertext, []byte("bravo-next")) {
		t.Fatalf("B secret=%v plain=%q nonce_reused=%v", b.IsSecret, b.Plain, bytes.Equal(b.Nonce, oldNonce))
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
	view, err := m.GetEnvSet(ctx, home.ID, "svc")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]store.EnvKey{}
	for _, key := range view.Keys {
		seen[key.Key] = key
	}
	if seen["A"].IsSecret || seen["A"].Value == nil || *seen["A"].Value != "alpha-next" || !seen["B"].IsSecret || seen["B"].Value != nil || !seen["C"].IsSecret || seen["C"].Value != nil {
		t.Fatalf("view leaked or reset visibility")
	}
	if _, err := m.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{
		sealOf("A", "alpha-next"),
		sealOf("C", "charlie-new"),
	}, owner.ID, at.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	got = envMaterialMap(t, m, ctx, home.ID, "svc")
	if _, ok := got["B"]; ok || len(got) != 2 || got["A"].IsSecret || got["A"].Plain != "alpha-next" || !got["C"].IsSecret {
		t.Fatal("B still stored or A/C visibility changed")
	}
	if _, err := m.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{
		sealOf("A", "alpha-next"),
		sealOf("B", "bravo-back"),
		sealOf("C", "charlie-new"),
	}, owner.ID, at.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	got = envMaterialMap(t, m, ctx, home.ID, "svc")
	if !got["B"].IsSecret || got["B"].Plain != "" {
		t.Fatal("re-added B kept a visibility")
	}
	opened, err = box.Open(seal.EnvAAD(pid, "svc", "B"), got["B"].Nonce, got["B"].Ciphertext)
	if err != nil || string(opened) != "bravo-back" {
		t.Fatalf("re-added B opened %q %v", opened, err)
	}
	if _, err := m.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{
		sealOf("B", "bravo-back"),
		sealOf("C", "charlie-new"),
	}, owner.ID, at.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, ok := envMaterialMap(t, m, ctx, home.ID, "svc")["A"]; ok {
		t.Fatal("A still stored")
	}
	if _, err := m.PutEnvSet(ctx, home.ID, "svc", []store.EnvSecret{
		sealOf("A", "alpha-again"),
		sealOf("B", "bravo-back"),
		sealOf("C", "charlie-new"),
	}, owner.ID, at.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	got = envMaterialMap(t, m, ctx, home.ID, "svc")
	if !got["A"].IsSecret || got["A"].Plain != "" {
		t.Fatal("re-added plain key stayed plain")
	}
	opened, err = box.Open(seal.EnvAAD(pid, "svc", "A"), got["A"].Nonce, got["A"].Ciphertext)
	if err != nil || string(opened) != "alpha-again" {
		t.Fatalf("re-added A opened %q %v", opened, err)
	}
}

func envMaterialMap(t *testing.T, m *Mem, ctx context.Context, projectID uuid.UUID, name string) map[string]store.EnvMaterial {
	t.Helper()
	mats, err := m.ListEnvMaterial(ctx, projectID, name)
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]store.EnvMaterial, len(mats))
	for _, item := range mats {
		out[item.Key] = item
	}
	return out
}

func TestImageInFlightAndRollback(t *testing.T) {
	ctx := context.Background()
	m := New()
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	owner := catalogUser(t, m, "flight-owner")
	home := catalogProject(t, m, owner.ID, "Home", "home", at)
	host := catalogHost(t, m, home, owner.ID, "pi", at)
	img, err := catalog.BuildImage("web", []byte(`{"kind":"service","image":"nginx"}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash := catalog.ImageHash(img, nil)
	entry, err := m.CreateCatalogEntry(ctx, home.ID, store.CatalogWrite{
		Name: "web", Kind: "image", ImageRaw: []byte(catalog.SpecJSON(img)),
		SpecHash: hash, CommandDisplay: img.Image, Actor: owner.ID, At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := m.BeginImageOp(ctx, entry.ID, host.ID, hash, owner.ID, "console", at, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.BeginImageOp(ctx, entry.ID, host.ID, hash, owner.ID, "console", at, at.Add(time.Hour)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second begin %v", err)
	}
	digests := make([]string, 4)
	for i := 0; i < 4; i++ {
		d := digestByte(byte(i + 1))
		digests[i] = d
		when := at.Add(time.Duration(i) * time.Minute)
		var row store.ImageDeploy
		if i == 0 {
			row = first
		} else {
			row, err = m.BeginImageOp(ctx, entry.ID, host.ID, hash, owner.ID, "console", when, when.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err := m.FinishImageDeploy(ctx, row.ID, "succeeded", &d, nil, when.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := m.RollbackDigests(ctx, entry.ID, host.ID)
	if err != nil || len(got) != 3 || got[0] != digests[3] || got[1] != digests[2] || got[2] != digests[1] {
		t.Fatalf("digests %#v %v", got, err)
	}
	if _, err := m.BeginImageOp(ctx, entry.ID, host.ID, hash, owner.ID, "console", at, at.Add(time.Hour)); err != nil {
		t.Fatalf("begin after finish %v", err)
	}
}

func sealKey(t *testing.T, box *seal.Box, projectID, set, key, plain string) store.EnvSecret {
	t.Helper()
	nonce, ciphertext, err := box.Seal(seal.EnvAAD(projectID, set, key), []byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	return store.EnvSecret{Key: key, Nonce: nonce, Ciphertext: ciphertext, KeyVersion: seal.KeyVersion}
}

func grantHas(grants []store.CatalogGrant, subject string, actions ...string) bool {
	for _, g := range grants {
		if g.Subject != subject || len(g.Actions) != len(actions) {
			continue
		}
		ok := true
		for i := range actions {
			if g.Actions[i] != actions[i] {
				ok = false
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func digestByte(b byte) string {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = b
	}
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 7+64)
	copy(out, "sha256:")
	for i, c := range buf {
		out[7+i*2] = hexdigits[c>>4]
		out[7+i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}
