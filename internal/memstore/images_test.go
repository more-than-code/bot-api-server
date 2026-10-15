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
	img, err := catalog.BuildImage("web", []byte(`{"kind":"service","image":"nginx","env_sets":["svc"]}`), catalog.SetKeys{"svc": {"A"}})
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

func TestImageInFlightAndRollback(t *testing.T) {
	ctx := context.Background()
	m := New()
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	owner := catalogUser(t, m, "flight-owner")
	home := catalogProject(t, m, owner.ID, "Home", "home", at)
	host := catalogHost(t, m, home, owner.ID, "pi", at)
	img, err := catalog.BuildImage("web", []byte(`{"kind":"service","image":"nginx"}`), nil)
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
