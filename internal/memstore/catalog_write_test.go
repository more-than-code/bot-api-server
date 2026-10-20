package memstore

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestCatalogWriteCommitCreate(t *testing.T) {
	m := New()
	ctx := context.Background()
	at := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	owner := catalogUser(t, m, "cw-owner")
	other := catalogUser(t, m, "cw-other")
	project := catalogProject(t, m, owner.ID, "Proj", "cwproj", at)
	in := imageWrite(t, "web", `{"kind":"service","image":"nginx"}`, owner.ID, at)

	n, err := m.CountEntryApprovals(ctx, project.ID, "web")
	if err != nil || n != 0 {
		t.Fatalf("missing count %d %v", n, err)
	}
	hash, row := putCatalogWrite(t, m, store.CatalogWriteConfirmation{
		UserID: owner.ID, ProjectID: project.ID, Action: "create", EntryName: "web",
		Body: in.ImageRaw, RequestHash: bytes32(1), IdempotencyKey: "cw-create",
		CreatedAt: at, ExpiresAt: at.Add(store.ConfirmationTTL),
	})
	got, err := m.GetCatalogWriteConfirmation(ctx, hash)
	if err != nil || got.Action != "create" || got.BaseSpecHash != "" || !store.SameJSON(got.Body, in.ImageRaw) || got.UsedAt != nil {
		t.Fatalf("row %+v %v", got, err)
	}
	if err := m.PutCatalogWriteConfirmation(ctx, hash, row); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate %v", err)
	}

	if _, _, err := m.CommitCatalogWrite(ctx, hash, other.ID, at, in); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign %v", err)
	}
	if again, err := m.GetCatalogWriteConfirmation(ctx, hash); err != nil || again.UsedAt != nil {
		t.Fatal("foreign commit marked the plan")
	}
	mismatch := in
	mismatch.Name = "other"
	if _, _, err := m.CommitCatalogWrite(ctx, hash, owner.ID, at, mismatch); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("name mismatch %v", err)
	}
	taken := in
	if _, err := m.CreateCatalogEntry(ctx, project.ID, taken); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.CommitCatalogWrite(ctx, hash, owner.ID, at, in); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("name taken %v", err)
	}
	if pending, err := m.GetCatalogWriteConfirmation(ctx, hash); err != nil || pending.UsedAt != nil {
		t.Fatal("conflict marked the plan")
	}
	if _, err := m.DeleteCatalogEntry(ctx, project.ID, "web"); err != nil {
		t.Fatal(err)
	}

	row.Body = spacedJSON(in.ImageRaw)
	hash, _ = putCatalogWrite(t, m, row)
	entry, _, err := commitImage(t, m, hash, owner.ID, at, in)
	if err != nil || entry.Name != "web" || entry.Kind != "image" || entry.SpecHash != in.SpecHash {
		t.Fatalf("commit %+v %v", entry, err)
	}
	if _, err := m.GetCatalogWriteConfirmation(ctx, hash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("applied create kept the plan %v", err)
	}
	if _, _, err = m.CommitCatalogWrite(ctx, hash, owner.ID, at, in); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second commit %v", err)
	}
	listed, err := m.ListCatalogEntries(ctx, project.ID)
	if err != nil || len(listed) != 1 {
		t.Fatalf("entries %+v %v", listed, err)
	}

	expired := row
	expired.IdempotencyKey = "cw-expired"
	expired.ExpiresAt = at.Add(-time.Second)
	expiredHash, _ := putCatalogWrite(t, m, expired)
	if _, _, err := m.CommitCatalogWrite(ctx, expiredHash, owner.ID, at, in); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired %v", err)
	}
	if kept, err := m.GetCatalogWriteConfirmation(ctx, expiredHash); err != nil || kept.UsedAt != nil {
		t.Fatal("expired commit removed the plan")
	}
	fresh := row
	fresh.IdempotencyKey = "cw-fresh"
	fresh.CreatedAt = at
	fresh.ExpiresAt = at.Add(time.Minute)
	freshHash, _ := putCatalogWrite(t, m, fresh)
	if _, err := m.GetCatalogWriteConfirmation(ctx, expiredHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("new plan kept an expired row %v", err)
	}
	if _, err := m.GetCatalogWriteConfirmation(ctx, freshHash); err != nil {
		t.Fatalf("new plan %v", err)
	}
}

func TestCatalogWriteCommitUpdateAndDelete(t *testing.T) {
	m := New()
	ctx := context.Background()
	at := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	owner := catalogUser(t, m, "cw-owner")
	project := catalogProject(t, m, owner.ID, "Proj", "cwupd", at)
	hostA := catalogHost(t, m, project, owner.ID, "a", at)
	hostB := catalogHost(t, m, project, owner.ID, "b", at)
	current := imageWrite(t, "web", `{"kind":"service","image":"nginx"}`, owner.ID, at)
	entry, err := m.CreateCatalogEntry(ctx, project.ID, current)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApproveCatalog(ctx, hostA.ID, entry.ID, entry.SpecHash, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApproveCatalog(ctx, hostB.ID, entry.ID, entry.SpecHash, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if n, err := m.CountEntryApprovals(ctx, project.ID, "web"); err != nil || n != 2 {
		t.Fatalf("approvals %d %v", n, err)
	}

	same := current
	sameHash, _ := putCatalogWrite(t, m, store.CatalogWriteConfirmation{
		UserID: owner.ID, ProjectID: project.ID, Action: "update", EntryName: "web",
		BaseSpecHash: entry.SpecHash, Body: same.ImageRaw, RequestHash: bytes32(2),
		IdempotencyKey: "cw-same", CreatedAt: at, ExpiresAt: at.Add(time.Minute),
	})
	if _, _, err := m.CommitCatalogWrite(ctx, sameHash, owner.ID, at, same); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetCatalogWriteConfirmation(ctx, sameHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("applied same-hash update kept the plan %v", err)
	}
	if n, err := m.CountEntryApprovals(ctx, project.ID, "web"); err != nil || n != 2 {
		t.Fatalf("same hash voided %d %v", n, err)
	}

	next := imageWrite(t, "web", `{"kind":"service","image":"nginx:1.27"}`, owner.ID, at)
	staleHash, _ := putCatalogWrite(t, m, store.CatalogWriteConfirmation{
		UserID: owner.ID, ProjectID: project.ID, Action: "update", EntryName: "web",
		BaseSpecHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Body:         next.ImageRaw, RequestHash: bytes32(3), IdempotencyKey: "cw-stale",
		CreatedAt: at, ExpiresAt: at.Add(time.Minute),
	})
	if _, _, err := m.CommitCatalogWrite(ctx, staleHash, owner.ID, at, next); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale %v", err)
	}
	kept, err := m.GetCatalogEntry(ctx, project.ID, "web")
	if err != nil || kept.SpecHash != entry.SpecHash {
		t.Fatal("stale commit changed the entry")
	}
	if pending, err := m.GetCatalogWriteConfirmation(ctx, staleHash); err != nil || pending.UsedAt != nil {
		t.Fatal("stale commit marked the plan")
	}

	updHash, _ := putCatalogWrite(t, m, store.CatalogWriteConfirmation{
		UserID: owner.ID, ProjectID: project.ID, Action: "update", EntryName: "web",
		BaseSpecHash: entry.SpecHash, Body: next.ImageRaw, RequestHash: bytes32(4),
		IdempotencyKey: "cw-upd", CreatedAt: at, ExpiresAt: at.Add(time.Minute),
	})
	old, updated, err := m.CommitCatalogWrite(ctx, updHash, owner.ID, at, next)
	if err != nil || old != entry.SpecHash || updated.SpecHash != next.SpecHash {
		t.Fatalf("update %s %+v %v", old, updated, err)
	}
	if _, err := m.GetCatalogWriteConfirmation(ctx, updHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("applied update kept the plan %v", err)
	}
	if n, err := m.CountEntryApprovals(ctx, project.ID, "web"); err != nil || n != 0 {
		t.Fatalf("voided %d %v", n, err)
	}

	if _, err := m.ApproveCatalog(ctx, hostA.ID, entry.ID, updated.SpecHash, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	grants, err := m.ListCatalogGrants(ctx, entry.ID)
	if err != nil || len(grants) == 0 {
		t.Fatalf("grants %#v %v", grants, err)
	}
	delHash, _ := putCatalogWrite(t, m, store.CatalogWriteConfirmation{
		UserID: owner.ID, ProjectID: project.ID, Action: "delete", EntryName: "web",
		BaseSpecHash: updated.SpecHash, RequestHash: bytes32(5), IdempotencyKey: "cw-del",
		CreatedAt: at, ExpiresAt: at.Add(time.Minute),
	})
	_, deleted, err := m.CommitCatalogWrite(ctx, delHash, owner.ID, at, store.CatalogWrite{Name: "web"})
	if err != nil || deleted.Name != "web" {
		t.Fatalf("delete %+v %v", deleted, err)
	}
	if _, err := m.GetCatalogWriteConfirmation(ctx, delHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("applied delete kept the plan %v", err)
	}
	if _, err := m.GetCatalogEntry(ctx, project.ID, "web"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("entry remains %v", err)
	}
	if _, err := m.ListCatalogGrants(ctx, entry.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("grants remain %v", err)
	}
	if n, err := m.CountEntryApprovals(ctx, project.ID, "web"); err != nil || n != 0 {
		t.Fatalf("approvals remain %d %v", n, err)
	}

	gone := imageWrite(t, "gone", `{"kind":"service","image":"nginx"}`, owner.ID, at)
	pendingEntry, err := m.CreateCatalogEntry(ctx, project.ID, gone)
	if err != nil {
		t.Fatal(err)
	}
	pendingHash, _ := putCatalogWrite(t, m, store.CatalogWriteConfirmation{
		UserID: owner.ID, ProjectID: project.ID, Action: "update", EntryName: "gone",
		BaseSpecHash: pendingEntry.SpecHash, Body: gone.ImageRaw, RequestHash: bytes32(6),
		IdempotencyKey: "cw-gone", CreatedAt: at, ExpiresAt: at.Add(time.Minute),
	})
	if _, err := m.DeleteCatalogEntry(ctx, project.ID, "gone"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetCatalogWriteConfirmation(ctx, pendingHash); err != nil {
		t.Fatal("deleting the entry dropped the pending plan")
	}
	if _, _, err := m.CommitCatalogWrite(ctx, pendingHash, owner.ID, at, gone); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("deleted entry commit %v", err)
	}
}

func TestCatalogWriteProjectDeleteDropsPlans(t *testing.T) {
	m := New()
	ctx := context.Background()
	at := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	owner := catalogUser(t, m, "cw-owner")
	project := catalogProject(t, m, owner.ID, "Proj", "cwdrop", at)
	hash, _ := putCatalogWrite(t, m, store.CatalogWriteConfirmation{
		UserID: owner.ID, ProjectID: project.ID, Action: "create", EntryName: "web",
		Body: []byte(`{"kind":"service"}`), RequestHash: bytes32(7), IdempotencyKey: "cw-drop",
		CreatedAt: at, ExpiresAt: at.Add(time.Minute),
	})
	if _, err := m.DeleteProject(ctx, project.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetCatalogWriteConfirmation(ctx, hash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("project delete kept the plan %v", err)
	}
}

func putCatalogWrite(t *testing.T, m *Mem, row store.CatalogWriteConfirmation) ([]byte, store.CatalogWriteConfirmation) {
	t.Helper()
	_, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.PutCatalogWriteConfirmation(context.Background(), hash, row); err != nil {
		t.Fatal(err)
	}
	return hash, row
}

func imageWrite(t *testing.T, name, raw string, actor uuid.UUID, at time.Time) store.CatalogWrite {
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

func commitImage(t *testing.T, m *Mem, hash []byte, user uuid.UUID, at time.Time, in store.CatalogWrite) (store.CatalogEntry, string, error) {
	t.Helper()
	old, entry, err := m.CommitCatalogWrite(context.Background(), hash, user, at, in)
	return entry, old, err
}

func spacedJSON(raw []byte) []byte {
	return bytes.Replace(raw, []byte(":"), []byte(": "), 1)
}

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
