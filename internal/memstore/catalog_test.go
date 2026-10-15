package memstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestCatalogDefaultsVoidAndIdempotency(t *testing.T) {
	ctx := context.Background()
	m := New()
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	owner := catalogUser(t, m, "owner")
	home := catalogProject(t, m, owner.ID, "Home", "home", at)
	host := catalogHost(t, m, home, owner.ID, "pi", at)
	spec, hash, display := catalogSpec(t, "pnpm run dev")
	entry, err := m.CreateCatalogEntry(ctx, home.ID, store.CatalogWrite{
		Name: "web", Spec: spec, SpecHash: hash, CommandDisplay: display, Actor: owner.ID, At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	grants, err := m.ListCatalogGrants(ctx, entry.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 2 || grants[0].Subject != "role:admin" || grants[1].Subject != "role:viewer" || len(grants[1].Actions) != 1 || grants[1].Actions[0] != "logs" {
		t.Fatalf("grants %#v", grants)
	}
	if _, err := m.ApproveCatalog(ctx, host.ID, entry.ID, hash, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	same, sameHash, sameDisplay := catalogSpec(t, "pnpm run dev")
	if _, _, err := m.ReplaceCatalogEntry(ctx, home.ID, "web", store.CatalogWrite{
		Spec: same, SpecHash: sameHash, CommandDisplay: sameDisplay, Actor: owner.ID, At: at,
	}); err != nil {
		t.Fatal(err)
	}
	kept, err := m.ListCatalogApprovals(ctx, host.ID)
	if err != nil || len(kept) != 1 || kept[0].Status != "approved" || kept[0].Exec != "pnpm" || kept[0].RequestedBy != owner.ID {
		t.Fatalf("same hash %#v %v", kept, err)
	}
	if kept[0].Env == nil || len(kept[0].Args) != 2 || kept[0].Args[0] != "run" {
		t.Fatalf("approval spec %#v", kept[0])
	}
	if err := m.UpsertPendingApproval(ctx, entry.ID, host.ID, hash, owner.ID, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	kept, err = m.ListCatalogApprovals(ctx, host.ID)
	if err != nil || len(kept) != 1 || kept[0].Status != "approved" || !kept[0].RequestedAt.Equal(at) {
		t.Fatalf("upsert cleared approval %#v %v", kept, err)
	}
	other, otherHash, otherDisplay := catalogSpec(t, "pnpm run start")
	if _, _, err := m.ReplaceCatalogEntry(ctx, home.ID, "web", store.CatalogWrite{
		Spec: other, SpecHash: otherHash, CommandDisplay: otherDisplay, Actor: owner.ID, At: at,
	}); err != nil {
		t.Fatal(err)
	}
	left, err := m.ListCatalogApprovals(ctx, host.ID)
	if err != nil || len(left) != 0 {
		t.Fatalf("approvals %#v %v", left, err)
	}

	body := []byte(`{"code":"ok","msg":"ok","payload":null}`)
	var sum [32]byte
	sum[0] = 7
	rec := store.IdempotencyRecord{RequestHash: sum[:], Status: 202, Body: body, CreatedAt: at}
	if err := m.PutIdempotency(ctx, owner.ID, "k", rec); err != nil {
		t.Fatal(err)
	}
	if err := m.PutIdempotency(ctx, owner.ID, "k", rec); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate %v", err)
	}
	got, err := m.GetIdempotency(ctx, owner.ID, "k", at.Add(23*time.Hour))
	if err != nil || string(got.Body) != string(body) {
		t.Fatalf("replay %+v %v", got, err)
	}
	next := []byte(`{"code":"ok","msg":"ok","payload":{"unit":"u"}}`)
	if err := m.ReplaceIdempotencyResponse(ctx, owner.ID, "k", 200, next); err != nil {
		t.Fatal(err)
	}
	got, err = m.GetIdempotency(ctx, owner.ID, "k", at.Add(23*time.Hour))
	if err != nil || got.Status != 200 || string(got.Body) != string(next) {
		t.Fatalf("replaced %+v %v", got, err)
	}
	if _, err := m.GetIdempotency(ctx, owner.ID, "k", at.Add(store.IdempotencyTTL)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expiry %v", err)
	}
	if _, err := m.ApproveCatalog(ctx, host.ID, entry.ID, hash, owner.ID, at); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale approve %v", err)
	}
	if left, err := m.ListCatalogApprovals(ctx, host.ID); err != nil || len(left) != 0 {
		t.Fatalf("stale approve stored %#v %v", left, err)
	}
}

func TestClaimIdempotency(t *testing.T) {
	ctx := context.Background()
	m := New()
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	owner := catalogUser(t, m, "claim-owner")
	other := catalogUser(t, m, "claim-other")
	var hash, different [32]byte
	hash[0] = 1
	different[0] = 2
	rec, claimed, err := m.ClaimIdempotency(ctx, owner.ID, "k", hash[:], at)
	if err != nil || !claimed || !rec.Pending {
		t.Fatalf("claim %+v %v %v", rec, claimed, err)
	}
	if _, _, err := m.ClaimIdempotency(ctx, owner.ID, "k", hash[:], at); !errors.Is(err, store.ErrPending) {
		t.Fatalf("in progress %v", err)
	}
	if _, _, err := m.ClaimIdempotency(ctx, owner.ID, "k", different[:], at); !errors.Is(err, store.ErrPending) {
		t.Fatalf("in progress other hash %v", err)
	}
	body := []byte(`{"code":"error","msg":"start_failed","payload":null}`)
	if err := m.ReplaceIdempotencyResponse(ctx, owner.ID, "k", 500, body); err != nil {
		t.Fatal(err)
	}
	got, claimed, err := m.ClaimIdempotency(ctx, owner.ID, "k", hash[:], at.Add(6*time.Minute))
	if err != nil || claimed || got.Pending || got.Status != 500 || string(got.Body) != string(body) {
		t.Fatalf("replay after confirmation ttl %+v %v %v", got, claimed, err)
	}
	if _, _, err := m.ClaimIdempotency(ctx, owner.ID, "k", different[:], at); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("different request %v", err)
	}
	if _, claimed, err := m.ClaimIdempotency(ctx, other.ID, "k", different[:], at); err != nil || !claimed {
		t.Fatalf("other user %v %v", claimed, err)
	}
}

func TestCatalogDeleteKeepsSiblingConfirmations(t *testing.T) {
	ctx := context.Background()
	m := New()
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	owner := catalogUser(t, m, "owner2")
	home := catalogProject(t, m, owner.ID, "Home", "home2", at)
	host := catalogHost(t, m, home, owner.ID, "pi", at)
	spec, hash, display := catalogSpec(t, "pnpm run dev")
	first, err := m.CreateCatalogEntry(ctx, home.ID, store.CatalogWrite{Name: "one", Spec: spec, SpecHash: hash, CommandDisplay: display, Actor: owner.ID, At: at})
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.CreateCatalogEntry(ctx, home.ID, store.CatalogWrite{Name: "two", Spec: spec, SpecHash: hash, CommandDisplay: display, Actor: owner.ID, At: at})
	if err != nil {
		t.Fatal(err)
	}
	var h1, h2 [32]byte
	h1[0] = 1
	h2[0] = 2
	put := func(hash []byte, entry store.CatalogEntry, key string) {
		t.Helper()
		err := m.PutConfirmation(ctx, hash, store.CatalogConfirmation{
			UserID: owner.ID, ProjectID: home.ID, EntryID: entry.ID, EntryName: entry.Name, HostID: host.ID,
			Action: "run", SpecHash: entry.SpecHash, IdempotencyKey: key, RequestHash: hash,
			CreatedAt: at, ExpiresAt: at.Add(time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	put(h1[:], first, "a")
	put(h2[:], second, "b")
	if _, err := m.DeleteCatalogEntry(ctx, home.ID, "one"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetConfirmation(ctx, h1[:]); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted entry confirmation %v", err)
	}
	if _, err := m.GetConfirmation(ctx, h2[:]); err != nil {
		t.Fatalf("sibling confirmation %v", err)
	}
}

func TestOwnedIngestMemstore(t *testing.T) {
	ctx := context.Background()
	m := New()
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	owner := catalogUser(t, m, "own")
	home := catalogProject(t, m, owner.ID, "Home", "ownedproj", at)
	boxOwner := catalogUser(t, m, "box")
	box := catalogProject(t, m, boxOwner.ID, "Box", "box", at)
	host := catalogHost(t, m, box, boxOwner.ID, "pi-box", at)
	spec, hash, display := catalogSpec(t, "pnpm run dev")
	if _, err := m.CreateCatalogEntry(ctx, home.ID, store.CatalogWrite{
		Name: "webapp", Spec: spec, SpecHash: hash, CommandDisplay: display, Actor: owner.ID, At: at,
	}); err != nil {
		t.Fatal(err)
	}
	unit := "deploybot-missing-nope.service"
	scope := "system"
	if err := m.UpsertDiscovered(ctx, host.ID, []store.Discovered{{
		Name: "not-the-entry", Kind: "systemd", Ports: []int{3031},
		SystemdUnit: &unit, SystemdScope: &scope,
		Owner: &store.DiscoveredOwner{Kind: "program", Project: "ownedproj", Entry: "webapp"},
	}, {
		Name: "other", Kind: "systemd", Ports: []int{9},
		SystemdUnit: &unit, SystemdScope: &scope,
		Owner: &store.DiscoveredOwner{Kind: "program", Project: "missing", Entry: "nope"},
	}}, at, true, true); err != nil {
		t.Fatal(err)
	}
	items, err := m.ListServices(ctx, host.ID, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	owned := findService(t, items, "webapp")
	if owned.Source != "owned" || owned.ProjectID != home.ID || owned.CatalogEntry == nil || *owned.CatalogEntry != "webapp" {
		t.Fatalf("owned %+v", owned)
	}
	miss := findService(t, items, unit)
	if miss.Source != "discovered" || miss.ProjectID != box.ID || miss.CatalogEntry != nil {
		t.Fatalf("fallback %+v", miss)
	}
	absent := "deploybot-ownedproj-absent.service"
	if err := m.UpsertDiscovered(ctx, host.ID, []store.Discovered{{
		Name: "reported", Kind: "systemd", Ports: []int{4},
		SystemdUnit: &absent, SystemdScope: &scope,
		Owner: &store.DiscoveredOwner{Kind: "program", Project: "ownedproj", Entry: "no-such"},
	}}, at, true, true); err != nil {
		t.Fatal(err)
	}
	items, err = m.ListServices(ctx, host.ID, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	wrong := findService(t, items, absent)
	if wrong.Source != "discovered" || wrong.ProjectID != box.ID || wrong.CatalogEntry != nil {
		t.Fatalf("wrong entry %+v", wrong)
	}
	huge := strings.Repeat("b", 80)
	if err := m.UpsertDiscovered(ctx, host.ID, []store.Discovered{{
		Name: "shortname", Kind: "systemd", Ports: []int{5},
		SystemdUnit: &huge, SystemdScope: &scope,
		Owner: &store.DiscoveredOwner{Kind: "program", Project: "missing", Entry: "nope"},
	}}, at, true, true); err != nil {
		t.Fatal(err)
	}
	items, err = m.ListServices(ctx, host.ID, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	kept := findService(t, items, "shortname")
	if kept.Source != "discovered" || kept.Name != "shortname" {
		t.Fatalf("huge unit %+v", kept)
	}
}

func catalogUser(t *testing.T, m *Mem, subject string) store.User {
	t.Helper()
	user, err := m.UpsertGoogleUser(context.Background(), store.GoogleSignIn{
		Subject: subject, Email: subject + "@example.com", Name: subject, At: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func catalogProject(t *testing.T, m *Mem, owner uuid.UUID, name, slug string, at time.Time) store.Project {
	t.Helper()
	project, err := m.CreateProject(context.Background(), owner, name, slug, at)
	if err != nil {
		t.Fatal(err)
	}
	return project
}

func catalogHost(t *testing.T, m *Mem, project store.Project, owner uuid.UUID, name string, at time.Time) store.Host {
	t.Helper()
	_, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateJoinToken(context.Background(), project.ID, hash, nil, owner, at.Add(time.Hour), at); err != nil {
		t.Fatal(err)
	}
	_, credHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	host, err := m.ConsumeJoinToken(context.Background(), hash, store.EnrollInput{
		Name: name, NodeType: "pi", OS: "linux", Arch: "arm64", AlwaysOn: true, AgentVersion: "0.1.0",
	}, uuid.New(), credHash, at)
	if err != nil {
		t.Fatal(err)
	}
	return host
}

func catalogSpec(t *testing.T, command string) (store.ProgramSpec, string, string) {
	t.Helper()
	p, err := catalog.BuildProgram(catalog.ProgramInput{Command: command, Dir: "/home/joe/app", RunAs: "joe"})
	if err != nil {
		t.Fatal(err)
	}
	return store.ProgramSpec{
		Dir: p.Dir, Exec: p.Exec, Args: append([]string{}, p.Args...), Shell: p.Shell,
		RunAs: p.RunAs, Env: p.Env, Port: p.Port, Restart: p.Restart,
	}, catalog.SpecHash(p), p.Display
}

func findService(t *testing.T, items []store.Service, name string) store.Service {
	t.Helper()
	for _, item := range items {
		if item.Name == name {
			return item
		}
	}
	t.Fatalf("missing %s", name)
	return store.Service{}
}
