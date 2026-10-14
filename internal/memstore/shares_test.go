package memstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestHostFactsReturnsEveryShare(t *testing.T) {
	ctx := context.Background()
	mem := New()
	at := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	owner := mustUser(t, mem, "owner@ex.com", at)
	guest := mustUser(t, mem, "guest@ex.com", at)
	home, err := mem.CreateProject(ctx, owner.ID, "Home", "home", at)
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := mem.CreateProject(ctx, guest.ID, "Metrics", "metrics", at)
	if err != nil {
		t.Fatal(err)
	}
	deploy, err := mem.CreateProject(ctx, owner.ID, "Deploy", "deploy", at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mem.AddMember(ctx, deploy.ID, guest.ID, "admin", owner.ID, at); err != nil {
		t.Fatal(err)
	}
	host := enrollMem(t, mem, home.ID, owner.ID, "pi", at)
	if _, _, err := mem.PutHostShare(ctx, host.ID, metrics.ID, "metrics", owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mem.PutHostShare(ctx, host.ID, deploy.ID, "deploy", owner.ID, at); err != nil {
		t.Fatal(err)
	}
	facts, err := mem.HostFacts(ctx, guest.ID, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if facts.OwnerRole != "" || len(facts.Shares) != 2 {
		t.Fatalf("facts %+v", facts)
	}
	got := map[uuid.UUID]store.HostShareAccess{}
	for _, sh := range facts.Shares {
		got[sh.ProjectID] = sh
	}
	if got[metrics.ID].Level != "metrics" || got[metrics.ID].Role != "owner" {
		t.Fatalf("metrics share %+v", got[metrics.ID])
	}
	if got[deploy.ID].Level != "deploy" || got[deploy.ID].Role != "admin" {
		t.Fatalf("deploy share %+v", got[deploy.ID])
	}
	ownerFacts, err := mem.HostFacts(ctx, owner.ID, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ownerFacts.OwnerRole != "owner" || len(ownerFacts.Shares) != 1 || ownerFacts.Shares[0].ProjectID != deploy.ID {
		t.Fatalf("owner facts %+v", ownerFacts)
	}
}

func TestHostListCursorResumesWithoutLookup(t *testing.T) {
	ctx := context.Background()
	mem := New()
	at := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	homeOwner := mustUser(t, mem, "home@ex.com", at)
	boardOwner := mustUser(t, mem, "board@ex.com", at)
	home, err := mem.CreateProject(ctx, homeOwner.ID, "Home", "home", at)
	if err != nil {
		t.Fatal(err)
	}
	board, err := mem.CreateProject(ctx, boardOwner.ID, "Board", "board", at)
	if err != nil {
		t.Fatal(err)
	}
	a := enrollMem(t, mem, home.ID, homeOwner.ID, "a-owned", at)
	b := enrollMem(t, mem, home.ID, homeOwner.ID, "b-owned", at)
	c := enrollMem(t, mem, board.ID, boardOwner.ID, "c-shared", at)
	d := enrollMem(t, mem, board.ID, boardOwner.ID, "d-shared", at)
	if _, _, err := mem.PutHostShare(ctx, c.ID, home.ID, "deploy", boardOwner.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mem.PutHostShare(ctx, d.ID, home.ID, "metrics", boardOwner.ID, at); err != nil {
		t.Fatal(err)
	}
	owned, _, err := mem.ListHosts(ctx, board.ID, 50, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(owned) != 2 {
		t.Fatalf("owning project list %d", len(owned))
	}
	for i, h := range owned {
		if h.Relation != "owner" || h.ShareLevel != nil {
			t.Fatalf("owning row %d relation %s level %v", i, h.Relation, h.ShareLevel)
		}
	}
	want := []uuid.UUID{a.ID, b.ID, c.ID, d.ID}
	var cur *store.Cursor
	var got []uuid.UUID
	for page := 0; page < len(want)+1; page++ {
		items, next, err := mem.ListHosts(ctx, home.ID, 1, cur)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) == 0 {
			if next != nil {
				t.Fatal("empty page has a cursor")
			}
			break
		}
		if len(items) != 1 {
			t.Fatalf("page %d len %d", page, len(items))
		}
		got = append(got, items[0].ID)
		if next == nil {
			break
		}
		if next.Rank == nil || next.Name != items[0].Name || next.ID != items[0].ID.String() {
			t.Fatalf("cursor %+v for %s", next, items[0].Name)
		}
		if items[0].ID == c.ID {
			if _, err := mem.DeleteHostShare(ctx, c.ID, home.ID, false); err != nil {
				t.Fatal(err)
			}
		}
		cur = next
	}
	if len(got) != len(want) {
		t.Fatalf("resumed %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order %v, want %v", got, want)
		}
	}
}

func TestPutHostShareRequiresLiveOwner(t *testing.T) {
	ctx := context.Background()
	mem := New()
	at := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	owner := mustUser(t, mem, "owner@ex.com", at)
	guest := mustUser(t, mem, "guest@ex.com", at)
	home, err := mem.CreateProject(ctx, owner.ID, "Home", "home", at)
	if err != nil {
		t.Fatal(err)
	}
	other, err := mem.CreateProject(ctx, guest.ID, "Other", "other", at)
	if err != nil {
		t.Fatal(err)
	}
	host := enrollMem(t, mem, home.ID, owner.ID, "pi", at)
	if _, err := mem.DeleteProject(ctx, home.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mem.PutHostShare(ctx, host.ID, other.ID, "metrics", owner.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("share after owner delete: %v", err)
	}
	shares, err := mem.ListHostShares(ctx, host.ID)
	if err != nil || len(shares) != 0 {
		t.Fatalf("shares left: %v %+v", err, shares)
	}
}

func TestEmptyProjectFilterMatchesNothing(t *testing.T) {
	ctx := context.Background()
	mem := New()
	at := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	owner := mustUser(t, mem, "owner@ex.com", at)
	home, err := mem.CreateProject(ctx, owner.ID, "Home", "home", at)
	if err != nil {
		t.Fatal(err)
	}
	host := enrollMem(t, mem, home.ID, owner.ID, "pi", at)
	svc := mem.PutDeclared(host.ID, "api", "process", nil, at)
	all, err := mem.ListServices(ctx, host.ID, nil, at)
	if err != nil || len(all) != 1 || all[0].ID != svc.ID {
		t.Fatalf("nil filter %+v %v", all, err)
	}
	none, err := mem.ListServices(ctx, host.ID, []uuid.UUID{}, at)
	if err != nil || len(none) != 0 {
		t.Fatalf("empty filter %+v %v", none, err)
	}
}

func mustUser(t *testing.T, mem *Mem, email string, at time.Time) store.User {
	t.Helper()
	u, err := mem.UpsertGoogleUser(context.Background(), store.GoogleSignIn{
		Subject: email, Email: email, Name: email, At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func enrollMem(t *testing.T, mem *Mem, projectID, ownerID uuid.UUID, name string, at time.Time) store.Host {
	t.Helper()
	ctx := context.Background()
	_, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mem.CreateJoinToken(ctx, projectID, hash, nil, ownerID, at.Add(time.Hour), at); err != nil {
		t.Fatal(err)
	}
	_, credHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	host, err := mem.ConsumeJoinToken(ctx, hash, store.EnrollInput{
		Name: name, NodeType: "pi", OS: "linux", Arch: "arm64", AlwaysOn: true, AgentVersion: "0.1.0",
	}, uuid.New(), credHash, at)
	if err != nil {
		t.Fatal(err)
	}
	return host
}
