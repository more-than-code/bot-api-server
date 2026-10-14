package memstore

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestInviteHashAtRest(t *testing.T) {
	m, owner, project, at := inviteFixture(t)
	plain, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	inv, err := m.CreateInvite(context.Background(), project.ID, hash, "viewer", owner.ID, at.Add(time.Hour), at, 1)
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := m.invites[inv.ID]
	if !ok || !bytes.Equal(rec.hash, secret.Hash(plain)) || bytes.Equal(rec.hash, []byte(plain)) {
		t.Fatal("token hash was not stored as secret.Hash")
	}
	if m.HoldsPlaintext(plain) {
		t.Fatal("invite plaintext is stored")
	}
}

func TestInviteAcceptExactlyMaxUses(t *testing.T) {
	const n = 8
	const extra = 5
	m, owner, project, at := inviteFixture(t)
	_, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	inv, err := m.CreateInvite(context.Background(), project.ID, hash, "viewer", owner.ID, at.Add(time.Hour), at, n)
	if err != nil {
		t.Fatal(err)
	}
	users := make([]store.User, n+extra)
	for i := range users {
		users[i] = inviteUser(t, m, at, i)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	okN := 0
	miss := 0
	winners := map[uuid.UUID]bool{}
	var bad []string
	wg.Add(len(users))
	for _, u := range users {
		go func(id uuid.UUID) {
			defer wg.Done()
			<-start
			res, err := m.AcceptInvite(context.Background(), hash, id, at)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				okN++
				if res.Role != "viewer" || res.ProjectID != project.ID || res.InviteID != inv.ID {
					bad = append(bad, "wrong accept result")
				}
				winners[id] = true
			case errors.Is(err, store.ErrNotFound):
				miss++
			default:
				bad = append(bad, err.Error())
			}
		}(u.ID)
	}
	close(start)
	wg.Wait()
	if len(bad) > 0 || okN != n || miss != extra || len(winners) != n {
		t.Fatalf("ok=%d miss=%d winners=%d bad=%v", okN, miss, len(winners), bad)
	}
	if m.invites[inv.ID].Uses != n {
		t.Fatalf("uses %d", m.invites[inv.ID].Uses)
	}
	viewers := 0
	for _, mem := range m.members {
		if mem.ProjectID != project.ID || mem.Role != "viewer" {
			continue
		}
		viewers++
		if mem.AddedBy != owner.ID || !winners[mem.UserID] {
			t.Fatalf("member %#v", mem)
		}
	}
	if viewers != n {
		t.Fatalf("viewers %d", viewers)
	}
}

func TestInviteAcceptKeepsMember(t *testing.T) {
	m, owner, project, at := inviteFixture(t)
	_, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	inv, err := m.CreateInvite(context.Background(), project.ID, hash, "viewer", owner.ID, at.Add(time.Hour), at, 1)
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.AcceptInvite(context.Background(), hash, owner.ID, at)
	if err != nil || res.Role != "owner" {
		t.Fatalf("owner accept %v %#v", err, res)
	}
	if m.invites[inv.ID].Uses != 0 || m.members[memberKey(project.ID, owner.ID)].Role != "owner" {
		t.Fatal("existing member consumed a use or changed role")
	}
	guest := inviteUser(t, m, at, 0)
	res, err = m.AcceptInvite(context.Background(), hash, guest.ID, at)
	if err != nil || res.Role != "viewer" {
		t.Fatalf("guest accept %v %#v", err, res)
	}
	if m.invites[inv.ID].Uses != 1 {
		t.Fatalf("uses %d", m.invites[inv.ID].Uses)
	}
	if m.members[memberKey(project.ID, owner.ID)].Role != "owner" {
		t.Fatal("owner role changed")
	}
	mem := m.members[memberKey(project.ID, guest.ID)]
	if mem.Role != "viewer" || mem.AddedBy != owner.ID {
		t.Fatalf("guest member %#v", mem)
	}
}

func TestInviteDeleteProjectRemovesRows(t *testing.T) {
	m, owner, project, at := inviteFixture(t)
	other, err := m.CreateProject(context.Background(), owner.ID, "Other", "other", at)
	if err != nil {
		t.Fatal(err)
	}
	_, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	inv, err := m.CreateInvite(context.Background(), project.ID, hash, "viewer", owner.ID, at.Add(time.Hour), at, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, otherHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	kept, err := m.CreateInvite(context.Background(), other.ID, otherHash, "admin", owner.ID, at.Add(time.Hour), at, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.DeleteProject(context.Background(), project.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.invites[inv.ID]; ok {
		t.Fatal("invite row survived project delete")
	}
	if _, ok := m.inviteByHash[hashKey(hash)]; ok {
		t.Fatal("invite hash index survived project delete")
	}
	if _, err := m.LookupInvite(context.Background(), hash, owner.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted project lookup: %v", err)
	}
	if _, ok := m.invites[kept.ID]; !ok {
		t.Fatal("other project's invite was deleted")
	}
	look, err := m.LookupInvite(context.Background(), otherHash, owner.ID, at)
	if err != nil || look.ProjectID != other.ID || look.Role != "admin" {
		t.Fatalf("other lookup %v %#v", err, look)
	}
}

func inviteFixture(t *testing.T) (*Mem, store.User, store.Project, time.Time) {
	t.Helper()
	m := New()
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	owner := inviteUser(t, m, at, -1)
	project, err := m.CreateProject(context.Background(), owner.ID, "Lab", "lab", at)
	if err != nil {
		t.Fatal(err)
	}
	return m, owner, project, at
}

func inviteUser(t *testing.T, m *Mem, at time.Time, n int) store.User {
	t.Helper()
	email := "user@example.com"
	if n >= 0 {
		email = "user" + strconv.Itoa(n) + "@example.com"
	}
	u, err := m.UpsertGoogleUser(context.Background(), store.GoogleSignIn{
		Subject: email, Email: email, Name: email, At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	return u
}
