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

func autoFixture(t *testing.T) (*Mem, store.User, store.CatalogEntry, store.Host) {
	t.Helper()
	ctx := context.Background()
	m := New()
	at := time.Now().UTC().Truncate(time.Second)
	user, err := m.UpsertGoogleUser(ctx, store.GoogleSignIn{Subject: "s", Email: "a@b.c", Name: "A", At: at})
	if err != nil {
		t.Fatal(err)
	}
	project, err := m.CreateProject(ctx, user.ID, "P", "p", at)
	if err != nil {
		t.Fatal(err)
	}
	_, joinHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateJoinToken(ctx, project.ID, joinHash, nil, user.ID, at.Add(time.Hour), at); err != nil {
		t.Fatal(err)
	}
	_, credHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	host, err := m.ConsumeJoinToken(ctx, joinHash, store.EnrollInput{Name: "pi", NodeType: "pi", OS: "linux", Arch: "arm64", AlwaysOn: true, AgentVersion: "1"}, uuid.New(), credHash, at)
	if err != nil {
		t.Fatal(err)
	}
	img, err := catalog.BuildImage("web", []byte(`{"kind":"service","image":"redis","healthcheck":{"test":["redis-cli","ping"]},"health_policy":{"on_unhealthy":"rollback"}}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := m.CreateCatalogEntry(ctx, project.ID, store.CatalogWrite{
		Name: "web", Kind: "image", ImageRaw: []byte(catalog.SpecJSON(img)),
		SpecHash: catalog.ImageHash(img, nil), CommandDisplay: img.Image, Actor: user.ID, At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m, user, entry, host
}

func memDigest(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

func TestAutoActionDigestInheritance(t *testing.T) {
	ctx := context.Background()
	m, user, entry, host := autoFixture(t)
	at := time.Now().UTC().Truncate(time.Second)
	userDigest := memDigest('1')
	row, err := m.BeginImageOp(ctx, entry.ID, host.ID, strings.Repeat("a", 64), user.ID, "console", at.Add(-time.Hour), at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.FinishImageDeploy(ctx, row.ID, "succeeded", &userDigest, nil, at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	// A later failed user deploy with a digest is not inherited either.
	failedDigest := memDigest('4')
	row, err = m.BeginImageOp(ctx, entry.ID, host.ID, strings.Repeat("a", 64), user.ID, "console", at.Add(-30*time.Minute), at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.FinishImageDeploy(ctx, row.ID, "failed", &failedDigest, nil, at.Add(-30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	x := memDigest('9')
	if _, ok, err := m.RecordAutoAction(ctx, store.AutoAction{ID: uuid.New(), EntryID: entry.ID, HostID: host.ID, Outcome: "auto_rolled_back", Digest: &x, At: at}); err != nil || !ok {
		t.Fatal(err)
	}
	restart, ok, err := m.RecordAutoAction(ctx, store.AutoAction{ID: uuid.New(), EntryID: entry.ID, HostID: host.ID, Outcome: "auto_restarted", At: at.Add(time.Second)})
	if err != nil || !ok || restart.Digest == nil || *restart.Digest != userDigest {
		t.Fatalf("restart digest %v (want the last succeeded user digest) %v", restart.Digest, err)
	}
	failed, ok, err := m.RecordAutoAction(ctx, store.AutoAction{ID: uuid.New(), EntryID: entry.ID, HostID: host.ID, Outcome: "auto_failed", Digest: &x, At: at.Add(2 * time.Second)})
	if err != nil || !ok || failed.Digest != nil {
		t.Fatalf("auto_failed digest %v %v", failed.Digest, err)
	}
}

func TestAutoActionWindowBoundary(t *testing.T) {
	ctx := context.Background()
	m, _, entry, host := autoFixture(t)
	b := time.Now().UTC().Truncate(time.Second).Add(-3 * time.Hour)
	for i := 0; i < store.AutoActionsPerHour; i++ {
		if _, ok, err := m.RecordAutoAction(ctx, store.AutoAction{ID: uuid.New(), EntryID: entry.ID, HostID: host.ID, Outcome: "auto_restarted", At: b}); err != nil || !ok {
			t.Fatalf("fill %d %v", i, err)
		}
	}
	// At-1h+1s: the rows at b count.
	if _, _, err := m.RecordAutoAction(ctx, store.AutoAction{ID: uuid.New(), EntryID: entry.ID, HostID: host.ID, Outcome: "auto_restarted", At: b.Add(time.Hour - time.Second)}); !errors.Is(err, store.ErrAutoActionLimit) {
		t.Fatalf("one second inside the window: %v", err)
	}
	// Exactly At-1h: the rows at b do not count.
	if _, ok, err := m.RecordAutoAction(ctx, store.AutoAction{ID: uuid.New(), EntryID: entry.ID, HostID: host.ID, Outcome: "auto_restarted", At: b.Add(time.Hour)}); err != nil || !ok {
		t.Fatalf("at the boundary: %v", err)
	}
}
