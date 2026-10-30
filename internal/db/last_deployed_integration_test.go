package db

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// TestCatalogLastDeployed checks the two api-v1 v1.21 queries against
// Postgres. It skips without DEPLOYBOT_TEST_DATABASE_URL.
func TestCatalogLastDeployed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	d, owner, host, images := autoStoreFixture(t, ctx, 3)
	projectID := images[0].ProjectID
	at := time.Now().UTC().Truncate(time.Second)
	tag := strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	other := enrollHostDB(t, d, ctx, projectID, owner.ID, "last-host-"+tag, at)
	otherProject := catalogProject(t, d, ctx, owner.ID, "LastOther", "lastother"+tag, at)

	web, idle, auto := images[0], images[1], images[2]
	hash := strings.Repeat("a", 64)
	digest := "sha256:" + strings.Repeat("1", 64)
	finishDeploy(t, d, ctx, web.ID, host.ID, hash, owner.ID, "succeeded", digest, at.Add(-3*time.Hour))
	mcp, err := d.BeginImageOp(ctx, web.ID, other.ID, hash, owner.ID, "mcp", at.Add(-2*time.Hour), at.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.FinishImageDeploy(ctx, mcp.ID, "failed", nil, nil, at.Add(-2*time.Hour+time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uuid.UUID{web.ID, auto.ID} {
		autoAt(t, d, ctx, id, host.ID, "auto_restarted", nil, at.Add(-time.Hour))
	}

	programs := map[string]store.CatalogEntry{}
	for _, name := range []string{"tra", "quiet", "mcp-run"} {
		spec, specHash, display := catalogSpec(t, "pnpm run dev")
		e, err := d.CreateCatalogEntry(ctx, projectID, store.CatalogWrite{
			Name: name, Spec: spec, SpecHash: specHash, CommandDisplay: display, Actor: owner.ID, At: at,
		})
		if err != nil {
			t.Fatal(err)
		}
		programs[name] = e
	}
	audit := func(project uuid.UUID, action, decision, via, entry string, when time.Time) {
		t.Helper()
		if err := d.InsertAudit(ctx, store.AuditRow{
			At: when, ActorUserID: &owner.ID, Via: via, ProjectID: &project, HostID: &host.ID,
			Action: action, Decision: decision, Detail: map[string]any{"entry": entry},
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Program entries were created at `at`; runs count from then.
	audit(projectID, "program.run", "allowed", "console", "tra", at)
	audit(projectID, "program.run", "allowed", "console", "tra", at.Add(time.Hour))
	audit(projectID, "program.run", "denied", "console", "tra", at.Add(2*time.Hour))
	audit(projectID, "program.stop", "allowed", "console", "tra", at.Add(2*time.Hour))
	audit(projectID, "program.restart", "allowed", "mcp", "tra", at.Add(2*time.Hour))
	audit(projectID, "program.run", "allowed", "agent", "tra", at.Add(2*time.Hour))
	audit(otherProject.ID, "program.run", "allowed", "console", "tra", at.Add(2*time.Hour))
	audit(otherProject.ID, "program.run", "allowed", "console", "quiet", at.Add(2*time.Hour))
	audit(projectID, "program.run", "allowed", "console", "quiet", at.Add(-time.Minute))
	audit(projectID, "program.run", "allowed", "mcp", "mcp-run", at.Add(30*time.Minute))

	all, err := d.ListCatalogEntries(ctx, projectID)
	if err != nil || len(all) != 6 {
		t.Fatalf("entries %d %v", len(all), err)
	}
	got, err := d.CatalogLastDeployed(ctx, projectID, all)
	if err != nil {
		t.Fatal(err)
	}
	want := map[uuid.UUID]time.Time{
		web.ID:                 at.Add(-2 * time.Hour),
		programs["tra"].ID:     at.Add(time.Hour),
		programs["mcp-run"].ID: at.Add(30 * time.Minute),
	}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for id, w := range want {
		if !got[id].Equal(w) {
			t.Fatalf("%s got %v want %v", id, got[id], w)
		}
	}
	for _, id := range []uuid.UUID{idle.ID, auto.ID, programs["quiet"].ID} {
		if _, ok := got[id]; ok {
			t.Fatalf("%s should be absent: %v", id, got[id])
		}
	}
	if none, err := d.CatalogLastDeployed(ctx, projectID, nil); err != nil || len(none) != 0 {
		t.Fatalf("empty %v %v", none, err)
	}

	// Entries are matched within the given project only.
	if got, err := d.CatalogLastDeployed(ctx, otherProject.ID, all); err != nil || len(got) != 0 {
		t.Fatalf("other project %v %v", got, err)
	}

	// A run before a delete and re-create under the same name does not count.
	if _, err := d.DeleteCatalogEntry(ctx, projectID, "tra"); err != nil {
		t.Fatal(err)
	}
	spec, specHash, display := catalogSpec(t, "pnpm run dev")
	redo, err := d.CreateCatalogEntry(ctx, projectID, store.CatalogWrite{
		Name: "tra", Spec: spec, SpecHash: specHash, CommandDisplay: display, Actor: owner.ID, At: at.Add(3 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := d.CatalogLastDeployed(ctx, projectID, []store.CatalogEntry{redo}); err != nil || len(got) != 0 {
		t.Fatalf("re-created %v %v", got, err)
	}
	audit(projectID, "program.run", "allowed", "console", "tra", at.Add(4*time.Hour))
	if got, err := d.CatalogLastDeployed(ctx, projectID, []store.CatalogEntry{redo}); err != nil || !got[redo.ID].Equal(at.Add(4*time.Hour)) {
		t.Fatalf("re-created after run %v %v", got, err)
	}
}
