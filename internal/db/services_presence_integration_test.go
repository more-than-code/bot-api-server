package db

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
	"github.com/more-than-code/bot-api-server/migrations"
)

func TestServicePresenceIntegration(t *testing.T) {
	d, ctx := openPresenceDB(t)
	t.Run("column", func(t *testing.T) { assertGoneColumn(t, d, ctx) })
	t.Run("mark", func(t *testing.T) { assertPresenceMark(t, d, ctx) })
	t.Run("views", func(t *testing.T) { assertServiceViews(t, d, ctx) })
	t.Run("status", func(t *testing.T) { assertStatusSortGoneLast(t, d, ctx) })
	t.Run("filters", func(t *testing.T) { assertServiceViewFilters(t, d, ctx) })
	t.Run("placed", func(t *testing.T) { assertPresencePlacedName(t, d, ctx) })
	t.Run("backfill", func(t *testing.T) { assertServiceGoneBackfill(t, d, ctx) })
}

func openPresenceDB(t *testing.T) (*DB, context.Context) {
	t.Helper()
	url := os.Getenv("DEPLOYBOT_TEST_DATABASE_URL")
	if url == "" {
		t.Skip()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	d, err := Open(ctx, url)
	if err != nil {
		t.Fatal("connect failed")
	}
	t.Cleanup(d.Close)
	var dbName string
	if err := d.pool.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatal("database name lookup failed")
	}
	if dbName != "deploybot_test" {
		t.Fatalf("refusing database %s", dbName)
	}
	if err := Migrate(ctx, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return d, ctx
}

func assertGoneColumn(t *testing.T, d *DB, ctx context.Context) {
	t.Helper()
	var dataType, nullable string
	err := d.pool.QueryRow(ctx, `
SELECT data_type, is_nullable
FROM information_schema.columns
WHERE table_schema = 'app' AND table_name = 'services' AND column_name = 'gone_at'
`).Scan(&dataType, &nullable)
	if err != nil {
		t.Fatal(err)
	}
	if dataType != "timestamp with time zone" || nullable != "YES" {
		t.Fatalf("gone_at %s nullable %s", dataType, nullable)
	}
}

func assertPresenceMark(t *testing.T, d *DB, ctx context.Context) {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Microsecond)
	tag := strings.ReplaceAll(uuid.New().String(), "-", "")[:10]
	user := mustSvcUser(t, d, ctx, "presence-"+tag, at)
	project := mustSvcProject(t, d, ctx, user.ID, "Presence", "presence-"+tag, at)
	host := enrollHostDB(t, d, ctx, project.ID, user.ID, "presence-"+tag, at)
	other := enrollHostDB(t, d, ctx, project.ID, user.ID, "presence-other-"+tag, at)
	declaredID := insertPresenceRow(t, d, ctx, host.ID, project.ID, "declared", "declared", nil, at)
	gammaID := insertPresenceRow(t, d, ctx, other.ID, project.ID, "gamma", "discovered", nil, at)

	t1 := at.Add(time.Minute)
	if err := d.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "alpha", Kind: "process", Ports: []int{1}},
		{Name: "beta", Kind: "process", Ports: []int{2}},
	}, t1, true, true); err != nil {
		t.Fatal(err)
	}
	alpha := serviceByNameDB(t, d, ctx, host.ID, "alpha", t1)
	beta := serviceByNameDB(t, d, ctx, host.ID, "beta", t1)
	if alpha.GoneAt != nil || beta.GoneAt != nil {
		t.Fatalf("reported gone alpha %v beta %v", alpha.GoneAt, beta.GoneAt)
	}
	marked := mustServiceDB(t, d, ctx, declaredID, t1)
	if marked.Source != "declared" || marked.GoneAt == nil || !marked.GoneAt.Equal(t1) {
		t.Fatalf("declared source %s gone %v", marked.Source, marked.GoneAt)
	}
	if got := mustServiceDB(t, d, ctx, gammaID, t1); got.GoneAt != nil {
		t.Fatalf("other host %v", got.GoneAt)
	}

	display := "Beta"
	if _, err := d.SetServiceDisplayName(ctx, beta.ID, &display, t1); err != nil {
		t.Fatal(err)
	}
	path := "/"
	checks, err := d.ReplaceHealthChecks(ctx, beta.ID, []store.HealthCheckInput{{
		Protocol: "http", Port: 2, Path: &path, IntervalSec: 30,
		ExpectStatusMin: 200, ExpectStatusMax: 299, Enabled: true,
	}})
	if err != nil || len(checks) != 1 {
		t.Fatalf("checks %v %v", checks, err)
	}

	t2 := t1.Add(time.Minute)
	if err := d.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "alpha", Kind: "process", Ports: []int{1}},
	}, t2, true, true); err != nil {
		t.Fatal(err)
	}
	beta = mustServiceDB(t, d, ctx, beta.ID, t2)
	if beta.GoneAt == nil || !beta.GoneAt.Equal(t2) || beta.ID != checks[0].ServiceID {
		t.Fatalf("omitted %v", beta.GoneAt)
	}
	marked = mustServiceDB(t, d, ctx, declaredID, t2)
	if marked.GoneAt == nil || !marked.GoneAt.Equal(t1) || marked.Source != "declared" {
		t.Fatalf("declared moved %v %s", marked.GoneAt, marked.Source)
	}
	if got := mustServiceDB(t, d, ctx, alpha.ID, t2); got.GoneAt != nil {
		t.Fatal("alpha marked")
	}
	if got := mustServiceDB(t, d, ctx, gammaID, t2); got.GoneAt != nil {
		t.Fatal("other host marked")
	}

	t3 := t2.Add(time.Minute)
	if err := d.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "alpha", Kind: "process", Ports: []int{1}},
	}, t3, true, true); err != nil {
		t.Fatal(err)
	}
	beta = mustServiceDB(t, d, ctx, beta.ID, t3)
	if beta.GoneAt == nil || !beta.GoneAt.Equal(t2) {
		t.Fatalf("already gone moved to %v", beta.GoneAt)
	}

	if err := d.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "alpha", Kind: "process"},
		{Name: "beta", Kind: "process"},
		{Name: "intruder", Kind: "process"},
	}, t3.Add(time.Second), false, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := findServiceDB(t, d, ctx, host.ID, "intruder", t3); ok {
		t.Fatal("incomplete report inserted a row")
	}
	if got := mustServiceDB(t, d, ctx, beta.ID, t3); got.GoneAt == nil || !got.GoneAt.Equal(t2) {
		t.Fatalf("incomplete changed gone_at %v", got.GoneAt)
	}
	if err := d.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "alpha", Kind: "process"},
		{Name: "beta", Kind: "process"},
		{Name: "intruder", Kind: "process"},
	}, t3.Add(time.Second), false, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := findServiceDB(t, d, ctx, host.ID, "intruder", t3); ok {
		t.Fatal("incomplete report inserted a row")
	}
	if got := mustServiceDB(t, d, ctx, beta.ID, t3); got.GoneAt == nil || !got.GoneAt.Equal(t2) {
		t.Fatalf("presence ignored on incomplete %v", got.GoneAt)
	}

	t4 := t3.Add(2 * time.Second)
	if err := d.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "beta", Kind: "process", Ports: []int{2}},
	}, t4, true, false); err != nil {
		t.Fatal(err)
	}
	beta = mustServiceDB(t, d, ctx, beta.ID, t4)
	if beta.GoneAt != nil {
		t.Fatalf("partial report left beta gone %v", beta.GoneAt)
	}
	if got := mustServiceDB(t, d, ctx, alpha.ID, t4); got.GoneAt != nil {
		t.Fatal("partial report marked alpha")
	}
	marked = mustServiceDB(t, d, ctx, declaredID, t4)
	if marked.GoneAt == nil || !marked.GoneAt.Equal(t1) {
		t.Fatalf("partial report moved declared %v", marked.GoneAt)
	}

	t5 := t3.Add(time.Minute)
	if err := d.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "alpha", Kind: "process", Ports: []int{1}},
		{Name: "beta", Kind: "process", Ports: []int{9}},
	}, t5, true, true); err != nil {
		t.Fatal(err)
	}
	beta = mustServiceDB(t, d, ctx, beta.ID, t5)
	if beta.GoneAt != nil || beta.ID != checks[0].ServiceID {
		t.Fatalf("returned gone %v id %s", beta.GoneAt, beta.ID)
	}
	if beta.DisplayName == nil || *beta.DisplayName != "Beta" {
		t.Fatalf("display %v", beta.DisplayName)
	}
	gotChecks, err := d.ListHealthChecks(ctx, beta.ID)
	if err != nil || len(gotChecks) != 1 || gotChecks[0].ID != checks[0].ID {
		t.Fatalf("health checks %+v %v", gotChecks, err)
	}

	t6 := t5.Add(time.Minute)
	if err := d.UpsertDiscovered(ctx, host.ID, []store.Discovered{}, t6, true, true); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uuid.UUID{alpha.ID, beta.ID} {
		got := mustServiceDB(t, d, ctx, id, t6)
		if got.GoneAt == nil || !got.GoneAt.Equal(t6) {
			t.Fatalf("%s empty report %v", got.Name, got.GoneAt)
		}
	}
	marked = mustServiceDB(t, d, ctx, declaredID, t6)
	if marked.GoneAt == nil || !marked.GoneAt.Equal(t1) {
		t.Fatalf("declared empty report %v", marked.GoneAt)
	}
	if got := mustServiceDB(t, d, ctx, gammaID, t6); got.GoneAt != nil {
		t.Fatalf("other host empty report %v", got.GoneAt)
	}
}

func assertServiceViews(t *testing.T, d *DB, ctx context.Context) {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Microsecond)
	tag := strings.ReplaceAll(uuid.New().String(), "-", "")[:10]
	user := mustSvcUser(t, d, ctx, "views-"+tag, at)
	project := mustSvcProject(t, d, ctx, user.ID, "Views", "views-"+tag, at)
	host := enrollHostDB(t, d, ctx, project.ID, user.ID, "views-"+tag, at)
	gone := at
	rows := []struct {
		name, source string
		gone         *time.Time
	}{
		{"declared-gone", "declared", &gone},
		{"declared-up", "declared", nil},
		{"found-gone", "discovered", &gone},
		{"found-up", "discovered", nil},
		{"owned-gone", "owned", &gone},
		{"owned-up", "owned", nil},
	}
	for _, row := range rows {
		insertPresenceRow(t, d, ctx, host.ID, project.ID, row.name, row.source, row.gone, at)
	}
	all := []string{"declared-gone", "declared-up", "found-gone", "found-up", "owned-gone", "owned-up"}
	deploybot := []string{"declared-gone", "declared-up", "owned-gone", "owned-up"}
	withFound := []string{"declared-gone", "declared-up", "found-up", "owned-gone", "owned-up"}
	for _, tc := range []struct {
		view string
		want []string
	}{
		{"", all},
		{"all", all},
		{"deploybot", deploybot},
		{"deploybot_and_discovered", withFound},
	} {
		page, err := d.ListProjectServices(ctx, project.ID, store.ServiceListQuery{Sort: "name", Dir: "asc", Limit: 50, View: tc.view}, at)
		if err != nil || !sameLive(livePageNames(page), tc.want) {
			t.Fatalf("view %q %v %v", tc.view, livePageNames(page), err)
		}
	}
	page, err := d.ListProjectServices(ctx, project.ID, store.ServiceListQuery{
		Sort: "name", Dir: "asc", Limit: 1, View: "deploybot",
	}, at)
	if err != nil || page.Total != 4 || len(page.Items) != 1 {
		t.Fatalf("total %d items %d %v", page.Total, len(page.Items), err)
	}
}

func assertStatusSortGoneLast(t *testing.T, d *DB, ctx context.Context) {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Microsecond)
	tag := strings.ReplaceAll(uuid.New().String(), "-", "")[:10]
	user := mustSvcUser(t, d, ctx, "status-"+tag, at)
	project := mustSvcProject(t, d, ctx, user.ID, "Status", "status-"+tag, at)
	host := enrollHostDB(t, d, ctx, project.ID, user.ID, "status-"+tag, at)
	if err := d.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "a-gone", Kind: "process"},
		{Name: "a-present", Kind: "process"},
		{Name: "b-gone", Kind: "process"},
		{Name: "b-present", Kind: "process"},
	}, at, true, true); err != nil {
		t.Fatal(err)
	}
	ids := map[string]uuid.UUID{}
	for _, name := range []string{"a-gone", "a-present", "b-gone", "b-present"} {
		ids[name] = serviceByNameDB(t, d, ctx, host.ID, name, at).ID
	}
	for _, row := range []struct{ name, result string }{
		{"b-present", "success"},
		{"a-present", "fail"},
		{"b-gone", "success"},
	} {
		if _, err := d.pool.Exec(ctx, `
INSERT INTO metrics.health_results (time, host_id, service_id, result, latency_ms)
VALUES ($1, $2::uuid, $3::uuid, $4, 1)
`, at, host.ID.String(), ids[row.name].String(), row.result); err != nil {
			t.Fatal(err)
		}
	}
	later := at.Add(time.Minute)
	if err := d.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "b-present", Kind: "process"},
		{Name: "a-present", Kind: "process"},
	}, later, true, true); err != nil {
		t.Fatal(err)
	}
	asc, err := d.ListProjectServices(ctx, project.ID, store.ServiceListQuery{Sort: "status", Dir: "asc", Limit: 50}, later)
	if err != nil || !sameLive(livePageNames(asc), []string{"b-present", "a-present", "b-gone", "a-gone"}) {
		t.Fatalf("asc %v %v", livePageNames(asc), err)
	}
	desc, err := d.ListProjectServices(ctx, project.ID, store.ServiceListQuery{Sort: "status", Dir: "desc", Limit: 50}, later)
	if err != nil || !sameLive(livePageNames(desc), []string{"a-present", "b-present", "a-gone", "b-gone"}) {
		t.Fatalf("desc %v %v", livePageNames(desc), err)
	}
}

func assertServiceViewFilters(t *testing.T, d *DB, ctx context.Context) {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Microsecond)
	tag := strings.ReplaceAll(uuid.New().String(), "-", "")[:10]
	homeUser := mustSvcUser(t, d, ctx, "vhome-"+tag, at)
	guestUser := mustSvcUser(t, d, ctx, "vguest-"+tag, at)
	home := mustSvcProject(t, d, ctx, homeUser.ID, "Home", "vhome-"+tag, at)
	guest := mustSvcProject(t, d, ctx, guestUser.ID, "Guest", "vguest-"+tag, at)
	host := enrollHostDB(t, d, ctx, home.ID, homeUser.ID, "vhost-"+tag, at)
	other := enrollHostDB(t, d, ctx, home.ID, homeUser.ID, "vother-"+tag, at)
	gone := at
	insertPresenceRow(t, d, ctx, host.ID, guest.ID, "api", "declared", nil, at)
	insertPresenceRow(t, d, ctx, host.ID, home.ID, "api-old", "declared", &gone, at)
	insertPresenceRow(t, d, ctx, host.ID, guest.ID, "found", "discovered", nil, at)
	insertPresenceRow(t, d, ctx, host.ID, home.ID, "found-old", "discovered", &gone, at)
	insertPresenceRow(t, d, ctx, other.ID, home.ID, "api-remote", "declared", nil, at)
	if _, _, err := d.PutHostShare(ctx, host.ID, guest.ID, "deploy", homeUser.ID, at); err != nil {
		t.Fatal(err)
	}
	list := func(project uuid.UUID, q store.ServiceListQuery) []string {
		t.Helper()
		page, err := d.ListProjectServices(ctx, project, q, at)
		if err != nil {
			t.Fatal(err)
		}
		return livePageNames(page)
	}
	base := store.ServiceListQuery{Sort: "name", Dir: "asc", Limit: 50}
	homeAPI := base
	homeAPI.Q = "api"
	homeAPI.View = "deploybot"
	if got := list(home.ID, homeAPI); !sameLive(got, []string{"api", "api-old", "api-remote"}) {
		t.Fatalf("q api deploybot %v", got)
	}
	homeFound := base
	homeFound.Q = "found"
	homeFound.View = "deploybot"
	if got := list(home.ID, homeFound); len(got) != 0 {
		t.Fatalf("q found deploybot %v", got)
	}
	homeFound.View = "deploybot_and_discovered"
	if got := list(home.ID, homeFound); !sameLive(got, []string{"found"}) {
		t.Fatalf("q found with discovered %v", got)
	}
	hostID := host.ID
	hosted := base
	hosted.Q = "api"
	hosted.View = "deploybot"
	hosted.HostID = &hostID
	if got := list(home.ID, hosted); !sameLive(got, []string{"api", "api-old"}) {
		t.Fatalf("host_id %v", got)
	}
	guestDeploy := base
	guestDeploy.View = "deploybot"
	if got := list(guest.ID, guestDeploy); !sameLive(got, []string{"api"}) {
		t.Fatalf("guest deploybot %v", got)
	}
	guestBoth := base
	guestBoth.View = "deploybot_and_discovered"
	if got := list(guest.ID, guestBoth); !sameLive(got, []string{"api", "found"}) {
		t.Fatalf("guest both %v", got)
	}
}

func assertPresencePlacedName(t *testing.T, d *DB, ctx context.Context) {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Microsecond)
	tag := strings.ReplaceAll(uuid.New().String(), "-", "")[:10]
	owner := catalogUser(t, d, ctx, "placed-own-"+tag, at)
	boxOwner := catalogUser(t, d, ctx, "placed-box-"+tag, at)
	home := catalogProject(t, d, ctx, owner.ID, "Home", "placed-"+tag, at)
	box := catalogProject(t, d, ctx, boxOwner.ID, "Box", "placedbox-"+tag, at)
	host := enrollHostDB(t, d, ctx, box.ID, boxOwner.ID, "placed-"+tag, at)
	spec, hash, display := catalogSpec(t, "pnpm run dev")
	if _, err := d.CreateCatalogEntry(ctx, home.ID, store.CatalogWrite{
		Name: "webapp", Spec: spec, SpecHash: hash, CommandDisplay: display, Actor: owner.ID, At: at,
	}); err != nil {
		t.Fatal(err)
	}
	other := insertPresenceRow(t, d, ctx, host.ID, box.ID, "other", "discovered", nil, at)
	if err := d.UpsertDiscovered(ctx, host.ID, []store.Discovered{{
		Name: "not-the-entry", Kind: "process", Ports: []int{80},
		Owner: &store.DiscoveredOwner{Kind: "program", Project: "placed-" + tag, Entry: "webapp"},
	}}, at, true, true); err != nil {
		t.Fatal(err)
	}
	placed := serviceByNameDB(t, d, ctx, host.ID, "webapp", at)
	if placed.Source != "owned" || placed.GoneAt != nil || placed.ProjectID != home.ID {
		t.Fatalf("placed source %s gone %v project %s", placed.Source, placed.GoneAt, placed.ProjectID)
	}
	if _, ok := findServiceDB(t, d, ctx, host.ID, "not-the-entry", at); ok {
		t.Fatal("agent name stored")
	}
	got := mustServiceDB(t, d, ctx, other, at)
	if got.GoneAt == nil || !got.GoneAt.Equal(at) {
		t.Fatalf("sibling %v", got.GoneAt)
	}
}

func assertServiceGoneBackfill(t *testing.T, d *DB, ctx context.Context) {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Microsecond)
	tag := strings.ReplaceAll(uuid.New().String(), "-", "")[:10]
	user := mustSvcUser(t, d, ctx, "backfill-"+tag, at)
	project := mustSvcProject(t, d, ctx, user.ID, "Backfill", "backfill-"+tag, at)
	hostA := enrollHostDB(t, d, ctx, project.ID, user.ID, "backfill-a-"+tag, at)
	hostB := enrollHostDB(t, d, ctx, project.ID, user.ID, "backfill-b-"+tag, at)
	early := time.Date(2026, 10, 15, 14, 0, 0, 0, time.UTC)
	mid := time.Date(2026, 10, 15, 14, 13, 0, 0, time.UTC)
	maxA := time.Date(2026, 10, 15, 15, 0, 0, 0, time.UTC)
	maxB := time.Date(2026, 10, 15, 16, 0, 0, 0, time.UTC)
	aEarly := insertSeen(t, d, ctx, hostA.ID, project.ID, "a-early", early)
	aMid := insertSeen(t, d, ctx, hostA.ID, project.ID, "a-mid", mid)
	aMax1 := insertSeen(t, d, ctx, hostA.ID, project.ID, "a-max-1", maxA)
	aMax2 := insertSeen(t, d, ctx, hostA.ID, project.ID, "a-max-2", maxA)
	bEarly := insertSeen(t, d, ctx, hostB.ID, project.ID, "b-early", early)
	bMax := insertSeen(t, d, ctx, hostB.ID, project.ID, "b-max", maxB)
	if _, err := d.pool.Exec(ctx, serviceGoneBackfillSQL(t)); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	assertGoneAt(t, d, ctx, aEarly, &early)
	assertGoneAt(t, d, ctx, aMid, &mid)
	assertGoneAt(t, d, ctx, aMax1, nil)
	assertGoneAt(t, d, ctx, aMax2, nil)
	assertGoneAt(t, d, ctx, bEarly, &early)
	assertGoneAt(t, d, ctx, bMax, nil)
}

func serviceGoneBackfillSQL(t *testing.T) string {
	t.Helper()
	body, err := migrations.FS.ReadFile("0008_service_gone.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range splitSQL(string(body)) {
		if strings.Contains(stmt, "SET gone_at") {
			return stmt
		}
	}
	t.Fatal("backfill UPDATE missing")
	return ""
}

func insertPresenceRow(t *testing.T, d *DB, ctx context.Context, hostID, projectID uuid.UUID, name, source string, gone *time.Time, at time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := d.pool.Exec(ctx, `
INSERT INTO app.services (
    id, host_id, name, source, kind, ports, first_seen_at, last_seen_at, gone_at, project_id
) VALUES (
    $1::uuid, $2::uuid, $3, $4, 'process', '{}', $5, $5, $6, $7::uuid
)`, id.String(), hostID.String(), name, source, at, gone, projectID.String()); err != nil {
		t.Fatal(err)
	}
	return id
}

func insertSeen(t *testing.T, d *DB, ctx context.Context, hostID, projectID uuid.UUID, name string, seen time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := d.pool.Exec(ctx, `
INSERT INTO app.services (
    id, host_id, name, source, kind, ports, first_seen_at, last_seen_at, project_id
) VALUES (
    $1::uuid, $2::uuid, $3, 'discovered', 'process', '{}', $4, $4, $5::uuid
)`, id.String(), hostID.String(), name, seen, projectID.String()); err != nil {
		t.Fatal(err)
	}
	return id
}

func assertGoneAt(t *testing.T, d *DB, ctx context.Context, id uuid.UUID, want *time.Time) {
	t.Helper()
	var got *time.Time
	if err := d.pool.QueryRow(ctx, `SELECT gone_at FROM app.services WHERE id = $1::uuid`, id.String()).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if want == nil {
		if got != nil {
			t.Fatalf("%s gone_at %s", id, got)
		}
		return
	}
	if got == nil || !got.Equal(*want) {
		t.Fatalf("%s gone_at %v want %s", id, got, want.Format(time.RFC3339))
	}
}

func mustServiceDB(t *testing.T, d *DB, ctx context.Context, id uuid.UUID, at time.Time) store.Service {
	t.Helper()
	svc, err := d.GetService(ctx, id, at)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func serviceByNameDB(t *testing.T, d *DB, ctx context.Context, hostID uuid.UUID, name string, at time.Time) store.Service {
	t.Helper()
	svc, ok := findServiceDB(t, d, ctx, hostID, name, at)
	if !ok {
		t.Fatalf("missing %s", name)
	}
	return svc
}

func findServiceDB(t *testing.T, d *DB, ctx context.Context, hostID uuid.UUID, name string, at time.Time) (store.Service, bool) {
	t.Helper()
	items, err := d.ListServices(ctx, hostID, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.Name == name {
			return item, true
		}
	}
	return store.Service{}, false
}
