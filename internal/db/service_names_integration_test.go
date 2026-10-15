package db

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// assertServiceNamesLive is the Postgres half of service names and the
// project services list. It uses fresh projects so it does not depend on
// rows the shared-hosts scenario deletes.
func assertServiceNamesLive(t *testing.T, d *DB, ctx context.Context, at time.Time) {
	t.Helper()
	assertServiceNameSchema(t, d, ctx)

	homeUser := mustSvcUser(t, d, ctx, "svc-home", at)
	deployUser := mustSvcUser(t, d, ctx, "svc-deploy", at)
	metricsUser := mustSvcUser(t, d, ctx, "svc-metrics", at)
	home := mustSvcProject(t, d, ctx, homeUser.ID, "SvcHome", "svc-home", at)
	deploy := mustSvcProject(t, d, ctx, deployUser.ID, "SvcDeploy", "svc-deploy", at)
	metrics := mustSvcProject(t, d, ctx, metricsUser.ID, "SvcMetrics", "svc-metrics", at)
	homeHost := enrollHostDB(t, d, ctx, home.ID, homeUser.ID, "home-host", at)
	deployHost := enrollHostDB(t, d, ctx, deploy.ID, deployUser.ID, "deploy-host", at)
	tieHost := enrollHostDB(t, d, ctx, deploy.ID, deployUser.ID, "deploy-tie", at)
	metricsHost := enrollHostDB(t, d, ctx, metrics.ID, metricsUser.ID, "metrics-host", at)
	if _, _, err := d.PutHostShare(ctx, homeHost.ID, deploy.ID, "deploy", homeUser.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.PutHostShare(ctx, homeHost.ID, metrics.ID, "metrics", homeUser.ID, at); err != nil {
		t.Fatal(err)
	}

	ids := map[string]uuid.UUID{}
	put := func(host store.Host, project uuid.UUID, name, kind, source string, ports []int32, display, owner *string, seen time.Time) {
		t.Helper()
		ids[name] = insertLiveService(t, d, ctx, host.ID, project, name, kind, source, ports, display, owner, seen)
	}
	put(homeHost, home.ID, "m-discovered", "process", "discovered", []int32{8080}, nil, strp("root"), at)
	put(homeHost, home.ID, "z-discovered", "container", "discovered", []int32{9}, strp("a-label"), strp("www-data"), at.Add(time.Second))
	put(homeHost, deploy.ID, "shared-svc", "systemd", "discovered", []int32{443}, strp("Shared"), strp("deployer"), at.Add(2*time.Second))
	put(homeHost, metrics.ID, "metered", "process", "discovered", []int32{5555}, strp("100%"), nil, at.Add(3*time.Second))
	put(homeHost, home.ID, "slash-svc", "process", "discovered", []int32{7}, strp(`a\b`), nil, at.Add(4*time.Second))
	put(homeHost, home.ID, "keep-name", "process", "discovered", []int32{80}, strp("Kept"), strp("old"), at.Add(5*time.Second))
	put(homeHost, home.ID, "plain", "process", "discovered", []int32{2}, nil, nil, at.Add(6*time.Second))
	put(homeHost, home.ID, "declared-svc", "process", "declared", []int32{80, 443}, strp("Kept2"), nil, at)
	put(deployHost, deploy.ID, "local-svc", "process", "discovered", []int32{80}, strp("Local"), strp("local-user"), at)
	put(deployHost, deploy.ID, "tie-b", "process", "discovered", nil, strp("Same"), nil, at)
	put(tieHost, deploy.ID, "tie-a", "process", "discovered", nil, strp("same"), nil, at)
	put(metricsHost, metrics.ID, "mine-svc", "process", "discovered", []int32{1}, strp("a_b"), strp("mine-user"), at)
	if _, err := d.pool.Exec(ctx, `
INSERT INTO metrics.health_results (time, host_id, service_id, result, latency_ms)
VALUES ($1, $2::uuid, $3::uuid, 'success', 1), ($1, $2::uuid, $4::uuid, 'fail', 1)
`, at, homeHost.ID.String(), ids["z-discovered"].String(), ids["shared-svc"].String()); err != nil {
		t.Fatalf("health: %v", err)
	}

	homeOrder := []string{"metered", "z-discovered", "slash-svc", "keep-name", "declared-svc", "m-discovered", "plain", "shared-svc"}
	got := liveNames(t, d, ctx, home.ID, store.ServiceListQuery{Sort: "name", Dir: "asc", Limit: 50}, at)
	if !sameLive(got, homeOrder) {
		t.Fatalf("home name asc %v", got)
	}
	if page, err := d.ListProjectServices(ctx, home.ID, store.ServiceListQuery{Sort: "name", Dir: "asc", Limit: 50}, at); err != nil || page.Total != len(homeOrder) {
		t.Fatalf("home total %+v %v", page.Total, err)
	}
	tie := tieOrder(ids, "tie-a", "tie-b")
	deployRows := liveNames(t, d, ctx, deploy.ID, store.ServiceListQuery{Sort: "name", Dir: "asc", Limit: 50}, at)
	if !sameLive(deployRows, []string{"local-svc", tie[0], tie[1], "shared-svc"}) {
		t.Fatalf("deploy rows %v", deployRows)
	}
	desc := liveNames(t, d, ctx, deploy.ID, store.ServiceListQuery{Sort: "name", Dir: "desc", Limit: 50}, at)
	if !sameLive(desc, []string{"shared-svc", tie[0], tie[1], "local-svc"}) {
		t.Fatalf("tie desc %v", desc)
	}
	metricsRows := liveNames(t, d, ctx, metrics.ID, store.ServiceListQuery{Sort: "name", Dir: "asc", Limit: 50}, at)
	if !sameLive(metricsRows, []string{"mine-svc"}) {
		t.Fatalf("metrics rows %v", metricsRows)
	}

	search := func(project uuid.UUID, q string, want ...string) {
		t.Helper()
		got := liveNames(t, d, ctx, project, store.ServiceListQuery{Q: q, Sort: "name", Dir: "asc", Limit: 50}, at)
		if !sameLive(got, want) {
			t.Fatalf("q %q got %v want %v", q, got, want)
		}
	}
	search(home.ID, "a-label", "z-discovered")
	search(home.ID, "m-discovered", "m-discovered")
	search(home.ID, "container", "z-discovered")
	search(home.ID, "systemd", "shared-svc")
	search(home.ID, "home-host", homeOrder...)
	search(home.ID, "www-data", "z-discovered")
	search(home.ID, "8080", "m-discovered")
	search(home.ID, "%", "metered")
	search(home.ID, "100%", "metered")
	search(home.ID, "_")
	search(home.ID, `\`, "slash-svc")
	search(home.ID, `a\b`, "slash-svc")
	search(metrics.ID, "_", "mine-svc")
	search(deploy.ID, "deploy-tie", "tie-a")
	search(home.ID, "shared", "shared-svc")
	search(home.ID, "KEPT", "keep-name", "declared-svc")
	search(deploy.ID, "lOcAl", "local-svc")

	homeHostID := homeHost.ID
	filtered := liveNames(t, d, ctx, home.ID, store.ServiceListQuery{HostID: &homeHostID, Sort: "name", Dir: "asc", Limit: 50}, at)
	if !sameLive(filtered, homeOrder) {
		t.Fatalf("host filter %v", filtered)
	}
	onlyShared := liveNames(t, d, ctx, deploy.ID, store.ServiceListQuery{HostID: &homeHostID, Sort: "name", Dir: "asc", Limit: 50}, at)
	if !sameLive(onlyShared, []string{"shared-svc"}) {
		t.Fatalf("deploy host filter %v", onlyShared)
	}
	qPage, err := d.ListProjectServices(ctx, home.ID, store.ServiceListQuery{Q: "home-host", Sort: "name", Dir: "asc", Limit: 2}, at)
	if err != nil || qPage.Total != len(homeOrder) || len(qPage.Items) != 2 || qPage.Total <= 2 {
		t.Fatalf("q total %d items %d %v", qPage.Total, len(qPage.Items), err)
	}
	hostPage, err := d.ListProjectServices(ctx, home.ID, store.ServiceListQuery{HostID: &homeHostID, Sort: "name", Dir: "asc", Limit: 1}, at)
	if err != nil || hostPage.Total != len(homeOrder) || len(hostPage.Items) != 1 || hostPage.Total <= 1 {
		t.Fatalf("host total %d items %d %v", hostPage.Total, len(hostPage.Items), err)
	}
	deployHostID := deployHost.ID
	if _, err := d.ListProjectServices(ctx, home.ID, store.ServiceListQuery{HostID: &deployHostID, Sort: "name", Dir: "asc", Limit: 50}, at); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("unreachable host %v", err)
	}
	if _, err := d.ListProjectServices(ctx, metrics.ID, store.ServiceListQuery{HostID: &homeHostID, Sort: "name", Dir: "asc", Limit: 50}, at); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("metrics host %v", err)
	}

	status := liveNames(t, d, ctx, home.ID, store.ServiceListQuery{Sort: "status", Dir: "asc", Limit: 50}, at)
	if !sameLive(status, []string{"z-discovered", "shared-svc", "metered", "slash-svc", "keep-name", "declared-svc", "m-discovered", "plain"}) {
		t.Fatalf("status %v", status)
	}
	wantIDs := make([]uuid.UUID, len(homeOrder))
	for i, name := range homeOrder {
		wantIDs[i] = ids[name]
	}
	assertIDPageWalk(t, d, ctx, home.ID, wantIDs, at)

	assertNullsLast(t, d, ctx)
	assertDisplayConflict(t, d, ctx, ids, at)
	assertLiveRediscovery(t, d, ctx, homeHost.ID, ids, at)
	assertNameByteOrder(t, d, ctx, at)
	assertHostNameByteOrder(t, d, ctx, at)
	assertStaleHealth(t, d, ctx, home.ID, homeHost.ID, ids["plain"], at)
}

// assertNameByteOrder proves '-' < '\' < '_' after lower(), and that Same/same
// tie by id. The labels are ASCII. Postgres lower() can differ from Go for
// some non-ASCII letters, so this case does not use those.
func assertNameByteOrder(t *testing.T, d *DB, ctx context.Context, at time.Time) {
	t.Helper()
	user := mustSvcUser(t, d, ctx, "svc-punct", at)
	project := mustSvcProject(t, d, ctx, user.ID, "SvcPunct", "svc-punct", at)
	host := enrollHostDB(t, d, ctx, project.ID, user.ID, "punct-host", at)
	other := enrollHostDB(t, d, ctx, project.ID, user.ID, "punct-other", at)
	ids := map[string]uuid.UUID{}
	put := func(on store.Host, name, display string) {
		t.Helper()
		ids[name] = insertLiveService(t, d, ctx, on.ID, project.ID, name, "process", "discovered", nil, strp(display), nil, at)
	}
	// Same and same are one lowercased key. They sit on different hosts so the
	// per-host unique index does not reject the tie.
	put(host, "under-svc", "a_b")
	put(host, "slash-punct", `a\b`)
	put(host, "label-svc", "a-label")
	put(host, "tie-upper", "Same")
	put(other, "tie-lower", "same")
	tie := tieOrder(ids, "tie-lower", "tie-upper")
	want := []string{"label-svc", "slash-punct", "under-svc", tie[0], tie[1]}
	got := liveNames(t, d, ctx, project.ID, store.ServiceListQuery{Sort: "name", Dir: "asc", Limit: 50}, at)
	if !sameLive(got, want) {
		t.Fatalf("punctuation %v", got)
	}
	desc := liveNames(t, d, ctx, project.ID, store.ServiceListQuery{Sort: "name", Dir: "desc", Limit: 50}, at)
	if !sameLive(desc, []string{tie[0], tie[1], "under-svc", "slash-punct", "label-svc"}) {
		t.Fatalf("punctuation desc %v", desc)
	}
}

// assertHostNameByteOrder is the host list '-' < '1' case. The cursor page
// uses the same collation as ORDER BY.
func assertHostNameByteOrder(t *testing.T, d *DB, ctx context.Context, at time.Time) {
	t.Helper()
	user := mustSvcUser(t, d, ctx, "svc-host-byte", at)
	project := mustSvcProject(t, d, ctx, user.ID, "SvcHostByte", "svc-host-byte", at)
	plain := enrollHostDB(t, d, ctx, project.ID, user.ID, "a1", at)
	hyphen := enrollHostDB(t, d, ctx, project.ID, user.ID, "a-1", at)
	all, _, err := d.ListHosts(ctx, project.ID, 50, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].ID != hyphen.ID || all[0].Name != "a-1" || all[1].ID != plain.ID || all[1].Name != "a1" {
		t.Fatalf("host byte order %+v", hostNames(all))
	}
	first, next, err := d.ListHosts(ctx, project.ID, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].Name != "a-1" || next == nil || next.Name != "a-1" {
		t.Fatalf("first host page %+v cursor %+v", hostNames(first), next)
	}
	second, next2, err := d.ListHosts(ctx, project.ID, 1, next)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || second[0].Name != "a1" || next2 != nil {
		t.Fatalf("second host page %+v cursor %+v", hostNames(second), next2)
	}
}

func hostNames(items []store.Host) []string {
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = item.Name
	}
	return out
}

func assertIDPageWalk(t *testing.T, d *DB, ctx context.Context, project uuid.UUID, want []uuid.UUID, at time.Time) {
	t.Helper()
	const limit = 2
	if len(want) < 5 {
		t.Fatalf("page walk needs 5 rows, got %d", len(want))
	}
	var pages [][]uuid.UUID
	total := -1
	finished := false
	for offset := 0; offset < len(want)+limit; offset += limit {
		page, err := d.ListProjectServices(ctx, project, store.ServiceListQuery{Sort: "name", Dir: "asc", Limit: limit, Offset: offset}, at)
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != len(want) {
			t.Fatalf("total %d", page.Total)
		}
		if total < 0 {
			total = page.Total
		}
		got := pageIDs(page)
		if len(got) == 0 {
			t.Fatal("empty page")
		}
		pages = append(pages, got)
		if offset+limit >= page.Total {
			finished = true
			break
		}
	}
	if !finished {
		t.Fatal("page walk did not reach the end")
	}
	var flat []uuid.UUID
	for _, ids := range pages {
		flat = append(flat, ids...)
	}
	if !sameIDs(flat, want) {
		t.Fatalf("paged ids %v", flat)
	}
	for i := len(pages) - 2; i >= 0; i-- {
		page, err := d.ListProjectServices(ctx, project, store.ServiceListQuery{Sort: "name", Dir: "asc", Limit: limit, Offset: i * limit}, at)
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != total || !sameIDs(pageIDs(page), pages[i]) {
			t.Fatalf("prev page %d %v", i, pageIDs(page))
		}
	}
}

func assertStaleHealth(t *testing.T, d *DB, ctx context.Context, project, host, service uuid.UUID, at time.Time) {
	t.Helper()
	staleAt := at.Add(-store.HealthStale - time.Second)
	if _, err := d.pool.Exec(ctx, `
INSERT INTO metrics.health_results (time, host_id, service_id, result, latency_ms)
VALUES ($1, $2::uuid, $3::uuid, 'success', 1)
`, staleAt, host.String(), service.String()); err != nil {
		t.Fatalf("stale health: %v", err)
	}
	page, err := d.ListProjectServices(ctx, project, store.ServiceListQuery{Sort: "status", Dir: "asc", Limit: 50}, at)
	if err != nil {
		t.Fatal(err)
	}
	// Labels stored before this sort. assertDisplayConflict renamed
	// m-discovered to foo and left slash-svc at a\b. Rediscovery does not
	// write display_name. Health is a fresh success, a fresh fail, and this
	// stale success. Every other row has no sample.
	wantLabel := map[string]*string{
		"m-discovered": strp("foo"),
		"z-discovered": strp("a-label"),
		"shared-svc":   strp("Shared"),
		"metered":      strp("100%"),
		"slash-svc":    strp(`a\b`),
		"keep-name":    strp("Kept"),
		"plain":        nil,
		"declared-svc": strp("Kept2"),
	}
	wantStatus := map[string]string{
		"z-discovered": "up",
		"shared-svc":   "down",
	}
	if len(page.Items) != len(wantLabel) {
		t.Fatalf("stale rows %v", livePageNames(page))
	}
	rows := make([]struct {
		name  string
		order store.ServiceOrder
	}, 0, len(page.Items))
	foundStale := false
	for _, item := range page.Items {
		label, ok := wantLabel[item.Name]
		if !ok || !samePtr(item.DisplayName, label) {
			t.Fatalf("%s display %q", item.Name, deref(item.DisplayName))
		}
		status := "unknown"
		if got, known := wantStatus[item.Name]; known {
			status = got
		}
		if item.Health.Status != status {
			t.Fatalf("%s status %s", item.Name, item.Health.Status)
		}
		if item.ID == service {
			foundStale = true
		}
		key := item.Name
		if label != nil {
			key = *label
		}
		rows = append(rows, struct {
			name  string
			order store.ServiceOrder
		}{
			name: item.Name,
			order: store.ServiceOrder{
				ID:         item.ID,
				NameKey:    strings.ToLower(key),
				StatusRank: store.HealthRank(status),
				Gone:       item.GoneAt != nil,
			},
		})
	}
	if !foundStale {
		t.Fatal("stale row missing")
	}
	sort.Slice(rows, func(i, j int) bool {
		return store.ServiceBefore(rows[i].order, rows[j].order, "status", "asc")
	})
	want := make([]string, len(rows))
	for i, row := range rows {
		want[i] = row.name
	}
	if !sameLive(livePageNames(page), want) {
		t.Fatalf("stale sort %v want %v", livePageNames(page), want)
	}
}

func pageIDs(page store.ServicePage) []uuid.UUID {
	out := make([]uuid.UUID, len(page.Items))
	for i, item := range page.Items {
		out[i] = item.ID
	}
	return out
}

func sameIDs(got, want []uuid.UUID) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func assertServiceNameSchema(t *testing.T, d *DB, ctx context.Context) {
	t.Helper()
	rows, err := d.pool.Query(ctx, `
SELECT column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_schema = 'app' AND table_name = 'services'
  AND column_name IN ('display_name', 'owner_user')
ORDER BY column_name
`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]string{}
	for rows.Next() {
		var name, dataType, nullable string
		if err := rows.Scan(&name, &dataType, &nullable); err != nil {
			t.Fatal(err)
		}
		got[name] = dataType + " " + nullable
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if got["display_name"] != "text YES" || got["owner_user"] != "text YES" {
		t.Fatalf("columns %#v", got)
	}
	var indexdef string
	if err := d.pool.QueryRow(ctx, `
SELECT indexdef FROM pg_indexes
WHERE schemaname = 'app' AND indexname = 'services_host_display_name_uidx'
`).Scan(&indexdef); err != nil {
		t.Fatalf("unique index: %v", err)
	}
	for _, want := range []string{"UNIQUE", "host_id", "lower(display_name)", "display_name IS NOT NULL"} {
		if !strings.Contains(indexdef, want) {
			t.Fatalf("indexdef %s", indexdef)
		}
	}
	var projectIdx int
	if err := d.pool.QueryRow(ctx, `
SELECT count(*) FROM pg_indexes
WHERE schemaname = 'app' AND indexname = 'services_project_idx'
`).Scan(&projectIdx); err != nil || projectIdx != 1 {
		t.Fatalf("project index %d %v", projectIdx, err)
	}
	grants := map[string]bool{}
	privs, err := d.pool.Query(ctx, `
SELECT privilege_type FROM information_schema.role_table_grants
WHERE grantee = 'deploybot_api' AND table_schema = 'app' AND table_name = 'services'
`)
	if err != nil {
		t.Fatal(err)
	}
	defer privs.Close()
	for privs.Next() {
		var priv string
		if err := privs.Scan(&priv); err != nil {
			t.Fatal(err)
		}
		grants[priv] = true
	}
	if err := privs.Err(); err != nil {
		t.Fatal(err)
	}
	for _, priv := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
		if !grants[priv] {
			t.Fatalf("grants %#v", grants)
		}
	}
}

func assertNullsLast(t *testing.T, d *DB, ctx context.Context) {
	t.Helper()
	for _, dir := range []string{"asc", "desc"} {
		order := projectServiceOrder("last_seen", dir)
		if !strings.Contains(order, "NULLS LAST") {
			t.Fatalf("order %s", order)
		}
		query := `
SELECT id FROM (VALUES
    (1, NULL::timestamptz),
    (2, timestamptz '2020-01-02'),
    (3, timestamptz '2020-01-01')
) AS s(id, last_seen_at)
ORDER BY ` + order
		rows, err := d.pool.Query(ctx, query)
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		var got []int
		for rows.Next() {
			var id int
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			got = append(got, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		want := []int{3, 2, 1}
		if dir == "desc" {
			want = []int{2, 3, 1}
		}
		if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
			t.Fatalf("%s order %v", dir, got)
		}
	}
}

func assertDisplayConflict(t *testing.T, d *DB, ctx context.Context, ids map[string]uuid.UUID, at time.Time) {
	t.Helper()
	if _, err := d.SetServiceDisplayName(ctx, ids["m-discovered"], strp("Foo"), at); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SetServiceDisplayName(ctx, ids["slash-svc"], strp("foo"), at); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate %v", err)
	}
	if _, err := d.SetServiceDisplayName(ctx, ids["m-discovered"], strp("foo"), at); err != nil {
		t.Fatalf("same row %v", err)
	}
	if _, err := d.SetServiceDisplayName(ctx, ids["local-svc"], strp("foo"), at); err != nil {
		t.Fatalf("other host %v", err)
	}
	_, err := d.pool.Exec(ctx, `UPDATE app.services SET display_name = 'foo' WHERE id = $1::uuid`, ids["slash-svc"].String())
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("raw unique %v", err)
	}
}

func assertLiveRediscovery(t *testing.T, d *DB, ctx context.Context, hostID uuid.UUID, ids map[string]uuid.UUID, at time.Time) {
	t.Helper()
	later := at.Add(time.Minute)
	if err := d.UpsertDiscovered(ctx, hostID, []store.Discovered{{
		Name: "keep-name", Kind: "container", Ports: []int{1}, OwnerUser: strp("alice"),
	}}, later, true, true); err != nil {
		t.Fatal(err)
	}
	display, owner, kind, ports := readLiveService(t, d, ctx, ids["keep-name"])
	if display != "Kept" || owner != "alice" || kind != "container" || len(ports) != 1 || ports[0] != 1 {
		t.Fatalf("rediscover display %s owner %s kind %s ports %v", display, owner, kind, ports)
	}
	if err := d.UpsertDiscovered(ctx, hostID, []store.Discovered{{
		Name: "keep-name", Kind: "container", Ports: []int{1}, OwnerUser: strp("a\nb"),
	}}, later.Add(time.Minute), true, true); err != nil {
		t.Fatal(err)
	}
	display, owner, _, _ = readLiveService(t, d, ctx, ids["keep-name"])
	if display != "Kept" || owner != "" {
		t.Fatalf("bad user display %s owner %q", display, owner)
	}
	if err := d.UpsertDiscovered(ctx, hostID, []store.Discovered{{
		Name: "declared-svc", Kind: "container", Ports: []int{1}, OwnerUser: strp("bob"),
	}}, later, true, true); err != nil {
		t.Fatal(err)
	}
	display, owner, kind, ports = readLiveService(t, d, ctx, ids["declared-svc"])
	if display != "Kept2" || owner != "bob" || kind != "process" || len(ports) != 2 || ports[0] != 80 || ports[1] != 443 {
		t.Fatalf("declared display %s owner %s kind %s ports %v", display, owner, kind, ports)
	}
}

func insertLiveService(t *testing.T, d *DB, ctx context.Context, hostID, projectID uuid.UUID, name, kind, source string, ports []int32, display, owner *string, seen time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if ports == nil {
		ports = []int32{}
	}
	if _, err := d.pool.Exec(ctx, `
INSERT INTO app.services (
    id, host_id, project_id, name, source, kind, ports, display_name, owner_user, first_seen_at, last_seen_at
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7::integer[], $8, $9, $10, $10
)`, id.String(), hostID.String(), projectID.String(), name, source, kind, ports, display, owner, seen); err != nil {
		t.Fatalf("insert %s: %v", name, err)
	}
	return id
}

func readLiveService(t *testing.T, d *DB, ctx context.Context, id uuid.UUID) (string, string, string, []int32) {
	t.Helper()
	var display, owner *string
	var kind string
	var ports []int32
	if err := d.pool.QueryRow(ctx, `
SELECT display_name, owner_user, kind, ports FROM app.services WHERE id = $1::uuid
`, id.String()).Scan(&display, &owner, &kind, &ports); err != nil {
		t.Fatal(err)
	}
	return deref(display), deref(owner), kind, ports
}

func liveNames(t *testing.T, d *DB, ctx context.Context, project uuid.UUID, q store.ServiceListQuery, at time.Time) []string {
	t.Helper()
	page, err := d.ListProjectServices(ctx, project, q, at)
	if err != nil {
		t.Fatal(err)
	}
	if q.HostID == nil && q.Q == "" && q.Limit >= page.Total && page.Total != len(page.Items) {
		t.Fatalf("total %d items %d", page.Total, len(page.Items))
	}
	for _, item := range page.Items {
		if item.HostName == "" || item.ProjectName == "" {
			t.Fatalf("row %s missing host or project name", item.Name)
		}
	}
	return livePageNames(page)
}

func livePageNames(page store.ServicePage) []string {
	out := make([]string, len(page.Items))
	for i, item := range page.Items {
		out[i] = item.Name
	}
	return out
}

func mustSvcUser(t *testing.T, d *DB, ctx context.Context, email string, at time.Time) store.User {
	t.Helper()
	user, err := d.UpsertGoogleUser(ctx, store.GoogleSignIn{Subject: email, Email: email + "@example.com", Name: email, At: at})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func mustSvcProject(t *testing.T, d *DB, ctx context.Context, owner uuid.UUID, name, slug string, at time.Time) store.Project {
	t.Helper()
	project, err := d.CreateProject(ctx, owner, name, slug, at)
	if err != nil {
		t.Fatal(err)
	}
	return project
}

func tieOrder(ids map[string]uuid.UUID, a, b string) []string {
	left, right := ids[a], ids[b]
	for i := range left {
		if left[i] == right[i] {
			continue
		}
		if left[i] < right[i] {
			return []string{a, b}
		}
		return []string{b, a}
	}
	return []string{a, b}
}

func sameLive(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func deref(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func samePtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func strp(s string) *string { return &s }
