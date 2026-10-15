package memstore

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestListProjectServices(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	mem := New()
	homeUser := mustUser(t, mem, "home@ex.com", now)
	deployUser := mustUser(t, mem, "deploy@ex.com", now)
	metricsUser := mustUser(t, mem, "metrics@ex.com", now)
	home := makeProject(t, mem, homeUser.ID, "Home", "home", now)
	deploy := makeProject(t, mem, deployUser.ID, "Deploy", "deploy", now)
	metrics := makeProject(t, mem, metricsUser.ID, "Metrics", "metrics", now)
	alpha := enrollMem(t, mem, home.ID, homeUser.ID, "alpha-host", now)
	beta := enrollMem(t, mem, deploy.ID, deployUser.ID, "beta-host", now)
	gamma := enrollMem(t, mem, metrics.ID, metricsUser.ID, "gamma-host", now)
	delta := enrollMem(t, mem, home.ID, homeUser.ID, "delta-host", now)
	epsilon := enrollMem(t, mem, home.ID, homeUser.ID, "epsilon-host", now)
	zeta := enrollMem(t, mem, home.ID, homeUser.ID, "zeta-host", now)
	if _, _, err := mem.PutHostShare(ctx, alpha.ID, deploy.ID, "deploy", homeUser.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mem.PutHostShare(ctx, alpha.ID, metrics.ID, "metrics", homeUser.ID, now); err != nil {
		t.Fatal(err)
	}

	ids := map[string]uuid.UUID{}
	put := func(host store.Host, project uuid.UUID, name, kind string, ports []int, owner *string, display *string, at time.Time) {
		t.Helper()
		svc := discoverService(t, mem, host.ID, name, kind, ports, owner, at)
		if svc.ProjectID != host.ProjectID {
			t.Fatalf("%s project %s", name, svc.ProjectID)
		}
		mem.SetServiceProject(svc.ID, project)
		if display != nil {
			if _, err := mem.SetServiceDisplayName(ctx, svc.ID, display, now); err != nil {
				t.Fatal(err)
			}
		}
		ids[name] = svc.ID
	}
	put(alpha, home.ID, "svc-name", "process", []int{8080}, strp("owner-one"), strp("Label One"), now)
	put(alpha, deploy.ID, "other-name", "container", []int{9}, strp("owner-two"), strp("100%"), now.Add(time.Second))
	put(alpha, metrics.ID, "met-name", "systemd", []int{443}, nil, nil, now.Add(2*time.Second))
	put(alpha, home.ID, "slash-svc", "process", []int{7}, nil, strp(`a\b`), now.Add(3*time.Second))
	put(beta, deploy.ID, "local-name", "process", []int{80}, strp("local-user"), strp("Local"), now.Add(4*time.Second))
	put(gamma, metrics.ID, "mine-name", "process", []int{5555}, strp("mine-user"), strp("a_b"), now.Add(5*time.Second))
	put(delta, home.ID, "z-discovered", "process", []int{1}, strp("tie-user"), strp("a-label"), now.Add(6*time.Second))
	put(delta, home.ID, "m-discovered", "process", []int{2}, nil, nil, now.Add(6*time.Second))
	put(epsilon, home.ID, "tie-left", "process", []int{3}, nil, strp("Same"), now.Add(7*time.Second))
	put(zeta, home.ID, "tie-right", "process", []int{4}, nil, strp("same"), now.Add(7*time.Second))
	putHealth(t, mem, alpha.ID, "svc-name", "success", now)
	putHealth(t, mem, alpha.ID, "other-name", "fail", now)
	putHealth(t, mem, alpha.ID, "met-name", "success", now.Add(-3*time.Minute))

	t5 := byID(ids, "z-discovered", "m-discovered")
	t6 := byID(ids, "tie-left", "tie-right")
	nameAsc := cat([]string{"other-name", "z-discovered", "slash-svc", "svc-name", "m-discovered", "met-name"}, t6)
	nameDesc := cat(t6, []string{"met-name", "m-discovered", "svc-name", "slash-svc", "z-discovered", "other-name"})
	alphaNames := byID(ids, "svc-name", "other-name", "met-name", "slash-svc")
	deltaNames := byID(ids, "z-discovered", "m-discovered")
	hostAsc := cat(alphaNames, deltaNames, []string{"tie-left", "tie-right"})
	hostDesc := cat([]string{"tie-right", "tie-left"}, deltaNames, alphaNames)
	procs := byID(ids, "svc-name", "slash-svc", "z-discovered", "m-discovered", "tie-left", "tie-right")
	kindAsc := cat([]string{"other-name"}, procs, []string{"met-name"})
	kindDesc := cat([]string{"met-name"}, procs, []string{"other-name"})
	seenAsc := cat([]string{"svc-name", "other-name", "met-name", "slash-svc"}, t5, t6)
	seenDesc := cat(t6, t5, []string{"slash-svc", "met-name", "other-name", "svc-name"})
	statusAsc := cat([]string{"svc-name", "other-name", "z-discovered", "slash-svc", "m-discovered", "met-name"}, t6)
	statusDesc := cat(t6, []string{"met-name", "m-discovered", "slash-svc", "z-discovered", "other-name", "svc-name"})

	homeNames := func(q store.ServiceListQuery) []string {
		t.Helper()
		return projectNames(t, mem, home.ID, q, now)
	}
	if got := homeNames(sq("name", "asc", 50, 0)); !sameNames(got, nameAsc) {
		t.Fatalf("name asc %v", got)
	}
	if got := homeNames(sq("name", "desc", 50, 0)); !sameNames(got, nameDesc) {
		t.Fatalf("name desc %v", got)
	}
	if got := homeNames(sq("host", "asc", 50, 0)); !sameNames(got, hostAsc) {
		t.Fatalf("host asc %v", got)
	}
	if got := homeNames(sq("host", "desc", 50, 0)); !sameNames(got, hostDesc) {
		t.Fatalf("host desc %v", got)
	}
	if got := homeNames(sq("kind", "asc", 50, 0)); !sameNames(got, kindAsc) {
		t.Fatalf("kind asc %v", got)
	}
	if got := homeNames(sq("kind", "desc", 50, 0)); !sameNames(got, kindDesc) {
		t.Fatalf("kind desc %v", got)
	}
	if got := homeNames(sq("last_seen", "asc", 50, 0)); !sameNames(got, seenAsc) {
		t.Fatalf("last_seen asc %v", got)
	}
	if got := homeNames(sq("last_seen", "desc", 50, 0)); !sameNames(got, seenDesc) {
		t.Fatalf("last_seen desc %v", got)
	}
	if got := homeNames(sq("status", "asc", 50, 0)); !sameNames(got, statusAsc) {
		t.Fatalf("status asc %v", got)
	}
	if got := homeNames(sq("status", "desc", 50, 0)); !sameNames(got, statusDesc) {
		t.Fatalf("status desc %v", got)
	}
	left, right := ids[t6[0]], ids[t6[1]]
	if bytes.Compare(left[:], right[:]) >= 0 {
		t.Fatal("tie ids")
	}
	for _, dir := range []string{"asc", "desc"} {
		got := homeNames(sq("name", dir, 50, 0))
		if !containsSeq(got, t6) {
			t.Fatalf("name %s tie %v", dir, got)
		}
	}

	search := func(q string, want ...string) {
		t.Helper()
		got := homeNames(store.ServiceListQuery{Q: q, Sort: "name", Dir: "asc", Limit: 50})
		if !sameNames(got, want) {
			t.Fatalf("q %q got %v want %v", q, got, want)
		}
	}
	search("LABEL ONE", "svc-name")
	search("svc-name", "svc-name")
	search("container", "other-name")
	search("systemd", "met-name")
	search("alpha-host", "other-name", "slash-svc", "svc-name", "met-name")
	search("delta-host", "z-discovered", "m-discovered")
	search("owner-one", "svc-name")
	search("TIE-USER", "z-discovered")
	search("8080", "svc-name")
	search("%", "other-name")
	search("100%", "other-name")
	search("_")
	search(`\`, "slash-svc")
	search(`a\b`, "slash-svc")
	search("a-label", "z-discovered")
	search("m-discovered", "m-discovered")
	search("z-discovered", "z-discovered")
	search("no-such")

	metricsGot := projectNames(t, mem, metrics.ID, sq("name", "asc", 50, 0), now)
	if !sameNames(metricsGot, []string{"mine-name"}) {
		t.Fatalf("metrics rows %v", metricsGot)
	}
	if got := projectNames(t, mem, metrics.ID, store.ServiceListQuery{Q: "_", Sort: "name", Dir: "asc", Limit: 50}, now); !sameNames(got, []string{"mine-name"}) {
		t.Fatalf("underscore %v", got)
	}
	deployGot := projectNames(t, mem, deploy.ID, sq("name", "asc", 50, 0), now)
	if !sameNames(deployGot, []string{"other-name", "local-name"}) {
		t.Fatalf("deploy rows %v", deployGot)
	}

	qPage, err := mem.ListProjectServices(ctx, home.ID, store.ServiceListQuery{Q: "alpha-host", Sort: "name", Dir: "asc", Limit: 1}, now)
	if err != nil || qPage.Total != 4 || len(qPage.Items) != 1 || qPage.Total <= 1 {
		t.Fatalf("q total %d items %d %v", qPage.Total, len(qPage.Items), err)
	}
	alphaID := alpha.ID
	hostPage, err := mem.ListProjectServices(ctx, home.ID, store.ServiceListQuery{HostID: &alphaID, Sort: "name", Dir: "asc", Limit: 1}, now)
	if err != nil || hostPage.Total != 4 || len(hostPage.Items) != 1 || hostPage.Total <= 1 {
		t.Fatalf("host total %d items %d %v", hostPage.Total, len(hostPage.Items), err)
	}
	filtered := projectNames(t, mem, home.ID, store.ServiceListQuery{HostID: &alphaID, Sort: "name", Dir: "asc", Limit: 50}, now)
	if !sameNames(filtered, []string{"other-name", "slash-svc", "svc-name", "met-name"}) {
		t.Fatalf("host filter %v", filtered)
	}
	betaID := beta.ID
	if _, err := mem.ListProjectServices(ctx, home.ID, store.ServiceListQuery{HostID: &betaID, Sort: "name", Dir: "asc", Limit: 50}, now); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("unreachable host %v", err)
	}
	if _, err := mem.ListProjectServices(ctx, metrics.ID, store.ServiceListQuery{HostID: &alphaID, Sort: "name", Dir: "asc", Limit: 50}, now); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("metrics host %v", err)
	}
	missing := uuid.New()
	if _, err := mem.ListProjectServices(ctx, home.ID, store.ServiceListQuery{HostID: &missing, Sort: "name", Dir: "asc", Limit: 50}, now); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("missing host %v", err)
	}
	onlyDeploy := projectNames(t, mem, deploy.ID, store.ServiceListQuery{HostID: &alphaID, Sort: "name", Dir: "asc", Limit: 50}, now)
	if !sameNames(onlyDeploy, []string{"other-name"}) {
		t.Fatalf("deploy host filter %v", onlyDeploy)
	}

	var walked []string
	for offset := 0; ; offset += 2 {
		page, err := mem.ListProjectServices(ctx, home.ID, sq("name", "asc", 2, offset), now)
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != len(nameAsc) {
			t.Fatalf("total %d", page.Total)
		}
		walked = append(walked, namesOfPage(page)...)
		if offset+2 >= page.Total {
			if len(page.Items) == 0 {
				t.Fatal("last page empty")
			}
			break
		}
	}
	if !sameNames(walked, nameAsc) {
		t.Fatalf("paged %v", walked)
	}
	past, err := mem.ListProjectServices(ctx, home.ID, sq("name", "asc", 2, 100), now)
	if err != nil || past.Total != len(nameAsc) || len(past.Items) != 0 {
		t.Fatalf("past end %+v %v", past, err)
	}
	all, err := mem.ListProjectServices(ctx, home.ID, store.ServiceListQuery{Sort: "name", Dir: "asc"}, now)
	if err != nil || all.Total != len(nameAsc) || len(all.Items) != len(nameAsc) {
		t.Fatalf("default limit %+v %v", len(all.Items), err)
	}

	row := findRow(t, mem, home.ID, "other-name", now)
	if row.HostName != "alpha-host" || row.ProjectName != "Deploy" || row.DisplayName == nil || *row.DisplayName != "100%" {
		t.Fatalf("row %+v", row)
	}
	if row.Health.Status != "down" {
		t.Fatalf("status %s", row.Health.Status)
	}
	up := findRow(t, mem, home.ID, "svc-name", now)
	if up.Health.Status != "up" || up.ProjectName != "Home" {
		t.Fatalf("up %+v", up.Health.Status)
	}
	unknown := findRow(t, mem, home.ID, "met-name", now)
	if unknown.Health.Status != "unknown" || unknown.DisplayName != nil {
		t.Fatalf("stale %+v display %v", unknown.Health.Status, unknown.DisplayName)
	}
}

func TestRediscoveryKeepsDisplayName(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	mem := New()
	owner := mustUser(t, mem, "owner@ex.com", at)
	project := makeProject(t, mem, owner.ID, "Home", "home", at)
	host := enrollMem(t, mem, project.ID, owner.ID, "pi", at)
	svc := discoverService(t, mem, host.ID, "api", "process", []int{8080}, strp("root"), at)
	renamed, err := mem.SetServiceDisplayName(ctx, svc.ID, strp("Hello"), at)
	if err != nil || renamed.DisplayName == nil || *renamed.DisplayName != "Hello" {
		t.Fatalf("rename %+v %v", renamed.DisplayName, err)
	}
	alias := "Hello"
	if _, err := mem.SetServiceDisplayName(ctx, svc.ID, &alias, at); err != nil {
		t.Fatal(err)
	}
	alias = "changed"
	got, err := mem.GetService(ctx, svc.ID, at)
	if err != nil || got.DisplayName == nil || *got.DisplayName != "Hello" {
		t.Fatalf("alias %+v %v", got.DisplayName, err)
	}
	next := strp("www-data")
	if err := mem.UpsertDiscovered(ctx, host.ID, []store.Discovered{{
		Name: "api", Kind: "container", Ports: []int{9}, OwnerUser: next,
	}}, at.Add(time.Minute), true, true); err != nil {
		t.Fatal(err)
	}
	got, err = mem.GetService(ctx, svc.ID, at)
	if err != nil {
		t.Fatal(err)
	}
	if got.DisplayName == nil || *got.DisplayName != "Hello" || got.OwnerUser == nil || *got.OwnerUser != "www-data" {
		t.Fatalf("rediscover display %v owner %v", got.DisplayName, got.OwnerUser)
	}
	if got.Kind != "container" || len(got.Ports) != 1 || got.Ports[0] != 9 {
		t.Fatalf("discovered fields %+v", got)
	}
	bad := "a\nb"
	if err := mem.UpsertDiscovered(ctx, host.ID, []store.Discovered{{
		Name: "api", Kind: "container", Ports: []int{9}, OwnerUser: &bad,
	}}, at.Add(2*time.Minute), true, true); err != nil {
		t.Fatal(err)
	}
	got, err = mem.GetService(ctx, svc.ID, at)
	if err != nil || got.OwnerUser != nil || got.DisplayName == nil || *got.DisplayName != "Hello" {
		t.Fatalf("bad owner %+v display %v", got.OwnerUser, got.DisplayName)
	}

	declared := mem.PutDeclared(host.ID, "web", "process", []int{80, 443}, at)
	if _, err := mem.SetServiceDisplayName(ctx, declared.ID, strp("Kept"), at); err != nil {
		t.Fatal(err)
	}
	if err := mem.UpsertDiscovered(ctx, host.ID, []store.Discovered{{
		Name: "web", Kind: "container", Ports: []int{1}, OwnerUser: strp("alice"),
	}}, at.Add(time.Minute), true, true); err != nil {
		t.Fatal(err)
	}
	got, err = mem.GetService(ctx, declared.ID, at)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != "declared" || got.Kind != "process" || len(got.Ports) != 2 || got.Ports[0] != 80 {
		t.Fatalf("declared overwritten %+v", got)
	}
	if got.DisplayName == nil || *got.DisplayName != "Kept" || got.OwnerUser == nil || *got.OwnerUser != "alice" {
		t.Fatalf("declared name %v owner %v", got.DisplayName, got.OwnerUser)
	}

	peer := discoverService(t, mem, host.ID, "peer", "process", nil, nil, at)
	if _, err := mem.SetServiceDisplayName(ctx, peer.ID, strp("hello"), at); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate %v", err)
	}
	if _, err := mem.SetServiceDisplayName(ctx, svc.ID, strp("hello"), at); err != nil {
		t.Fatalf("same row %v", err)
	}
	other := enrollMem(t, mem, project.ID, owner.ID, "other", at)
	second := discoverService(t, mem, other.ID, "api", "process", nil, nil, at)
	if _, err := mem.SetServiceDisplayName(ctx, second.ID, strp("hello"), at); err != nil {
		t.Fatalf("other host %v", err)
	}
	if _, err := mem.SetServiceDisplayName(ctx, svc.ID, nil, at); err != nil {
		t.Fatal(err)
	}
	cleared, err := mem.GetService(ctx, svc.ID, at)
	if err != nil || cleared.DisplayName != nil {
		t.Fatalf("clear %v", cleared.DisplayName)
	}
}

func TestProjectServiceNameByteOrder(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	mem := New()
	user := mustUser(t, mem, "punct@ex.com", now)
	project := makeProject(t, mem, user.ID, "Punct", "punct", now)
	host := enrollMem(t, mem, project.ID, user.ID, "punct-host", now)
	other := enrollMem(t, mem, project.ID, user.ID, "punct-other", now)
	ids := map[string]uuid.UUID{}
	put := func(on store.Host, name, display string) {
		t.Helper()
		svc := discoverService(t, mem, on.ID, name, "process", nil, nil, now)
		if _, err := mem.SetServiceDisplayName(ctx, svc.ID, strp(display), now); err != nil {
			t.Fatal(err)
		}
		ids[name] = svc.ID
	}
	// Same and same are one lowercased key. They sit on different hosts so the
	// per-host duplicate check does not reject the tie.
	put(host, "under-svc", "a_b")
	put(host, "slash-punct", `a\b`)
	put(host, "label-svc", "a-label")
	put(host, "tie-upper", "Same")
	put(other, "tie-lower", "same")
	upper, lower := ids["tie-upper"], ids["tie-lower"]
	tie := []string{"tie-lower", "tie-upper"}
	if bytes.Compare(upper[:], lower[:]) < 0 {
		tie = []string{"tie-upper", "tie-lower"}
	}
	got := projectNames(t, mem, project.ID, store.ServiceListQuery{Sort: "name", Dir: "asc", Limit: 50}, now)
	want := []string{"label-svc", "slash-punct", "under-svc", tie[0], tie[1]}
	if !sameNames(got, want) {
		t.Fatalf("punctuation %v", got)
	}
}

// TestStaleStatusSort is the memstore half of the home list after
// assertDisplayConflict. m-discovered's label is foo. slash-svc stays a\b.
// A success older than HealthStale stays unknown and sorts with the other
// unknown rows by that label.
func TestStaleStatusSort(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	mem := New()
	user := mustUser(t, mem, "stale@ex.com", now)
	project := makeProject(t, mem, user.ID, "Stale", "stale", now)
	host := enrollMem(t, mem, project.ID, user.ID, "stale-host", now)

	initial := map[string]*string{
		"m-discovered": nil,
		"z-discovered": strp("a-label"),
		"shared-svc":   strp("Shared"),
		"metered":      strp("100%"),
		"slash-svc":    strp(`a\b`),
		"keep-name":    strp("Kept"),
		"plain":        nil,
		"declared-svc": strp("Kept2"),
	}
	kinds := map[string]string{
		"m-discovered": "process",
		"z-discovered": "container",
		"shared-svc":   "systemd",
		"metered":      "process",
		"slash-svc":    "process",
		"keep-name":    "process",
		"plain":        "process",
		"declared-svc": "process",
	}
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

	ids := map[string]uuid.UUID{}
	for name, display := range initial {
		svc := discoverService(t, mem, host.ID, name, kinds[name], nil, nil, now)
		if display != nil {
			if _, err := mem.SetServiceDisplayName(ctx, svc.ID, display, now); err != nil {
				t.Fatal(err)
			}
		}
		ids[name] = svc.ID
	}
	if _, err := mem.SetServiceDisplayName(ctx, ids["m-discovered"], strp("Foo"), now); err != nil {
		t.Fatal(err)
	}
	if _, err := mem.SetServiceDisplayName(ctx, ids["slash-svc"], strp("foo"), now); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate %v", err)
	}
	if _, err := mem.SetServiceDisplayName(ctx, ids["m-discovered"], strp("foo"), now); err != nil {
		t.Fatalf("same row %v", err)
	}
	putHealth(t, mem, host.ID, "z-discovered", "success", now)
	putHealth(t, mem, host.ID, "shared-svc", "fail", now)
	putHealth(t, mem, host.ID, "plain", "success", now.Add(-store.HealthStale-time.Second))

	page, err := mem.ListProjectServices(ctx, project.ID, store.ServiceListQuery{Sort: "status", Dir: "asc", Limit: 50}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != len(wantLabel) {
		t.Fatalf("rows %v", namesOfPage(page))
	}
	rows := make([]struct {
		name  string
		order store.ServiceOrder
	}, 0, len(page.Items))
	for _, item := range page.Items {
		label, ok := wantLabel[item.Name]
		if !ok || !samePtr(item.DisplayName, label) {
			t.Fatalf("%s display %q", item.Name, derefStr(item.DisplayName))
		}
		status := "unknown"
		if got, known := wantStatus[item.Name]; known {
			status = got
		}
		if item.Health.Status != status {
			t.Fatalf("%s status %s", item.Name, item.Health.Status)
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
			},
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return store.ServiceBefore(rows[i].order, rows[j].order, "status", "asc")
	})
	want := make([]string, len(rows))
	for i, row := range rows {
		want[i] = row.name
	}
	if !sameNames(namesOfPage(page), want) {
		t.Fatalf("stale sort %v want %v", namesOfPage(page), want)
	}
}

func samePtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func derefStr(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func makeProject(t *testing.T, mem *Mem, owner uuid.UUID, name, slug string, at time.Time) store.Project {
	t.Helper()
	p, err := mem.CreateProject(context.Background(), owner, name, slug, at)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func discoverService(t *testing.T, mem *Mem, hostID uuid.UUID, name, kind string, ports []int, owner *string, at time.Time) store.Service {
	t.Helper()
	return mem.PutDiscovered(hostID, name, kind, ports, owner, at)
}

func putHealth(t *testing.T, mem *Mem, hostID uuid.UUID, service, result string, at time.Time) {
	t.Helper()
	_, err := mem.InsertBatch(context.Background(), hostID, uuid.New(), []store.Sample{{
		M:    "health",
		T:    at,
		Tags: map[string]string{"service": service},
		Strs: map[string]string{"result": result},
	}}, at)
	if err != nil {
		t.Fatal(err)
	}
}

func projectNames(t *testing.T, mem *Mem, project uuid.UUID, q store.ServiceListQuery, now time.Time) []string {
	t.Helper()
	page, err := mem.ListProjectServices(context.Background(), project, q, now)
	if err != nil {
		t.Fatal(err)
	}
	if q.Q == "" && q.HostID == nil && page.Total != len(page.Items) && q.Limit >= page.Total {
		t.Fatalf("total %d items %d", page.Total, len(page.Items))
	}
	return namesOfPage(page)
}

func namesOfPage(page store.ServicePage) []string {
	out := make([]string, len(page.Items))
	for i, item := range page.Items {
		out[i] = item.Name
	}
	return out
}

func findRow(t *testing.T, mem *Mem, project uuid.UUID, name string, now time.Time) store.ProjectService {
	t.Helper()
	page, err := mem.ListProjectServices(context.Background(), project, sq("name", "asc", 50, 0), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range page.Items {
		if item.Name == name {
			return item
		}
	}
	t.Fatalf("missing %s", name)
	return store.ProjectService{}
}

func sq(sort, dir string, limit, offset int) store.ServiceListQuery {
	return store.ServiceListQuery{Sort: sort, Dir: dir, Limit: limit, Offset: offset}
}

func byID(ids map[string]uuid.UUID, names ...string) []string {
	out := append([]string(nil), names...)
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			right, left := ids[out[j]], ids[out[i]]
			if bytes.Compare(right[:], left[:]) < 0 {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func cat(parts ...[]string) []string {
	var out []string
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func sameNames(got, want []string) bool {
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

func containsSeq(got, seq []string) bool {
	if len(seq) == 0 || len(got) < len(seq) {
		return false
	}
	for i := 0; i+len(seq) <= len(got); i++ {
		ok := true
		for j := range seq {
			if got[i+j] != seq[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func strp(s string) *string { return &s }
