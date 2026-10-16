package memstore

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestPresenceMarkAndClear(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	mem := New()
	owner := mustUser(t, mem, "presence@ex.com", at)
	project := makeProject(t, mem, owner.ID, "Presence", "presence", at)
	host := enrollMem(t, mem, project.ID, owner.ID, "presence-host", at)
	otherHost := enrollMem(t, mem, project.ID, owner.ID, "presence-other", at)
	declared := mem.PutDeclared(host.ID, "declared", "process", []int{80}, at)
	gamma := mem.PutDiscovered(otherHost.ID, "gamma", "process", nil, nil, at)

	t1 := at.Add(time.Minute)
	if err := mem.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "alpha", Kind: "process", Ports: []int{1}},
		{Name: "beta", Kind: "process", Ports: []int{2}},
	}, t1, true, true); err != nil {
		t.Fatal(err)
	}
	alpha := serviceByName(t, mem, host.ID, "alpha", t1)
	beta := serviceByName(t, mem, host.ID, "beta", t1)
	if alpha.GoneAt != nil || beta.GoneAt != nil {
		t.Fatalf("reported gone alpha %v beta %v", alpha.GoneAt, beta.GoneAt)
	}
	marked := mustService(t, mem, declared.ID, t1)
	if marked.Source != "declared" || marked.GoneAt == nil || !marked.GoneAt.Equal(t1) {
		t.Fatalf("declared %+v", marked.GoneAt)
	}
	if got := mustService(t, mem, gamma.ID, t1); got.GoneAt != nil {
		t.Fatalf("other host %v", got.GoneAt)
	}

	display := "Beta"
	if _, err := mem.SetServiceDisplayName(ctx, beta.ID, &display, t1); err != nil {
		t.Fatal(err)
	}
	checks, err := mem.ReplaceHealthChecks(ctx, beta.ID, []store.HealthCheckInput{{
		Protocol: "http", Port: 2, IntervalSec: 30,
		ExpectStatusMin: 200, ExpectStatusMax: 299, Enabled: true,
	}})
	if err != nil || len(checks) != 1 {
		t.Fatalf("checks %v %v", checks, err)
	}

	t2 := t1.Add(time.Minute)
	if err := mem.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "alpha", Kind: "process", Ports: []int{1}},
	}, t2, true, true); err != nil {
		t.Fatal(err)
	}
	beta = mustService(t, mem, beta.ID, t2)
	if beta.GoneAt == nil || !beta.GoneAt.Equal(t2) {
		t.Fatalf("omitted %v", beta.GoneAt)
	}
	marked = mustService(t, mem, declared.ID, t2)
	if marked.GoneAt == nil || !marked.GoneAt.Equal(t1) || marked.Source != "declared" {
		t.Fatalf("declared moved %v %s", marked.GoneAt, marked.Source)
	}
	if got := mustService(t, mem, alpha.ID, t2); got.GoneAt != nil || got.ID != alpha.ID {
		t.Fatalf("alpha %+v", got.GoneAt)
	}
	if got := mustService(t, mem, gamma.ID, t2); got.GoneAt != nil {
		t.Fatalf("other host after omit %v", got.GoneAt)
	}

	t3 := t2.Add(time.Minute)
	if err := mem.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "alpha", Kind: "process", Ports: []int{1}},
	}, t3, true, true); err != nil {
		t.Fatal(err)
	}
	beta = mustService(t, mem, beta.ID, t3)
	if beta.GoneAt == nil || !beta.GoneAt.Equal(t2) {
		t.Fatalf("already gone moved to %v", beta.GoneAt)
	}

	if err := mem.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "alpha", Kind: "process"},
		{Name: "beta", Kind: "process"},
		{Name: "intruder", Kind: "process"},
	}, t3.Add(time.Second), false, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := findNamed(t, mem, host.ID, "intruder", t3); ok {
		t.Fatal("incomplete report inserted a row")
	}
	if got := mustService(t, mem, beta.ID, t3); got.GoneAt == nil || !got.GoneAt.Equal(t2) {
		t.Fatalf("incomplete changed gone_at %v", got.GoneAt)
	}
	if got := mustService(t, mem, alpha.ID, t3); got.GoneAt != nil {
		t.Fatal("incomplete marked alpha")
	}
	if err := mem.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "alpha", Kind: "process"},
		{Name: "beta", Kind: "process"},
		{Name: "intruder", Kind: "process"},
	}, t3.Add(time.Second), false, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := findNamed(t, mem, host.ID, "intruder", t3); ok {
		t.Fatal("incomplete report inserted a row")
	}
	if got := mustService(t, mem, beta.ID, t3); got.GoneAt == nil || !got.GoneAt.Equal(t2) {
		t.Fatalf("presence ignored on incomplete %v", got.GoneAt)
	}

	t4 := t3.Add(2 * time.Second)
	if err := mem.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "beta", Kind: "process", Ports: []int{2}},
	}, t4, true, false); err != nil {
		t.Fatal(err)
	}
	beta = mustService(t, mem, beta.ID, t4)
	if beta.GoneAt != nil {
		t.Fatalf("partial report left beta gone %v", beta.GoneAt)
	}
	if got := mustService(t, mem, alpha.ID, t4); got.GoneAt != nil {
		t.Fatal("partial report marked alpha")
	}
	marked = mustService(t, mem, declared.ID, t4)
	if marked.GoneAt == nil || !marked.GoneAt.Equal(t1) {
		t.Fatalf("partial report moved declared %v", marked.GoneAt)
	}

	t5 := t3.Add(time.Minute)
	if err := mem.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "alpha", Kind: "process", Ports: []int{1}},
		{Name: "beta", Kind: "process", Ports: []int{9}},
	}, t5, true, true); err != nil {
		t.Fatal(err)
	}
	beta = mustService(t, mem, beta.ID, t5)
	if beta.ID != checks[0].ServiceID || beta.GoneAt != nil {
		t.Fatalf("returned id %s gone %v", beta.ID, beta.GoneAt)
	}
	if beta.DisplayName == nil || *beta.DisplayName != "Beta" {
		t.Fatalf("display %v", beta.DisplayName)
	}
	gotChecks, err := mem.ListHealthChecks(ctx, beta.ID)
	if err != nil || len(gotChecks) != 1 || gotChecks[0].ID != checks[0].ID {
		t.Fatalf("health checks %+v %v", gotChecks, err)
	}

	t6 := t5.Add(time.Minute)
	if err := mem.UpsertDiscovered(ctx, host.ID, []store.Discovered{}, t6, true, true); err != nil {
		t.Fatal(err)
	}
	for _, svc := range []store.Service{mustService(t, mem, alpha.ID, t6), mustService(t, mem, beta.ID, t6)} {
		if svc.GoneAt == nil || !svc.GoneAt.Equal(t6) {
			t.Fatalf("%s empty report %v", svc.Name, svc.GoneAt)
		}
	}
	marked = mustService(t, mem, declared.ID, t6)
	if marked.GoneAt == nil || !marked.GoneAt.Equal(t1) {
		t.Fatalf("declared empty report %v", marked.GoneAt)
	}
	if got := mustService(t, mem, gamma.ID, t6); got.GoneAt != nil {
		t.Fatalf("other host empty report %v", got.GoneAt)
	}
}

func TestServiceViews(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 10, 15, 13, 0, 0, 0, time.UTC)
	mem := New()
	owner := mustUser(t, mem, "views@ex.com", at)
	project := makeProject(t, mem, owner.ID, "Views", "views", at)
	host := enrollMem(t, mem, project.ID, owner.ID, "views-host", at)
	names := []string{"declared-gone", "declared-up", "found-gone", "found-up", "owned-gone", "owned-up"}
	for _, name := range names {
		mem.PutDiscovered(host.ID, name, "process", nil, nil, at)
	}
	setSource(t, mem, "declared-gone", "declared")
	setSource(t, mem, "declared-up", "declared")
	setSource(t, mem, "owned-gone", "owned")
	setSource(t, mem, "owned-up", "owned")
	if err := mem.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "declared-up", Kind: "process"},
		{Name: "found-up", Kind: "process"},
		{Name: "owned-up", Kind: "process"},
	}, at, true, true); err != nil {
		t.Fatal(err)
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
		got := projectNames(t, mem, project.ID, store.ServiceListQuery{Sort: "name", Dir: "asc", Limit: 50, View: tc.view}, at)
		if !sameNames(got, tc.want) {
			t.Fatalf("view %q %v", tc.view, got)
		}
	}
	page, err := mem.ListProjectServices(ctx, project.ID, store.ServiceListQuery{
		Sort: "name", Dir: "asc", Limit: 1, View: "deploybot",
	}, at)
	if err != nil || page.Total != 4 || len(page.Items) != 1 {
		t.Fatalf("total %d items %d %v", page.Total, len(page.Items), err)
	}
}

// A gone owned row whose catalog entry was deleted leaves the deploybot views;
// "all" still lists it. A deleted entry's row that is still reported stays.
func TestDeploybotViewHidesGoneRowsOfDeletedEntries(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 10, 16, 13, 0, 0, 0, time.UTC)
	mem := New()
	owner := mustUser(t, mem, "deleted@ex.com", at)
	project := makeProject(t, mem, owner.ID, "Deleted", "deleted", at)
	host := enrollMem(t, mem, project.ID, owner.ID, "deleted-host", at)
	for _, name := range []string{"kept", "dropped", "running"} {
		spec, hash, display := catalogSpec(t, "pnpm run dev")
		if _, err := mem.CreateCatalogEntry(ctx, project.ID, store.CatalogWrite{
			Name: name, Spec: spec, SpecHash: hash, CommandDisplay: display, Actor: owner.ID, At: at,
		}); err != nil {
			t.Fatal(err)
		}
		mem.PutDiscovered(host.ID, name, "process", nil, nil, at)
		setOwnedEntry(t, mem, name, name)
	}
	if err := mem.UpsertDiscovered(ctx, host.ID, []store.Discovered{{Name: "running", Kind: "process"}}, at, true, true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dropped", "running"} {
		if _, err := mem.DeleteCatalogEntry(ctx, project.ID, name); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		view string
		want []string
	}{
		{"all", []string{"dropped", "kept", "running"}},
		{"deploybot", []string{"kept", "running"}},
		{"deploybot_and_discovered", []string{"kept", "running"}},
	} {
		got := projectNames(t, mem, project.ID, store.ServiceListQuery{Sort: "name", Dir: "asc", Limit: 50, View: tc.view}, at)
		if !sameNames(got, tc.want) {
			t.Fatalf("view %q %v", tc.view, got)
		}
	}
}

func TestStatusSortGoneLast(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 10, 15, 14, 0, 0, 0, time.UTC)
	mem := New()
	owner := mustUser(t, mem, "status@ex.com", at)
	project := makeProject(t, mem, owner.ID, "Status", "status", at)
	host := enrollMem(t, mem, project.ID, owner.ID, "status-host", at)
	for _, name := range []string{"a-gone", "a-present", "b-gone", "b-present"} {
		mem.PutDiscovered(host.ID, name, "process", nil, nil, at)
	}
	putHealth(t, mem, host.ID, "b-present", "success", at)
	putHealth(t, mem, host.ID, "a-present", "fail", at)
	putHealth(t, mem, host.ID, "b-gone", "success", at)
	if err := mem.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "b-present", Kind: "process"},
		{Name: "a-present", Kind: "process"},
	}, at, true, true); err != nil {
		t.Fatal(err)
	}
	asc := projectNames(t, mem, project.ID, store.ServiceListQuery{Sort: "status", Dir: "asc", Limit: 50}, at)
	if !sameNames(asc, []string{"b-present", "a-present", "b-gone", "a-gone"}) {
		t.Fatalf("asc %v", asc)
	}
	desc := projectNames(t, mem, project.ID, store.ServiceListQuery{Sort: "status", Dir: "desc", Limit: 50}, at)
	if !sameNames(desc, []string{"a-present", "b-present", "a-gone", "b-gone"}) {
		t.Fatalf("desc %v", desc)
	}
}

func TestServiceViewFilters(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 10, 15, 15, 0, 0, 0, time.UTC)
	mem := New()
	homeUser := mustUser(t, mem, "view-home@ex.com", at)
	guestUser := mustUser(t, mem, "view-guest@ex.com", at)
	home := makeProject(t, mem, homeUser.ID, "Home", "view-home", at)
	guest := makeProject(t, mem, guestUser.ID, "Guest", "view-guest", at)
	host := enrollMem(t, mem, home.ID, homeUser.ID, "view-host", at)
	other := enrollMem(t, mem, home.ID, homeUser.ID, "view-other", at)
	api := mem.PutDeclared(host.ID, "api", "process", nil, at)
	mem.PutDeclared(host.ID, "api-old", "process", nil, at)
	found := mem.PutDiscovered(host.ID, "found", "process", nil, nil, at)
	mem.PutDiscovered(host.ID, "found-old", "process", nil, nil, at)
	mem.PutDeclared(other.ID, "api-remote", "process", nil, at)
	if err := mem.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "api", Kind: "process"},
		{Name: "found", Kind: "process"},
	}, at, true, true); err != nil {
		t.Fatal(err)
	}
	mem.SetServiceProject(api.ID, guest.ID)
	mem.SetServiceProject(found.ID, guest.ID)
	if _, _, err := mem.PutHostShare(ctx, host.ID, guest.ID, "deploy", homeUser.ID, at); err != nil {
		t.Fatal(err)
	}
	base := store.ServiceListQuery{Sort: "name", Dir: "asc", Limit: 50}
	homeAPI := base
	homeAPI.Q = "api"
	homeAPI.View = "deploybot"
	if got := projectNames(t, mem, home.ID, homeAPI, at); !sameNames(got, []string{"api", "api-old", "api-remote"}) {
		t.Fatalf("q api deploybot %v", got)
	}
	homeFound := base
	homeFound.Q = "found"
	homeFound.View = "deploybot"
	if got := projectNames(t, mem, home.ID, homeFound, at); len(got) != 0 {
		t.Fatalf("q found deploybot %v", got)
	}
	homeFound.View = "deploybot_and_discovered"
	if got := projectNames(t, mem, home.ID, homeFound, at); !sameNames(got, []string{"found"}) {
		t.Fatalf("q found with discovered %v", got)
	}
	hostID := host.ID
	hosted := base
	hosted.Q = "api"
	hosted.View = "deploybot"
	hosted.HostID = &hostID
	if got := projectNames(t, mem, home.ID, hosted, at); !sameNames(got, []string{"api", "api-old"}) {
		t.Fatalf("host_id %v", got)
	}
	guestDeploy := base
	guestDeploy.View = "deploybot"
	if got := projectNames(t, mem, guest.ID, guestDeploy, at); !sameNames(got, []string{"api"}) {
		t.Fatalf("guest deploybot %v", got)
	}
	guestBoth := base
	guestBoth.View = "deploybot_and_discovered"
	if got := projectNames(t, mem, guest.ID, guestBoth, at); !sameNames(got, []string{"api", "found"}) {
		t.Fatalf("guest both %v", got)
	}
}

func TestPresenceUsesPlacedName(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 10, 15, 16, 0, 0, 0, time.UTC)
	mem := New()
	owner := catalogUser(t, mem, "placed-own")
	home := catalogProject(t, mem, owner.ID, "Home", "placedproj", at)
	boxOwner := catalogUser(t, mem, "placed-box")
	box := catalogProject(t, mem, boxOwner.ID, "Box", "placedbox", at)
	host := catalogHost(t, mem, box, boxOwner.ID, "placed-pi", at)
	spec, hash, display := catalogSpec(t, "pnpm run dev")
	if _, err := mem.CreateCatalogEntry(ctx, home.ID, store.CatalogWrite{
		Name: "webapp", Spec: spec, SpecHash: hash, CommandDisplay: display, Actor: owner.ID, At: at,
	}); err != nil {
		t.Fatal(err)
	}
	other := mem.PutDiscovered(host.ID, "other", "process", nil, nil, at)
	if err := mem.UpsertDiscovered(ctx, host.ID, []store.Discovered{{
		Name: "not-the-entry", Kind: "process", Ports: []int{80},
		Owner: &store.DiscoveredOwner{Kind: "program", Project: "placedproj", Entry: "webapp"},
	}}, at, true, true); err != nil {
		t.Fatal(err)
	}
	items, err := mem.ListServices(ctx, host.ID, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	placed := findService(t, items, "webapp")
	if placed.Source != "owned" || placed.GoneAt != nil || placed.ProjectID != home.ID {
		t.Fatalf("placed %+v", placed)
	}
	if _, ok := findNamed(t, mem, host.ID, "not-the-entry", at); ok {
		t.Fatal("agent name stored")
	}
	got := mustService(t, mem, other.ID, at)
	if got.GoneAt == nil || !got.GoneAt.Equal(at) {
		t.Fatalf("sibling %v", got.GoneAt)
	}
}

func setOwnedEntry(t *testing.T, mem *Mem, name, entry string) {
	t.Helper()
	mem.mu.Lock()
	defer mem.mu.Unlock()
	for id, svc := range mem.services {
		if svc.Name != name {
			continue
		}
		svc.Source = "owned"
		svc.CatalogEntry = &entry
		mem.services[id] = svc
		return
	}
	t.Fatalf("missing %s", name)
}

func setSource(t *testing.T, mem *Mem, name, source string) {
	t.Helper()
	mem.mu.Lock()
	defer mem.mu.Unlock()
	for id, svc := range mem.services {
		if svc.Name != name {
			continue
		}
		svc.Source = source
		mem.services[id] = svc
		return
	}
	t.Fatalf("missing %s", name)
}

func mustService(t *testing.T, mem *Mem, id uuid.UUID, at time.Time) store.Service {
	t.Helper()
	svc, err := mem.GetService(context.Background(), id, at)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func serviceByName(t *testing.T, mem *Mem, hostID uuid.UUID, name string, at time.Time) store.Service {
	t.Helper()
	svc, ok := findNamed(t, mem, hostID, name, at)
	if !ok {
		t.Fatalf("missing %s", name)
	}
	return svc
}

func findNamed(t *testing.T, mem *Mem, hostID uuid.UUID, name string, at time.Time) (store.Service, bool) {
	t.Helper()
	items, err := mem.ListServices(context.Background(), hostID, nil, at)
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
