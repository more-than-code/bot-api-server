package api

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestProjectServiceView(t *testing.T) {
	w := newWorld(t)
	owner := w.user("view-owner@ex.com", "Owner")
	project, err := w.mem.CreateProject(context.Background(), owner.ID, "View", "viewproj", w.now)
	if err != nil {
		t.Fatal(err)
	}
	host := enrollAPIHost(t, w, project.ID, owner.ID, "view-host", true)
	tok := w.token(owner.ID)
	w.mem.PutDeclared(host.ID, "declared-up", "process", []int{80}, w.now)
	w.mem.PutDeclared(host.ID, "declared-gone", "process", []int{81}, w.now)
	w.mem.PutDiscovered(host.ID, "found-up", "process", nil, nil, w.now)
	gone := w.mem.PutDiscovered(host.ID, "found-gone", "process", nil, nil, w.now)
	if err := w.mem.UpsertDiscovered(context.Background(), host.ID, []store.Discovered{
		{Name: "declared-up", Kind: "process", Ports: []int{80}},
		{Name: "found-up", Kind: "process"},
	}, w.now, true, true); err != nil {
		t.Fatal(err)
	}
	home := project.ID.String()
	for _, view := range []string{"bogus", "ALL"} {
		q := url.Values{}
		q.Set("view", view)
		code, env := w.do(tok, http.MethodGet, servicesPath(home, q), "")
		if code != http.StatusBadRequest || env.Code != "bad_request" || env.Msg != "invalid view" {
			t.Fatalf("view %s %d %s %s", view, code, env.Code, env.Msg)
		}
	}
	for _, tc := range []struct {
		view string
		want []string
	}{
		{"", []string{"declared-gone", "declared-up", "found-gone", "found-up"}},
		{"all", []string{"declared-gone", "declared-up", "found-gone", "found-up"}},
		{"deploybot", []string{"declared-gone", "declared-up"}},
		{"deploybot_and_discovered", []string{"declared-gone", "declared-up", "found-up"}},
	} {
		q := url.Values{}
		if tc.view != "" {
			q.Set("view", tc.view)
		}
		if got := itemNames(t, listView(t, w, tok, home, q)); !sameStrings(got, tc.want) {
			t.Fatalf("view %q %v", tc.view, got)
		}
	}
	limited := url.Values{}
	limited.Set("view", "deploybot")
	limited.Set("limit", "1")
	page := listView(t, w, tok, home, limited)
	payload := objectPayload(t, page)
	if int(payload["total"].(float64)) != 2 || len(listItems(t, page)) != 1 {
		t.Fatalf("total %v items %d", payload["total"], len(listItems(t, page)))
	}

	firstQ := url.Values{}
	firstQ.Set("limit", "1")
	first := listView(t, w, tok, home, firstQ)
	next, _ := objectPayload(t, first)["next_cursor"].(string)
	if next == "" {
		t.Fatal("missing cursor")
	}
	mismatch := url.Values{}
	mismatch.Set("limit", "1")
	mismatch.Set("view", "deploybot")
	mismatch.Set("cursor", next)
	code, env := w.do(tok, http.MethodGet, servicesPath(home, mismatch), "")
	if code != http.StatusBadRequest || env.Code != "bad_request" || env.Msg != "cursor does not match query" {
		t.Fatalf("cursor %d %s %s", code, env.Code, env.Msg)
	}
	for _, view := range []string{"all", ""} {
		q := url.Values{}
		q.Set("limit", "1")
		q.Set("cursor", next)
		if view != "" {
			q.Set("view", view)
		}
		if code, env := w.do(tok, http.MethodGet, servicesPath(home, q), ""); code != http.StatusOK || env.Code != "ok" {
			t.Fatalf("cursor view %q %d %s", view, code, env.Msg)
		}
	}

	items := listItems(t, listView(t, w, tok, home, nil))
	assertGoneJSON(t, findItem(t, items, "name", "found-gone"), "2026-10-13T12:00:00Z")
	assertGoneJSON(t, findItem(t, items, "name", "declared-up"), "")
	code, env = w.do(tok, http.MethodGet, "/v1/hosts/"+host.ID.String()+"/services", "")
	if code != http.StatusOK {
		t.Fatalf("host list %d %s", code, env.Msg)
	}
	hostItems := listItems(t, env)
	assertGoneJSON(t, findItem(t, hostItems, "name", "found-gone"), "2026-10-13T12:00:00Z")
	assertGoneJSON(t, findItem(t, hostItems, "name", "declared-up"), "")
	code, env = w.do(tok, http.MethodGet, "/v1/services/"+gone.ID.String(), "")
	if code != http.StatusOK {
		t.Fatalf("get %d %s", code, env.Msg)
	}
	assertGoneJSON(t, objectPayload(t, env), "2026-10-13T12:00:00Z")
	code, env = w.do(tok, http.MethodGet, "/v1/services/"+findItem(t, items, "name", "declared-up")["id"].(string), "")
	if code != http.StatusOK {
		t.Fatalf("get present %d %s", code, env.Msg)
	}
	assertGoneJSON(t, objectPayload(t, env), "")
}

func TestProjectServiceStatusGoneLast(t *testing.T) {
	w := newWorld(t)
	owner := w.user("status-owner@ex.com", "Owner")
	project, err := w.mem.CreateProject(context.Background(), owner.ID, "Status", "statusproj", w.now)
	if err != nil {
		t.Fatal(err)
	}
	host := enrollAPIHost(t, w, project.ID, owner.ID, "status-host", true)
	for _, name := range []string{"a-gone", "a-present", "b-gone", "b-present"} {
		w.mem.PutDiscovered(host.ID, name, "process", nil, nil, w.now)
	}
	putAPIHealth(t, w, host.ID, "b-present", "success", w.now)
	putAPIHealth(t, w, host.ID, "a-present", "fail", w.now)
	putAPIHealth(t, w, host.ID, "b-gone", "success", w.now)
	if err := w.mem.UpsertDiscovered(context.Background(), host.ID, []store.Discovered{
		{Name: "b-present", Kind: "process"},
		{Name: "a-present", Kind: "process"},
	}, w.now, true, true); err != nil {
		t.Fatal(err)
	}
	tok := w.token(owner.ID)
	home := project.ID.String()
	for _, tc := range []struct {
		dir  string
		want []string
	}{
		{"asc", []string{"b-present", "a-present", "b-gone", "a-gone"}},
		{"desc", []string{"a-present", "b-present", "a-gone", "b-gone"}},
	} {
		q := url.Values{}
		q.Set("sort", "status")
		q.Set("dir", tc.dir)
		if got := itemNames(t, listView(t, w, tok, home, q)); !sameStrings(got, tc.want) {
			t.Fatalf("%s %v", tc.dir, got)
		}
	}
}

func TestProjectServiceViewFilters(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	homeUser := w.user("view-filter-home@ex.com", "Home")
	guestUser := w.user("view-filter-guest@ex.com", "Guest")
	home, err := w.mem.CreateProject(ctx, homeUser.ID, "Home", "viewfilter", w.now)
	if err != nil {
		t.Fatal(err)
	}
	guest, err := w.mem.CreateProject(ctx, guestUser.ID, "Guest", "viewguest", w.now)
	if err != nil {
		t.Fatal(err)
	}
	host := enrollAPIHost(t, w, home.ID, homeUser.ID, "filter-host", true)
	other := enrollAPIHost(t, w, home.ID, homeUser.ID, "filter-other", true)
	api := w.mem.PutDeclared(host.ID, "api", "process", nil, w.now)
	w.mem.PutDeclared(host.ID, "api-old", "process", nil, w.now)
	found := w.mem.PutDiscovered(host.ID, "found", "process", nil, nil, w.now)
	w.mem.PutDiscovered(host.ID, "found-old", "process", nil, nil, w.now)
	w.mem.PutDeclared(other.ID, "api-remote", "process", nil, w.now)
	if err := w.mem.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "api", Kind: "process"},
		{Name: "found", Kind: "process"},
	}, w.now, true, true); err != nil {
		t.Fatal(err)
	}
	w.mem.SetServiceProject(api.ID, guest.ID)
	w.mem.SetServiceProject(found.ID, guest.ID)
	if _, _, err := w.mem.PutHostShare(ctx, host.ID, guest.ID, "deploy", homeUser.ID, w.now); err != nil {
		t.Fatal(err)
	}
	homeTok := w.token(homeUser.ID)
	guestTok := w.token(guestUser.ID)
	homeID := home.ID.String()
	guestID := guest.ID.String()

	q := url.Values{}
	q.Set("q", "api")
	q.Set("view", "deploybot")
	if got := itemNames(t, listView(t, w, homeTok, homeID, q)); !sameStrings(got, []string{"api", "api-old", "api-remote"}) {
		t.Fatalf("q api %v", got)
	}
	q.Set("q", "found")
	if got := itemNames(t, listView(t, w, homeTok, homeID, q)); len(got) != 0 {
		t.Fatalf("q found deploybot %v", got)
	}
	q.Set("view", "deploybot_and_discovered")
	if got := itemNames(t, listView(t, w, homeTok, homeID, q)); !sameStrings(got, []string{"found"}) {
		t.Fatalf("q found with discovered %v", got)
	}
	q.Set("q", "api")
	q.Set("view", "deploybot")
	q.Set("host_id", host.ID.String())
	if got := itemNames(t, listView(t, w, homeTok, homeID, q)); !sameStrings(got, []string{"api", "api-old"}) {
		t.Fatalf("host_id %v", got)
	}
	guestQ := url.Values{}
	guestQ.Set("view", "deploybot")
	if got := itemNames(t, listView(t, w, guestTok, guestID, guestQ)); !sameStrings(got, []string{"api"}) {
		t.Fatalf("guest deploybot %v", got)
	}
	guestQ.Set("view", "deploybot_and_discovered")
	if got := itemNames(t, listView(t, w, guestTok, guestID, guestQ)); !sameStrings(got, []string{"api", "found"}) {
		t.Fatalf("guest both %v", got)
	}
}

func listView(t *testing.T, w *world, tok, project string, q url.Values) envelope {
	t.Helper()
	code, env := w.do(tok, http.MethodGet, servicesPath(project, q), "")
	if code != http.StatusOK || env.Code != "ok" {
		t.Fatalf("list %d %s %s", code, env.Code, env.Msg)
	}
	return env
}

func assertGoneJSON(t *testing.T, item map[string]any, want string) {
	t.Helper()
	got, ok := item["gone_at"]
	if !ok {
		t.Fatal("missing gone_at")
	}
	if want == "" {
		if got != nil {
			t.Fatalf("gone_at %#v", got)
		}
		return
	}
	if got != want {
		t.Fatalf("gone_at %#v", got)
	}
}

func TestProjectServicesRevokedHost(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("revoke-rows@ex.com", "Owner")
	project, err := w.mem.CreateProject(ctx, owner.ID, "Revoke", "revokerows", w.now)
	if err != nil {
		t.Fatal(err)
	}
	revoked := enrollAPIHost(t, w, project.ID, owner.ID, "revoked-host", true)
	live := enrollAPIHost(t, w, project.ID, owner.ID, "live-host", true)
	w.mem.PutDeclared(revoked.ID, "revoked-declared", "process", nil, w.now)
	w.mem.PutDiscovered(revoked.ID, "revoked-found", "process", nil, nil, w.now)
	old := w.mem.PutDiscovered(revoked.ID, "revoked-old", "process", nil, nil, w.now)
	w.mem.PutDeclared(live.ID, "live-declared", "process", nil, w.now)
	w.mem.PutDiscovered(live.ID, "live-found", "process", nil, nil, w.now)
	early := w.now.Add(-time.Hour)
	if err := w.mem.UpsertDiscovered(ctx, revoked.ID, []store.Discovered{
		{Name: "revoked-declared", Kind: "process"},
		{Name: "revoked-found", Kind: "process"},
	}, early, true, true); err != nil {
		t.Fatal(err)
	}
	tok := w.token(owner.ID)
	code, env := w.do(tok, http.MethodDelete, "/v1/hosts/"+revoked.ID.String()+"/credential", "")
	if code != http.StatusOK || env.Code != "ok" {
		t.Fatalf("revoke %d %s %s", code, env.Code, env.Msg)
	}
	code, env = w.do(tok, http.MethodDelete, "/v1/hosts/"+revoked.ID.String()+"/credential", "")
	if code != http.StatusOK || env.Code != "ok" {
		t.Fatalf("second revoke %d %s %s", code, env.Code, env.Msg)
	}

	home := project.ID.String()
	wantAll := []string{"live-declared", "live-found", "revoked-declared", "revoked-found", "revoked-old"}
	for _, tc := range []struct {
		view  string
		want  []string
		total int
	}{
		{"deploybot", []string{"live-declared"}, 1},
		{"deploybot_and_discovered", []string{"live-declared", "live-found"}, 2},
		{"all", wantAll, 5},
		{"", wantAll, 5},
	} {
		q := url.Values{}
		q.Set("sort", "name")
		if tc.view != "" {
			q.Set("view", tc.view)
		}
		page := listView(t, w, tok, home, q)
		payload := objectPayload(t, page)
		if int(payload["total"].(float64)) != tc.total {
			t.Fatalf("view %q total %v", tc.view, payload["total"])
		}
		if got := itemNames(t, page); !sameStrings(got, tc.want) {
			t.Fatalf("view %q %v", tc.view, got)
		}
	}
	items := listItems(t, listView(t, w, tok, home, url.Values{"sort": {"name"}, "view": {"all"}}))
	assertGoneJSON(t, findItem(t, items, "name", "revoked-declared"), "2026-10-13T12:00:00Z")
	assertGoneJSON(t, findItem(t, items, "name", "revoked-found"), "2026-10-13T12:00:00Z")
	assertGoneJSON(t, findItem(t, items, "name", "revoked-old"), "2026-10-13T11:00:00Z")
	assertGoneJSON(t, findItem(t, items, "name", "live-declared"), "")
	assertGoneJSON(t, findItem(t, items, "name", "live-found"), "")
	if findItem(t, items, "name", "revoked-declared")["host_status"] != "revoked" {
		t.Fatalf("host_status %v", findItem(t, items, "name", "revoked-declared")["host_status"])
	}

	limited := url.Values{}
	limited.Set("view", "deploybot")
	limited.Set("sort", "name")
	limited.Set("limit", "1")
	limitedPage := listView(t, w, tok, home, limited)
	limitedPayload := objectPayload(t, limitedPage)
	if int(limitedPayload["total"].(float64)) != 1 || limitedPayload["next_cursor"] != nil {
		t.Fatalf("deploybot page total %v cursor %v", limitedPayload["total"], limitedPayload["next_cursor"])
	}
	if got := itemNames(t, limitedPage); !sameStrings(got, []string{"live-declared"}) {
		t.Fatalf("deploybot page %v", got)
	}

	code, env = w.do(tok, http.MethodGet, "/v1/hosts/"+revoked.ID.String()+"/services", "")
	if code != http.StatusOK {
		t.Fatalf("host list %d %s", code, env.Msg)
	}
	hostItems := listItems(t, env)
	if got := itemNames(t, env); !sameStrings(got, []string{"revoked-declared", "revoked-found", "revoked-old"}) {
		t.Fatalf("host services %v", got)
	}
	assertGoneJSON(t, findItem(t, hostItems, "name", "revoked-declared"), "2026-10-13T12:00:00Z")
	assertGoneJSON(t, findItem(t, hostItems, "name", "revoked-old"), "2026-10-13T11:00:00Z")
	code, env = w.do(tok, http.MethodGet, "/v1/services/"+old.ID.String(), "")
	if code != http.StatusOK {
		t.Fatalf("get %d %s", code, env.Msg)
	}
	assertGoneJSON(t, objectPayload(t, env), "2026-10-13T11:00:00Z")
	code, env = w.do(tok, http.MethodGet, "/v1/services/"+findItem(t, items, "name", "revoked-found")["id"].(string), "")
	if code != http.StatusOK {
		t.Fatalf("get found %d %s", code, env.Msg)
	}
	assertGoneJSON(t, objectPayload(t, env), "2026-10-13T12:00:00Z")
}

func TestProjectDeleteMarksHostRowsGone(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("delgone@ex.com", "Owner")
	otherUser := w.user("delother@ex.com", "Other")
	project, err := w.mem.CreateProject(ctx, owner.ID, "Del", "delgone", w.now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := w.mem.CreateProject(ctx, otherUser.ID, "Other", "delother", w.now)
	if err != nil {
		t.Fatal(err)
	}
	host := enrollAPIHost(t, w, project.ID, owner.ID, "delhost", true)
	earlyHost := enrollAPIHost(t, w, project.ID, owner.ID, "delearly", true)
	foreignHost := enrollAPIHost(t, w, other.ID, otherUser.ID, "delforeign", true)
	earlyRevoke := w.now.Add(-2 * time.Hour)
	if err := w.mem.RevokeHost(ctx, earlyHost.ID, earlyRevoke); err != nil {
		t.Fatal(err)
	}
	present := w.mem.PutDiscovered(host.ID, "present", "process", nil, nil, w.now)
	already := w.mem.PutDiscovered(host.ID, "already", "process", nil, nil, w.now)
	straggler := w.mem.PutDiscovered(earlyHost.ID, "straggler", "process", nil, nil, w.now)
	foreign := w.mem.PutDiscovered(foreignHost.ID, "foreign", "process", nil, nil, w.now)
	w.mem.SetServiceProject(foreign.ID, project.ID)
	kept := w.now.Add(-time.Hour)
	if err := w.mem.UpsertDiscovered(ctx, host.ID, []store.Discovered{
		{Name: "present", Kind: "process"},
	}, kept, true, true); err != nil {
		t.Fatal(err)
	}
	code, env := w.do(w.token(owner.ID), http.MethodDelete, "/v1/projects/"+project.ID.String(), "")
	if code != http.StatusOK || env.Code != "ok" {
		t.Fatalf("delete %d %s %s", code, env.Code, env.Msg)
	}
	presentRow, err := w.mem.GetService(ctx, present.ID, w.now)
	if err != nil || presentRow.GoneAt == nil || !presentRow.GoneAt.Equal(w.now) {
		t.Fatalf("present %v %v", presentRow.GoneAt, err)
	}
	alreadyRow, err := w.mem.GetService(ctx, already.ID, w.now)
	if err != nil || alreadyRow.GoneAt == nil || !alreadyRow.GoneAt.Equal(kept) {
		t.Fatalf("already %v %v", alreadyRow.GoneAt, err)
	}
	stragglerRow, err := w.mem.GetService(ctx, straggler.ID, w.now)
	if err != nil || stragglerRow.GoneAt == nil || !stragglerRow.GoneAt.Equal(earlyRevoke) {
		t.Fatalf("straggler %v %v", stragglerRow.GoneAt, err)
	}
	foreignRow, err := w.mem.GetService(ctx, foreign.ID, w.now)
	if err != nil || foreignRow.GoneAt != nil || foreignRow.ProjectID != other.ID {
		t.Fatalf("foreign gone %v project %s err %v", foreignRow.GoneAt, foreignRow.ProjectID, err)
	}
	foreignHostRow, err := w.mem.GetHost(ctx, foreignHost.ID)
	if err != nil || foreignHostRow.RevokedAt != nil {
		t.Fatalf("foreign host %v %v", foreignHostRow.RevokedAt, err)
	}
}
