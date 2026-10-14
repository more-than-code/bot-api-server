package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestProjectServiceList(t *testing.T) {
	fx := newProjectServiceFixture(t)
	home := fx.home.ID.String()
	full := fx.list(t, fx.tok["home"], home, url.Values{})
	if !sameStrings(itemNames(t, full), []string{"nap", "web", "api", "met"}) {
		t.Fatalf("home %v", itemNames(t, full))
	}
	if int(objectPayload(t, full)["total"].(float64)) != 4 {
		t.Fatalf("total %#v", objectPayload(t, full)["total"])
	}
	viewer := fx.list(t, fx.tok["viewer"], home, url.Values{})
	if !sameStrings(itemNames(t, viewer), itemNames(t, full)) {
		t.Fatalf("viewer %v", itemNames(t, viewer))
	}
	deploy := fx.list(t, fx.tok["deploy"], fx.deploy.ID.String(), url.Values{})
	if !sameStrings(itemNames(t, deploy), []string{"web", "local"}) {
		t.Fatalf("deploy %v", itemNames(t, deploy))
	}
	deployViewer := fx.list(t, fx.tok["deploy_viewer"], fx.deploy.ID.String(), url.Values{})
	if !sameStrings(itemNames(t, deployViewer), []string{"web", "local"}) {
		t.Fatalf("deploy viewer %v", itemNames(t, deployViewer))
	}
	metrics := fx.list(t, fx.tok["metrics"], fx.metrics.ID.String(), url.Values{})
	if !sameStrings(itemNames(t, metrics), []string{"mine"}) {
		t.Fatalf("metrics %v", itemNames(t, metrics))
	}
	for _, tok := range []string{fx.tok["outsider"], fx.tok["metrics"]} {
		code, env := fx.w.do(tok, http.MethodGet, "/v1/projects/"+home+"/services", "")
		if code != http.StatusNotFound || env.Code != "not_found" {
			t.Fatalf("non-member %d %s", code, env.Code)
		}
	}

	api := findItem(t, listItems(t, full), "name", "api")
	if api["host_name"] != "pi-home" || api["host_status"] != "offline" || api["project_name"] != "Home" || api["display_name"] != "Alpha" || api["owner_user"] != "root" {
		t.Fatalf("api row %#v", api)
	}
	web := findItem(t, listItems(t, full), "name", "web")
	if web["project_name"] != "Deploy" || web["display_name"] != "a_b" || web["host_status"] != "offline" {
		t.Fatalf("web row %#v", web)
	}
	nap := findItem(t, listItems(t, full), "name", "nap")
	if nap["host_name"] != "pi-asleep" || nap["host_status"] != "asleep" || nap["display_name"] != "100%" {
		t.Fatalf("nap row %#v", nap)
	}
	met := findItem(t, listItems(t, full), "name", "met")
	if _, present := met["display_name"]; !present || met["display_name"] != nil || met["owner_user"] != nil || met["project_name"] != "Metrics" {
		t.Fatalf("met row %#v", met)
	}

	if code, env := fx.w.do(fx.tok["viewer"], http.MethodGet, "/v1/services/"+fx.webID.String(), ""); code != http.StatusOK {
		t.Fatalf("owner viewer read shared service %d %s", code, env.Code)
	}
	if code, env := fx.w.do(fx.tok["deploy_viewer"], http.MethodGet, "/v1/services/"+fx.webID.String(), ""); code != http.StatusOK {
		t.Fatalf("deploy viewer read own service %d %s", code, env.Code)
	}
	if code, env := fx.w.do(fx.tok["deploy"], http.MethodGet, "/v1/services/"+fx.apiID.String(), ""); code != http.StatusForbidden {
		t.Fatalf("deploy read owner service %d %s", code, env.Code)
	}
	if code, env := fx.w.do(fx.tok["metrics"], http.MethodGet, "/v1/services/"+fx.metID.String(), ""); code != http.StatusForbidden {
		t.Fatalf("metrics read own service on metrics share %d %s", code, env.Code)
	}

	q := url.Values{}
	q.Set("q", "8080")
	if got := itemNames(t, fx.list(t, fx.tok["home"], home, q)); !sameStrings(got, []string{"api"}) {
		t.Fatalf("port search %v", got)
	}
	q.Set("q", "%")
	if got := itemNames(t, fx.list(t, fx.tok["home"], home, q)); !sameStrings(got, []string{"nap"}) {
		t.Fatalf("percent %v", got)
	}
	q.Set("q", "_")
	if got := itemNames(t, fx.list(t, fx.tok["home"], home, q)); !sameStrings(got, []string{"web"}) {
		t.Fatalf("underscore %v", got)
	}
	q.Set("q", "  alpha  ")
	if got := itemNames(t, fx.list(t, fx.tok["home"], home, q)); !sameStrings(got, []string{"api"}) {
		t.Fatalf("trim %v", got)
	}
	q.Set("q", "pi")
	q.Set("limit", "1")
	piPage := fx.list(t, fx.tok["home"], home, q)
	if total := int(objectPayload(t, piPage)["total"].(float64)); total != 4 || len(listItems(t, piPage)) != 1 || total <= 1 {
		t.Fatalf("q total %v items %d", objectPayload(t, piPage)["total"], len(listItems(t, piPage)))
	}
	hostLimited := url.Values{}
	hostLimited.Set("host_id", fx.homeHost.ID.String())
	hostLimited.Set("limit", "1")
	hostPage := fx.list(t, fx.tok["home"], home, hostLimited)
	if total := int(objectPayload(t, hostPage)["total"].(float64)); total != 3 || len(listItems(t, hostPage)) != 1 || total <= 1 {
		t.Fatalf("host total %v items %d", objectPayload(t, hostPage)["total"], len(listItems(t, hostPage)))
	}

	hostQ := url.Values{}
	hostQ.Set("host_id", fx.homeHost.ID.String())
	if got := itemNames(t, fx.list(t, fx.tok["home"], home, hostQ)); !sameStrings(got, []string{"web", "api", "met"}) {
		t.Fatalf("host filter %v", got)
	}
	hostQ.Set("host_id", fx.homeHost.ID.String())
	if got := itemNames(t, fx.list(t, fx.tok["deploy"], fx.deploy.ID.String(), hostQ)); !sameStrings(got, []string{"web"}) {
		t.Fatalf("deploy host filter %v", got)
	}
	badHost := []string{fx.homeHost.ID.String(), fx.deployHost.ID.String(), uuid.New().String(), "not-a-uuid"}
	for _, id := range badHost[:1] {
		q := url.Values{}
		q.Set("host_id", id)
		code, env := fx.w.do(fx.tok["metrics"], http.MethodGet, servicesPath(fx.metrics.ID.String(), q), "")
		if code != http.StatusBadRequest || env.Msg != "invalid host_id" {
			t.Fatalf("metrics host %s %d %s", id, code, env.Msg)
		}
	}
	for _, id := range []string{fx.deployHost.ID.String(), uuid.New().String(), "not-a-uuid"} {
		q := url.Values{}
		q.Set("host_id", id)
		code, env := fx.w.do(fx.tok["home"], http.MethodGet, servicesPath(home, q), "")
		if code != http.StatusBadRequest || env.Code != "bad_request" || env.Msg != "invalid host_id" {
			t.Fatalf("bad host %s %d %s %s", id, code, env.Code, env.Msg)
		}
	}

	for _, raw := range []string{"0", "201", "-1", "abc"} {
		q := url.Values{}
		q.Set("limit", raw)
		code, env := fx.w.do(fx.tok["home"], http.MethodGet, servicesPath(home, q), "")
		if code != http.StatusBadRequest || env.Msg != "invalid limit" {
			t.Fatalf("limit %s %d %s", raw, code, env.Msg)
		}
	}
	for _, raw := range []string{"1", "200"} {
		q := url.Values{}
		q.Set("limit", raw)
		if code, env := fx.w.do(fx.tok["home"], http.MethodGet, servicesPath(home, q), ""); code != http.StatusOK {
			t.Fatalf("limit %s %d %s", raw, code, env.Msg)
		}
	}
	long := strings.Repeat("é", 100)
	q = url.Values{}
	q.Set("q", long)
	if code, env := fx.w.do(fx.tok["home"], http.MethodGet, servicesPath(home, q), ""); code != http.StatusOK {
		t.Fatalf("100 runes %d %s", code, env.Msg)
	}
	q.Set("q", long+"é")
	if code, env := fx.w.do(fx.tok["home"], http.MethodGet, servicesPath(home, q), ""); code != http.StatusBadRequest || env.Msg != "invalid q" {
		t.Fatalf("101 runes %d %s", code, env.Msg)
	}
	q = url.Values{}
	q.Set("sort", "nope")
	if code, env := fx.w.do(fx.tok["home"], http.MethodGet, servicesPath(home, q), ""); code != http.StatusBadRequest || env.Msg != "invalid sort" {
		t.Fatalf("sort %d %s", code, env.Msg)
	}
	q.Set("sort", "name")
	q.Set("dir", "sideways")
	if code, env := fx.w.do(fx.tok["home"], http.MethodGet, servicesPath(home, q), ""); code != http.StatusBadRequest || env.Msg != "invalid dir" {
		t.Fatalf("dir %d %s", code, env.Msg)
	}

	asc := url.Values{}
	asc.Set("sort", "name")
	asc.Set("dir", "asc")
	desc := url.Values{}
	desc.Set("sort", "name")
	desc.Set("dir", "desc")
	if got := itemNames(t, fx.list(t, fx.tok["home"], home, desc)); !sameStrings(got, []string{"met", "api", "web", "nap"}) {
		t.Fatalf("name desc %v", got)
	}
	seen := url.Values{}
	seen.Set("sort", "last_seen")
	if got := itemNames(t, fx.list(t, fx.tok["home"], home, seen)); !sameStrings(got, []string{"met", "web", "api", "nap"}) {
		t.Fatalf("last_seen default %v", got)
	}
	seen.Set("dir", "asc")
	if got := itemNames(t, fx.list(t, fx.tok["home"], home, seen)); !sameStrings(got, []string{"nap", "api", "web", "met"}) {
		t.Fatalf("last_seen asc %v", got)
	}

	var walked []string
	var firstNext string
	cursor := ""
	for page := 0; page < 6; page++ {
		q := url.Values{}
		q.Set("sort", "name")
		q.Set("limit", "1")
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		code, env := fx.w.do(fx.tok["home"], http.MethodGet, servicesPath(home, q), "")
		if code != http.StatusOK {
			t.Fatalf("page %d %d %s", page, code, env.Msg)
		}
		payload := objectPayload(t, env)
		if int(payload["total"].(float64)) != 4 {
			t.Fatalf("page total %#v", payload["total"])
		}
		items := listItems(t, env)
		if page == 0 {
			if payload["prev_cursor"] != nil {
				t.Fatal("prev_cursor on the first page")
			}
			firstNext, _ = payload["next_cursor"].(string)
		}
		if len(items) == 0 {
			t.Fatal("empty page")
		}
		walked = append(walked, items[0]["name"].(string))
		next, _ := payload["next_cursor"].(string)
		if page == 3 {
			if payload["next_cursor"] != nil {
				t.Fatal("next_cursor after the last row")
			}
			prev, _ := payload["prev_cursor"].(string)
			back := url.Values{}
			back.Set("sort", "name")
			back.Set("limit", "1")
			back.Set("cursor", prev)
			got := fx.list(t, fx.tok["home"], home, back)
			if itemNames(t, got)[0] != walked[2] || objectPayload(t, got)["prev_cursor"] == nil {
				t.Fatalf("prev %v", itemNames(t, got))
			}
			break
		}
		cursor = next
	}
	if !sameStrings(walked, []string{"nap", "web", "api", "met"}) {
		t.Fatalf("walked %v", walked)
	}

	for _, tc := range []struct {
		name string
		set  func(q url.Values)
	}{
		{"q", func(q url.Values) { q.Set("q", "other") }},
		{"host_id", func(q url.Values) { q.Set("host_id", fx.asleepHost.ID.String()) }},
		{"sort", func(q url.Values) { q.Set("sort", "host") }},
		{"dir", func(q url.Values) { q.Set("dir", "desc") }},
	} {
		q := url.Values{}
		q.Set("cursor", firstNext)
		tc.set(q)
		code, env := fx.w.do(fx.tok["home"], http.MethodGet, servicesPath(home, q), "")
		if code != http.StatusBadRequest || env.Msg != "cursor does not match query" {
			t.Fatalf("%s mismatch %d %s", tc.name, code, env.Msg)
		}
	}
	garbage := url.Values{}
	garbage.Set("cursor", "not-a-cursor")
	code, env := fx.w.do(fx.tok["home"], http.MethodGet, servicesPath(home, garbage), "")
	if code != http.StatusBadRequest || env.Msg != "invalid cursor" {
		t.Fatalf("garbage cursor %d %s", code, env.Msg)
	}
	wider := url.Values{}
	wider.Set("sort", "name")
	wider.Set("limit", "2")
	wider.Set("cursor", firstNext)
	if code, env := fx.w.do(fx.tok["home"], http.MethodGet, servicesPath(home, wider), ""); code != http.StatusOK {
		t.Fatalf("limit is not part of the cursor %d %s", code, env.Msg)
	}
	padded := url.Values{}
	padded.Set("q", "  a  ")
	padded.Set("limit", "1")
	trimmed := fx.list(t, fx.tok["home"], home, padded)
	next, _ := objectPayload(t, trimmed)["next_cursor"].(string)
	if next == "" {
		t.Fatal("trimmed search has no next cursor")
	}
	reuse := url.Values{}
	reuse.Set("q", "a")
	reuse.Set("cursor", next)
	if code, env := fx.w.do(fx.tok["home"], http.MethodGet, servicesPath(home, reuse), ""); code != http.StatusOK {
		t.Fatalf("trimmed cursor %d %s", code, env.Msg)
	}
	upper := url.Values{}
	upper.Set("host_id", strings.ToUpper(fx.homeHost.ID.String()))
	upperPage := fx.list(t, fx.tok["home"], home, upper)
	upperNext, _ := objectPayload(t, upperPage)["next_cursor"].(string)
	lower := url.Values{}
	lower.Set("host_id", fx.homeHost.ID.String())
	lower.Set("cursor", upperNext)
	if code, env := fx.w.do(fx.tok["home"], http.MethodGet, servicesPath(home, lower), ""); code != http.StatusOK {
		t.Fatalf("host id case %d %s", code, env.Msg)
	}

	for _, raw := range []string{"%%%", "abc", serviceCursor(`{"o":-1,"h":"abc"}`), serviceCursor(`{"o":0,"h":"abc","x":1}`), serviceCursor(`{"o":0,"h":""}`)} {
		q := url.Values{}
		q.Set("cursor", raw)
		code, env := fx.w.do(fx.tok["home"], http.MethodGet, servicesPath(home, q), "")
		if code != http.StatusBadRequest || env.Msg != "invalid cursor" {
			t.Fatalf("cursor %q %d %s", raw, code, env.Msg)
		}
	}
	wrong := url.Values{}
	wrong.Set("cursor", serviceCursor(`{"o":0,"h":"ffff"}`))
	code, env = fx.w.do(fx.tok["home"], http.MethodGet, servicesPath(home, wrong), "")
	if code != http.StatusBadRequest || env.Msg != "cursor does not match query" {
		t.Fatalf("wrong hash %d %s", code, env.Msg)
	}

	if err := fx.w.mem.RevokeHost(context.Background(), fx.homeHost.ID, fx.w.now); err != nil {
		t.Fatal(err)
	}
	revoked := findItem(t, listItems(t, fx.list(t, fx.tok["home"], home, url.Values{})), "name", "api")
	if revoked["host_status"] != "revoked" {
		t.Fatalf("revoked status %#v", revoked["host_status"])
	}
}

func TestProjectServiceCursorWalk(t *testing.T) {
	fx := newProjectServiceFixture(t)
	putProjectService(t, fx.w, fx.homeHost.ID, fx.home.ID, "extra", "process", []int{1}, nil, strPtr("z-end"), fx.w.now)
	home := fx.home.ID.String()
	full := fx.list(t, fx.tok["home"], home, url.Values{"sort": {"name"}})
	want := itemIDs(t, full)
	if len(want) < 5 || !sameStrings(itemNames(t, full), []string{"nap", "web", "api", "met", "extra"}) {
		t.Fatalf("rows %v", itemNames(t, full))
	}
	var forward [][]string
	var total float64
	cursor := ""
	var back string
	for page := 0; page < len(want); page++ {
		q := url.Values{}
		q.Set("sort", "name")
		q.Set("limit", "2")
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		code, env := fx.w.do(fx.tok["home"], http.MethodGet, servicesPath(home, q), "")
		if code != http.StatusOK {
			t.Fatalf("page %d %d %s", page, code, env.Msg)
		}
		payload := objectPayload(t, env)
		gotTotal := payload["total"].(float64)
		if page == 0 {
			total = gotTotal
			if payload["prev_cursor"] != nil {
				t.Fatal("prev_cursor on the first page")
			}
		} else if gotTotal != total {
			t.Fatalf("total changed %v %v", total, gotTotal)
		}
		ids := itemIDs(t, env)
		if len(ids) == 0 {
			t.Fatal("empty page")
		}
		forward = append(forward, ids)
		if payload["next_cursor"] == nil {
			prev, _ := payload["prev_cursor"].(string)
			if prev == "" {
				t.Fatal("last page has no prev_cursor")
			}
			back = prev
			break
		}
		cursor = payload["next_cursor"].(string)
	}
	var flat []string
	for _, ids := range forward {
		flat = append(flat, ids...)
	}
	if back == "" || !sameStrings(flat, want) || int(total) != len(want) {
		t.Fatalf("walked %v total %v", flat, total)
	}
	for i := len(forward) - 2; i >= 0; i-- {
		q := url.Values{}
		q.Set("sort", "name")
		q.Set("limit", "2")
		q.Set("cursor", back)
		code, env := fx.w.do(fx.tok["home"], http.MethodGet, servicesPath(home, q), "")
		if code != http.StatusOK {
			t.Fatalf("prev %d %d %s", i, code, env.Msg)
		}
		payload := objectPayload(t, env)
		if payload["total"].(float64) != total || !sameStrings(itemIDs(t, env), forward[i]) {
			t.Fatalf("prev page %d %v", i, itemIDs(t, env))
		}
		if i == 0 {
			if payload["prev_cursor"] != nil {
				t.Fatal("prev_cursor on the first page")
			}
			break
		}
		prev, _ := payload["prev_cursor"].(string)
		if prev == "" {
			t.Fatalf("page %d lost prev_cursor", i)
		}
		back = prev
	}
}

func TestProjectServiceSortKeys(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("sort@ex.com", "Sort")
	project, err := w.mem.CreateProject(ctx, owner.ID, "Sort", "sort", w.now)
	if err != nil {
		t.Fatal(err)
	}
	a := enrollAPIHost(t, w, project.ID, owner.ID, "a-host", true)
	b := enrollAPIHost(t, w, project.ID, owner.ID, "b-host", true)
	c := enrollAPIHost(t, w, project.ID, owner.ID, "c-host", true)
	putProjectService(t, w, a.ID, project.ID, "up-svc", "process", []int{1}, nil, strPtr("a"), w.now)
	putProjectService(t, w, b.ID, project.ID, "down-svc", "container", []int{1}, nil, strPtr("z"), w.now)
	putProjectService(t, w, c.ID, project.ID, "unk-svc", "systemd", []int{1}, nil, strPtr("m"), w.now)
	putAPIHealth(t, w, a.ID, "up-svc", "success", w.now)
	putAPIHealth(t, w, b.ID, "down-svc", "fail", w.now)
	tok := w.token(owner.ID)
	home := project.ID.String()
	for _, tc := range []struct {
		sort, dir string
		want      []string
	}{
		{"host", "asc", []string{"up-svc", "down-svc", "unk-svc"}},
		{"host", "desc", []string{"unk-svc", "down-svc", "up-svc"}},
		{"kind", "asc", []string{"down-svc", "up-svc", "unk-svc"}},
		{"kind", "desc", []string{"unk-svc", "up-svc", "down-svc"}},
		{"status", "asc", []string{"up-svc", "down-svc", "unk-svc"}},
		{"status", "desc", []string{"unk-svc", "down-svc", "up-svc"}},
	} {
		q := url.Values{}
		q.Set("sort", tc.sort)
		q.Set("dir", tc.dir)
		code, env := w.do(tok, http.MethodGet, servicesPath(home, q), "")
		if code != http.StatusOK || !sameStrings(itemNames(t, env), tc.want) {
			t.Fatalf("%s %s %d %v", tc.sort, tc.dir, code, itemNames(t, env))
		}
	}
}

func putAPIHealth(t *testing.T, w *world, hostID uuid.UUID, service, result string, at time.Time) {
	t.Helper()
	_, err := w.mem.InsertBatch(context.Background(), hostID, uuid.New(), []store.Sample{{
		M:    "health",
		T:    at,
		Tags: map[string]string{"service": service},
		Strs: map[string]string{"result": result},
	}}, at)
	if err != nil {
		t.Fatal(err)
	}
}

type projectServiceFixture struct {
	w                                *world
	home, deploy, metrics            store.Project
	homeHost, deployHost, asleepHost store.Host
	apiID, webID, metID              uuid.UUID
	tok                              map[string]string
}

func newProjectServiceFixture(t *testing.T) *projectServiceFixture {
	t.Helper()
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("owner@ex.com", "Owner")
	viewer := w.user("viewer@ex.com", "Viewer")
	deployOwner := w.user("deploy-owner@ex.com", "DeployOwner")
	deployAdmin := w.user("deploy-admin@ex.com", "DeployAdmin")
	deployViewer := w.user("deploy-viewer@ex.com", "DeployViewer")
	metricsOwner := w.user("metrics@ex.com", "Metrics")
	outsider := w.user("outsider@ex.com", "Outsider")
	home, err := w.mem.CreateProject(ctx, owner.ID, "Home", "home", w.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, home.ID, viewer.ID, "viewer", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	deploy, err := w.mem.CreateProject(ctx, deployOwner.ID, "Deploy", "deploy", w.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, deploy.ID, deployAdmin.ID, "admin", deployOwner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, deploy.ID, deployViewer.ID, "viewer", deployOwner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	metrics, err := w.mem.CreateProject(ctx, metricsOwner.ID, "Metrics", "metrics", w.now)
	if err != nil {
		t.Fatal(err)
	}
	homeHost := enrollAPIHost(t, w, home.ID, owner.ID, "pi-home", true)
	asleepHost := enrollAPIHost(t, w, home.ID, owner.ID, "pi-asleep", false)
	deployHost := enrollAPIHost(t, w, deploy.ID, deployOwner.ID, "pi-deploy", true)
	metricsHost := enrollAPIHost(t, w, metrics.ID, metricsOwner.ID, "pi-metrics", true)
	if _, _, err := w.mem.PutHostShare(ctx, homeHost.ID, deploy.ID, "deploy", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.mem.PutHostShare(ctx, homeHost.ID, metrics.ID, "metrics", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	api := putProjectService(t, w, homeHost.ID, home.ID, "api", "process", []int{8080}, strPtr("root"), strPtr("Alpha"), w.now)
	web := putProjectService(t, w, homeHost.ID, deploy.ID, "web", "container", []int{9090}, nil, strPtr("a_b"), w.now.Add(time.Second))
	met := putProjectService(t, w, homeHost.ID, metrics.ID, "met", "systemd", []int{443}, nil, nil, w.now.Add(2*time.Second))
	putProjectService(t, w, asleepHost.ID, home.ID, "nap", "process", []int{1}, nil, strPtr("100%"), w.now.Add(-time.Second))
	putProjectService(t, w, deployHost.ID, deploy.ID, "local", "process", []int{80}, nil, strPtr("Local"), w.now)
	putProjectService(t, w, metricsHost.ID, metrics.ID, "mine", "process", []int{5555}, nil, strPtr("Mine"), w.now)
	return &projectServiceFixture{
		w: w, home: home, deploy: deploy, metrics: metrics,
		homeHost: homeHost, deployHost: deployHost, asleepHost: asleepHost,
		apiID: api, webID: web, metID: met,
		tok: map[string]string{
			"home":          w.token(owner.ID),
			"viewer":        w.token(viewer.ID),
			"deploy":        w.token(deployAdmin.ID),
			"deploy_viewer": w.token(deployViewer.ID),
			"metrics":       w.token(metricsOwner.ID),
			"outsider":      w.token(outsider.ID),
		},
	}
}

func (fx *projectServiceFixture) list(t *testing.T, token, project string, q url.Values) envelope {
	t.Helper()
	code, env := fx.w.do(token, http.MethodGet, servicesPath(project, q), "")
	if code != http.StatusOK || env.Code != "ok" {
		t.Fatalf("list %d %s %s", code, env.Code, env.Msg)
	}
	return env
}

func putProjectService(t *testing.T, w *world, hostID, projectID uuid.UUID, name, kind string, ports []int, owner, display *string, at time.Time) uuid.UUID {
	t.Helper()
	if err := w.mem.UpsertDiscovered(context.Background(), hostID, []store.Discovered{{
		Name: name, Kind: kind, Ports: ports, OwnerUser: owner,
	}}, at); err != nil {
		t.Fatal(err)
	}
	items, err := w.mem.ListServices(context.Background(), hostID, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	for _, item := range items {
		if item.Name == name {
			id = item.ID
		}
	}
	if id == uuid.Nil {
		t.Fatalf("missing %s", name)
	}
	w.mem.SetServiceProject(id, projectID)
	if display != nil {
		if _, err := w.mem.SetServiceDisplayName(context.Background(), id, display, at); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func servicesPath(project string, q url.Values) string {
	path := "/v1/projects/" + project + "/services"
	if len(q) != 0 {
		path += "?" + q.Encode()
	}
	return path
}

func serviceCursor(body string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(body))
}

func itemNames(t *testing.T, env envelope) []string {
	t.Helper()
	items := listItems(t, env)
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = item["name"].(string)
	}
	return out
}

func itemIDs(t *testing.T, env envelope) []string {
	t.Helper()
	items := listItems(t, env)
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = item["id"].(string)
	}
	return out
}

func sameStrings(got, want []string) bool {
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
