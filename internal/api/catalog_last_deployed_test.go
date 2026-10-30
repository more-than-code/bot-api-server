package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// api-v1 v1.21: last_deployed_at on catalog entries.

func TestCatalogLastDeployedImage(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	other, _, _ := enrollAgentHost(t, w, sc.project, owner.ID, "pi5")
	web := createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx"}`)
	createImage(t, w, tok, sc.project.ID, "idle", `{"kind":"service","image":"nginx"}`)
	auto := createImage(t, w, tok, sc.project.ID, "auto", `{"kind":"service","image":"nginx"}`)
	if web["last_deployed_at"] != nil {
		t.Fatalf("create response %#v", web["last_deployed_at"])
	}
	webID := uuid.MustParse(web["id"].(string))
	autoID := uuid.MustParse(auto["id"].(string))
	hash := web["spec_hash"].(string)

	t0 := w.now.Add(-3 * time.Hour)
	deploy := func(entryID, hostID uuid.UUID, via string, at time.Time, outcome string) {
		t.Helper()
		row, err := w.mem.BeginImageOp(ctx, entryID, hostID, hash, owner.ID, via, at, at.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.mem.FinishImageDeploy(ctx, row.ID, outcome, nil, nil, at.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	deploy(webID, sc.host.ID, "console", t0, "succeeded")
	// Newest by a person or AI: an mcp deploy on another host that failed.
	deploy(webID, other.ID, "mcp", t0.Add(time.Hour), "failed")
	// Automatic rows never count, even when newer.
	for i, id := range []uuid.UUID{webID, autoID} {
		if _, _, err := w.mem.RecordAutoAction(ctx, store.AutoAction{
			ID: uuid.New(), EntryID: id, HostID: sc.host.ID, Outcome: "auto_restarted", At: t0.Add(time.Duration(2+i) * time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}

	got := lastDeployedByName(t, w, tok, sc.project.ID)
	want := t0.Add(time.Hour).Format(time.RFC3339)
	if got["web"] != want {
		t.Fatalf("web %#v want %s", got["web"], want)
	}
	if got["idle"] != nil || got["auto"] != nil {
		t.Fatalf("idle %#v auto %#v", got["idle"], got["auto"])
	}
	// The store matches entries within the given project only.
	entries, err := w.mem.ListCatalogEntries(ctx, sc.project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := w.mem.CatalogLastDeployed(ctx, uuid.New(), entries); err != nil || len(got) != 0 {
		t.Fatalf("other project %v %v", got, err)
	}
	one := createImageGet(t, w, tok, sc.project.ID, "web")
	if one["last_deployed_at"] != want {
		t.Fatalf("get web %#v", one["last_deployed_at"])
	}
	if v, ok := createImageGet(t, w, tok, sc.project.ID, "idle")["last_deployed_at"]; !ok || v != nil {
		t.Fatalf("get idle %#v present %v", v, ok)
	}
}

func TestCatalogLastDeployedProgram(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	createProgram(t, w, tok, sc.project.ID, "tra", "pnpm run dev", false)
	createProgram(t, w, tok, sc.project.ID, "quiet", "pnpm run dev", false)
	createProgram(t, w, tok, sc.project.ID, "mcp-run", "pnpm run dev", false)

	other, err := w.mem.CreateProject(ctx, owner.ID, "Other", "other", w.now)
	if err != nil {
		t.Fatal(err)
	}
	// Entries are created at w.now; runs count from then.
	t0 := w.now
	audit := func(project uuid.UUID, action, decision, via, entry string, at time.Time) {
		t.Helper()
		if err := w.mem.InsertAudit(ctx, store.AuditRow{
			At: at, ActorUserID: &owner.ID, Via: via, ProjectID: &project, HostID: &sc.host.ID,
			Action: action, Decision: decision, Detail: map[string]any{"entry": entry, "spec_hash": "x"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	p := sc.project.ID
	audit(p, "program.run", "allowed", "console", "tra", t0)
	// A run that reached the agent and failed is still allowed and counts.
	audit(p, "program.run", "allowed", "console", "tra", t0.Add(time.Hour))
	// None of these count for tra.
	audit(p, "program.run", "denied", "console", "tra", t0.Add(2*time.Hour))
	audit(p, "program.stop", "allowed", "console", "tra", t0.Add(2*time.Hour))
	audit(p, "program.restart", "allowed", "mcp", "tra", t0.Add(2*time.Hour))
	audit(p, "program.run", "allowed", "agent", "tra", t0.Add(2*time.Hour))
	audit(p, "program.run", "allowed", "system", "tra", t0.Add(2*time.Hour))
	audit(p, "program.confirmation", "allowed", "mcp", "tra", t0.Add(2*time.Hour))
	audit(other.ID, "program.run", "allowed", "console", "tra", t0.Add(2*time.Hour))
	audit(other.ID, "program.run", "allowed", "console", "quiet", t0.Add(2*time.Hour))
	audit(p, "program.run", "allowed", "mcp", "mcp-run", t0.Add(3*time.Hour))
	// Before quiet was created.
	audit(p, "program.run", "allowed", "console", "quiet", t0.Add(-time.Minute))

	got := lastDeployedByName(t, w, tok, p)
	if want := t0.Add(time.Hour).Format(time.RFC3339); got["tra"] != want {
		t.Fatalf("tra %#v want %s", got["tra"], want)
	}
	if want := t0.Add(3 * time.Hour).Format(time.RFC3339); got["mcp-run"] != want {
		t.Fatalf("mcp-run %#v want %s", got["mcp-run"], want)
	}
	if got["quiet"] != nil {
		t.Fatalf("quiet %#v", got["quiet"])
	}
	status, env, _ := mustCall(t, w, tok, http.MethodGet, "/v1/projects/"+p.String()+"/catalog/tra", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if v := objectPayload(t, env)["last_deployed_at"]; v != t0.Add(time.Hour).Format(time.RFC3339) {
		t.Fatalf("get tra %#v", v)
	}
}

func TestCatalogLastDeployedRecreatedName(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	p := sc.project.ID
	createProgram(t, w, tok, p, "tra", "pnpm run dev", false)
	run := func(at time.Time) {
		t.Helper()
		if err := w.mem.InsertAudit(ctx, store.AuditRow{
			At: at, ActorUserID: &owner.ID, Via: "console", ProjectID: &p, HostID: &sc.host.ID,
			Action: "program.run", Decision: "allowed", Detail: map[string]any{"entry": "tra"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	run(w.now.Add(time.Minute))
	if got := lastDeployedByName(t, w, tok, p)["tra"]; got != w.now.Add(time.Minute).Format(time.RFC3339) {
		t.Fatalf("before delete %#v", got)
	}
	status, env, _ := mustCall(t, w, tok, http.MethodDelete, "/v1/projects/"+p.String()+"/catalog/tra", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	later := w.now.Add(time.Hour)
	w.srv.Now = func() time.Time { return later }
	createProgram(t, w, tok, p, "tra", "pnpm run dev", false)
	if got := lastDeployedByName(t, w, tok, p)["tra"]; got != nil {
		t.Fatalf("re-created entry inherited %#v", got)
	}
	run(later)
	if got := lastDeployedByName(t, w, tok, p)["tra"]; got != later.Format(time.RFC3339) {
		t.Fatalf("after re-create %#v", got)
	}
}

func TestCatalogLastDeployedReplaceResponse(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	p := sc.project.ID
	path := "/v1/projects/" + p.String() + "/catalog"
	web := createImage(t, w, tok, p, "web", `{"kind":"service","image":"nginx"}`)
	prog := createProgram(t, w, tok, p, "tra", "pnpm run dev", false)
	if web["last_deployed_at"] != nil || prog["last_deployed_at"] != nil {
		t.Fatalf("create responses %#v %#v", web["last_deployed_at"], prog["last_deployed_at"])
	}
	webID := uuid.MustParse(web["id"].(string))
	at := w.now.Add(time.Minute)
	row, err := w.mem.BeginImageOp(ctx, webID, sc.host.ID, web["spec_hash"].(string), owner.ID, "console", at, at.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.FinishImageDeploy(ctx, row.ID, "succeeded", nil, nil, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := w.mem.InsertAudit(ctx, store.AuditRow{
		At: at, ActorUserID: &owner.ID, Via: "mcp", ProjectID: &p, HostID: &sc.host.ID,
		Action: "program.run", Decision: "allowed", Detail: map[string]any{"entry": "tra"},
	}); err != nil {
		t.Fatal(err)
	}
	want := at.Format(time.RFC3339)
	status, env, _ := mustCall(t, w, tok, http.MethodPut, path+"/web", `{"kind":"image","spec":{"kind":"service","image":"nginx:1.27"}}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if got := objectPayload(t, env)["last_deployed_at"]; got != want {
		t.Fatalf("image replace %#v", got)
	}
	status, env, _ = mustCall(t, w, tok, http.MethodPut, path+"/tra", `{"kind":"program","command":"pnpm run start","dir":"/home/joe/app","run_as":"joe"}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if got := objectPayload(t, env)["last_deployed_at"]; got != want {
		t.Fatalf("program replace %#v", got)
	}
}

// lastDeployedCounter counts CatalogLastDeployed calls, records the entry
// ids of the last call, and fails every call when fail is set.
type lastDeployedCounter struct {
	store.Store
	n    int
	ids  []uuid.UUID
	fail bool
}

func (c *lastDeployedCounter) CatalogLastDeployed(ctx context.Context, projectID uuid.UUID, entries []store.CatalogEntry) (map[uuid.UUID]time.Time, error) {
	c.n++
	c.ids = c.ids[:0]
	for _, e := range entries {
		c.ids = append(c.ids, e.ID)
	}
	if c.fail {
		return nil, errors.New("last deployed read failed")
	}
	return c.Store.CatalogLastDeployed(ctx, projectID, entries)
}

func TestCatalogLastDeployedReadFailure(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	p := sc.project.ID
	path := "/v1/projects/" + p.String() + "/catalog"
	createImage(t, w, tok, p, "web", `{"kind":"service","image":"nginx"}`)
	createProgram(t, w, tok, p, "tra", "pnpm run dev", false)
	counter := &lastDeployedCounter{Store: w.srv.Store, fail: true}
	w.srv.Store = counter

	for _, c := range []struct{ name, body string }{
		{"web", `{"kind":"image","spec":{"kind":"service","image":"nginx:1.27"}}`},
		{"tra", `{"kind":"program","command":"pnpm run start","dir":"/home/joe/app","run_as":"joe"}`},
	} {
		before := auditCount(auditRows(t, w, p), "catalog.update", "allowed")
		status, env, _ := mustCall(t, w, tok, http.MethodPut, path+"/"+c.name, c.body)
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
		payload := objectPayload(t, env)
		if v, ok := payload["last_deployed_at"]; !ok || v != nil {
			t.Fatalf("%s replace with failed read %#v present %v", c.name, v, ok)
		}
		if payload["my_actions"] == nil {
			t.Fatalf("%s replace lost my_actions", c.name)
		}
		if after := auditCount(auditRows(t, w, p), "catalog.update", "allowed"); after != before+1 {
			t.Fatalf("%s catalog.update rows %d -> %d", c.name, before, after)
		}
	}
	for _, get := range []string{path, path + "/web"} {
		status, _, _ := mustCall(t, w, tok, http.MethodGet, get, "")
		if status == http.StatusOK {
			t.Fatalf("GET %s succeeded with a failed read", get)
		}
	}
}

func TestCatalogLastDeployedVisibleOnly(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	viewer := w.user("v@ex.com", "V")
	sc := w.scene(owner, w.user("a@ex.com", "A"), viewer, w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	p := sc.project.ID
	path := "/v1/projects/" + p.String() + "/catalog"
	shown := createProgram(t, w, tok, p, "shown", "pnpm run dev", false)
	hidden := createProgram(t, w, tok, p, "hidden", "pnpm run dev", false)
	status, env, _ := mustCall(t, w, tok, http.MethodPut, path+"/hidden/permissions", `{"grants":[{"subject":"role:admin","actions":["run"]}]}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	counter := &lastDeployedCounter{Store: w.srv.Store}
	w.srv.Store = counter

	got := lastDeployedByName(t, w, w.token(viewer.ID), p)
	if _, ok := got["hidden"]; ok || len(got) != 1 {
		t.Fatalf("viewer list %#v", got)
	}
	shownID := uuid.MustParse(shown["id"].(string))
	hiddenID := uuid.MustParse(hidden["id"].(string))
	if counter.n != 1 || len(counter.ids) != 1 || counter.ids[0] != shownID {
		t.Fatalf("calls %d ids %v (hidden %s)", counter.n, counter.ids, hiddenID)
	}
	counter.n = 0
	status, env, _ = mustCall(t, w, w.token(viewer.ID), http.MethodGet, path+"/hidden", "")
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	if counter.n != 0 {
		t.Fatalf("forbidden GET read last_deployed_at %d times", counter.n)
	}
}

func TestCatalogLastDeployedOneBatch(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	counter := &lastDeployedCounter{Store: w.srv.Store}
	w.srv.Store = counter
	path := "/v1/projects/" + sc.project.ID.String() + "/catalog"

	status, env, _ := mustCall(t, w, tok, http.MethodGet, path, "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if counter.n != 0 {
		t.Fatalf("empty list made %d calls", counter.n)
	}
	for _, n := range []int{1, 7} {
		for i := len(lastDeployedByName(t, w, tok, sc.project.ID)); i < n; i++ {
			if i%2 == 0 {
				createProgram(t, w, tok, sc.project.ID, "prog"+string(rune('a'+i)), "pnpm run dev", false)
			} else {
				createImage(t, w, tok, sc.project.ID, "img"+string(rune('a'+i)), `{"kind":"service","image":"nginx"}`)
			}
		}
		counter.n = 0
		if got := len(lastDeployedByName(t, w, tok, sc.project.ID)); got != n {
			t.Fatalf("entries %d want %d", got, n)
		}
		if counter.n != 1 {
			t.Fatalf("%d entries made %d calls", n, counter.n)
		}
	}
}

func TestCatalogWriteRefusesLastDeployed(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	path := "/v1/projects/" + sc.project.ID.String() + "/catalog"
	const ts = `,"last_deployed_at":"2026-10-30T00:00:00Z"}`
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, path, `{"name":"tra","kind":"program","command":"pnpm run dev","dir":"/home/joe/app","run_as":"joe"` + ts},
		{http.MethodPost, path, `{"name":"web","kind":"image","spec":{"kind":"service","image":"nginx"}` + ts},
		{http.MethodPost, path, `{"name":"web","kind":"image","spec":{"kind":"service","image":"nginx","last_deployed_at":null}}`},
	} {
		status, env, _ := mustCall(t, w, tok, c.method, c.path, c.body)
		if status != http.StatusBadRequest || env.Code != "bad_request" {
			t.Fatalf("%s %s: %d %s %s", c.method, c.body, status, env.Code, env.Msg)
		}
	}
	createProgram(t, w, tok, sc.project.ID, "tra", "pnpm run dev", false)
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx"}`)
	for _, c := range []struct{ name, body string }{
		{"tra", `{"kind":"program","command":"pnpm run start","dir":"/home/joe/app","run_as":"joe"` + ts},
		{"web", `{"kind":"image","spec":{"kind":"service","image":"nginx"}` + ts},
	} {
		status, env, _ := mustCall(t, w, tok, http.MethodPut, path+"/"+c.name, c.body)
		if status != http.StatusBadRequest || env.Code != "bad_request" {
			t.Fatalf("PUT %s: %d %s %s", c.name, status, env.Code, env.Msg)
		}
	}
}

func lastDeployedByName(t *testing.T, w *world, tok string, project uuid.UUID) map[string]any {
	t.Helper()
	status, env, _ := mustCall(t, w, tok, http.MethodGet, "/v1/projects/"+project.String()+"/catalog", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	items, _ := objectPayload(t, env)["items"].([]any)
	out := map[string]any{}
	for _, raw := range items {
		item := raw.(map[string]any)
		v, ok := item["last_deployed_at"]
		if !ok {
			t.Fatalf("last_deployed_at missing on %v", item["name"])
		}
		out[item["name"].(string)] = v
	}
	return out
}
