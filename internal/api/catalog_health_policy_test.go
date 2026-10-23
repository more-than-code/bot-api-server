package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const policyHealthcheck = `"healthcheck":{"test":["redis-cli","ping"]}`

func TestHealthPolicyHTTP(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()

	status, env, _ := mustCall(t, w, tok, http.MethodPost, "/v1/projects/"+project+"/catalog", `{"name":"bad","kind":"image","spec":{"kind":"service","image":"nginx","health_policy":{"on_unhealthy":"restart"}}}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "health_policy.on_unhealthy needs a healthcheck")
	status, env, _ = mustCall(t, w, tok, http.MethodPost, "/v1/projects/"+project+"/catalog", `{"name":"bad","kind":"image","spec":{"kind":"job","image":"nginx","health_policy":{}}}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "health_policy applies to services")
	status, env, _ = mustCall(t, w, tok, http.MethodPost, "/v1/projects/"+project+"/catalog", `{"name":"bad","kind":"image","spec":{"kind":"service","image":"nginx","health_policy":{"max_actions_per_hour":11}}}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid health_policy.max_actions_per_hour")

	sick := createImage(t, w, tok, sc.project.ID, "sick", `{"kind":"service","image":"redis",`+policyHealthcheck+`,"health_policy":{"on_unhealthy":"restart"}}`)
	spec, _ := sick["spec"].(map[string]any)
	got, _ := spec["health_policy"].(map[string]any)
	if len(got) != 1 || got["on_unhealthy"] != "restart" {
		t.Fatalf("stored health_policy %#v", spec["health_policy"])
	}
	stop := createImage(t, w, tok, sc.project.ID, "stop", `{"kind":"service","image":"nginx","health_policy":{"on_deploy_failure":"stop"}}`)
	plain := createImage(t, w, tok, sc.project.ID, "plain", `{"kind":"service","image":"nginx"}`)
	dflt := createImage(t, w, tok, sc.project.ID, "dflt", `{"kind":"service","image":"nginx","health_policy":{"on_deploy_failure":"rollback"}}`)
	if dflt["spec_hash"] != plain["spec_hash"] {
		t.Fatal("a policy at the defaults changed spec_hash")
	}

	// Healthcheck support only: health_policy is not advertised.
	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: true, PolicyHash: "abc", Healthcheck: true})
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, map[string]any{"enabled": true, "run_as": []string{"joe"}, "allow_shell": false, "policy_hash": "abc", "images": true, "docker": true, "healthcheck": true}, nil)
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return imageDeployReply(msg, shaDigest(2))
	})
	host := sc.host.ID.String()
	const refuse = "this host's agent does not support health policies"
	for _, tc := range []struct {
		entry map[string]any
		name  string
	}{{sick, "sick"}, {stop, "stop"}} {
		status, env, _ = postImage(t, w, tok, project, tc.name, "deploy", host, tc.name+"-1", nil)
		mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", refuse)
		if log.count() != 0 || loggingDeploys(t, w, tc.entry, sc.host.ID) != 0 {
			t.Fatalf("%s: unsupported deploy sent a task or wrote a deploy row", tc.name)
		}
		status, env, _ = postImage(t, w, tok, project, tc.name, "rollback", host, tc.name+"-roll", map[string]any{"digest": shaDigest(2)})
		mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", refuse)
		if log.count() != 0 {
			t.Fatalf("%s: unsupported rollback sent a task", tc.name)
		}
	}
	status, env, _ = postImage(t, w, tok, project, "dflt", "deploy", host, "dflt-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 1 || policyOf(t, log.raw(0)) != nil || hasPolicyKey(t, log.raw(0)) {
		t.Fatal("older agent received health_policy for an entry at the defaults")
	}

	// Delegated: the gate runs again at confirm.
	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: true, PolicyHash: "abc", Healthcheck: true, HealthPolicy: true})
	delegated := tokenKind(t, w, owner.ID, store.KindDelegated)
	status, env, _ = postImage(t, w, delegated, project, "sick", "deploy", host, "sick-del", nil)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, _ := objectPayload(t, env)["confirmation_id"].(string)
	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: true, PolicyHash: "abc", Healthcheck: true})
	status, env, _ = mustCall(t, w, delegated, http.MethodPost, "/v1/confirmations/"+id, confirmBody("sick-del"))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", refuse)
	if log.count() != 1 || loggingDeploys(t, w, sick, sc.host.ID) != 0 {
		t.Fatal("confirm dispatched without health_policy support")
	}

	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: true, PolicyHash: "abc", Healthcheck: true, HealthPolicy: true})
	status, env, _ = mustCall(t, w, delegated, http.MethodPost, "/v1/confirmations/"+id, confirmBody("sick-del"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 2 {
		t.Fatal("confirm did not dispatch after health_policy support returned")
	}
	sent := policyOf(t, log.raw(1))
	if len(sent) != 1 || sent["on_unhealthy"] != "restart" {
		t.Fatalf("task health_policy %#v", sent)
	}
	status, env, _ = postImage(t, w, tok, project, "dflt", "deploy", host, "dflt-2", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if kept := policyOf(t, log.raw(2)); kept == nil || kept["on_deploy_failure"] != "rollback" {
		t.Fatalf("capable agent did not receive the stored policy %#v", kept)
	}
	status, env, _ = postImage(t, w, tok, project, "plain", "deploy", host, "plain-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if hasPolicyKey(t, log.raw(3)) {
		t.Fatal("entry without health_policy sent the key")
	}
}

func policyOf(t *testing.T, task map[string]any) map[string]any {
	t.Helper()
	frame, _ := task["spec"].(map[string]any)
	nested, _ := frame["spec"].(map[string]any)
	got, _ := nested["health_policy"].(map[string]any)
	return got
}

func hasPolicyKey(t *testing.T, task map[string]any) bool {
	t.Helper()
	frame, _ := task["spec"].(map[string]any)
	nested, _ := frame["spec"].(map[string]any)
	_, ok := nested["health_policy"]
	return ok
}

func TestHealthPolicyPlan(t *testing.T) {
	plain := mustPlanImage(t, "web", `{"kind":"service","image":"redis",`+policyHealthcheck+`}`, nil, nil)
	if strings.Contains(catalogCreatePlan("Proj", "web", plain), "health_policy") {
		t.Fatal("plan mentioned absent health_policy")
	}
	dflt := mustPlanImage(t, "web", `{"kind":"service","image":"redis",`+policyHealthcheck+`,"health_policy":{"on_deploy_failure":"rollback"}}`, nil, nil)
	if strings.Contains(catalogCreatePlan("Proj", "web", dflt), "health_policy") {
		t.Fatal("plan mentioned a health_policy at the defaults")
	}
	img := mustPlanImage(t, "web", `{"kind":"service","image":"redis",`+policyHealthcheck+`,"health_policy":{"on_unhealthy":"restart","max_actions_per_hour":5}}`, nil, nil)
	const phrase = "on_deploy_failure=rollback on_unhealthy=restart unhealthy_after_sec=45 max_actions_per_hour=5"
	if got := catalogCreatePlan("Proj", "web", img); !strings.Contains(got, "; health_policy "+phrase) {
		t.Fatalf("create plan %s", got)
	}
	const defaults = "on_deploy_failure=rollback on_unhealthy=none unhealthy_after_sec=45 max_actions_per_hour=3"
	if got := catalogUpdatePlan("web", plain, img, 1); !strings.Contains(got, "health_policy: "+defaults+" → "+phrase) {
		t.Fatalf("added plan %s", got)
	}
	if got := catalogUpdatePlan("web", img, plain, 1); !strings.Contains(got, "health_policy: "+phrase+" → "+defaults) {
		t.Fatalf("removed plan %s", got)
	}
	if got := catalogUpdatePlan("web", plain, dflt, 0); strings.Contains(got, "health_policy") {
		t.Fatalf("defaults-only update listed health_policy: %s", got)
	}
	next := mustPlanImage(t, "web", `{"kind":"service","image":"redis",`+policyHealthcheck+`,"health_policy":{"on_unhealthy":"rollback","on_deploy_failure":"stop"}}`, nil, nil)
	want := "health_policy: " + phrase + " → on_deploy_failure=stop on_unhealthy=rollback unhealthy_after_sec=45 max_actions_per_hour=3"
	if got := catalogUpdatePlan("web", img, next, 0); !strings.Contains(got, want) {
		t.Fatalf("changed plan %s", got)
	}
}

func TestAutoActionHistoryHTTP(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	host := sc.host.ID.String()
	ctx := context.Background()
	web := createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"redis",`+policyHealthcheck+`,"health_policy":{"on_unhealthy":"restart"}}`)
	entryID, err := uuid.Parse(web["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Second)
	digest := shaDigest(1)
	// 55 user rows a minute apart: the newest 50 run from base-195m to base-146m.
	for i := 0; i < 55; i++ {
		at := base.Add(time.Duration(i-200) * time.Minute)
		row, err := w.mem.BeginImageOp(ctx, entryID, sc.host.ID, strings.Repeat("a", 64), owner.ID, "console", at, at.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.mem.FinishImageDeploy(ctx, row.ID, "succeeded", &digest, nil, at); err != nil {
			t.Fatal(err)
		}
	}
	// Older than the oldest listed user row: not listed.
	if _, _, err := w.mem.RecordAutoAction(ctx, store.AutoAction{ID: uuid.New(), EntryID: entryID, HostID: sc.host.ID, Outcome: "auto_restarted", At: base.Add(-199 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	outcomes := []string{"auto_restarted", "auto_rolled_back", "auto_gave_up", "auto_failed"}
	for i := 0; i < 25; i++ {
		at := base.Add(time.Duration(i*61) * time.Minute)
		if _, _, err := w.mem.RecordAutoAction(ctx, store.AutoAction{ID: uuid.New(), EntryID: entryID, HostID: sc.host.ID, Outcome: outcomes[i%4], At: at}); err != nil {
			t.Fatal(err)
		}
	}
	status, env, _ := mustCall(t, w, tok, http.MethodGet, "/v1/projects/"+project+"/catalog/web/deploys?host_id="+host, "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	items, _ := objectPayload(t, env)["items"].([]any)
	manual, auto := 0, 0
	seen := map[string]bool{}
	prev := ""
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		finished, _ := item["finished_at"].(string)
		if prev != "" && finished > prev {
			t.Fatalf("history not newest first: %s after %s", finished, prev)
		}
		prev = finished
		if item["via"] == "agent" {
			auto++
			if by, ok := item["by"]; !ok || by != nil {
				t.Fatalf("automatic row by %#v", item["by"])
			}
			seen[item["outcome"].(string)] = true
			if item["outcome"] == "auto_failed" && item["digest"] != nil {
				t.Fatalf("auto_failed digest %#v", item["digest"])
			}
			if at, _ := time.Parse(time.RFC3339Nano, finished); at.Before(base) {
				t.Fatal("automatic row older than the oldest user row was listed")
			}
		} else {
			manual++
			if item["by"] != owner.ID.String() {
				t.Fatalf("user row by %#v", item["by"])
			}
		}
	}
	if manual != 50 || auto != 20 || len(seen) != 4 {
		t.Fatalf("manual %d auto %d outcomes %v", manual, auto, seen)
	}
	if first, _ := items[0].(map[string]any); first["via"] != "agent" {
		t.Fatal("newest row is not the newest automatic row")
	}
	// Automatic rows are never rollback candidates.
	if digests, err := w.mem.RollbackDigests(ctx, entryID, sc.host.ID); err != nil || len(digests) != 1 || digests[0] != digest {
		t.Fatalf("rollback digests %v %v", digests, err)
	}
}

func TestHostProgramsHealthPolicyFalse(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	status, env, _ := mustCall(t, w, tok, http.MethodGet, "/v1/hosts/"+sc.host.ID.String(), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	programs, _ := objectPayload(t, env)["programs"].(map[string]any)
	if v, ok := programs["health_policy"]; !ok || v != false {
		t.Fatalf("host programs %#v", programs)
	}
	status, env, _ = mustCall(t, w, tok, http.MethodGet, "/v1/projects/"+sc.project.ID.String()+"/hosts", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	found := false
	for _, item := range listItems(t, env) {
		if item["id"] == sc.host.ID.String() {
			p, _ := item["programs"].(map[string]any)
			found = true
			if v, ok := p["health_policy"]; !ok || v != false {
				t.Fatalf("listed programs %#v", p)
			}
		}
	}
	if !found {
		t.Fatal("host not listed")
	}
}

func TestHealthPolicyUpdateHTTP(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	created := createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"redis",`+policyHealthcheck+`}`)
	put := "/v1/projects/" + project + "/catalog/web"
	for _, tc := range []struct{ body, msg string }{
		{`{"kind":"image","spec":{"kind":"service","image":"redis",` + policyHealthcheck + `,"health_policy":{"on_unhealthy":"stop"}}}`, "invalid health_policy.on_unhealthy"},
		{`{"kind":"image","spec":{"kind":"service","image":"redis",` + policyHealthcheck + `,"health_policy":{"on_sick":"restart"}}}`, "unknown field health_policy.on_sick"},
		{`{"kind":"image","spec":{"kind":"service","image":"redis",` + policyHealthcheck + `,"health_policy":{"on_deploy_failure":"keep","on_unhealthy":"restart"}}}`, "health_policy.on_unhealthy cannot be combined with keep"},
		{`{"kind":"image","spec":{"kind":"service","image":"redis","health_policy":{"on_unhealthy":"restart"}}}`, "health_policy.on_unhealthy needs a healthcheck"},
	} {
		status, env, _ := mustCall(t, w, tok, http.MethodPut, put, tc.body)
		mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", tc.msg)
	}
	status, env, _ := mustCall(t, w, tok, http.MethodPut, put, `{"kind":"image","spec":{"kind":"service","image":"redis",`+policyHealthcheck+`,"health_policy":{"on_deploy_failure":"rollback"}}}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if objectPayload(t, env)["spec_hash"] != created["spec_hash"] {
		t.Fatal("a policy at the defaults changed spec_hash on update")
	}
	status, env, _ = mustCall(t, w, tok, http.MethodPut, put, `{"kind":"image","spec":{"kind":"service","image":"redis",`+policyHealthcheck+`,"health_policy":{"on_unhealthy":"restart","max_actions_per_hour":5}}}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	updated := objectPayload(t, env)
	if updated["spec_hash"] == created["spec_hash"] {
		t.Fatal("a non-default policy did not change spec_hash")
	}
	spec, _ := updated["spec"].(map[string]any)
	policy, _ := spec["health_policy"].(map[string]any)
	if len(policy) != 2 || policy["on_unhealthy"] != "restart" || policy["max_actions_per_hour"] != float64(5) {
		t.Fatalf("stored policy %#v", spec["health_policy"])
	}
	status, env, _ = mustCall(t, w, tok, http.MethodGet, "/v1/projects/"+project+"/catalog/web", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if objectPayload(t, env)["spec_hash"] != updated["spec_hash"] {
		t.Fatal("GET does not show the updated spec_hash")
	}
}

func TestImageNameOldSuffixHTTP(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	path := "/v1/projects/" + sc.project.ID.String() + "/catalog"
	status, env, raw := mustCall(t, w, tok, http.MethodPost, path, `{"name":"web-old","kind":"image","spec":{"kind":"service","image":"nginx"}}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid name")
	if strings.Contains(raw, "web-old") {
		t.Fatal("error echoes the name")
	}
	// Replace of a missing entry is not_found, as for -prev. A legacy entry
	// already named web-old (seeded past the API rule) cannot be replaced.
	status, env, _ = mustCall(t, w, tok, http.MethodPut, path+"/web-old", `{"kind":"image","spec":{"kind":"service","image":"nginx"}}`)
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	legacy, err := catalog.BuildImage("web", []byte(`{"kind":"service","image":"nginx"}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.CreateCatalogEntry(context.Background(), sc.project.ID, store.CatalogWrite{
		Name: "web-old", Kind: "image", ImageRaw: []byte(catalog.SpecJSON(legacy)),
		SpecHash: catalog.ImageHash(legacy, nil), CommandDisplay: legacy.Image, Actor: owner.ID, At: w.now,
	}); err != nil {
		t.Fatal(err)
	}
	status, env, raw = mustCall(t, w, tok, http.MethodPut, path+"/web-old", `{"kind":"image","spec":{"kind":"service","image":"nginx:1.27"}}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid name")
	if strings.Contains(raw, "web-old") {
		t.Fatal("error echoes the name")
	}
	for _, name := range []string{"web-old2", "old"} {
		createImage(t, w, tok, sc.project.ID, name, `{"kind":"service","image":"nginx"}`)
		status, env, _ = mustCall(t, w, tok, http.MethodPut, path+"/"+name, `{"kind":"image","spec":{"kind":"service","image":"nginx:1.27"}}`)
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	}
}
