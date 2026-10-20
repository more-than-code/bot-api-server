package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestHealthcheckHTTP(t *testing.T) {
	const sentinel = "SENTINEL_ARGV"
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()

	status, env, raw := mustCall(t, w, tok, http.MethodPost, "/v1/projects/"+project+"/catalog", `{"name":"job","kind":"image","spec":{"kind":"job","image":"nginx","healthcheck":{"test":["`+sentinel+`"]}}}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "healthcheck applies to services")
	if strings.Contains(raw, sentinel) {
		t.Fatalf("job error echoed argv %s", raw)
	}
	status, env, raw = mustCall(t, w, tok, http.MethodPost, "/v1/projects/"+project+"/catalog", `{"name":"web","kind":"image","spec":{"kind":"service","image":"nginx","healthcheck":{"test":["`+sentinel+`\u0000"]}}}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid healthcheck.test")
	if strings.Contains(raw, sentinel) {
		t.Fatalf("field error echoed argv %s", raw)
	}

	created := createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","healthcheck":{"test":["CMD","wget"]}}`)
	spec, _ := created["spec"].(map[string]any)
	hc, _ := spec["healthcheck"].(map[string]any)
	if hc["interval_sec"] != float64(30) || hc["timeout_sec"] != float64(5) || hc["retries"] != float64(3) || hc["start_period_sec"] != float64(0) {
		t.Fatalf("stored defaults %#v", hc)
	}
	createImage(t, w, tok, sc.project.ID, "bare", `{"kind":"service","image":"nginx"}`)

	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return imageDeployReply(msg, shaDigest(2))
	})
	host := sc.host.ID.String()
	status, env, _ = postImage(t, w, tok, project, "bare", "deploy", host, "bare-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	frame, _ := log.raw(0)["spec"].(map[string]any)
	nested, _ := frame["spec"].(map[string]any)
	if _, ok := nested["healthcheck"]; ok {
		t.Fatalf("bare task sent healthcheck %#v", nested)
	}
	status, env, _ = postImage(t, w, tok, project, "web", "deploy", host, "hc-1", nil)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "this host's agent does not support healthcheck")
	if log.count() != 1 {
		t.Fatal("unsupported host dispatched")
	}
	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: true, PolicyHash: "abc", Healthcheck: true})
	status, env, _ = postImage(t, w, tok, project, "web", "deploy", host, "hc-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 2 {
		t.Fatal("healthcheck support did not send the task")
	}
	frame, _ = log.raw(1)["spec"].(map[string]any)
	nested, _ = frame["spec"].(map[string]any)
	got, _ := nested["healthcheck"].(map[string]any)
	if got["interval_sec"] != float64(30) || got["timeout_sec"] != float64(5) {
		t.Fatalf("task healthcheck %#v", nested["healthcheck"])
	}
	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: true, PolicyHash: "abc"})
	status, env, _ = postImage(t, w, tok, project, "web", "rollback", host, "hc-roll", map[string]any{"digest": shaDigest(2)})
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "this host's agent does not support healthcheck")
	if log.count() != 2 {
		t.Fatal("unsupported rollback dispatched")
	}
	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: true, PolicyHash: "abc", Healthcheck: true})
	delegated := tokenKind(t, w, owner.ID, store.KindDelegated)
	status, env, _ = postImage(t, w, delegated, project, "web", "deploy", host, "hc-del", nil)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	if log.count() != 2 {
		t.Fatal("confirmation dispatched")
	}
	id, _ := objectPayload(t, env)["confirmation_id"].(string)
	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: true, PolicyHash: "abc"})
	status, env, _ = mustCall(t, w, delegated, http.MethodPost, "/v1/confirmations/"+id, confirmBody("hc-del"))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "this host's agent does not support healthcheck")
	if log.count() != 2 {
		t.Fatal("confirm dispatched without healthcheck support")
	}
	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: true, PolicyHash: "abc", Healthcheck: true})
	status, env, _ = mustCall(t, w, delegated, http.MethodPost, "/v1/confirmations/"+id, confirmBody("hc-del"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 3 {
		t.Fatal("confirm did not dispatch after healthcheck support returned")
	}
}
