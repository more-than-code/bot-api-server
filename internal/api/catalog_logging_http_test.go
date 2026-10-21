package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestLoggingHTTP(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()

	status, env, _ := mustCall(t, w, tok, http.MethodPost, "/v1/projects/"+project+"/catalog", `{"name":"bad","kind":"image","spec":{"kind":"service","image":"nginx","logging":{"max_size_mb":0,"max_files":1}}}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid logging.max_size_mb")

	web := createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","logging":{"max_size_mb":10,"max_files":3}}`)
	spec, _ := web["spec"].(map[string]any)
	got, _ := spec["logging"].(map[string]any)
	if got["max_size_mb"] != float64(10) || got["max_files"] != float64(3) {
		t.Fatalf("stored logging %#v", spec["logging"])
	}
	batch := createImage(t, w, tok, sc.project.ID, "batch", `{"kind":"job","image":"nginx","logging":{"max_size_mb":5,"max_files":2}}`)
	createImage(t, w, tok, sc.project.ID, "bare", `{"kind":"service","image":"nginx"}`)

	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return imageDeployReply(msg, shaDigest(2))
	})
	host := sc.host.ID.String()
	status, env, _ = postImage(t, w, tok, project, "bare", "deploy", host, "bare-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if loggingOf(t, log.raw(0)) != nil {
		t.Fatal("bare task sent logging")
	}
	status, env, _ = postImage(t, w, tok, project, "web", "deploy", host, "log-1", nil)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "this host's agent does not support log settings")
	if log.count() != 1 || loggingDeploys(t, w, web, sc.host.ID) != 0 {
		t.Fatal("unsupported deploy sent a task or wrote a deploy row")
	}
	status, env, _ = postImage(t, w, tok, project, "batch", "deploy", host, "job-1", nil)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "this host's agent does not support log settings")
	if log.count() != 1 || loggingDeploys(t, w, batch, sc.host.ID) != 0 {
		t.Fatal("unsupported job run sent a task or wrote a deploy row")
	}
	status, env, _ = postImage(t, w, tok, project, "web", "rollback", host, "log-roll", map[string]any{"digest": shaDigest(2)})
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "this host's agent does not support log settings")
	if log.count() != 1 || loggingDeploys(t, w, web, sc.host.ID) != 0 {
		t.Fatal("unsupported rollback sent a task or wrote a deploy row")
	}

	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: true, PolicyHash: "abc", Logging: true})
	status, env, _ = postImage(t, w, tok, project, "bare", "deploy", host, "bare-2", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if loggingOf(t, log.raw(1)) != nil {
		t.Fatal("capable host received logging for an entry without it")
	}
	status, env, _ = postImage(t, w, tok, project, "web", "deploy", host, "log-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 3 {
		t.Fatal("logging support did not send the task")
	}
	logged := loggingOf(t, log.raw(2))
	if logged["max_size_mb"] != float64(10) || logged["max_files"] != float64(3) {
		t.Fatalf("task logging %#v", logged)
	}
	status, env, _ = postImage(t, w, tok, project, "batch", "deploy", host, "job-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	jobLog := loggingOf(t, log.raw(3))
	if jobLog["max_size_mb"] != float64(5) || jobLog["max_files"] != float64(2) {
		t.Fatalf("job task logging %#v", jobLog)
	}

	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: true, PolicyHash: "abc", Logging: true})
	delegated := tokenKind(t, w, owner.ID, store.KindDelegated)
	status, env, _ = postImage(t, w, delegated, project, "web", "deploy", host, "log-del", nil)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	if log.count() != 4 {
		t.Fatal("confirmation dispatched")
	}
	id, _ := objectPayload(t, env)["confirmation_id"].(string)
	before := loggingDeploys(t, w, web, sc.host.ID)
	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: true, PolicyHash: "abc"})
	status, env, _ = mustCall(t, w, delegated, http.MethodPost, "/v1/confirmations/"+id, confirmBody("log-del"))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "this host's agent does not support log settings")
	if log.count() != 4 || loggingDeploys(t, w, web, sc.host.ID) != before {
		t.Fatal("confirm dispatched without logging support")
	}
	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: true, PolicyHash: "abc", Logging: true})
	status, env, _ = mustCall(t, w, delegated, http.MethodPost, "/v1/confirmations/"+id, confirmBody("log-del"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 5 {
		t.Fatal("confirm did not dispatch after logging support returned")
	}
	confirmed := loggingOf(t, log.raw(4))
	if confirmed["max_size_mb"] != float64(10) || confirmed["max_files"] != float64(3) {
		t.Fatalf("confirmed task logging %#v", confirmed)
	}
}

func loggingOf(t *testing.T, task map[string]any) map[string]any {
	t.Helper()
	frame, _ := task["spec"].(map[string]any)
	nested, _ := frame["spec"].(map[string]any)
	got, _ := nested["logging"].(map[string]any)
	return got
}

func loggingDeploys(t *testing.T, w *world, entry map[string]any, hostID uuid.UUID) int {
	t.Helper()
	id, _ := entry["id"].(string)
	parsed, err := uuid.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := w.mem.ListImageDeploys(context.Background(), parsed, hostID)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}
