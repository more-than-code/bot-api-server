package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/seal"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const (
	envSecret = "sekret-env-VALUE-9f3a"
	regSecret = "sekret\"token-VALUE-9f3a"
)

func TestImageCatalogShape(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("admin@ex.com", "Admin")
	viewer := w.user("viewer@ex.com", "Viewer")
	extra := w.user("extra@ex.com", "Extra")
	sc := w.scene(owner, admin, viewer, w.user("spare@ex.com", "Spare"), extra)
	tok := w.token(owner.ID)
	path := "/v1/projects/" + sc.project.ID.String() + "/catalog"
	status, env, raw := mustCall(t, w, tok, http.MethodPost, path, `{"name":"web","kind":"image","spec":{"kind":"service","image":"Nginx"}}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid image")
	if strings.Contains(raw, "Nginx") {
		t.Fatal("error echoes the image")
	}
	status, env, raw = mustCall(t, w, tok, http.MethodPost, path, `{"name":"web-prev","kind":"image","spec":{"kind":"service","image":"nginx"}}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid name")
	if strings.Contains(raw, "web-prev") {
		t.Fatal("error echoes the name")
	}
	status, env, _ = mustCall(t, w, tok, http.MethodPost, path, `{"name":"web","kind":"image","spec":{"kind":"service","image":"nginx","env":{"DB_PASSWORD":"x"}}}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "use secret_env")
	status, env, _ = mustCall(t, w, tok, http.MethodPost, path, `{"name":"web","kind":"image","spec":{"kind":"service","image":"nginx"},"shell":true}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid json")

	created := createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx"}`)
	if created["command_display"] != "docker.io/library/nginx:latest" {
		t.Fatalf("display %#v", created["command_display"])
	}
	spec, _ := created["spec"].(map[string]any)
	if spec["image"] != "docker.io/library/nginx:latest" || spec["restart"] != "unless-stopped" {
		t.Fatalf("spec %#v", spec)
	}
	actions, _ := created["my_actions"].([]any)
	if strings.Join(anyStrings(t, actions), ",") != "run,stop,restart,logs,deploy,status" {
		t.Fatalf("owner actions %#v", actions)
	}
	prog := createProgram(t, w, tok, sc.project.ID, "tra", "pnpm run dev", false)
	progActs, _ := prog["my_actions"].([]any)
	if strings.Join(anyStrings(t, progActs), ",") != "run,stop,restart,logs,status" {
		t.Fatalf("program actions %#v", progActs)
	}
	status, env, _ = mustCall(t, w, tok, http.MethodGet, path+"/web/permissions", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	grants := objectPayload(t, env)["grants"].([]any)
	if !grantJSON(grants, "role:admin", "run,stop,restart,logs,deploy") || !grantJSON(grants, "role:viewer", "logs") {
		t.Fatalf("grants %#v", grants)
	}
	status, env, _ = mustCall(t, w, w.token(viewer.ID), http.MethodGet, path+"/web", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if strings.Join(anyStrings(t, objectPayload(t, env)["my_actions"].([]any)), ",") != "logs,status" {
		t.Fatalf("viewer %#v", env.Payload)
	}
	status, env, _ = mustCall(t, w, tok, http.MethodPut, path+"/web", `{"kind":"program","command":"pnpm","shell":false,"dir":"/home/joe/app","run_as":"joe"}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "kind must be image")
	status, env, _ = mustCall(t, w, tok, http.MethodPost, path+"/tra/deploy", `{"host_id":"`+sc.host.ID.String()+`","idempotency_key":"prog-deploy"}`)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
}

func TestImageCheckOrder(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	viewer := w.user("viewer@ex.com", "Viewer")
	extra := w.user("extra@ex.com", "Extra")
	sc := w.scene(owner, w.user("a@ex.com", "A"), viewer, w.user("s@ex.com", "S"), extra)
	tok := w.token(owner.ID)
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx"}`)
	project := sc.project.ID.String()
	host := sc.host.ID.String()
	view := w.token(viewer.ID)

	status, env, _ := mustCall(t, w, w.token(extra.ID), http.MethodPost, imagePath(project, "web", "deploy"), `{"host_id":"nope"}`)
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	status, env, _ = postImage(t, w, view, project, "web", "deploy", host, "v-deploy", nil)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env, _ = postImage(t, w, view, project, "web", "run", host, "v-run", nil)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env, _ = postImage(t, w, tok, project, "web", "deploy", host, "own-deploy", nil)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "this host does not run containers")
	status, env, _ = postImage(t, w, tok, project, "web", "logs", host, "", map[string]any{"lines": 2001})
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid lines")
	status, env, _ = postImage(t, w, tok, project, "web", "logs", host, "", map[string]any{"lines": 2000})
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "this host does not run containers")
	status, env, _ = postImage(t, w, view, project, "web", "logs", host, "", nil)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "this host does not run containers")

	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: false, PolicyHash: "abc"})
	status, env, _ = postImage(t, w, tok, project, "web", "status", host, "", nil)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "this host does not run containers")
	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: true, PolicyHash: "abc"})
	status, env, _ = postImage(t, w, tok, project, "web", "deploy", host, "off-deploy", nil)
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "host unavailable")

	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	log := watchTasks(t, conn, imageStatusReply)
	status, env, _ = postImage(t, w, view, project, "web", "logs", host, "", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 1 || log.raw(0)["kind"] != "image_logs" || log.raw(0)["timeout_sec"] != float64(60) {
		t.Fatalf("logs task %#v", log.raw(0))
	}
	spec, _ := log.raw(0)["spec"].(map[string]any)
	if strings.Join(mapKeys(spec), ",") != "entry,lines,project" || spec["lines"] != float64(200) {
		t.Fatalf("logs spec %#v", spec)
	}
	if log.raw(0)["expires_at"] != w.now.Add(60*time.Second).UTC().Format(time.RFC3339) {
		t.Fatalf("logs ttl %#v", log.raw(0)["expires_at"])
	}
	payload := objectPayload(t, env)
	if _, ok := payload["container"]; !ok || payload["lines"] == nil {
		t.Fatalf("logs body %#v", payload)
	}
	before := len(auditRows(t, w, sc.project.ID))
	status, env, _ = postImage(t, w, view, project, "web", "status", host, "", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if objectPayload(t, env)["state"] != "running" || len(auditRows(t, w, sc.project.ID)) != before {
		t.Fatal("status audited or not an image status")
	}
	status, env, _ = postImage(t, w, view, project, "web", "deploy", host, "v-deploy-2", nil)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	deploys := "/v1/projects/" + project + "/catalog/web/deploys?host_id=" + host
	status, env, _ = mustCall(t, w, view, http.MethodGet, deploys, "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if objectPayload(t, env)["items"] == nil {
		t.Fatalf("history %#v", env.Payload)
	}
}

func TestImageTaskFrame(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putEnv(t, w, tok, project, "svc", "NODE_ENV=from-set\nOTHER=from-set\nDB_PASSWORD=from-set-secret\n")
	putEnv(t, w, tok, project, "lock", "DB_PASSWORD=from-lock\n")
	putRegistry(t, w, tok, project, "docker.io", "bot", "dock-token-value")
	putRegistry(t, w, tok, project, "ghcr.io", "other", "ghcr-token-value")
	created := createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","env_sets":["svc"],"secret_env":{"DB_PASSWORD":"lock.DB_PASSWORD"},"env":{"NODE_ENV":"from-inline"}}`)
	hash, _ := created["spec_hash"].(string)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return imageDeployReply(msg, shaDigest(9))
	})
	host := sc.host.ID.String()
	status, env, _ := postImage(t, w, tok, project, "web", "deploy", host, "frame-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 1 {
		t.Fatalf("tasks %d", log.count())
	}
	frame := log.raw(0)
	if frame["kind"] != "image_deploy" || frame["timeout_sec"] != float64(390) || frame["service"] != nil {
		t.Fatalf("frame %#v", frame)
	}
	if frame["expires_at"] != w.now.Add(390*time.Second).UTC().Format(time.RFC3339) {
		t.Fatalf("deploy ttl %#v", frame["expires_at"])
	}
	spec, _ := frame["spec"].(map[string]any)
	if strings.Join(mapKeys(spec), ",") != "entry,env,force,project,registry_auth,spec,spec_hash" {
		t.Fatalf("spec keys %#v", spec)
	}
	if spec["project"] != "proj" || spec["entry"] != "web" || spec["force"] != false || spec["spec_hash"] != hash {
		t.Fatalf("spec %#v", spec)
	}
	envMap, _ := spec["env"].(map[string]any)
	if envMap["NODE_ENV"] != "from-inline" || envMap["OTHER"] != "from-set" || envMap["DB_PASSWORD"] != "from-lock" || len(envMap) != 3 {
		t.Fatalf("env %#v", envMap)
	}
	nested, _ := spec["spec"].(map[string]any)
	nestedEnv, _ := nested["env"].(map[string]any)
	nestedSets, _ := nested["env_sets"].([]any)
	nestedSecret, _ := nested["secret_env"].(map[string]any)
	if nestedEnv["NODE_ENV"] != "from-inline" || len(nestedEnv) != 1 || len(nestedSets) != 1 || nestedSets[0] != "svc" || nestedSecret["DB_PASSWORD"] != "lock.DB_PASSWORD" || len(nestedSecret) != 1 {
		t.Fatalf("stored spec %#v", nested)
	}
	reg, _ := spec["registry_auth"].(map[string]any)
	if strings.Join(mapKeys(reg), ",") != "host,token,username" || reg["host"] != "docker.io" || reg["username"] != "bot" || reg["token"] != "dock-token-value" {
		t.Fatalf("registry %#v", reg)
	}
	raw, _ := json.Marshal(frame)
	if strings.Contains(string(raw), "ghcr-token-value") || strings.Contains(string(raw), "from-set-secret") {
		t.Fatal("frame attached the wrong secret")
	}
	if strings.Count(string(raw), "from-lock") != 1 || strings.Count(string(raw), "dock-token-value") != 1 {
		t.Fatalf("secret copies %s", raw)
	}
	body := objectPayload(t, env)
	deploy, _ := body["deploy"].(map[string]any)
	if deploy["outcome"] != "succeeded" || deploy["by"] != owner.ID.String() || deploy["by_user"] != nil {
		t.Fatalf("deploy %#v", deploy)
	}
	if strings.Contains(mustText(body), "from-lock") || strings.Contains(mustText(body), "dock-token-value") {
		t.Fatal("response contains a secret")
	}
	status, env, _ = postImage(t, w, tok, project, "web", "deploy", host, "frame-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 1 || objectPayload(t, env)["deploy"].(map[string]any)["outcome"] != "succeeded" {
		t.Fatal("replay dispatched again")
	}
	status, env, _ = postImage(t, w, tok, project, "web", "deploy", host, "frame-1", map[string]any{"force": true})
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")
	if log.count() != 1 {
		t.Fatal("force change dispatched")
	}

	delegated := tokenKind(t, w, owner.ID, store.KindDelegated)
	status, env, rawText := postImage(t, w, delegated, project, "web", "deploy", host, "del-1", nil)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	pending := objectPayload(t, env)
	if pending["plan"] != "will deploy web (docker.io/library/nginx:latest) on pi4" || strings.Contains(rawText, "from-lock") || strings.Contains(rawText, "dock-token-value") {
		t.Fatalf("plan %#v", pending)
	}
	if log.count() != 1 {
		t.Fatal("confirmation dispatched")
	}
	id, _ := pending["confirmation_id"].(string)
	status, env, _ = mustCall(t, w, delegated, http.MethodPost, "/v1/confirmations/"+id, confirmBody("del-1"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 2 {
		t.Fatalf("confirm tasks %d", log.count())
	}
	status, env, _ = postImage(t, w, tok, project, "web", "deploy", host, "frame-force", map[string]any{"force": true})
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 3 {
		t.Fatalf("force tasks %d", log.count())
	}
	forced, _ := log.raw(2)["spec"].(map[string]any)
	if forced["force"] != true {
		t.Fatalf("force %#v", forced["force"])
	}
	createImage(t, w, tok, sc.project.ID, "pub", `{"kind":"service","image":"quay.io/joe/app"}`)
	status, env, _ = postImage(t, w, tok, project, "pub", "deploy", host, "frame-pub", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	pub, _ := log.raw(3)["spec"].(map[string]any)
	if _, ok := pub["registry_auth"]; !ok || pub["registry_auth"] != nil {
		t.Fatalf("registry_auth %#v", pub["registry_auth"])
	}
}

func TestImageSecretBoundary(t *testing.T) {
	w := newWorld(t)
	logs := captureLog(w)
	owner := w.user("owner@ex.com", "Owner")
	viewer := w.user("viewer@ex.com", "Viewer")
	extra := w.user("extra@ex.com", "Extra")
	sc := w.scene(owner, w.user("a@ex.com", "A"), viewer, w.user("s@ex.com", "S"), extra)
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	var seen bytes.Buffer

	status, env, raw := mustCall(t, w, w.token(viewer.ID), http.MethodPut, envPath(project, "svc"), `{"dotenv":"A=b\n"}`)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	seen.WriteString(raw)
	status, env, raw = mustCall(t, w, w.token(extra.ID), http.MethodGet, "/v1/projects/"+project+"/env-sets", "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	seen.WriteString(raw)
	status, env, raw = mustCall(t, w, tok, http.MethodPut, envPath(project, "svc"), `{"dotenv":"FOO=`+envSecret+`\nFOO=again\n"}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "line 2: FOO duplicate")
	if strings.Contains(raw, envSecret) || strings.Contains(raw, "again") {
		t.Fatal("dotenv error echoes a value")
	}
	seen.WriteString(raw)
	status, env, raw = mustCall(t, w, tok, http.MethodPut, envPath(project, "svc"), `{"dotenv":"FOO=`+envSecret+`\n"}`)
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "secrets key not configured")
	seen.WriteString(raw)
	regBody, err := json.Marshal(map[string]string{"username": "bot", "token": regSecret})
	if err != nil {
		t.Fatal(err)
	}
	status, env, raw = mustCall(t, w, tok, http.MethodPut, regPath(project, "ghcr.io"), string(regBody))
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "secrets key not configured")
	seen.WriteString(raw)
	status, env, raw = mustCall(t, w, tok, http.MethodPut, regPath(project, "GHCR.IO"), `{"username":"bot","token":"x"}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid host")
	if strings.Contains(raw, "GHCR") {
		t.Fatal("host error echoes the host")
	}
	seen.WriteString(raw)

	w.srv.Secrets = testBox(t)
	putEnv(t, w, tok, project, "svc", "FOO="+envSecret+"\n")
	status, env, raw = mustCall(t, w, tok, http.MethodGet, envPath(project, "svc"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	keys, _ := objectPayload(t, env)["keys"].([]any)
	key0, _ := keys[0].(map[string]any)
	if len(keys) != 1 || key0["key"] != "FOO" || key0["is_secret"] != true || key0["value"] != nil {
		t.Fatalf("set %#v", env.Payload)
	}
	seen.WriteString(raw)
	putRegistry(t, w, tok, project, "ghcr.io", "bot", regSecret)
	status, env, raw = mustCall(t, w, tok, http.MethodGet, "/v1/projects/"+project+"/registries", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	seen.WriteString(raw)
	created := createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"ghcr.io/joe/app","env_sets":["svc"]}`)
	entryID := created["id"].(string)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return imageDeployReply(msg, shaDigest(4))
	})
	host := sc.host.ID.String()
	w.srv.Secrets = nil
	status, env, raw = postImage(t, w, tok, project, "web", "deploy", host, "need-key", nil)
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "secrets key not configured")
	if log.count() != 0 {
		t.Fatal("missing key dispatched")
	}
	seen.WriteString(raw)
	status, env, raw = postImage(t, w, tok, project, "web", "status", host, "", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	seen.WriteString(raw)
	status, env, raw = postImage(t, w, tok, project, "web", "remove", host, "rm-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	seen.WriteString(raw)
	plain := createImage(t, w, tok, sc.project.ID, "plain", `{"kind":"service","image":"nginx"}`)
	_ = plain
	status, env, raw = postImage(t, w, tok, project, "plain", "deploy", host, "plain-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	seen.WriteString(raw)

	w.srv.Secrets = testBox(t)
	status, env, raw = postImage(t, w, tok, project, "web", "deploy", host, "need-key", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() < 2 {
		t.Fatal("configured key did not deploy")
	}
	seen.WriteString(raw)
	frameMsg := log.raw(log.count() - 1)
	spec, _ := frameMsg["spec"].(map[string]any)
	envMap, _ := spec["env"].(map[string]any)
	reg, _ := spec["registry_auth"].(map[string]any)
	if envMap["FOO"] != envSecret || reg["token"] != regSecret {
		t.Fatal("task frame lost the secret the leak scan must ignore")
	}
	delegated := tokenKind(t, w, owner.ID, store.KindDelegated)
	status, env, raw = postImage(t, w, delegated, project, "web", "deploy", host, "del-secret", nil)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	if strings.Contains(raw, envSecret) || objectPayload(t, env)["plan"] != "will deploy web (ghcr.io/joe/app:latest) on pi4" {
		t.Fatalf("plan leaked %#v", env.Payload)
	}
	seen.WriteString(raw)
	hist := "/v1/projects/" + project + "/catalog/web/deploys?host_id=" + host
	status, env, raw = mustCall(t, w, tok, http.MethodGet, hist, "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	seen.WriteString(raw)

	w.srv.Secrets = testBoxByte(t, 3)
	tasks := log.count()
	status, env, raw = postImage(t, w, tok, project, "web", "deploy", host, "bad-key", nil)
	mustHTTP(t, status, env, http.StatusInternalServerError, "error", "internal error")
	if log.count() != tasks {
		t.Fatal("decrypt failure dispatched")
	}
	seen.WriteString(raw)
	rows, err := w.mem.ListImageDeploys(context.Background(), uuid.MustParse(entryID), sc.host.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.InFlight {
			t.Fatal("decrypt failure left an in-flight row")
		}
	}
	auditBlob := auditBlob(t, w, sc.project.ID)
	if !strings.Contains(auditBlob, "decrypt failed") {
		t.Fatal("decrypt denial was not audited")
	}
	seen.WriteString(auditBlob)
	seen.WriteString(logs.String())
	assertNoSecret(t, seen.String())
}

func TestImageSharedApproval(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	guestUser := w.user("guest@ex.com", "Guest")
	guest, err := w.mem.CreateProject(context.Background(), guestUser.ID, "Guest", "guest", w.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.mem.PutHostShare(context.Background(), sc.host.ID, guest.ID, "deploy", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	gtok := w.token(guestUser.ID)
	gpath := guest.ID.String()
	putEnv(t, w, gtok, gpath, "svc", "FOO="+envSecret+"\n")
	created := createImage(t, w, gtok, guest.ID, "web", `{"kind":"service","image":"nginx","env_sets":["svc"]}`)
	hash, _ := created["spec_hash"].(string)
	entryID, _ := created["id"].(string)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return imageDeployReply(msg, shaDigest(8))
	})
	host := sc.host.ID.String()
	status, env, raw := postImage(t, w, gtok, gpath, "web", "deploy", host, "share-1", nil)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "waiting for the host owner's approval")
	if strings.Contains(raw, envSecret) || log.count() != 0 {
		t.Fatal("waiting deploy leaked or dispatched")
	}
	status, env, _ = mustCall(t, w, w.token(owner.ID), http.MethodPost, "/v1/hosts/"+host+"/catalog-approvals", `{"entry_id":"`+entryID+`","spec_hash":"`+hash+`"}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env, _ = postImage(t, w, gtok, gpath, "web", "deploy", host, "share-2", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 1 {
		t.Fatalf("approved tasks %d", log.count())
	}
	putEnv(t, w, gtok, gpath, "svc", "FOO="+envSecret+"-other\n")
	if got := createImageGet(t, w, gtok, guest.ID, "web"); got["spec_hash"] != hash {
		t.Fatal("value rewrite changed the hash")
	}
	if n := len(listApprovals(t, w, owner.ID, sc.host.ID)); n != 1 {
		t.Fatalf("value rewrite voided the approval: %d", n)
	}
	putEnv(t, w, gtok, gpath, "svc", "FOO="+envSecret+"\nBAR=1\n")
	if n := len(listApprovals(t, w, owner.ID, sc.host.ID)); n != 0 {
		t.Fatalf("approval survived a new key: %d", n)
	}
	got := createImageGet(t, w, gtok, guest.ID, "web")
	if got["spec_hash"] == hash {
		t.Fatal("spec_hash ignored the new key")
	}
	status, env, _ = postImage(t, w, gtok, gpath, "web", "deploy", host, "share-3", nil)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "waiting for the host owner's approval")
	items := listApprovals(t, w, owner.ID, sc.host.ID)
	if len(items) != 1 || items[0]["status"] != "pending" || items[0]["spec_hash"] != got["spec_hash"] {
		t.Fatalf("pending %#v", items)
	}
	if log.count() != 1 {
		t.Fatal("voided approval dispatched")
	}
	twoKey, _ := got["spec_hash"].(string)
	putEnv(t, w, gtok, gpath, "svc", "FOO="+envSecret+"\n")
	restored := createImageGet(t, w, gtok, guest.ID, "web")
	if restored["spec_hash"] == twoKey {
		t.Fatal("deleting a key did not change the hash")
	}
	if n := len(listApprovals(t, w, owner.ID, sc.host.ID)); n != 0 {
		t.Fatalf("approval survived deleting a key: %d", n)
	}
}

func TestImageFlightRollbackDisconnect(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	created := createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx"}`)
	entryID := uuid.MustParse(created["id"].(string))
	hash, _ := created["spec_hash"].(string)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	project := sc.project.ID.String()
	host := sc.host.ID.String()
	digests := make([]string, 4)
	for i := 0; i < 4; i++ {
		digests[i] = shaDigest(byte(i + 1))
		when := w.now.Add(-time.Duration(4-i) * time.Minute)
		row, err := w.mem.BeginImageOp(context.Background(), entryID, sc.host.ID, hash, owner.ID, "console", when, when.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.mem.FinishImageDeploy(context.Background(), row.ID, "succeeded", &digests[i], nil, when.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	before := len(auditRows(t, w, sc.project.ID))
	stage := "rollback"
	var stageMu sync.Mutex
	setStage := func(next string) {
		stageMu.Lock()
		stage = next
		stageMu.Unlock()
	}
	release := make(chan struct{})
	got := make(chan struct{})
	seen := make(chan struct{})
	var blockOnce, dropOnce sync.Once
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		stageMu.Lock()
		now := stage
		stageMu.Unlock()
		switch now {
		case "block":
			blockOnce.Do(func() { close(got) })
			<-release
			return imageDeployReply(msg, shaDigest(7))
		case "drop":
			dropOnce.Do(func() { close(seen) })
			time.Sleep(150 * time.Millisecond)
			return imageDeployReply(msg, shaDigest(6))
		default:
			return imageDeployReply(msg, digests[3])
		}
	})
	status, env, raw := postImage(t, w, tok, project, "web", "rollback", host, "old", map[string]any{"digest": digests[0]})
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid digest")
	if strings.Contains(raw, digests[0]) || log.count() != 0 || len(auditRows(t, w, sc.project.ID)) != before {
		t.Fatal("old digest was echoed, audited, or dispatched")
	}
	status, env, raw = postImage(t, w, tok, project, "web", "rollback", host, "bad", map[string]any{"digest": "sha256:abcd"})
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid digest")
	if strings.Contains(raw, "abcd") {
		t.Fatal("invalid digest echoed")
	}
	status, env, _ = postImage(t, w, tok, project, "web", "rollback", host, "new", map[string]any{"digest": digests[3]})
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 1 || log.raw(0)["kind"] != "image_rollback" {
		t.Fatalf("rollback %#v", log.raw(0))
	}
	rb, _ := log.raw(0)["spec"].(map[string]any)
	if strings.Join(mapKeys(rb), ",") != "digest,entry,env,force,project,registry_auth,spec,spec_hash" || rb["digest"] != digests[3] {
		t.Fatalf("rollback spec %#v", rb)
	}
	if log.raw(0)["timeout_sec"] != float64(390) {
		t.Fatalf("rollback timeout %#v", log.raw(0)["timeout_sec"])
	}

	setStage("block")
	first := make(chan callResult, 1)
	go func() {
		status, env, raw, err := callRaw(w, tok, http.MethodPost, imagePath(project, "web", "deploy"), imageBody(host, "flight-1", nil))
		first <- callResult{status, env, raw, err}
	}()
	select {
	case <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight task was not sent")
	}
	status, env, _ = postImage(t, w, tok, project, "web", "deploy", host, "flight-2", nil)
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")
	close(release)
	gotFirst := <-first
	if gotFirst.err != nil {
		t.Fatal(gotFirst.err)
	}
	mustHTTP(t, gotFirst.status, gotFirst.env, http.StatusOK, "ok", "ok")

	setStage("drop")
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.http.URL+imagePath(project, "web", "deploy"), strings.NewReader(imageBody(host, "drop-1", nil)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	go func() {
		<-seen
		cancel()
	}()
	if _, err := w.client.Do(req); err == nil {
		t.Fatal("client stayed connected")
	}
	deadline := time.Now().Add(3 * time.Second)
	var rows []store.ImageDeploy
	for {
		rows, err = w.mem.ListImageDeploys(context.Background(), entryID, sc.host.ID)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, row := range rows {
			if row.Digest != nil && *row.Digest == shaDigest(6) {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("disconnect did not record the deploy")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestImageDiscovery(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx"}`)
	createProgram(t, w, tok, sc.project.ID, "tra", "pnpm run dev", false)
	digest := shaDigest(5)
	services := []any{
		map[string]any{"name": "not-web", "kind": "container", "ports": []int{80}, "container_name": "ctr-web", "image_digest": digest, "owner": map[string]any{"kind": "image", "project": "proj", "entry": "web"}},
		map[string]any{"name": "otherbox", "kind": "container", "ports": []int{81}, "container_name": "ctr-other", "image_digest": digest, "owner": map[string]any{"kind": "image", "project": "proj", "entry": "missing"}},
		map[string]any{"name": "progown", "kind": "container", "ports": []int{82}, "container_name": "ctr-prog", "image_digest": digest, "owner": map[string]any{"kind": "program", "project": "proj", "entry": "web"}},
	}
	helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), services)
	items := serviceItems(t, w, tok, sc.host.ID)
	owned := findMap(t, items, "name", "web")
	if owned["source"] != "owned" || owned["kind"] != "container" || owned["catalog_entry"] != "web" || owned["image_digest"] != digest || owned["container_name"] != "ctr-web" {
		t.Fatalf("owned %#v", owned)
	}
	if findMap(t, items, "name", "not-web") != nil {
		t.Fatal("reported container name was stored beside the entry")
	}
	other := findMap(t, items, "name", "otherbox")
	if other["source"] != "discovered" || other["catalog_entry"] != nil || other["image_digest"] != digest {
		t.Fatalf("other %#v", other)
	}
	prog := findMap(t, items, "name", "progown")
	if prog["source"] != "discovered" || prog["catalog_entry"] != nil {
		t.Fatalf("program owner on an image entry %#v", prog)
	}
}

func TestEnvRegistryRoutes(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putEnv(t, w, tok, project, "svc", "VISIBLE=visible-plain\nSECRET=hidden-value\nPLAIN=still-plain\n")
	status, env, raw := mustCall(t, w, tok, http.MethodPatch, envPath(project, "svc")+"/keys/VISIBLE", `{"is_secret":false}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if !strings.Contains(raw, "visible-plain") {
		t.Fatal("plain value was hidden from the admin")
	}
	for _, row := range auditRows(t, w, sc.project.ID) {
		if row.Action == "env_set.key_visibility" && strings.Contains(string(row.Detail), "visible-plain") {
			t.Fatal("visibility audit stored the value")
		}
	}
	status, env, raw = mustCall(t, w, tok, http.MethodPatch, envPath(project, "svc")+"/keys/VISIBLE", `{"is_secret":true}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if strings.Contains(raw, "visible-plain") {
		t.Fatal("secret value returned after the flip")
	}
	status, env, raw = mustCall(t, w, tok, http.MethodPatch, envPath(project, "svc")+"/keys/PLAIN", `{"is_secret":false}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if !strings.Contains(raw, "still-plain") {
		t.Fatal("plain value was hidden from the admin")
	}
	w.srv.Secrets = nil
	status, env, _ = mustCall(t, w, tok, http.MethodPatch, envPath(project, "svc")+"/keys/SECRET", `{"is_secret":true}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env, raw = mustCall(t, w, tok, http.MethodPatch, envPath(project, "svc")+"/keys/PLAIN", `{"is_secret":true}`)
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "secrets key not configured")
	status, env, raw = mustCall(t, w, tok, http.MethodPut, envPath(project, "svc"), `{"dotenv":""}`)
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "secrets key not configured")
	w.srv.Secrets = testBox(t)
	status, env, raw = mustCall(t, w, tok, http.MethodGet, envPath(project, "svc"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if !strings.Contains(raw, "still-plain") || !strings.Contains(raw, "SECRET") || !strings.Contains(raw, "VISIBLE") {
		t.Fatal("nil key changed the env set")
	}
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","env_sets":["svc"]}`)
	status, env, _ = mustCall(t, w, tok, http.MethodDelete, envPath(project, "svc"), "")
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")
	status, env, _ = mustCall(t, w, tok, http.MethodPut, "/v1/projects/"+project+"/catalog/web", `{"kind":"image","spec":{"kind":"service","image":"nginx"}}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env, _ = mustCall(t, w, tok, http.MethodDelete, envPath(project, "svc"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	userBody, err := json.Marshal(map[string]string{"username": "bo\nt\r\x00t", "token": "clean-token-value"})
	if err != nil {
		t.Fatal(err)
	}
	status, env, raw = mustCall(t, w, tok, http.MethodPut, regPath(project, "ctrl.example"), string(userBody))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid username")
	if strings.Contains(raw, "clean-token-value") || strings.Contains(raw, "bo\n") {
		t.Fatal("username error echoed a credential")
	}
	tokenBody, err := json.Marshal(map[string]string{"username": "bot", "token": "sek\nX-Registry-Auth\r\x00VALUE"})
	if err != nil {
		t.Fatal(err)
	}
	status, env, raw = mustCall(t, w, tok, http.MethodPut, regPath(project, "ctrl.example"), string(tokenBody))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid token")
	if strings.Contains(raw, "X-Registry-Auth") || strings.Contains(raw, "sek\n") {
		t.Fatal("token error echoed a credential")
	}
	status, env, _ = mustCall(t, w, tok, http.MethodGet, "/v1/projects/"+project+"/registries", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	for _, item := range listItems(t, env) {
		if item["host"] == "ctrl.example" {
			t.Fatal("control-character registry was stored")
		}
	}
	status, env, raw = mustCall(t, w, tok, http.MethodPut, regPath(project, "ghcr.io"), `{"username":"","token":"x"}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid username")
	token := strings.Repeat("b", 4097)
	status, env, raw = mustCall(t, w, tok, http.MethodPut, regPath(project, "ghcr.io"), `{"username":"bot","token":"`+token+`"}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid token")
	if strings.Contains(raw, token) {
		t.Fatal("token echoed")
	}
	status, env, _ = mustCall(t, w, tok, http.MethodDelete, regPath(project, "ghcr.io"), "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	putRegistry(t, w, tok, project, "localhost:5000", "bot", "tok")
	status, env, _ = mustCall(t, w, tok, http.MethodDelete, regPath(project, "localhost:5000"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	gotAudit := map[string]bool{"env_set.key_visibility": false, "env_set.delete": false, "registry.delete": false}
	for _, row := range auditRows(t, w, sc.project.ID) {
		detail := string(row.Detail)
		switch row.Action {
		case "env_set.key_visibility":
			if strings.Contains(detail, `"set":"svc"`) && strings.Contains(detail, `"key":"VISIBLE"`) {
				gotAudit[row.Action] = true
			}
		case "env_set.delete":
			if strings.Contains(detail, `"set":"svc"`) {
				gotAudit[row.Action] = true
			}
		case "registry.delete":
			if strings.Contains(detail, `"host":"localhost:5000"`) {
				gotAudit[row.Action] = true
			}
		}
		if row.Action == "env_set.key_visibility" || row.Action == "env_set.delete" || row.Action == "registry.delete" {
			if strings.Contains(detail, "visible-plain") || strings.Contains(detail, "hidden-value") || strings.Contains(detail, "still-plain") || strings.Contains(detail, `"token"`) {
				t.Fatalf("%s stored a secret %s", row.Action, detail)
			}
		}
	}
	for action, ok := range gotAudit {
		if !ok {
			t.Fatalf("missing audit %s", action)
		}
	}
}

func TestEnvRegistryConsoleOnly(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBoxByte(t, 9)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putEnv(t, w, tok, project, "svc", "FOO="+envSecret+"\n")
	putRegistry(t, w, tok, project, "ghcr.io", "bot", regSecret)
	delegated := tokenKind(t, w, owner.ID, store.KindDelegated)
	w.srv.Secrets = testBoxByte(t, 4)
	routes := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/v1/projects/" + project + "/env-sets", ""},
		{http.MethodGet, envPath(project, "svc"), ""},
		{http.MethodPut, envPath(project, "svc"), `{"dotenv":"FOO=next\n"}`},
		{http.MethodDelete, envPath(project, "svc"), ""},
		{http.MethodPatch, envPath(project, "svc") + "/keys/FOO", `{"is_secret":false}`},
		{http.MethodGet, "/v1/projects/" + project + "/registries", ""},
		{http.MethodPut, regPath(project, "ghcr.io"), `{"username":"bot","token":"next-token-value"}`},
		{http.MethodDelete, regPath(project, "ghcr.io"), ""},
	}
	for _, route := range routes {
		status, env, raw := mustCall(t, w, delegated, route.method, route.path, route.body)
		mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
		if strings.Contains(raw, envSecret) || strings.Contains(raw, regSecret) {
			t.Fatalf("%s %s returned a secret", route.method, route.path)
		}
	}
	w.srv.Secrets = testBoxByte(t, 9)
	status, env, raw := mustCall(t, w, tok, http.MethodGet, envPath(project, "svc"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	keys, _ := objectPayload(t, env)["keys"].([]any)
	key0, _ := keys[0].(map[string]any)
	if len(keys) != 1 || key0["is_secret"] != true || key0["value"] != nil {
		t.Fatalf("delegated patch changed the key %#v", keys)
	}
	if strings.Contains(raw, envSecret) {
		t.Fatal("secret value returned")
	}
	status, env, _ = mustCall(t, w, tok, http.MethodGet, "/v1/projects/"+project+"/registries", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if len(listItems(t, env)) != 1 {
		t.Fatal("delegated registry call changed the row")
	}
}

func TestImageOutcomeMatrix(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	created := createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx"}`)
	entryID := uuid.MustParse(created["id"].(string))
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	var mu sync.Mutex
	next := "failed"
	exitCode := 7
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		mu.Lock()
		outcome := next
		mu.Unlock()
		kind, _ := msg["kind"].(string)
		if kind == "image_remove" {
			return map[string]any{
				"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "failed",
				"error_code": "conflict",
				"payload": map[string]any{
					"status": map[string]any{"container": "web", "state": "running", "restart_count": 0, "ports": []int{}},
				},
			}
		}
		if outcome == "bad-state" || outcome == "unknown-state" {
			state := "up"
			if outcome == "unknown-state" {
				state = "unknown"
			}
			return map[string]any{
				"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "succeeded",
				"payload": map[string]any{
					"outcome": "succeeded", "digest": shaDigest(3), "exit_code": 0,
					"status": map[string]any{"container": "web", "state": state, "restart_count": 0, "ports": []int{}},
					"lines":  []string{"up"},
				},
			}
		}
		return map[string]any{
			"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "failed",
			"error_code": outcome,
			"payload": map[string]any{
				"outcome": outcome, "digest": shaDigest(3), "exit_code": exitCode,
				"status": map[string]any{
					"container": "web", "state": "exited", "restart_count": 1,
					"exit_code": exitCode, "ports": []int{},
				},
				"lines": []string{"done"},
			},
		}
	})
	host := sc.host.ID.String()
	outcomes := []string{"failed", "unchanged", "rolled_back", "rollback_failed", "image_unavailable", "forbidden_spec", "conflict"}
	for i, outcome := range outcomes {
		mu.Lock()
		next = outcome
		mu.Unlock()
		status, env, _ := postImage(t, w, tok, project, "web", "deploy", host, fmt.Sprintf("out-%d", i), nil)
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
		deploy, _ := objectPayload(t, env)["deploy"].(map[string]any)
		if deploy["outcome"] != outcome || deploy["exit_code"] != float64(exitCode) {
			t.Fatalf("%s deploy %#v", outcome, deploy)
		}
		if objectPayload(t, env)["status"].(map[string]any)["state"] != "exited" {
			t.Fatalf("%s status %#v", outcome, objectPayload(t, env)["status"])
		}
	}
	if log.count() != len(outcomes) {
		t.Fatalf("tasks %d", log.count())
	}
	hist := "/v1/projects/" + project + "/catalog/web/deploys?host_id=" + host
	status, env, _ := mustCall(t, w, tok, http.MethodGet, hist, "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	items := listItems(t, env)
	if len(items) != len(outcomes) {
		t.Fatalf("history %d", len(items))
	}
	seen := map[string]bool{}
	for _, item := range items {
		seen[item["outcome"].(string)] = true
		if item["exit_code"] != float64(exitCode) {
			t.Fatalf("stored exit %#v", item)
		}
	}
	for _, outcome := range outcomes {
		if !seen[outcome] {
			t.Fatalf("history missing %s", outcome)
		}
	}
	rows, err := w.mem.ListImageDeploys(context.Background(), entryID, sc.host.ID)
	if err != nil || len(rows) != len(outcomes) || rows[0].ExitCode == nil || *rows[0].ExitCode != exitCode {
		t.Fatalf("store history %#v %v", rows, err)
	}
	mu.Lock()
	next = "bad-state"
	mu.Unlock()
	status, env, raw := postImage(t, w, tok, project, "web", "deploy", host, "out-bad", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	badDeploy, _ := objectPayload(t, env)["deploy"].(map[string]any)
	badLines, _ := objectPayload(t, env)["lines"].([]any)
	if badDeploy["outcome"] != "failed" || len(badLines) != 1 || badLines[0] != invalidAgentResult || strings.Contains(raw, `"state":"up"`) {
		t.Fatalf("invalid state %#v %s", env.Payload, raw)
	}
	mu.Lock()
	next = "unknown-state"
	mu.Unlock()
	status, env, raw = postImage(t, w, tok, project, "web", "deploy", host, "out-unknown", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	unknownDeploy, _ := objectPayload(t, env)["deploy"].(map[string]any)
	if unknownDeploy["outcome"] != "failed" || strings.Contains(raw, `"state":"unknown"`) {
		t.Fatalf("agent unknown accepted %#v %s", env.Payload, raw)
	}
	status, env, _ = postImage(t, w, tok, project, "web", "remove", host, "out-rm", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if objectPayload(t, env)["status"].(map[string]any)["state"] != "running" {
		t.Fatalf("remove status %#v", env.Payload)
	}
	var removeOutcome string
	for _, row := range auditRows(t, w, sc.project.ID) {
		if row.Action == "catalog.remove" && row.Result != nil {
			removeOutcome = *row.Result
		}
	}
	if removeOutcome != "conflict" {
		t.Fatalf("remove outcome %q", removeOutcome)
	}
}

func TestImageTimeoutClearsInFlight(t *testing.T) {
	w := newWorld(t)
	w.srv.imageBudget = 1
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	created := createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx"}`)
	entryID := uuid.MustParse(created["id"].(string))
	hash, _ := created["spec_hash"].(string)
	digest := shaDigest(5)
	seed, err := w.mem.BeginImageOp(context.Background(), entryID, sc.host.ID, hash, owner.ID, "console", w.now, w.now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.FinishImageDeploy(context.Background(), seed.ID, "succeeded", &digest, nil, w.now); err != nil {
		t.Fatal(err)
	}
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	watchTasks(t, conn, nil)
	host := sc.host.ID.String()
	status, env, raw := postImage(t, w, tok, project, "web", "deploy", host, "to-deploy", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	body := objectPayload(t, env)
	deploy, _ := body["deploy"].(map[string]any)
	st, _ := body["status"].(map[string]any)
	ports, _ := st["ports"].([]any)
	if deploy["outcome"] != "timeout" || st["state"] != "unknown" || st["restart_count"] != float64(0) || st["container"] != nil || st["exit_code"] != nil || st["digest"] != nil || st["started_at"] != nil || st["finished_at"] != nil || len(ports) != 0 || strings.Contains(raw, `"state":""`) || strings.Contains(raw, `"state":"missing"`) {
		t.Fatalf("deploy timeout %#v %s", body, raw)
	}
	status, env, _ = postImage(t, w, tok, project, "web", "deploy", host, "to-deploy-2", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if objectPayload(t, env)["deploy"].(map[string]any)["outcome"] != "timeout" {
		t.Fatal("second deploy did not run")
	}
	status, env, raw = postImage(t, w, tok, project, "web", "rollback", host, "to-roll", map[string]any{"digest": digest})
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	roll := objectPayload(t, env)
	rollDeploy, _ := roll["deploy"].(map[string]any)
	rollStatus, _ := roll["status"].(map[string]any)
	if rollDeploy["outcome"] != "timeout" || rollStatus["state"] != "unknown" || strings.Contains(raw, `"state":""`) {
		t.Fatalf("rollback timeout %#v %s", env.Payload, raw)
	}
	rows, err := w.mem.ListImageDeploys(context.Background(), entryID, sc.host.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.InFlight {
			t.Fatal("timeout left an in-flight row")
		}
	}
	before := len(rows)
	status, env, raw = postImage(t, w, tok, project, "web", "remove", host, "to-rm", nil)
	if status != http.StatusGatewayTimeout || env.Code != "timeout" {
		t.Fatalf("remove timeout %d %#v %s", status, env, raw)
	}
	if strings.Contains(raw, "missing") {
		t.Fatal("remove timeout reported missing")
	}
	rows, err = w.mem.ListImageDeploys(context.Background(), entryID, sc.host.ID)
	if err != nil || len(rows) != before {
		t.Fatalf("remove timeout wrote history %d %v", len(rows), err)
	}
	for _, row := range rows {
		if row.InFlight {
			t.Fatal("remove timeout left an in-flight row")
		}
	}
	var removeOutcome string
	for _, row := range auditRows(t, w, sc.project.ID) {
		if row.Action == "catalog.remove" {
			if row.Result != nil {
				removeOutcome = *row.Result
			}
			if !strings.Contains(string(row.Detail), `"outcome":"timeout"`) {
				t.Fatalf("remove audit %s", row.Detail)
			}
		}
	}
	if removeOutcome != "timeout" {
		t.Fatalf("remove audit result %q", removeOutcome)
	}
	status, env, _ = postImage(t, w, tok, project, "web", "status", host, "", nil)
	if status == http.StatusOK || env.Code != "timeout" {
		t.Fatalf("status timeout %d %#v", status, env)
	}
}

func TestImageStaleTakeover(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	created := createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx"}`)
	entryID := uuid.MustParse(created["id"].(string))
	hash, _ := created["spec_hash"].(string)
	stale, err := w.mem.BeginImageOp(context.Background(), entryID, sc.host.ID, hash, owner.ID, "console", w.now.Add(-time.Hour), w.now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := w.mem.BeginImageOp(context.Background(), entryID, sc.host.ID, hash, owner.ID, "console", w.now, w.now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.BeginImageOp(context.Background(), entryID, sc.host.ID, hash, owner.ID, "console", w.now, w.now.Add(time.Hour)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("fresh row %v", err)
	}
	rows, err := w.mem.ListImageDeploys(context.Background(), entryID, sc.host.ID)
	if err != nil || len(rows) != 1 || rows[0].ID != stale.ID || rows[0].Outcome != "timeout" || rows[0].InFlight {
		t.Fatalf("stale %#v %v", rows, err)
	}
	if err := w.mem.ReleaseImageOp(context.Background(), fresh.ID); err != nil {
		t.Fatal(err)
	}
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return imageDeployReply(msg, shaDigest(6))
	})
	stuck, err := w.mem.BeginImageOp(context.Background(), entryID, sc.host.ID, hash, owner.ID, "console", w.now.Add(-2*time.Hour), w.now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	status, env, _ := postImage(t, w, tok, project, "web", "deploy", sc.host.ID.String(), "stale-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if objectPayload(t, env)["deploy"].(map[string]any)["outcome"] != "succeeded" {
		t.Fatalf("takeover %#v", env.Payload)
	}
	rows, err = w.mem.ListImageDeploys(context.Background(), entryID, sc.host.ID)
	if err != nil {
		t.Fatal(err)
	}
	var sawStuck bool
	for _, row := range rows {
		if row.ID == stuck.ID && row.Outcome == "timeout" && !row.InFlight {
			sawStuck = true
		}
		if row.InFlight {
			t.Fatal("takeover left an in-flight row")
		}
	}
	if !sawStuck {
		t.Fatalf("stuck row %#v", rows)
	}
	open, err := w.mem.BeginImageOp(context.Background(), entryID, sc.host.ID, hash, owner.ID, "console", w.now, w.now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := w.mem.FinishImageDeploy(ctx, open.ID, "failed", nil, nil, w.now); err == nil {
		t.Fatal("finish used a cancelled context")
	}
	if err := w.mem.ReleaseImageOp(ctx, open.ID); err == nil {
		t.Fatal("release used a cancelled context")
	}
	if _, err := w.mem.BeginImageOp(context.Background(), entryID, sc.host.ID, hash, owner.ID, "console", w.now, w.now.Add(time.Hour)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("cancelled finish cleared the row: %v", err)
	}
}

func TestImageContainersFlag(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx"}`)
	programs := allowImages()
	programs["images"] = false
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, programs, nil)
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return imageDeployReply(msg, shaDigest(1))
	})
	host, err := w.mem.GetHost(context.Background(), sc.host.ID)
	if err != nil || host.Programs == nil || host.Programs.Images || !host.Programs.Docker {
		t.Fatalf("hello flags %#v %v", host.Programs, err)
	}
	status, env, _ := postImage(t, w, tok, sc.project.ID.String(), "web", "deploy", sc.host.ID.String(), "no-img", nil)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "this host does not run containers")
	if log.count() != 0 {
		t.Fatal("images=false dispatched")
	}
}

func TestImageNilKeyDoesNotStick(t *testing.T) {
	cases := []struct {
		name   string
		spec   string
		setup  string
		action string
	}{
		{name: "registry", spec: `{"kind":"service","image":"ghcr.io/joe/app"}`, setup: "registry", action: "deploy"},
		{name: "secret", spec: `{"kind":"service","image":"nginx","secret_env":{"DB_PASSWORD":"lock.DB_PASSWORD"}}`, setup: "secret", action: "deploy"},
		{name: "env", spec: `{"kind":"service","image":"nginx","env_sets":["svc"]}`, setup: "env", action: "deploy"},
		{name: "rollback", spec: `{"kind":"service","image":"nginx","env_sets":["svc"]}`, setup: "env", action: "rollback"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.srv.Secrets = testBox(t)
			owner := w.user("owner@ex.com", "Owner")
			sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
			tok := w.token(owner.ID)
			project := sc.project.ID.String()
			switch tc.setup {
			case "registry":
				putRegistry(t, w, tok, project, "ghcr.io", "bot", regSecret)
			case "secret":
				putEnv(t, w, tok, project, "lock", "DB_PASSWORD="+envSecret+"\n")
			default:
				putEnv(t, w, tok, project, "svc", "FOO="+envSecret+"\n")
			}
			created := createImage(t, w, tok, sc.project.ID, "web", tc.spec)
			entryID := uuid.MustParse(created["id"].(string))
			hash, _ := created["spec_hash"].(string)
			conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
			log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
				return imageDeployReply(msg, shaDigest(2))
			})
			host := sc.host.ID.String()
			extra := map[string]any{}
			if tc.action == "rollback" {
				digest := shaDigest(2)
				row, err := w.mem.BeginImageOp(context.Background(), entryID, sc.host.ID, hash, owner.ID, "console", w.now, w.now.Add(time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := w.mem.FinishImageDeploy(context.Background(), row.ID, "unchanged", &digest, nil, w.now); err != nil {
					t.Fatal(err)
				}
				extra["digest"] = digest
			}
			w.srv.Secrets = nil
			status, env, _ := postImage(t, w, tok, project, "web", tc.action, host, "stick-1", extra)
			mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "secrets key not configured")
			if log.count() != 0 {
				t.Fatal("missing key dispatched")
			}
			w.srv.Secrets = testBox(t)
			status, env, _ = postImage(t, w, tok, project, "web", tc.action, host, "stick-1", extra)
			mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
			if log.count() != 1 {
				t.Fatalf("retry dispatched %d", log.count())
			}
			if objectPayload(t, env)["deploy"].(map[string]any)["outcome"] != "succeeded" {
				t.Fatalf("replayed the error %#v", env.Payload)
			}
		})
	}
}

func TestImageRedactsAgentEcho(t *testing.T) {
	w := newWorld(t)
	logs := captureLog(w)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putEnv(t, w, tok, project, "svc", "FOO="+envSecret+"\n")
	putRegistry(t, w, tok, project, "ghcr.io", "bot", regSecret)
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"ghcr.io/joe/app","env_sets":["svc"]}`)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	var modeMu sync.Mutex
	mode := ""
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		modeMu.Lock()
		bad := mode == "bad"
		modeMu.Unlock()
		if bad {
			return map[string]any{
				"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "failed",
				"error_code": envSecret, "payload": map[string]any{"outcome": "nope", "lines": []string{envSecret}},
			}
		}
		return map[string]any{
			"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "succeeded",
			"payload": map[string]any{
				"outcome": "succeeded", "digest": shaDigest(4), "exit_code": 0,
				"status": map[string]any{"container": "web", "state": "running", "restart_count": 0, "ports": []int{}},
				"lines": []string{
					"raw " + envSecret,
					"std " + base64.StdEncoding.EncodeToString([]byte(envSecret)),
					"rawstd " + base64.RawStdEncoding.EncodeToString([]byte(envSecret)),
					"url " + base64.URLEncoding.EncodeToString([]byte(regSecret)),
					"json " + string(mustQuoted(regSecret)),
					"FOO=" + envSecret,
				},
			},
		}
	})
	host := sc.host.ID.String()
	status, env, raw := postImage(t, w, tok, project, "web", "deploy", host, "echo-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 1 {
		t.Fatal("echo did not dispatch")
	}
	assertNoSecret(t, raw)
	status, env, raw = postImage(t, w, tok, project, "web", "deploy", host, "echo-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 1 {
		t.Fatal("replay dispatched")
	}
	assertNoSecret(t, raw)
	assertNoSecret(t, auditBlob(t, w, sc.project.ID))
	assertNoSecret(t, logs.String())
	modeMu.Lock()
	mode = "bad"
	modeMu.Unlock()
	status, env, raw = postImage(t, w, tok, project, "web", "deploy", host, "echo-bad", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	deploy, _ := objectPayload(t, env)["deploy"].(map[string]any)
	lines, _ := objectPayload(t, env)["lines"].([]any)
	if deploy["outcome"] != "failed" || len(lines) != 1 || lines[0] != invalidAgentResult {
		t.Fatalf("invalid result %#v", env.Payload)
	}
	if strings.Contains(raw, envSecret) || strings.Contains(raw, "nope") {
		t.Fatal("invalid result echoed the agent")
	}
	assertNoSecret(t, raw)
}

func TestImageShortActionsRedactEcho(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putEnv(t, w, tok, project, "svc", "FOO="+envSecret+"\n")
	putRegistry(t, w, tok, project, "ghcr.io", "bot", regSecret)
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"ghcr.io/joe/app","env_sets":["svc"]}`)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	echo := secretEcho()
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		kind, _ := msg["kind"].(string)
		if kind == "image_logs" {
			return map[string]any{
				"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "succeeded",
				"payload": map[string]any{
					"container": echo, "lines": secretEchoLines(), "truncated": false,
				},
			}
		}
		return map[string]any{
			"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "succeeded",
			"payload": map[string]any{"status": map[string]any{
				"container": echo, "state": "running", "restart_count": 0, "ports": []int{},
				"started_at": envSecret, "finished_at": regSecret,
			}},
		}
	})
	host := sc.host.ID.String()
	actions := []string{"logs", "status", "run", "stop", "restart", "remove"}
	stored := map[string]string{}
	for _, action := range actions {
		extra := map[string]any{}
		key := ""
		if action == "logs" {
			extra["lines"] = 50
		}
		if action != "logs" && action != "status" {
			key = "redact-" + action
		}
		status, env, raw := postImage(t, w, tok, project, "web", action, host, key, extra)
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
		assertNoSecret(t, raw)
		assertShortImage(t, action, env)
		task := log.raw(log.count() - 1)
		if task["kind"] != imageKind(action) {
			t.Fatalf("%s kind %#v", action, task["kind"])
		}
		spec, _ := task["spec"].(map[string]any)
		want := "entry,project"
		if action == "logs" {
			want = "entry,lines,project"
			if spec["lines"] != float64(50) {
				t.Fatalf("logs lines %#v", spec["lines"])
			}
		}
		if strings.Join(mapKeys(spec), ",") != want {
			t.Fatalf("%s spec %#v", action, spec)
		}
		for _, forbidden := range []string{"env", "spec", "registry_auth", "secret_env"} {
			if _, ok := spec[forbidden]; ok {
				t.Fatalf("%s frame has %s", action, forbidden)
			}
		}
		frame, err := json.Marshal(task)
		if err != nil {
			t.Fatal(err)
		}
		assertNoSecret(t, string(frame))
		stored[action] = raw
	}
	if log.count() != len(actions) {
		t.Fatalf("dispatched %d", log.count())
	}
	for _, action := range []string{"run", "stop", "restart", "remove"} {
		status, env, raw := postImage(t, w, tok, project, "web", action, host, "redact-"+action, nil)
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
		if raw != stored[action] {
			t.Fatalf("%s replay body changed", action)
		}
		assertNoSecret(t, raw)
	}
	if log.count() != len(actions) {
		t.Fatal("replay dispatched")
	}
}

func TestImageShortRedactWithoutKey(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putEnv(t, w, tok, project, "svc", "FOO="+envSecret+"\n")
	putRegistry(t, w, tok, project, "ghcr.io", "bot", regSecret)
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"ghcr.io/joe/app","env_sets":["svc"]}`)
	w.srv.Secrets = nil
	logs := captureLog(w)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return map[string]any{
			"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "succeeded",
			"payload": map[string]any{
				"container": "password=hunter22",
				"lines":     []string{"password=hunter22", envSecret},
				"truncated": false,
			},
		}
	})
	status, env, raw := postImage(t, w, tok, project, "web", "logs", sc.host.ID.String(), "", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if !strings.Contains(raw, envSecret) || !strings.Contains(raw, "password=[REDACTED]") || strings.Contains(raw, "hunter22") {
		t.Fatalf("key unset body %s", raw)
	}
	if strings.Contains(logs.String(), "decrypt failed") || strings.Contains(logs.String(), envSecret) {
		t.Fatalf("key unset log %s", logs.String())
	}
}

func TestImageShortRedactDecryptFailure(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBoxByte(t, 1)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putEnv(t, w, tok, project, "svc", "FOO="+envSecret+"\nBAR="+envSecret+"\n")
	putRegistry(t, w, tok, project, "ghcr.io", "bot", regSecret)
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"ghcr.io/joe/app","env_sets":["svc"]}`)
	w.srv.Secrets = testBoxByte(t, 2)
	logs := captureLog(w)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	tasks := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return map[string]any{
			"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "succeeded",
			"payload": map[string]any{
				"container": envSecret,
				"lines":     []string{"password=hunter22", envSecret, regSecret},
				"truncated": false,
			},
		}
	})
	status, env, raw := postImage(t, w, tok, project, "web", "logs", sc.host.ID.String(), "", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if tasks.count() != 1 {
		t.Fatal("decrypt failure did not call the agent")
	}
	if !strings.Contains(raw, envSecret) || !strings.Contains(raw, "password=[REDACTED]") || strings.Contains(raw, "hunter22") {
		t.Fatalf("decrypt failure body %s", raw)
	}
	text := logs.String()
	if strings.Count(text, "decrypt failed") != 1 || strings.Contains(text, envSecret) || strings.Contains(text, regSecret) {
		t.Fatalf("decrypt log %s", text)
	}
}

func secretEchoLines() []string {
	return []string{
		envSecret,
		regSecret,
		base64.StdEncoding.EncodeToString([]byte(envSecret)),
		base64.RawStdEncoding.EncodeToString([]byte(envSecret)),
		base64.URLEncoding.EncodeToString([]byte(regSecret)),
		base64.RawURLEncoding.EncodeToString([]byte(regSecret)),
		string(mustQuoted(regSecret)),
	}
}

func secretEcho() string {
	return strings.Join(secretEchoLines(), " ")
}

func assertShortImage(t *testing.T, action string, env envelope) {
	t.Helper()
	payload := objectPayload(t, env)
	if action == "remove" {
		status, _ := payload["status"].(map[string]any)
		payload = status
	}
	if action == "logs" {
		lines, _ := payload["lines"].([]any)
		if payload["container"] == nil || len(lines) == 0 {
			t.Fatalf("logs %#v", payload)
		}
		return
	}
	ports, _ := payload["ports"].([]any)
	count, _ := payload["restart_count"].(float64)
	if payload["state"] != "running" || count < 0 || ports == nil {
		t.Fatalf("%s status %#v", action, payload)
	}
}

func TestImageAuditDetail(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putEnv(t, w, tok, project, "svc", "FOO="+envSecret+"\n")
	putRegistry(t, w, tok, project, "ghcr.io", "bot", regSecret)
	created := createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"ghcr.io/joe/app","env_sets":["svc"]}`)
	entryID := uuid.MustParse(created["id"].(string))
	hash, _ := created["spec_hash"].(string)
	digest := shaDigest(8)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	watchTasks(t, conn, func(msg map[string]any) map[string]any {
		kind, _ := msg["kind"].(string)
		if kind == "image_remove" {
			return imageStatusReply(msg)
		}
		return imageDeployReply(msg, digest)
	})
	host := sc.host.ID.String()
	status, env, _ := postImage(t, w, tok, project, "web", "deploy", host, "aud-d", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	row, err := w.mem.BeginImageOp(context.Background(), entryID, sc.host.ID, hash, owner.ID, "console", w.now, w.now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.FinishImageDeploy(context.Background(), row.ID, "succeeded", &digest, nil, w.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	status, env, _ = postImage(t, w, tok, project, "web", "rollback", host, "aud-r", map[string]any{"digest": digest})
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env, _ = postImage(t, w, tok, project, "web", "remove", host, "aud-m", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	want := map[string]bool{"catalog.deploy": false, "catalog.rollback": false, "catalog.remove": false, "env_set.replace": false, "registry.put": false}
	for _, row := range auditRows(t, w, sc.project.ID) {
		detail := string(row.Detail)
		if _, ok := want[row.Action]; ok {
			want[row.Action] = true
		}
		switch row.Action {
		case "catalog.deploy", "catalog.rollback", "catalog.remove":
			if !strings.Contains(detail, `"entry":"web"`) || !strings.Contains(detail, `"host":"pi4"`) || !strings.Contains(detail, `"outcome"`) {
				t.Fatalf("%s detail %s", row.Action, detail)
			}
			if strings.Contains(detail, envSecret) || strings.Contains(detail, regSecret) {
				t.Fatalf("%s stored a secret", row.Action)
			}
		case "env_set.replace":
			if !strings.Contains(detail, "FOO") || strings.Contains(detail, envSecret) {
				t.Fatalf("env audit %s", detail)
			}
		case "registry.put":
			if !strings.Contains(detail, "ghcr.io") || strings.Contains(detail, regSecret) || strings.Contains(detail, "bot") {
				t.Fatalf("registry audit %s", detail)
			}
		}
	}
	for action, ok := range want {
		if !ok {
			t.Fatalf("missing audit %s", action)
		}
	}
}

func TestImageFrameTooLarge(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	var dotenv strings.Builder
	value := strings.Repeat("<", 4096)
	for i := 0; i < 43; i++ {
		fmt.Fprintf(&dotenv, "K%02d=%s\n", i, value)
	}
	putEnv(t, w, tok, project, "big", dotenv.String())
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","env_sets":["big"]}`)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return imageDeployReply(msg, shaDigest(4))
	})
	host := sc.host.ID.String()
	before := auditRows(t, w, sc.project.ID)
	for _, key := range []string{"big-1", "big-2"} {
		status, env, raw := postImage(t, w, tok, project, "web", "deploy", host, key, nil)
		mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "the resolved environment is too large for one task")
		if strings.Contains(raw, "<") || strings.Contains(raw, `\u003c`) || log.count() != 0 {
			t.Fatalf("oversize %s dispatched or echoed a value", key)
		}
	}
	for _, row := range auditRows(t, w, sc.project.ID) {
		if row.Action == "catalog.deploy" {
			t.Fatalf("oversize audited a deploy %s", row.Detail)
		}
	}
	if len(auditRows(t, w, sc.project.ID)) < len(before) {
		t.Fatal("oversize removed an audit row")
	}
	createImage(t, w, tok, sc.project.ID, "tiny", `{"kind":"service","image":"nginx"}`)
	status, env, _ := postImage(t, w, tok, project, "tiny", "deploy", host, "tiny-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 1 || log.raw(0)["kind"] != "image_deploy" {
		t.Fatalf("connection did not take the next task %#v", log.raw(0))
	}
}

func TestImageClosedTaskSpecs(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putEnv(t, w, tok, project, "svc", "TOKEN="+envSecret+"\n")
	putRegistry(t, w, tok, project, "docker.io", "bot", "dock-token-value")
	created := createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","env_sets":["svc"]}`)
	entryID := uuid.MustParse(created["id"].(string))
	hash, _ := created["spec_hash"].(string)
	digest := shaDigest(2)
	seed, err := w.mem.BeginImageOp(context.Background(), entryID, sc.host.ID, hash, owner.ID, "console", w.now, w.now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.FinishImageDeploy(context.Background(), seed.ID, "succeeded", &digest, nil, w.now); err != nil {
		t.Fatal(err)
	}
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		kind, _ := msg["kind"].(string)
		if kind == "image_rollback" {
			return imageDeployReply(msg, digest)
		}
		return imageStatusReply(msg)
	})
	host := sc.host.ID.String()
	for _, action := range []string{"run", "stop", "restart", "status", "remove"} {
		key := ""
		if action != "status" {
			key = "closed-" + action
		}
		status, env, _ := postImage(t, w, tok, project, "web", action, host, key, nil)
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
		spec, _ := log.raw(log.count() - 1)["spec"].(map[string]any)
		raw, err := json.Marshal(log.raw(log.count() - 1))
		if err != nil || strings.Join(mapKeys(spec), ",") != "entry,project" || strings.Contains(string(raw), envSecret) || strings.Contains(string(raw), "dock-token-value") {
			t.Fatalf("%s spec %#v %s", action, spec, raw)
		}
	}
	status, env, _ := postImage(t, w, tok, project, "web", "rollback", host, "closed-roll", map[string]any{"digest": digest})
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	spec, _ := log.raw(log.count() - 1)["spec"].(map[string]any)
	if strings.Join(mapKeys(spec), ",") != "digest,entry,env,force,project,registry_auth,spec,spec_hash" {
		t.Fatalf("rollback keys %#v", spec)
	}
	frame, err := json.Marshal(log.raw(log.count() - 1))
	if err != nil || strings.Count(string(frame), envSecret) != 1 || strings.Count(string(frame), "dock-token-value") != 1 {
		t.Fatalf("rollback copies %s", frame)
	}
}

func TestImageEnvSetOrder(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putEnv(t, w, tok, project, "base", "FOO=base\nSHARED=base\nLAYER=base\n")
	putEnv(t, w, tok, project, "override", "FOO=override\nSHARED=override\nEXTRA=override\nLAYER=override\n")
	putEnv(t, w, tok, project, "lock", "SHARED=from-lock\n")
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","env_sets":["base","override"],"secret_env":{"SHARED":"lock.SHARED"},"env":{"FOO":"inline"}}`)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return imageDeployReply(msg, shaDigest(3))
	})
	status, env, _ := postImage(t, w, tok, project, "web", "deploy", sc.host.ID.String(), "order-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	spec, _ := log.raw(0)["spec"].(map[string]any)
	envMap, _ := spec["env"].(map[string]any)
	if envMap["FOO"] != "inline" || envMap["SHARED"] != "from-lock" || envMap["EXTRA"] != "override" || envMap["LAYER"] != "override" || len(envMap) != 4 {
		t.Fatalf("merged %#v", envMap)
	}
	nested, _ := spec["spec"].(map[string]any)
	nestedEnv, _ := nested["env"].(map[string]any)
	sets, _ := nested["env_sets"].([]any)
	secret, _ := nested["secret_env"].(map[string]any)
	if nestedEnv["FOO"] != "inline" || len(nestedEnv) != 1 || len(sets) != 2 || sets[0] != "base" || sets[1] != "override" || secret["SHARED"] != "lock.SHARED" {
		t.Fatalf("stored %#v", nested)
	}
	frame, err := json.Marshal(log.raw(0))
	if err != nil || strings.Count(string(frame), "from-lock") != 1 {
		t.Fatalf("lock copies %s", frame)
	}
}

func TestImageSecretEnvRehash(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	guestUser := w.user("guest@ex.com", "Guest")
	guest, err := w.mem.CreateProject(context.Background(), guestUser.ID, "Guest", "guest", w.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.mem.PutHostShare(context.Background(), sc.host.ID, guest.ID, "deploy", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	gtok := w.token(guestUser.ID)
	gpath := guest.ID.String()
	putEnv(t, w, gtok, gpath, "lock", "KEY="+envSecret+"\n")
	created := createImage(t, w, gtok, guest.ID, "web", `{"kind":"service","image":"nginx","secret_env":{"TOKEN":"lock.KEY"}}`)
	hash, _ := created["spec_hash"].(string)
	entryID, _ := created["id"].(string)
	host := sc.host.ID.String()
	status, env, _ := postImage(t, w, gtok, gpath, "web", "deploy", host, "sec-1", nil)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "waiting for the host owner's approval")
	approve := func(specHash string) {
		t.Helper()
		status, env, _ := mustCall(t, w, w.token(owner.ID), http.MethodPost, "/v1/hosts/"+host+"/catalog-approvals", `{"entry_id":"`+entryID+`","spec_hash":"`+specHash+`"}`)
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	}
	approve(hash)
	putEnv(t, w, gtok, gpath, "lock", "KEY="+envSecret+"-other\n")
	if createImageGet(t, w, gtok, guest.ID, "web")["spec_hash"] != hash || len(listApprovals(t, w, owner.ID, sc.host.ID)) != 1 {
		t.Fatal("value rewrite changed the hash or dropped the approval")
	}
	putEnv(t, w, gtok, gpath, "lock", "KEY="+envSecret+"\nBAR=1\n")
	added := createImageGet(t, w, gtok, guest.ID, "web")
	addedHash, _ := added["spec_hash"].(string)
	if addedHash == hash || len(listApprovals(t, w, owner.ID, sc.host.ID)) != 0 {
		t.Fatalf("adding a secret_env key kept the hash or the approval %#v", added)
	}
	approve(addedHash)
	if len(listApprovals(t, w, owner.ID, sc.host.ID)) != 1 {
		t.Fatal("re-approval did not stick")
	}
	putEnv(t, w, gtok, gpath, "lock", "KEY="+envSecret+"\n")
	removed := createImageGet(t, w, gtok, guest.ID, "web")
	if removed["spec_hash"] == addedHash || len(listApprovals(t, w, owner.ID, sc.host.ID)) != 0 {
		t.Fatalf("removing a secret_env key kept the hash or the approval %#v", removed)
	}
}

func TestRedactExactBeforeKeyword(t *testing.T) {
	secret := "s3cret token hunter22"
	got := redactExact("line "+secret, secretForms([]string{secret}))
	if strings.Contains(got, "s3cret") {
		t.Fatalf("keyword regex hid the value from exact replace: %q", got)
	}
}

func TestSettleRetriesOnFreshContext(t *testing.T) {
	srv := &Server{}
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	var calls int
	err := srv.settle(func(ctx context.Context) error {
		calls++
		if ctx.Err() != nil || ctx == parent {
			t.Fatalf("settle reused the cancelled context: %v", ctx.Err())
		}
		if calls == 1 {
			return errors.New("once")
		}
		return nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("retry %v calls %d", err, calls)
	}
	calls = 0
	err = srv.settle(func(context.Context) error {
		calls++
		return errors.New("still")
	})
	if err == nil || calls != 2 {
		t.Fatalf("two failures %v calls %d", err, calls)
	}
}

func mustQuoted(s string) []byte {
	raw, _ := json.Marshal(s)
	return raw
}

func allowImages() map[string]any {
	return map[string]any{"enabled": true, "run_as": []string{"joe"}, "allow_shell": false, "policy_hash": "abc", "images": true, "docker": true}
}

func testBox(t *testing.T) *seal.Box {
	t.Helper()
	return testBoxByte(t, 7)
}

func testBoxByte(t *testing.T, b byte) *seal.Box {
	t.Helper()
	box, err := seal.New(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return box
}

func captureLog(w *world) *bytes.Buffer {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	w.srv.Log = log
	w.srv.Audit.Log = log
	w.hub.SetLog(log)
	return &buf
}

func createImage(t *testing.T, w *world, tok string, project uuid.UUID, name, spec string) map[string]any {
	t.Helper()
	status, env, _ := mustCall(t, w, tok, http.MethodPost, "/v1/projects/"+project.String()+"/catalog", `{"name":"`+name+`","kind":"image","spec":`+spec+`}`)
	mustHTTP(t, status, env, http.StatusCreated, "ok", "ok")
	return objectPayload(t, env)
}

func createImageGet(t *testing.T, w *world, tok string, project uuid.UUID, name string) map[string]any {
	t.Helper()
	status, env, _ := mustCall(t, w, tok, http.MethodGet, "/v1/projects/"+project.String()+"/catalog/"+name, "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	return objectPayload(t, env)
}

func putEnv(t *testing.T, w *world, tok, project, set, dotenv string) {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"dotenv": dotenv})
	if err != nil {
		t.Fatal(err)
	}
	status, env, _ := mustCall(t, w, tok, http.MethodPut, envPath(project, set), string(raw))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
}

func putRegistry(t *testing.T, w *world, tok, project, host, user, token string) {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"username": user, "token": token})
	if err != nil {
		t.Fatal(err)
	}
	status, env, _ := mustCall(t, w, tok, http.MethodPut, regPath(project, host), string(raw))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
}

func postImage(t *testing.T, w *world, tok, project, name, action, host, key string, extra map[string]any) (int, envelope, string) {
	t.Helper()
	body := map[string]any{"host_id": host}
	if action != "logs" && action != "status" {
		body["idempotency_key"] = key
	}
	for k, v := range extra {
		body[k] = v
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return mustCall(t, w, tok, http.MethodPost, imagePath(project, name, action), string(raw))
}

func imagePath(project, name, action string) string {
	return "/v1/projects/" + project + "/catalog/" + name + "/" + action
}

func imageBody(host, key string, extra map[string]any) string {
	body := map[string]any{"host_id": host, "idempotency_key": key}
	for k, v := range extra {
		body[k] = v
	}
	raw, _ := json.Marshal(body)
	return string(raw)
}

func envPath(project, set string) string {
	return "/v1/projects/" + project + "/env-sets/" + set
}

func regPath(project, host string) string {
	return "/v1/projects/" + project + "/registries/" + host
}

type callResult struct {
	status int
	env    envelope
	raw    string
	err    error
}

func mustCall(t *testing.T, w *world, token, method, path, body string) (int, envelope, string) {
	t.Helper()
	status, env, raw, err := callRaw(w, token, method, path, body)
	if err != nil {
		t.Fatal(err)
	}
	return status, env, raw
}

func callRaw(w *world, token, method, path, body string) (int, envelope, string, error) {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, w.http.URL+path, rdr)
	if err != nil {
		return 0, envelope{}, "", err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := w.client.Do(req)
	if err != nil {
		return 0, envelope{}, "", err
	}
	defer res.Body.Close()
	buf, err := io.ReadAll(res.Body)
	if err != nil {
		return res.StatusCode, envelope{}, "", err
	}
	var env envelope
	if err := json.Unmarshal(buf, &env); err != nil {
		return res.StatusCode, envelope{}, string(buf), err
	}
	return res.StatusCode, env, string(buf), nil
}

func imageDeployReply(msg map[string]any, digest string) map[string]any {
	return map[string]any{
		"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "succeeded",
		"payload": map[string]any{
			"outcome": "succeeded", "digest": digest, "exit_code": 0,
			"status": map[string]any{
				"container": "web", "state": "running", "restart_count": 0,
				"exit_code": nil, "started_at": nil, "finished_at": nil,
				"digest": digest, "ports": []int{80},
			},
			"lines": []string{"pulled"},
		},
	}
}

func imageStatusReply(msg map[string]any) map[string]any {
	kind, _ := msg["kind"].(string)
	if kind == "image_logs" {
		return map[string]any{
			"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "succeeded",
			"payload": map[string]any{"container": "web", "lines": []string{"log"}, "truncated": false},
		}
	}
	return map[string]any{
		"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "succeeded",
		"payload": map[string]any{"status": map[string]any{
			"container": "web", "state": "running", "restart_count": 0, "ports": []int{},
		}},
	}
}

func shaDigest(n byte) string {
	return "sha256:" + strings.Repeat(fmt.Sprintf("%02x", n), 32)
}

func mapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func grantJSON(grants []any, subject, actions string) bool {
	for _, item := range grants {
		g, _ := item.(map[string]any)
		if g["subject"] != subject {
			continue
		}
		got, ok := g["actions"].([]any)
		if !ok {
			return false
		}
		parts := make([]string, len(got))
		for i, item := range got {
			s, ok := item.(string)
			if !ok {
				return false
			}
			parts[i] = s
		}
		return strings.Join(parts, ",") == actions
	}
	return false
}

func listApprovals(t *testing.T, w *world, owner uuid.UUID, host uuid.UUID) []map[string]any {
	t.Helper()
	status, env, _ := mustCall(t, w, w.token(owner), http.MethodGet, "/v1/hosts/"+host.String()+"/catalog-approvals", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	return listItems(t, env)
}

func mustText(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

func auditBlob(t *testing.T, w *world, project uuid.UUID) string {
	t.Helper()
	raw, err := json.Marshal(auditRows(t, w, project))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func assertNoSecret(t *testing.T, blob string) {
	t.Helper()
	for _, secret := range []string{envSecret, regSecret} {
		forms := []string{
			secret,
			base64.StdEncoding.EncodeToString([]byte(secret)),
			base64.RawStdEncoding.EncodeToString([]byte(secret)),
			base64.URLEncoding.EncodeToString([]byte(secret)),
			base64.RawURLEncoding.EncodeToString([]byte(secret)),
		}
		quoted, err := json.Marshal(secret)
		if err != nil {
			t.Fatal(err)
		}
		forms = append(forms, string(quoted))
		for _, form := range forms {
			if form != "" && strings.Contains(blob, form) {
				t.Fatalf("secret material leaked (%d bytes)", len(form))
			}
		}
	}
}
