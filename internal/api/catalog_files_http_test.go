package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestFileContentRules(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	base := "/v1/projects/" + project + "/files"

	for _, name := range []string{"Bad", ".env", "-a", strings.Repeat("b", 65)} {
		status, env, raw := mustCall(t, w, tok, http.MethodPut, base+"/"+name, `{"content":"x","secret":false}`)
		mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid name")
		if strings.Contains(raw, name) || len(raw) > 160 {
			t.Fatalf("name error echoed %s", name)
		}
	}
	marker := "BODYMARKER-do-not-echo"
	bodies := []struct {
		name string
		body string
		want string
	}{
		{"empty", `{"content":""}`, "invalid content"},
		{"missing", `{}`, "invalid content"},
		{"nul", `{"content":"` + marker + `\u0000"}`, "invalid content"},
		{"long", `{"content":"` + marker + strings.Repeat("a", catalog.MaxFileBytes) + `"}`, "invalid content"},
	}
	for _, tc := range bodies {
		status, env, raw := mustCall(t, w, tok, http.MethodPut, base+"/app.conf", tc.body)
		mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", tc.want)
		if strings.Contains(raw, marker) || strings.Contains(raw, "app.conf") {
			t.Fatalf("%s echoed content", tc.name)
		}
	}
	status, env, raw := mustCall(t, w, tok, http.MethodPut, base+"/app.conf", "{\"content\":\""+string([]byte{0xff})+"\"}")
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid json")
	if strings.Contains(raw, "\xff") {
		t.Fatal("invalid utf-8 was echoed")
	}

	const plainBody = "héllo"
	sum := sha256.Sum256([]byte(plainBody))
	wantHash := hex.EncodeToString(sum[:])
	status, env, raw = putFile(t, w, tok, project, "app.conf", plainBody, boolPtr(false))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	plain := objectPayload(t, env)
	if plain["is_secret"] != false || plain["sha256"] != wantHash || plain["content"] != nil || plain["size"] != float64(len(plainBody)) {
		t.Fatalf("plain put %#v", plain)
	}
	if strings.Contains(raw, "héllo") {
		t.Fatal("put returned content")
	}
	status, env, raw = mustCall(t, w, tok, http.MethodGet, base+"/app.conf", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	got := objectPayload(t, env)
	if got["content"] != plainBody || got["sha256"] != wantHash || got["is_secret"] != nil {
		t.Fatalf("plain get %#v", got)
	}
	full := strings.Repeat("c", catalog.MaxFileBytes)
	status, env, _ = putFile(t, w, tok, project, "full.txt", full, boolPtr(false))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env, raw = mustCall(t, w, tok, http.MethodGet, base+"/full.txt", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if objectPayload(t, env)["content"] != full {
		t.Fatal("max body was truncated")
	}

	status, env, raw = putFile(t, w, tok, project, "key.json", "sekret-file-VALUE", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	secretPut := objectPayload(t, env)
	if secretPut["is_secret"] != true || secretPut["sha256"] != nil {
		t.Fatalf("omitted secret %#v", secretPut)
	}
	assertSecretAbsent(t, "put", raw, "sekret-file-VALUE")
	status, env, raw = mustCall(t, w, tok, http.MethodPut, base+"/null.json", `{"content":"sekret-null-VALUE","secret":null}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if objectPayload(t, env)["is_secret"] != true {
		t.Fatal("null secret was not secret")
	}
	assertSecretAbsent(t, "null put", raw, "sekret-null-VALUE")
	status, env, raw = mustCall(t, w, tok, http.MethodGet, base+"/key.json", "")
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	assertSecretAbsent(t, "secret get", raw, "sekret-file-VALUE")
	if strings.Contains(raw, `"content"`) {
		t.Fatal("secret get returned content")
	}
	status, env, raw = mustCall(t, w, tok, http.MethodGet, base, "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertSecretAbsent(t, "list plain", raw, "héllo")
	assertSecretAbsent(t, "list secret", raw, "sekret-file-VALUE")
	if strings.Contains(raw, full[:32]) || strings.Contains(raw, `"content"`) {
		t.Fatal("list returned content")
	}
	items := listItems(t, env)
	if len(items) != 4 || items[0]["name"] != "app.conf" || items[1]["name"] != "full.txt" || items[2]["name"] != "key.json" || items[3]["name"] != "null.json" {
		t.Fatalf("order %#v", items)
	}
	if items[0]["sha256"] != wantHash || items[2]["sha256"] != nil || items[2]["is_secret"] != true {
		t.Fatalf("sha %#v", items)
	}
	status, env, _ = mustCall(t, w, tok, http.MethodGet, base+"/missing", "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	status, env, _ = mustCall(t, w, tok, http.MethodDelete, base+"/missing", "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")

	for i := 0; i < store.MaxProjectFiles-4; i++ {
		name := "f" + hex.EncodeToString([]byte{byte(i)})
		status, env, _ = putFile(t, w, tok, project, name, "x", boolPtr(false))
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	}
	status, env, raw = putFile(t, w, tok, project, "extra", "x", boolPtr(false))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "too many files")
	if strings.Contains(raw, "extra") && strings.Contains(raw, `"content"`) {
		t.Fatal("limit error echoed content")
	}
	status, env, _ = putFile(t, w, tok, project, "app.conf", "replaced", boolPtr(false))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	var sawPut, sawDelete bool
	status, env, _ = mustCall(t, w, tok, http.MethodDelete, base+"/null.json", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if env.Payload != nil {
		t.Fatalf("delete payload %#v", env.Payload)
	}
	for _, row := range auditRows(t, w, sc.project.ID) {
		detail := string(row.Detail)
		switch row.Action {
		case "file.put":
			if strings.Contains(detail, `"name":"key.json"`) && strings.Contains(detail, `"is_secret":true`) && strings.Contains(detail, `"size":`) {
				sawPut = true
			}
			if strings.Contains(detail, "sekret") || strings.Contains(detail, "sha256") || strings.Contains(detail, "héllo") {
				t.Fatalf("put audit %s", detail)
			}
		case "file.delete":
			if strings.Contains(detail, `"name":"null.json"`) && !strings.Contains(detail, "sekret") {
				sawDelete = true
			}
		}
	}
	if !sawPut || !sawDelete {
		t.Fatalf("audit put %v delete %v", sawPut, sawDelete)
	}
}

func TestFileGates(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("admin@ex.com", "Admin")
	viewer := w.user("viewer@ex.com", "Viewer")
	extra := w.user("extra@ex.com", "Extra")
	sc := w.scene(owner, admin, viewer, w.user("s@ex.com", "S"), extra)
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	base := "/v1/projects/" + project + "/files"
	putFile(t, w, tok, project, "app.conf", "plain-config-line", boolPtr(false))
	putFile(t, w, tok, project, "key.json", "sekret-gate-VALUE", nil)

	viewerTok := w.token(viewer.ID)
	for _, call := range []struct{ method, path, body string }{
		{http.MethodGet, base, ""},
		{http.MethodGet, base + "/app.conf", ""},
		{http.MethodPut, base + "/app.conf", `{"content":"nope","secret":false}`},
		{http.MethodDelete, base + "/app.conf", ""},
	} {
		status, env, raw := mustCall(t, w, viewerTok, call.method, call.path, call.body)
		mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
		if strings.Contains(raw, "plain-config-line") || strings.Contains(raw, "sekret-gate-VALUE") {
			t.Fatalf("viewer %s returned a file", call.method)
		}
	}
	status, env, _ := mustCall(t, w, w.token(extra.ID), http.MethodGet, base, "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	status, env, _ = mustCall(t, w, tokenKind(t, w, extra.ID, store.KindDelegated), http.MethodGet, base+"/app.conf", "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	for _, kind := range []string{store.KindDelegated, store.KindMCPAccess, store.KindMCPRefresh} {
		wantStatus, wantCode, wantMsg := http.StatusForbidden, "forbidden", "forbidden"
		// The audience rule refuses mcp_access and mcp_refresh on every /v1 route
		// as invalid_token before the handler. Delegated tokens reach requireConsole.
		if kind == store.KindMCPAccess || kind == store.KindMCPRefresh {
			wantStatus, wantCode, wantMsg = http.StatusUnauthorized, "invalid_token", "invalid token"
		}
		status, env, raw := mustCall(t, w, tokenKind(t, w, owner.ID, kind), http.MethodGet, base+"/app.conf", "")
		mustHTTP(t, status, env, wantStatus, wantCode, wantMsg)
		if strings.Contains(raw, "plain-config-line") || strings.Contains(raw, "sekret-gate-VALUE") {
			t.Fatalf("%s returned a file", kind)
		}
		status, env, _ = mustCall(t, w, tokenKind(t, w, owner.ID, kind), http.MethodPut, base+"/other.conf", `{"content":"nope","secret":false}`)
		mustHTTP(t, status, env, wantStatus, wantCode, wantMsg)
	}
	status, env, _ = mustCall(t, w, tok, http.MethodGet, base+"/other.conf", "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	status, env, _ = putFile(t, w, w.token(admin.ID), project, "admin.conf", "admin-plain", boolPtr(false))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env, _ = mustCall(t, w, tok, http.MethodGet, base+"/app.conf", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if objectPayload(t, env)["content"] != "plain-config-line" {
		t.Fatal("a forbidden call changed the file")
	}
}

func TestFileSecretLeak(t *testing.T) {
	const secretLine = "LINE-OF-SECRET-do-not-leak-9f3a"
	const secret = "SECRET<FILE>CONTENT-do-not-leak-9f3a\n" + secretLine
	w := newWorld(t)
	logs := captureLog(w)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putFile(t, w, tok, project, "zeta.json", secret, nil)
	putFile(t, w, tok, project, "alpha.conf", "plain-config-line", boolPtr(false))
	created := createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","files":[{"file":"zeta.json","target":"/run/secrets/zeta.json"},{"file":"alpha.conf","target":"/config/alpha.conf"}]}`)
	programs := allowImages()
	programs["files"] = true
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, programs, nil)
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		kind, _ := msg["kind"].(string)
		if kind == "image_logs" {
			return map[string]any{
				"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "succeeded",
				"payload": map[string]any{"container": "web", "lines": []string{secret, secretLine}, "truncated": false},
			}
		}
		reply := imageDeployReply(msg, shaDigest(8))
		reply["payload"].(map[string]any)["lines"] = []string{secret, secretLine}
		return reply
	})
	host := sc.host.ID.String()
	delegated := tokenKind(t, w, owner.ID, store.KindDelegated)
	status, env, raw := postImage(t, w, delegated, project, "web", "deploy", host, "leak-del", nil)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	if objectPayload(t, env)["plan"] != "will deploy web (docker.io/library/nginx:latest) on pi4" || log.count() != 0 {
		t.Fatalf("plan %#v tasks %d", env.Payload, log.count())
	}
	assertSecretAbsent(t, "plan", raw, secret)
	assertSecretAbsent(t, "plan line", raw, secretLine)
	status, env, raw = postImage(t, w, tok, project, "web", "deploy", host, "leak-run", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if !strings.Contains(raw, "[redacted]") || log.count() != 1 {
		t.Fatalf("deploy did not redact the echo or did not send one task: %s", raw)
	}
	assertSecretAbsent(t, "deploy", raw, secret)
	assertSecretAbsent(t, "deploy line", raw, secretLine)
	assertFrameSecret(t, log.raw(0), secret)
	status, env, raw = postImage(t, w, tok, project, "web", "deploy", host, "leak-run", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 1 {
		t.Fatal("replay dispatched again")
	}
	assertSecretAbsent(t, "replay", raw, secret)
	assertSecretAbsent(t, "replay line", raw, secretLine)
	status, env, raw = mustCall(t, w, tok, http.MethodGet, "/v1/projects/"+project+"/catalog/web/deploys?host_id="+host, "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertSecretAbsent(t, "history", raw, secret)
	assertSecretAbsent(t, "history line", raw, secretLine)
	status, env, raw = postImage(t, w, tok, project, "web", "logs", host, "", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if !strings.Contains(raw, "[redacted]") {
		t.Fatal("logs did not redact the echo")
	}
	assertSecretAbsent(t, "logs", raw, secret)
	assertSecretAbsent(t, "logs line", raw, secretLine)
	if log.count() != 2 || log.raw(1)["kind"] != "image_logs" {
		t.Fatalf("logs task %#v count %d", log.raw(1), log.count())
	}
	logsTask, err := json.Marshal(log.raw(1))
	if err != nil {
		t.Fatal(err)
	}
	assertSecretAbsent(t, "logs task", string(logsTask), secret)
	assertSecretAbsent(t, "logs task line", string(logsTask), secretLine)
	if strings.Contains(string(logsTask), "plain-config-line") {
		t.Fatal("image_logs carried file content")
	}
	logsSpec, _ := log.raw(1)["spec"].(map[string]any)
	if _, ok := logsSpec["files"]; ok {
		t.Fatal("image_logs has files")
	}
	status, env, raw = postImage(t, w, tok, project, "web", "rollback", host, "leak-roll", map[string]any{"digest": shaDigest(8)})
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertSecretAbsent(t, "rollback", raw, secret)
	assertSecretAbsent(t, "rollback line", raw, secretLine)
	if log.count() != 3 || log.raw(2)["kind"] != "image_rollback" {
		t.Fatalf("rollback tasks %d", log.count())
	}
	assertFrameSecret(t, log.raw(2), secret)
	audit := auditText(t, w, sc.project.ID)
	assertSecretAbsent(t, "audit", audit, secret)
	assertSecretAbsent(t, "audit line", audit, secretLine)
	serverLog := logs.String()
	assertSecretAbsent(t, "log", serverLog, secret)
	assertSecretAbsent(t, "log line", serverLog, secretLine)
	if created["spec_hash"] == "" {
		t.Fatal("missing hash")
	}
}

func TestFileHostSupport(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putFile(t, w, tok, project, "app.conf", "plain-config-line", boolPtr(false))
	createImage(t, w, tok, sc.project.ID, "bare", `{"kind":"service","image":"nginx"}`)
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/config/app.conf"}]}`)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return imageDeployReply(msg, shaDigest(2))
	})
	host := sc.host.ID.String()
	status, env, _ := postImage(t, w, tok, project, "bare", "deploy", host, "bare-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	spec, _ := log.raw(0)["spec"].(map[string]any)
	nested, _ := spec["spec"].(map[string]any)
	_, topFiles := spec["files"]
	_, nestedFiles := nested["files"]
	if log.raw(0)["kind"] != "image_deploy" || topFiles || nestedFiles || spec["spec_hash"] != "578b58b80ed177e86358709c3a24c704c76e0f70c90fe3ae9fd47ffc025a7e30" || strings.Join(mapKeys(spec), ",") != "entry,env,force,project,registry_auth,spec,spec_hash" {
		t.Fatalf("bare frame %#v", spec)
	}
	status, env, _ = postImage(t, w, tok, project, "web", "deploy", host, "files-1", nil)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "this host's agent does not support files")
	if log.count() != 1 {
		t.Fatal("unsupported host dispatched")
	}
	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: true, PolicyHash: "abc", Files: true})
	status, env, _ = postImage(t, w, tok, project, "web", "deploy", host, "files-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 2 {
		t.Fatal("files support did not send the refused key")
	}
	frame, _ := log.raw(1)["spec"].(map[string]any)
	rows, _ := frame["files"].([]any)
	row, _ := rows[0].(map[string]any)
	nestedSpec, _ := frame["spec"].(map[string]any)
	nestedRows, _ := nestedSpec["files"].([]any)
	nestedRow, _ := nestedRows[0].(map[string]any)
	secretKeys, isSlice := frame["secret_keys"].([]any)
	if len(rows) != 1 || row["name"] != "app.conf" || row["target"] != "/config/app.conf" || row["content"] != "plain-config-line" || row["secret"] != false || len(nestedRows) != 1 || nestedRow["file"] != "app.conf" || nestedRow["target"] != "/config/app.conf" || nestedRow["content"] != nil || !isSlice || len(secretKeys) != 0 {
		t.Fatalf("files frame %#v nested %#v secret_keys %#v", rows, nestedRows, frame["secret_keys"])
	}
	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: true, PolicyHash: "abc", Files: false})
	status, env, _ = postImage(t, w, tok, project, "web", "rollback", host, "files-roll", map[string]any{"digest": shaDigest(2)})
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "this host's agent does not support files")
	if log.count() != 2 {
		t.Fatal("unsupported rollback dispatched")
	}
	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: true, PolicyHash: "abc", Files: true})

	delegated := tokenKind(t, w, owner.ID, store.KindDelegated)
	status, env, _ = postImage(t, w, delegated, project, "web", "deploy", host, "files-del", nil)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	if log.count() != 2 {
		t.Fatal("confirmation dispatched")
	}
	id, _ := objectPayload(t, env)["confirmation_id"].(string)
	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: true, PolicyHash: "abc", Files: false})
	status, env, _ = mustCall(t, w, delegated, http.MethodPost, "/v1/confirmations/"+id, confirmBody("files-del"))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "this host's agent does not support files")
	if log.count() != 2 {
		t.Fatal("confirm dispatched without files support")
	}
	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, Images: true, Docker: true, PolicyHash: "abc", Files: true})
	status, env, _ = mustCall(t, w, delegated, http.MethodPost, "/v1/confirmations/"+id, confirmBody("files-del"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 3 {
		t.Fatal("confirm did not dispatch after files support returned")
	}
}

func TestImageDuplicateFileName(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putFile(t, w, tok, project, "app.conf", "plain-config-line", boolPtr(false))
	status, env, raw := mustCall(t, w, tok, http.MethodPost, "/v1/projects/"+project+"/catalog", `{"name":"web","kind":"image","spec":{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/config/a"},{"file":"app.conf","target":"/config/b"}]}}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid files")
	if strings.Contains(raw, "app.conf") || strings.Contains(raw, "/config") {
		t.Fatalf("duplicate name echoed %s", raw)
	}
}

func TestFileDeployEdges(t *testing.T) {
	const secret = "SECRET<FILE>CONTENT-do-not-leak-9f3a"
	w := newWorld(t)
	logs := captureLog(w)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	status, env, raw := putFile(t, w, tok, project, "app.conf", "plain-config-line", boolPtr(false))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env, raw = putFile(t, w, tok, project, "key.json", secret, nil)
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "secrets key not configured")
	assertSecretAbsent(t, "nokey put", raw, secret)
	created := createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/config/app.conf"}]}`)
	hash, _ := created["spec_hash"].(string)
	programs := allowImages()
	programs["files"] = true
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, programs, nil)
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return imageDeployReply(msg, shaDigest(3))
	})
	host := sc.host.ID.String()
	status, env, _ = postImage(t, w, tok, project, "web", "deploy", host, "plain-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	w.srv.Secrets = testBox(t)
	putFile(t, w, tok, project, "key.json", secret, nil)
	createImage(t, w, tok, sc.project.ID, "locked", `{"kind":"service","image":"nginx","files":[{"file":"key.json","target":"/run/secrets/key.json"}]}`)
	w.srv.Secrets = nil
	status, env, raw = postImage(t, w, tok, project, "locked", "deploy", host, "locked-1", nil)
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "secrets key not configured")
	assertSecretAbsent(t, "nokey deploy", raw, secret)
	if log.count() != 1 {
		t.Fatal("missing key dispatched")
	}
	w.srv.Secrets = testBox(t)
	status, env, _ = postImage(t, w, tok, project, "locked", "deploy", host, "locked-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 2 {
		t.Fatal("restored key did not run locked-1")
	}
	if objectPayload(t, env)["deploy"].(map[string]any)["outcome"] != "succeeded" {
		t.Fatalf("locked-1 replayed the refusal %#v", env.Payload)
	}
	if !w.mem.TamperProjectFile(sc.project.ID, "key.json") {
		t.Fatal("tamper missed the row")
	}
	status, env, raw = postImage(t, w, tok, project, "locked", "deploy", host, "tamper-1", nil)
	mustHTTP(t, status, env, http.StatusInternalServerError, "error", "internal error")
	assertSecretAbsent(t, "tamper", raw, secret)
	if log.count() != 2 || !strings.Contains(logs.String(), "decrypt failed") {
		t.Fatalf("tamper log %q tasks %d", logs.String(), log.count())
	}
	assertSecretAbsent(t, "tamper log", logs.String(), secret)
	putFile(t, w, tok, project, "key.json", secret, nil)
	status, env, _ = postImage(t, w, tok, project, "locked", "deploy", host, "tamper-2", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")

	w.mem.DropProjectFile(sc.project.ID, "app.conf")
	status, env, raw = postImage(t, w, tok, project, "web", "deploy", host, "gone-1", nil)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "file app.conf no longer exists")
	if strings.Contains(raw, "plain-config-line") || log.count() != 3 {
		t.Fatal("deleted file dispatched or echoed content")
	}
	const rewritten = "plain-config-rewritten"
	putFile(t, w, tok, project, "app.conf", rewritten, boolPtr(false))
	if createImageGet(t, w, tok, sc.project.ID, "web")["spec_hash"] != hash {
		t.Fatal("content rewrite changed spec_hash")
	}
	guestUser := w.user("guest@ex.com", "Guest")
	guest, err := w.mem.CreateProject(context.Background(), guestUser.ID, "Guest", "guest", w.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.mem.PutHostShare(context.Background(), sc.host.ID, guest.ID, "deploy", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	gtok := w.token(guestUser.ID)
	putFile(t, w, gtok, guest.ID.String(), "app.conf", "guest-file-body-one", boolPtr(false))
	shared := createImage(t, w, gtok, guest.ID, "web", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/config/app.conf"}]}`)
	sharedHash, _ := shared["spec_hash"].(string)
	sharedID, _ := shared["id"].(string)
	status, env, _ = mustCall(t, w, tok, http.MethodPost, "/v1/hosts/"+host+"/catalog-approvals", `{"entry_id":"`+sharedID+`","spec_hash":"`+sharedHash+`"}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	putFile(t, w, gtok, guest.ID.String(), "app.conf", "guest-file-body-two", boolPtr(false))
	if createImageGet(t, w, gtok, guest.ID, "web")["spec_hash"] != sharedHash {
		t.Fatal("shared content rewrite changed spec_hash")
	}
	approved := listApprovals(t, w, owner.ID, sc.host.ID)
	if len(approved) != 1 || approved[0]["status"] != "approved" || approved[0]["spec_hash"] != sharedHash {
		t.Fatalf("content rewrite voided the approval %#v", approved)
	}
	status, env, _ = mustCall(t, w, tok, http.MethodPut, "/v1/projects/"+project+"/catalog/web", `{"kind":"image","spec":{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/config/other.conf"}]}}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if objectPayload(t, env)["spec_hash"] == hash {
		t.Fatal("a new target kept spec_hash")
	}
	status, env, raw = mustCall(t, w, tok, http.MethodDelete, "/v1/projects/"+project+"/files/app.conf", "")
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "referenced by web")
	if strings.Contains(raw, rewritten) || strings.Contains(raw, "plain-config-line") {
		t.Fatal("conflict echoed content")
	}

	img, err := catalog.BuildImage("old", []byte(`{"kind":"service","image":"nginx"}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(catalog.SpecJSON(img)), &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "files")
	stripped, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	oldHash := catalog.ImageHash(img, nil)
	if _, err := w.mem.CreateCatalogEntry(context.Background(), sc.project.ID, store.CatalogWrite{
		Name: "old", Kind: "image", ImageRaw: stripped, SpecHash: "stored-hash",
		CommandDisplay: img.Image, Actor: owner.ID, At: w.now,
	}); err != nil {
		t.Fatal(err)
	}
	old := createImageGet(t, w, tok, sc.project.ID, "old")
	oldSpec, _ := old["spec"].(map[string]any)
	oldFiles, ok := oldSpec["files"].([]any)
	if !ok || len(oldFiles) != 0 || old["spec_hash"] != "stored-hash" || oldHash == "" {
		t.Fatalf("old spec %#v", old)
	}
}

func TestFileFrameSize(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	body := strings.Repeat("q", catalog.MaxFileBytes)
	var rows []string
	for i := 0; i < 16; i++ {
		name := "f" + hex.EncodeToString([]byte{byte(i)})
		status, env, _ := putFile(t, w, tok, project, name, body, boolPtr(false))
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
		rows = append(rows, `{"file":"`+name+`","target":"/opt/`+name+`"}`)
	}
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","files":[`+strings.Join(rows, ",")+`]}`)
	programs := allowImages()
	programs["files"] = true
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, programs, nil)
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return imageDeployReply(msg, shaDigest(5))
	})
	host := sc.host.ID.String()
	before := len(auditRows(t, w, sc.project.ID))
	status, env, raw := postImage(t, w, tok, project, "web", "deploy", host, "big-1", nil)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "the resolved environment and files are too large for one task")
	if strings.Contains(raw, strings.Repeat("q", 32)) || log.count() != 0 {
		t.Fatal("oversize dispatched or echoed a file")
	}
	for _, row := range auditRows(t, w, sc.project.ID) {
		if row.Action == "catalog.deploy" {
			t.Fatalf("oversize audited a deploy %s", row.Detail)
		}
	}
	if len(auditRows(t, w, sc.project.ID)) < before {
		t.Fatal("oversize removed an audit row")
	}
	createImage(t, w, tok, sc.project.ID, "tiny", `{"kind":"service","image":"nginx"}`)
	status, env, _ = postImage(t, w, tok, project, "tiny", "deploy", host, "tiny-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 1 {
		t.Fatal("connection did not take the next task")
	}
}

func TestFileFixtures(t *testing.T) {
	const secret = "SECRET-FILE-CONTENT-do-not-leak"
	const plainBody = "plain-config-line"
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	_, _, putRaw := putFile(t, w, tok, project, "key.json", secret, nil)
	putFile(t, w, tok, project, "app.conf", plainBody, boolPtr(false))
	web := createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/config/app.conf"},{"file":"key.json","target":"/run/secrets/key.json"}]}`)
	apiEntry := createImage(t, w, tok, sc.project.ID, "api", `{"kind":"service","image":"nginx","files":[{"file":"key.json","target":"/run/secrets/key.json"}]}`)
	_, _, listRaw := mustCall(t, w, tok, http.MethodGet, "/v1/projects/"+project+"/files", "")
	_, _, getRaw := mustCall(t, w, tok, http.MethodGet, "/v1/projects/"+project+"/files/app.conf", "")
	_, _, entryRaw := mustCall(t, w, tok, http.MethodGet, "/v1/projects/"+project+"/catalog/web", "")
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return imageDeployReply(msg, shaDigest(1))
	})
	_, _, denyRaw := postImage(t, w, tok, project, "web", "deploy", sc.host.ID.String(), "fix-deny", nil)
	if log.count() != 0 || !strings.Contains(denyRaw, "this host's agent does not support files") {
		t.Fatalf("fixture deploy %s tasks %d", denyRaw, log.count())
	}
	_, _, conflictRaw := mustCall(t, w, tok, http.MethodDelete, "/v1/projects/"+project+"/files/key.json", "")
	if !strings.Contains(conflictRaw, "referenced by api, web") {
		t.Fatalf("fixture conflict %s", conflictRaw)
	}
	programs := allowImages()
	programs["files"] = true
	helloAgent(t, w, sc.host, sc.credPlain, sc.credID, programs, nil)
	_, hostEnv, _ := mustCall(t, w, tok, http.MethodGet, "/v1/hosts/"+sc.host.ID.String(), "")
	hostPrograms := objectPayload(t, hostEnv)["programs"]
	if hostPrograms.(map[string]any)["files"] != true {
		t.Fatalf("programs %#v", hostPrograms)
	}
	ids := map[string]string{
		sc.project.ID.String():  "PROJECT",
		owner.ID.String():       "OWNER",
		web["id"].(string):      "ENTRY_WEB",
		apiEntry["id"].(string): "ENTRY_API",
	}
	doc := map[string]any{
		"list_files":         jsonValue(t, scrubIDs(listRaw, ids)),
		"get_plain":          jsonValue(t, scrubIDs(getRaw, ids)),
		"put_file":           jsonValue(t, scrubIDs(putRaw, ids)),
		"delete_conflict":    jsonValue(t, scrubIDs(conflictRaw, ids)),
		"catalog_entry":      jsonValue(t, scrubIDs(entryRaw, ids)),
		"host_programs":      hostPrograms,
		"deploy_unsupported": jsonValue(t, denyRaw),
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	sum := sha256.Sum256([]byte(secret))
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), hex.EncodeToString(sum[:])) {
		t.Fatal("fixture contains secret material")
	}
	if uuidRe.Match(raw) {
		t.Fatalf("fixture still has a uuid: %s", uuidRe.Find(raw))
	}
	path := filepath.Join("..", "..", "docs", "examples", "v1.9-files.json")
	if os.Getenv("DEPLOYBOT_UPDATE_FIXTURES") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("fixture missing (%v); regenerate with DEPLOYBOT_UPDATE_FIXTURES=1", err)
	}
	if string(got) != string(raw) {
		t.Fatal("docs/examples/v1.9-files.json is stale; regenerate with DEPLOYBOT_UPDATE_FIXTURES=1")
	}
}

func TestFileSecretPieceRedaction(t *testing.T) {
	const pemBody = "THROW-AWAY-PEM-BODY-LINE-9f3a7c"
	const plain = "PLAIN-FILE-CONTENT-keep-visible-9f3a"
	pem := "-----BEGIN PRIVATE KEY-----\n" + pemBody + "\n-----END PRIVATE KEY-----\n"
	quoted, err := json.Marshal(pem)
	if err != nil {
		t.Fatal(err)
	}
	doc := `{"type":"service_account","private_key":` + string(quoted) + `}`
	if len(pemBody) < 16 || len(pem) < 16 || len(pem) > 4096 || len(doc) < 6 || len(doc) > 4096 {
		t.Fatalf("fixture pem %d body %d doc %d", len(pem), len(pemBody), len(doc))
	}
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putFile(t, w, tok, project, "account.json", doc, nil)
	putFile(t, w, tok, project, "app.conf", plain, boolPtr(false))
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","files":[{"file":"account.json","target":"/run/secrets/account.json"},{"file":"app.conf","target":"/config/app.conf"}]}`)
	programs := allowImages()
	programs["files"] = true
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, programs, nil)
	printed := []string{pemBody, pem, plain}
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		kind, _ := msg["kind"].(string)
		if kind == "image_logs" {
			return map[string]any{
				"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "succeeded",
				"payload": map[string]any{"container": "web", "lines": printed, "truncated": false},
			}
		}
		reply := imageDeployReply(msg, shaDigest(4))
		reply["payload"].(map[string]any)["lines"] = printed
		return reply
	})
	host := sc.host.ID.String()
	status, env, raw := postImage(t, w, tok, project, "web", "deploy", host, "piece-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertPieceRedacted(t, "deploy", raw, pemBody, pem, plain)
	status, env, raw = postImage(t, w, tok, project, "web", "logs", host, "", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertPieceRedacted(t, "logs", raw, pemBody, pem, plain)
	if log.count() != 2 {
		t.Fatalf("tasks %d", log.count())
	}
}

func TestFileLogsRedactSkipsMissing(t *testing.T) {
	const kept = "KEPT-SECRET-FILE-CONTENT-9f3a"
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putFile(t, w, tok, project, "gone.json", "GONE-SECRET-FILE-CONTENT-9f3a", nil)
	putFile(t, w, tok, project, "kept.json", kept, nil)
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","files":[{"file":"gone.json","target":"/run/secrets/gone.json"},{"file":"kept.json","target":"/run/secrets/kept.json"}]}`)
	programs := allowImages()
	programs["files"] = true
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, programs, nil)
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		kind, _ := msg["kind"].(string)
		if kind == "image_logs" {
			return map[string]any{
				"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "succeeded",
				"payload": map[string]any{"container": "web", "lines": []string{kept}, "truncated": false},
			}
		}
		return imageDeployReply(msg, shaDigest(6))
	})
	w.mem.DropProjectFile(sc.project.ID, "gone.json")
	host := sc.host.ID.String()
	status, env, raw := postImage(t, w, tok, project, "web", "logs", host, "", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if !strings.Contains(raw, "[redacted]") {
		t.Fatal("logs dropped the later secret")
	}
	assertSecretAbsent(t, "logs kept", raw, kept)
	status, env, _ = postImage(t, w, tok, project, "web", "deploy", host, "gone-sib", nil)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "file gone.json no longer exists")
	if log.count() != 1 {
		t.Fatal("missing file dispatched a deploy")
	}
}

func TestFileLogsRedactWhenEnvDecryptFails(t *testing.T) {
	const fileLine = "FILE-LINE-OPENS-do-not-leak-9f3a"
	w := newWorld(t)
	w.srv.Secrets = testBoxByte(t, 1)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putEnv(t, w, tok, project, "svc", "FOO="+envSecret+"\n")
	w.srv.Secrets = testBoxByte(t, 2)
	putFile(t, w, tok, project, "kept.json", fileLine, nil)
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","env_sets":["svc"],"files":[{"file":"kept.json","target":"/run/secrets/kept.json"}]}`)
	logged := captureLog(w)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	tasks := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return map[string]any{
			"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "succeeded",
			"payload": map[string]any{"container": "web", "lines": []string{fileLine, envSecret}, "truncated": false},
		}
	})
	status, env, raw := postImage(t, w, tok, project, "web", "logs", sc.host.ID.String(), "", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if tasks.count() != 1 {
		t.Fatal("env decrypt failure did not call the agent")
	}
	if !strings.Contains(raw, "[redacted]") || !strings.Contains(raw, envSecret) {
		t.Fatalf("file line was not redacted beside the unopened env value: %s", raw)
	}
	assertSecretAbsent(t, "file line", raw, fileLine)
	text := logged.String()
	if strings.Count(text, "decrypt failed") != 1 || strings.Contains(text, fileLine) || strings.Contains(text, envSecret) {
		t.Fatalf("decrypt log %s", text)
	}
}

func TestFileLogsRefusesMissingKey(t *testing.T) {
	const secret = "SECRET-FILE-LINE-do-not-leak-9f3a"
	const plain = "plain-config-line"
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putFile(t, w, tok, project, "key.json", secret, nil)
	putFile(t, w, tok, project, "app.conf", plain, boolPtr(false))
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","files":[{"file":"key.json","target":"/run/secrets/key.json"}]}`)
	createImage(t, w, tok, sc.project.ID, "plain", `{"kind":"service","image":"nginx","files":[{"file":"app.conf","target":"/config/app.conf"}]}`)
	w.srv.Secrets = nil
	logged := captureLog(w)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	tasks := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return map[string]any{
			"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "succeeded",
			"payload": map[string]any{"container": "web", "lines": []string{"password=hunter22", plain}, "truncated": false},
		}
	})
	host := sc.host.ID.String()
	status, env, raw := postImage(t, w, tok, project, "web", "logs", host, "", nil)
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "secrets key not configured")
	if env.Payload != nil || tasks.count() != 0 {
		t.Fatalf("secret file logs dispatched or returned lines %s tasks %d", raw, tasks.count())
	}
	assertSecretAbsent(t, "refused", raw, secret)
	if strings.Contains(logged.String(), "decrypt failed") || strings.Contains(logged.String(), secret) {
		t.Fatalf("missing key log %s", logged.String())
	}
	status, env, raw = postImage(t, w, tok, project, "plain", "logs", host, "", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if tasks.count() != 1 || !strings.Contains(raw, plain) || !strings.Contains(raw, "password=[REDACTED]") || strings.Contains(raw, "hunter22") {
		t.Fatalf("plain file logs %s tasks %d", raw, tasks.count())
	}
}

func TestFileLogsRedactTamperedSibling(t *testing.T) {
	const early = "EARLY-SECRET-FILE-LINE-9f3a"
	const later = "LATER-SECRET-FILE-LINE-9f3a"
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putFile(t, w, tok, project, "early.json", early, nil)
	putFile(t, w, tok, project, "later.json", later, nil)
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","files":[{"file":"early.json","target":"/run/secrets/early.json"},{"file":"later.json","target":"/run/secrets/later.json"}]}`)
	logged := captureLog(w)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	if !w.mem.TamperProjectFile(sc.project.ID, "early.json") {
		t.Fatal("tamper")
	}
	tasks := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return map[string]any{
			"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "succeeded",
			"payload": map[string]any{"container": "web", "lines": []string{later}, "truncated": false},
		}
	})
	status, env, raw := postImage(t, w, tok, project, "web", "logs", sc.host.ID.String(), "", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if tasks.count() != 1 || !strings.Contains(raw, "[redacted]") {
		t.Fatalf("tampered sibling dropped the later line %s tasks %d", raw, tasks.count())
	}
	assertSecretAbsent(t, "later line", raw, later)
	text := logged.String()
	if strings.Count(text, "decrypt failed") != 1 || strings.Contains(text, early) || strings.Contains(text, later) {
		t.Fatalf("tamper log %s", text)
	}
}

func TestFileDeploySupportBeforeMissingKey(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putFile(t, w, tok, project, "key.json", "SECRET-FILE-LINE-do-not-leak-9f3a", nil)
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","files":[{"file":"key.json","target":"/run/secrets/key.json"}]}`)
	w.srv.Secrets = nil
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowImages(), nil)
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		return imageDeployReply(msg, shaDigest(3))
	})
	status, env, _ := postImage(t, w, tok, project, "web", "deploy", sc.host.ID.String(), "nofiles-1", nil)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "this host's agent does not support files")
	if log.count() != 0 {
		t.Fatal("unsupported host dispatched")
	}
}

func TestSecretFilePieces(t *testing.T) {
	if got := secretFilePieces("short"); len(got) != 0 {
		t.Fatalf("under 6: %#v", got)
	}
	if got := secretFilePieces("abcdef"); !samePieces(got, "abcdef") {
		t.Fatalf("six: %#v", got)
	}
	line15 := strings.Repeat("b", 15)
	if got := secretFilePieces(line15); !samePieces(got, line15) {
		t.Fatalf("fifteen: %#v", got)
	}
	line16 := strings.Repeat("c", 16)
	if got := secretFilePieces(line16); !samePieces(got, line16) {
		t.Fatalf("sixteen: %#v", got)
	}
	max := strings.Repeat("d", secretPieceMax)
	if got := secretFilePieces(max); !samePieces(got, max) {
		t.Fatalf("4096: %d", len(got))
	}
	if got := secretFilePieces(strings.Repeat("e", secretPieceMax+1)); len(got) != 0 {
		t.Fatalf("4097: %d", len(got))
	}
	body := "THROW-AWAY-PEM-BODY-LINE-9f3a7c"
	pem := "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n"
	quoted, err := json.Marshal(pem)
	if err != nil {
		t.Fatal(err)
	}
	doc := `{"private_key":` + string(quoted) + `,"n":1}`
	got := secretFilePieces(doc)
	for _, want := range []string{doc, pem, body, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"} {
		if !hasPiece(got, want) {
			t.Fatalf("missing %q in %d pieces", want, len(got))
		}
	}
	padded := "  " + line16 + "  "
	if !hasPiece(secretFilePieces(padded+"\n"), line16) {
		t.Fatal("trim missed")
	}
}

func samePieces(got []string, want string) bool {
	if len(got) == 0 {
		return false
	}
	for _, piece := range got {
		if piece != want {
			return false
		}
	}
	return true
}

func hasPiece(got []string, want string) bool {
	for _, piece := range got {
		if piece == want {
			return true
		}
	}
	return false
}

func assertPieceRedacted(t *testing.T, label, body, pemBody, pem, plain string) {
	t.Helper()
	if !strings.Contains(body, "[redacted]") || !strings.Contains(body, plain) {
		t.Fatalf("%s redaction %s", label, body)
	}
	assertSecretAbsent(t, label+" pem line", body, pemBody)
	assertSecretAbsent(t, label+" private_key", body, pem)
}

func putFile(t *testing.T, w *world, tok, project, name, content string, secret *bool) (int, envelope, string) {
	t.Helper()
	body := map[string]any{"content": content}
	if secret != nil {
		body["secret"] = *secret
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return mustCall(t, w, tok, http.MethodPut, "/v1/projects/"+project+"/files/"+name, string(raw))
}

func boolPtr(v bool) *bool { return &v }

func assertSecretAbsent(t *testing.T, label, body, secret string) {
	t.Helper()
	quoted, err := json.Marshal(secret)
	if err != nil {
		t.Fatal(err)
	}
	forms := []string{
		secret,
		string(quoted[1 : len(quoted)-1]),
		base64.StdEncoding.EncodeToString([]byte(secret)),
		base64.RawStdEncoding.EncodeToString([]byte(secret)),
		base64.URLEncoding.EncodeToString([]byte(secret)),
		base64.RawURLEncoding.EncodeToString([]byte(secret)),
	}
	for _, form := range forms {
		if form != "" && strings.Contains(body, form) {
			t.Fatalf("%s contains secret material", label)
		}
	}
}

func assertFrameSecret(t *testing.T, frame map[string]any, secret string) {
	t.Helper()
	spec, _ := frame["spec"].(map[string]any)
	files, _ := spec["files"].([]any)
	n := 0
	for _, item := range files {
		row, _ := item.(map[string]any)
		if row["content"] == secret {
			n++
		}
		if strings.Join(mapKeys(row), ",") != "content,name,secret,target" {
			t.Fatalf("file keys %#v", row)
		}
	}
	if n != 1 {
		t.Fatalf("frame secret copies %d %#v", n, files)
	}
	if len(files) != 2 {
		t.Fatalf("frame files %#v", files)
	}
	first, _ := files[0].(map[string]any)
	second, _ := files[1].(map[string]any)
	if first["name"] != "zeta.json" || first["secret"] != true || second["name"] != "alpha.conf" || second["secret"] != false || second["content"] != "plain-config-line" {
		t.Fatalf("frame order %#v", files)
	}
	nested, _ := spec["spec"].(map[string]any)
	nestedRaw, err := json.Marshal(nested)
	if err != nil {
		t.Fatal(err)
	}
	assertSecretAbsent(t, "nested spec", string(nestedRaw), secret)
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	quoted, _ := json.Marshal(secret)
	escaped := string(quoted[1 : len(quoted)-1])
	if strings.Count(string(raw), escaped) != 1 {
		t.Fatalf("marshalled frame copies %d", strings.Count(string(raw), escaped))
	}
	if strings.Contains(string(raw), base64.StdEncoding.EncodeToString([]byte(secret))) {
		t.Fatal("frame base64-encoded the secret")
	}
}

func auditText(t *testing.T, w *world, projectID uuid.UUID) string {
	t.Helper()
	var b strings.Builder
	for _, row := range auditRows(t, w, projectID) {
		b.WriteString(row.Action)
		b.Write(row.Detail)
		b.WriteByte('\n')
	}
	return b.String()
}

func jsonValue(t *testing.T, raw string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func scrubIDs(raw string, ids map[string]string) string {
	for from, to := range ids {
		raw = strings.ReplaceAll(raw, from, to)
	}
	return raw
}

var uuidRe = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
