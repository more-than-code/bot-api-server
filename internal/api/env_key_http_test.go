package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestEnvKeyPreviewAndPut(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	const long = "abcdefghij0123456789"
	const plain = "visible-plain"

	status, env, _ := mustCall(t, w, tok, http.MethodGet, envPath(project, "svc"), "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")

	status, env, raw := putKey(t, w, tok, project, "svc", "TOKEN", long, nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertSecretKey(t, objectPayload(t, env), catalog.SecretPreview(long))
	if _, ok := objectPayload(t, env)["keys"]; ok || strings.Contains(raw, long) {
		t.Fatalf("key put returned the set or the value %s", raw)
	}
	status, env, raw = mustCall(t, w, tok, http.MethodGet, envPath(project, "svc"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	got := keysByName(t, env)
	assertSecretKey(t, got["TOKEN"], catalog.SecretPreview(long))
	if strings.Contains(raw, long) {
		t.Fatal("get returned the secret")
	}
	if catalog.SecretPreview(long) != "abcd…" {
		t.Fatalf("preview %q", catalog.SecretPreview(long))
	}

	status, env, _ = putKey(t, w, tok, project, "svc", "VISIBLE", plain, boolPtr(false))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertPlainKey(t, objectPayload(t, env), plain)

	status, env, raw = putKey(t, w, tok, project, "svc", "TOKEN", long+"-next", boolPtr(true))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertSecretKey(t, objectPayload(t, env), catalog.SecretPreview(long+"-next"))
	if strings.Contains(raw, long) {
		t.Fatal("update echoed the value")
	}

	status, env, raw = putKey(t, w, tok, project, "svc", "TOKEN", "should-not-echo-zz", boolPtr(false))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "secret flag is fixed; delete and re-add the key")
	if strings.Contains(raw, "should-not-echo-zz") || strings.Contains(raw, long) {
		t.Fatalf("flag error echoed a value %s", raw)
	}
	status, env, _ = mustCall(t, w, tok, http.MethodGet, envPath(project, "svc"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	got = keysByName(t, env)
	assertSecretKey(t, got["TOKEN"], catalog.SecretPreview(long+"-next"))
	assertPlainKey(t, got["VISIBLE"], plain)

	status, env, _ = mustCall(t, w, tok, http.MethodGet, "/v1/projects/"+project+"/env-sets", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	items := listItems(t, env)
	if len(items) != 1 {
		t.Fatalf("list %#v", items)
	}
	listed := map[string]map[string]any{}
	for _, item := range items[0]["keys"].([]any) {
		row, _ := item.(map[string]any)
		listed[row["key"].(string)] = row
	}
	assertSecretKey(t, listed["TOKEN"], catalog.SecretPreview(long+"-next"))
	assertPlainKey(t, listed["VISIBLE"], plain)

	puts := map[string]map[string]any{}
	var tokenCreated []any
	for _, row := range auditRows(t, w, sc.project.ID) {
		if row.Action != audit.ActionEnvSetKeyPut || row.Decision != audit.DecisionAllowed {
			continue
		}
		if row.Via != audit.ViaConsole {
			t.Fatalf("via %s", row.Via)
		}
		detail := detailMap(t, row.Detail)
		name, _ := detail["key"].(string)
		if detail["set"] != "svc" || len(detail) != 3 {
			t.Fatalf("key_put detail %#v", detail)
		}
		puts[name] = detail
		if name == "TOKEN" {
			tokenCreated = append(tokenCreated, detail["created"])
		}
		if strings.Contains(string(row.Detail), long) || strings.Contains(string(row.Detail), plain) || strings.Contains(string(row.Detail), "should-not-echo-zz") {
			t.Fatalf("audit held a value %s", row.Detail)
		}
	}
	// ListAudit is newest first: the value update, then the create.
	if len(tokenCreated) != 2 || tokenCreated[0] != false || tokenCreated[1] != true {
		t.Fatalf("token created flags %#v", tokenCreated)
	}
	if puts["VISIBLE"]["created"] != true {
		t.Fatalf("visible audit %#v", puts["VISIBLE"])
	}
}

func TestEnvKeyValidation(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()

	status, env, raw := putKey(t, w, tok, project, "bad", "TOKEN", "", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertSecretKey(t, objectPayload(t, env), "••••")

	status, env, raw = mustCall(t, w, tok, http.MethodPut, envKeyPath(project, "bad", "TOKEN"), `{"value":"kept","is_secret":null}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertSecretKey(t, objectPayload(t, env), catalog.SecretPreview("kept"))

	status, env, raw = mustCall(t, w, tok, http.MethodPut, envKeyPath(project, "bad", "TOKEN"), `{"value":"nope","extra":true}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid json")
	if strings.Contains(raw, "nope") {
		t.Fatalf("unknown field echoed %s", raw)
	}

	for _, tc := range []struct {
		key, msg string
	}{
		{"1NO", "invalid env key"},
		{"PATH", "PATH is reserved"},
		{"LD_PRELOAD", "this variable changes what the program runs"},
	} {
		status, env, raw = putKey(t, w, tok, project, "bad", tc.key, "ZZKEYMARKER", nil)
		mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", tc.msg)
		if strings.Contains(raw, "ZZKEYMARKER") {
			t.Fatalf("%s echoed the value %s", tc.key, raw)
		}
	}

	longOK := strings.Repeat("b", 4096)
	status, env, raw = putKey(t, w, tok, project, "bad", "BOUND", longOK, nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertSecretKey(t, objectPayload(t, env), "bbbb…")
	if strings.Contains(raw, strings.Repeat("b", 20)) {
		t.Fatal("4096-byte value was returned")
	}
	for _, value := range []string{"ZZNEWLINE\nMARKER", "ZZNULMARKER\x00", strings.Repeat("c", 4097)} {
		body, err := json.Marshal(map[string]string{"value": value})
		if err != nil {
			t.Fatal(err)
		}
		status, env, raw = mustCall(t, w, tok, http.MethodPut, envKeyPath(project, "bad", "BOUND"), string(body))
		mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid env value")
		if strings.Contains(raw, "ZZNEWLINE") || strings.Contains(raw, "ZZNULMARKER") || strings.Contains(raw, strings.Repeat("c", 20)) {
			t.Fatalf("invalid value echoed %s", raw)
		}
	}

	w.srv.Secrets = nil
	status, env, raw = putKey(t, w, tok, project, "bad", "BOUND", "ZZUNSETMARKER", boolPtr(false))
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "secrets key not configured")
	if strings.Contains(raw, "ZZUNSETMARKER") {
		t.Fatalf("unset key echoed %s", raw)
	}
	body, err := json.Marshal(map[string]string{"value": "ZZBAD\nMARKER"})
	if err != nil {
		t.Fatal(err)
	}
	status, env, raw = mustCall(t, w, tok, http.MethodPut, envKeyPath(project, "bad", "BOUND"), string(body))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid env value")
	if strings.Contains(raw, "ZZBAD") {
		t.Fatalf("validation echoed %s", raw)
	}
	status, env, raw = mustCall(t, w, tok, http.MethodGet, envPath(project, "bad"), "")
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "secrets key not configured")
	if strings.Contains(raw, "kept") {
		t.Fatal("get without a key returned a secret")
	}
}

func TestEnvKeySecretEmpty(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	const kept = "kept-secret-value"

	status, env, _ := putKey(t, w, tok, project, "svc", "TOKEN", kept, nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env, _ = putKey(t, w, tok, project, "svc", "PLAIN", "x", boolPtr(false))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	before := countAction(w.mem.AllAudits(), audit.ActionEnvSetKeyPut)
	for _, secret := range []*bool{nil, boolPtr(true)} {
		status, env, _ = putKey(t, w, tok, project, "svc", "TOKEN", "", secret)
		mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "a secret value cannot be empty; delete the key instead")
	}
	if countAction(w.mem.AllAudits(), audit.ActionEnvSetKeyPut) != before {
		t.Fatal("refused empty secret wrote an env_set.key_put audit row")
	}
	status, env, _ = mustCall(t, w, tok, http.MethodGet, envPath(project, "svc"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertSecretKey(t, keysByName(t, env)["TOKEN"], catalog.SecretPreview(kept))

	status, env, _ = putKey(t, w, tok, project, "svc", "PLAIN", "", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertPlainKey(t, objectPayload(t, env), "")
	status, env, _ = putKey(t, w, tok, project, "svc", "FRESH", "", boolPtr(true))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertSecretKey(t, objectPayload(t, env), "••••")
}

func TestEnvKeyDeleteVoidsApprovals(t *testing.T) {
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
	tok := w.token(guestUser.ID)
	project := guest.ID.String()
	host := sc.host.ID.String()
	putKey(t, w, tok, project, "lock", "KEY", envSecret, nil)
	created := createImage(t, w, tok, guest.ID, "web", `{"kind":"service","image":"nginx","env_sets":["lock"]}`)
	hash, _ := created["spec_hash"].(string)
	entryID, _ := created["id"].(string)
	approve := func(specHash string) {
		t.Helper()
		status, env, _ := mustCall(t, w, w.token(owner.ID), http.MethodPost, "/v1/hosts/"+host+"/catalog-approvals", `{"entry_id":"`+entryID+`","spec_hash":"`+specHash+`"}`)
		mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	}
	approve(hash)
	status, env, _ := putKey(t, w, tok, project, "lock", "KEY", envSecret+"-other", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if createImageGet(t, w, tok, guest.ID, "web")["spec_hash"] != hash || len(listApprovals(t, w, owner.ID, sc.host.ID)) != 1 {
		t.Fatal("value rewrite changed the hash or dropped the approval")
	}
	status, env, _ = putKey(t, w, tok, project, "lock", "BAR", "1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	added := createImageGet(t, w, tok, guest.ID, "web")
	addedHash, _ := added["spec_hash"].(string)
	if addedHash == hash || len(listApprovals(t, w, owner.ID, sc.host.ID)) != 0 {
		t.Fatalf("adding a key kept the hash or the approval %#v", added)
	}
	approve(addedHash)
	status, env, raw := mustCall(t, w, tok, http.MethodDelete, envKeyPath(project, "lock", "BAR"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	payload, ok := env.Payload.(map[string]any)
	if !ok || len(payload) != 0 || !strings.Contains(raw, `"payload":{}`) {
		t.Fatalf("delete payload %#v raw %s", env.Payload, raw)
	}
	removed := createImageGet(t, w, tok, guest.ID, "web")
	if removed["spec_hash"] == addedHash || len(listApprovals(t, w, owner.ID, sc.host.ID)) != 0 {
		t.Fatalf("deleting a key kept the hash or the approval %#v", removed)
	}
	var deleted bool
	for _, row := range auditRows(t, w, guest.ID) {
		if row.Action != audit.ActionEnvSetKeyDelete {
			continue
		}
		detail := detailMap(t, row.Detail)
		if detail["set"] == "lock" && detail["key"] == "BAR" && len(detail) == 2 && row.Via == audit.ViaConsole {
			deleted = true
		}
		if strings.Contains(string(row.Detail), envSecret) {
			t.Fatalf("delete audit %s", row.Detail)
		}
	}
	if !deleted {
		t.Fatal("missing key_delete audit")
	}
	status, env, _ = mustCall(t, w, tok, http.MethodDelete, envKeyPath(project, "lock", "GONE"), "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	status, env, _ = mustCall(t, w, tok, http.MethodDelete, envKeyPath(project, "missing", "KEY"), "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	status, env, _ = mustCall(t, w, tok, http.MethodDelete, envKeyPath(project, "lock", "KEY"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env, raw = mustCall(t, w, tok, http.MethodGet, envPath(project, "lock"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if keys := objectPayload(t, env)["keys"].([]any); len(keys) != 0 || strings.Contains(raw, envSecret) {
		t.Fatalf("empty set %#v %s", objectPayload(t, env), raw)
	}
}

func TestEnvKeyPatchAbsent(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putKey(t, w, tok, project, "svc", "TOKEN", envSecret, nil)
	path := envKeyPath(project, "svc", "TOKEN")
	status, env, raw := mustCall(t, w, tok, http.MethodPatch, path, `{"is_secret":false}`)
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	if !strings.Contains(raw, `"payload":null`) {
		t.Fatalf("patch body %s", raw)
	}
	delegated := tokenKind(t, w, owner.ID, store.KindDelegated)
	before := countAction(w.mem.AllAudits(), audit.ActionDelegatedDenied)
	status, env, raw = mustCall(t, w, delegated, http.MethodPatch, path, `{"is_secret":false}`)
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	if countAction(w.mem.AllAudits(), audit.ActionDelegatedDenied) != before {
		t.Fatal("unregistered patch audited delegated.denied")
	}
	status, env, _ = mustCall(t, w, tok, http.MethodGet, "/v1/no-such-route", "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	status, env, _ = mustCall(t, w, tok, http.MethodGet, envPath(project, "svc"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertSecretKey(t, keysByName(t, env)["TOKEN"], catalog.SecretPreview(envSecret))
}

func TestEnvNewKeysSecret(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	const long = "abcdefghij0123456789"
	body, err := json.Marshal(map[string]any{"dotenv": "VISIBLE=visible-plain\n", "new_keys_secret": false})
	if err != nil {
		t.Fatal(err)
	}
	status, env, _ := mustCall(t, w, tok, http.MethodPut, envPath(project, "svc"), string(body))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertPlainKey(t, keysByName(t, env)["VISIBLE"], "visible-plain")
	body, err = json.Marshal(map[string]string{"dotenv": "VISIBLE=visible-next\nSECRET=" + long + "\n"})
	if err != nil {
		t.Fatal(err)
	}
	status, env, raw := mustCall(t, w, tok, http.MethodPut, envPath(project, "svc"), string(body))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	got := keysByName(t, env)
	assertPlainKey(t, got["VISIBLE"], "visible-next")
	assertSecretKey(t, got["SECRET"], catalog.SecretPreview(long))
	if strings.Contains(raw, long) {
		t.Fatal("dotenv put returned the secret")
	}
}

func TestEnvKeyRoles(t *testing.T) {
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("a@ex.com", "A")
	sc := w.scene(owner, admin, w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	project := sc.project.ID.String()
	path := envKeyPath(project, "svc", "TOKEN")
	viewer := w.token(sc.spare.ID)
	status, env := w.do(viewer, http.MethodPut, path, `{"value":"nope"}`)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env = w.do(viewer, http.MethodDelete, path, "")
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env = w.do(w.token(sc.extra.ID), http.MethodPut, path, `{"value":"nope"}`)
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")

	delegated := tokenKind(t, w, owner.ID, store.KindDelegated)
	before := len(w.mem.AllAudits())
	status, env = w.do(delegated, http.MethodPut, path, `{"value":"nope-delegated"}`)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	rows := w.mem.AllAudits()
	if len(rows) != before+1 {
		t.Fatalf("delegated put audits %d", len(rows)-before)
	}
	assertDelegatedDenied(t, rows[len(rows)-1], owner.ID, "PUT /v1/projects/{id}/env-sets/{set}/keys/{key}")
	before = len(rows)
	status, env = w.do(delegated, http.MethodDelete, path, "")
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	rows = w.mem.AllAudits()
	if len(rows) != before+1 {
		t.Fatalf("delegated delete audits %d", len(rows)-before)
	}
	assertDelegatedDenied(t, rows[len(rows)-1], owner.ID, "DELETE /v1/projects/{id}/env-sets/{set}/keys/{key}")
	if _, err := w.mem.GetEnvSet(context.Background(), sc.project.ID, "svc"); err != store.ErrNotFound {
		t.Fatal("delegated key route wrote a set")
	}

	status, env, _ = putKey(t, w, w.token(admin.ID), project, "svc", "TOKEN", "admin-secret-value", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertSecretKey(t, objectPayload(t, env), catalog.SecretPreview("admin-secret-value"))
}

func TestEnvSecretPreviewRedaction(t *testing.T) {
	const long = "abcdefghij0123456789"
	const short = "abcd1234"
	const fileSecret = "file-secret-piece-xyz"
	const reg = "registry-token-value"
	w := newWorld(t)
	w.srv.Secrets = testBox(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	project := sc.project.ID.String()
	putEnv(t, w, tok, project, "svc", "LONG="+long+"\nSHORT="+short+"\n")
	putFile(t, w, tok, project, "key.json", fileSecret, nil)
	putRegistry(t, w, tok, project, "docker.io", "bot", reg)
	createImage(t, w, tok, sc.project.ID, "web", `{"kind":"service","image":"nginx","env_sets":["svc"],"files":[{"file":"key.json","target":"/run/secrets/key.json"}]}`)
	programs := allowImages()
	programs["files"] = true
	b64 := base64.StdEncoding.EncodeToString([]byte(long))
	lines := []string{"long " + long, "b64 " + b64, "short " + short, "file " + fileSecret, "reg " + reg}
	want := []string{
		"long " + catalog.SecretPreview(long),
		"b64 " + catalog.SecretPreview(long),
		"short " + catalog.SecretPreview(short),
		"file [REDACTED]",
		"reg [REDACTED]",
	}
	if catalog.SecretPreview(long) != "abcd…" || catalog.SecretPreview(short) != "••••" {
		t.Fatalf("previews %q %q", catalog.SecretPreview(long), catalog.SecretPreview(short))
	}
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, programs, nil)
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		kind, _ := msg["kind"].(string)
		if kind == "image_logs" {
			return map[string]any{
				"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "succeeded",
				"payload": map[string]any{"container": "web", "lines": lines, "truncated": false},
			}
		}
		reply := imageDeployReply(msg, shaDigest(8))
		reply["payload"].(map[string]any)["lines"] = lines
		return reply
	})
	host := sc.host.ID.String()
	status, env, raw := postImage(t, w, tok, project, "web", "deploy", host, "prev-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertPreviewLines(t, "deploy", env, raw, want, []string{long, short, fileSecret, reg, b64})
	status, env, raw = postImage(t, w, tok, project, "web", "logs", host, "", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	assertPreviewLines(t, "logs", env, raw, want, []string{long, short, fileSecret, reg, b64})
	if log.count() != 2 {
		t.Fatalf("tasks %d", log.count())
	}
}

func TestEnvPreviewForms(t *testing.T) {
	v := "ab\"cd-0123456789"
	raw, err := json.Marshal(v)
	if err != nil || len(raw) < 2 {
		t.Fatal(err)
	}
	inner := string(raw[1 : len(raw)-1])
	forms := envValueForms([]string{v})
	preview := catalog.SecretPreview(v)
	for _, form := range []string{v, inner, base64.StdEncoding.EncodeToString([]byte(v))} {
		if got := redactExact("x "+form, forms); got != "x "+preview {
			t.Fatalf("form %q redacted to %q, want %q", form, got, "x "+preview)
		}
	}
	both := mergeSecretForms(envValueForms([]string{v}), redactedValueForms([]string{v}))
	if got := redactExact("x "+v, both); got != "x [REDACTED]" {
		t.Fatalf("collision %q", got)
	}
}

func putKey(t *testing.T, w *world, tok, project, set, key, value string, secret *bool) (int, envelope, string) {
	t.Helper()
	body := map[string]any{"value": value}
	if secret != nil {
		body["is_secret"] = *secret
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return mustCall(t, w, tok, http.MethodPut, envKeyPath(project, set, key), string(raw))
}

func envKeyPath(project, set, key string) string {
	return envPath(project, set) + "/keys/" + key
}

func keysByName(t *testing.T, env envelope) map[string]map[string]any {
	t.Helper()
	raw, ok := objectPayload(t, env)["keys"].([]any)
	if !ok {
		t.Fatalf("keys %#v", objectPayload(t, env)["keys"])
	}
	out := map[string]map[string]any{}
	for _, item := range raw {
		row, _ := item.(map[string]any)
		name, _ := row["key"].(string)
		out[name] = row
	}
	return out
}

func assertSecretKey(t *testing.T, row map[string]any, preview string) {
	t.Helper()
	if row["is_secret"] != true || row["value"] != nil || row["preview"] != preview {
		t.Fatalf("secret key %#v want preview %q", row, preview)
	}
}

func assertPlainKey(t *testing.T, row map[string]any, value string) {
	t.Helper()
	if row["is_secret"] != false || row["value"] != value || row["preview"] != nil {
		t.Fatalf("plain key %#v want %q", row, value)
	}
}

func assertPreviewLines(t *testing.T, label string, env envelope, raw string, want []string, absent []string) {
	t.Helper()
	got, _ := objectPayload(t, env)["lines"].([]any)
	if len(got) != len(want) {
		t.Fatalf("%s lines %#v", label, got)
	}
	for i, line := range want {
		if got[i] != line {
			t.Fatalf("%s line %d %q want %q", label, i, got[i], line)
		}
	}
	for _, secret := range absent {
		if secret != "" && strings.Contains(raw, secret) {
			t.Fatalf("%s still contains a %d-byte secret form", label, len(secret))
		}
	}
}
