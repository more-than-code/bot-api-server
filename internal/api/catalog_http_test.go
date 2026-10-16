package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestCatalogValidation(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("admin@ex.com", "Admin")
	viewer := w.user("viewer@ex.com", "Viewer")
	spare := w.user("spare@ex.com", "Spare")
	extra := w.user("extra@ex.com", "Extra")
	sc := w.scene(owner, admin, viewer, spare, extra)
	tok := w.token(owner.ID)
	path := "/v1/projects/" + sc.project.ID.String() + "/catalog"

	status, env := w.do(w.token(viewer.ID), http.MethodPost, path, programBody("a", "pnpm run dev", false))
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env = w.do(w.token(extra.ID), http.MethodPost, path, programBody("a", "pnpm run dev", false))
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	status, env = w.do(tok, http.MethodPost, path, `{"kind":"image","command":"pnpm","shell":false,"dir":"/home/joe/app","run_as":"joe"}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid json")
	status, env = w.do(tok, http.MethodPost, path, `{"kind":"program","secret_env":{"A":"b"},"command":"pnpm","shell":false,"dir":"/home/joe/app","run_as":"joe"}`)
	mustHTTP(t, status, env, http.StatusNotImplemented, "not_implemented", "not implemented")
	status, env = w.do(tok, http.MethodPost, path, `{"command":"pnpm","shell":false,"dir":"/home/joe/app","run_as":"joe","name":"a"}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "kind must be program")

	cases := []struct{ name, body, msg string }{
		{"empty", programBody("c1", "", false), "command is empty"},
		{"long", programBody("c2", strings.Repeat("a", 4097), false), "command is too long"},
		{"newline", programBody("c3", "pnpm\nrun", false), "newline is not allowed"},
		{"pipe", programBody("c4", "pnpm | cat", false), "pipe is not allowed"},
		{"and", programBody("c5", "pnpm && cat", false), "operator & is not allowed"},
		{"semicolon", programBody("c6", "pnpm; cat", false), "operator ; is not allowed"},
		{"redirect", programBody("c7", "pnpm > out", false), "redirect is not allowed"},
		{"dollar", programBody("c8", "echo $X", false), "variable expansion is not allowed"},
		{"backtick", programBody("c9", "echo `x`", false), "command substitution is not allowed"},
		{"glob", programBody("c10", "echo *", false), "glob is not allowed"},
		{"question", programBody("c11", "echo file?", false), "glob is not allowed"},
		{"bracket", programBody("c12", "echo file[a]", false), "glob is not allowed"},
		{"paren", programBody("c13", "echo (x)", false), "parenthesis is not allowed"},
		{"brace", programBody("c14", "echo {a}", false), "brace expansion is not allowed"},
		{"tilde", programBody("c15", "~/bin/pnpm", false), "tilde expansion is not allowed"},
		{"cd", programBody("c16", "cd /tmp", false), "use the working directory field"},
		{"exec", programBody("c17", "bin/pnpm", false), "invalid exec"},
		{"args", programBody("c18", "pnpm "+strings.Repeat("a ", 33), false), "too many args"},
		{"dir", programBodyDir("c19", "pnpm", "tmp/app"), "invalid dir"},
		{"run_as", programBodyRun("c20", "root"), "invalid run_as"},
		{"secret", programBodyEnv("c21", "API_KEY", "x"), "use secret_env"},
		{"path", programBodyEnv("c22", "PATH", "/bin"), "PATH is reserved"},
		{"home", programBodyEnv("c23", "HOME", "/home/joe"), "HOME is reserved"},
		{"envkey", programBodyEnv("c24", "node", "1"), "invalid env key"},
		{"envval", programBodyEnv("c25", "FOO", "a\nb"), "invalid env value"},
		{"port", programBodyPort("c26", 0), "invalid port"},
		{"restart", programBodyRestart("c27", "always"), "invalid restart"},
		{"name", programBody("Bad", "pnpm", false), "invalid name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, env := w.do(tok, http.MethodPost, path, tc.body)
			mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", tc.msg)
		})
	}
	envBody := map[string]any{
		"name": "c28", "kind": "program", "command": "pnpm", "shell": false,
		"dir": "/home/joe/app", "run_as": "joe", "env": map[string]string{},
	}
	for i := 0; i < 65; i++ {
		envBody["env"].(map[string]string)[envKey(i)] = "1"
	}
	raw, err := json.Marshal(envBody)
	if err != nil {
		t.Fatal(err)
	}
	status, env = w.do(tok, http.MethodPost, path, string(raw))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "too many env keys")

	created := createProgram(t, w, tok, sc.project.ID, "tra", "pnpm run dev", false)
	if created["kind"] != "program" || created["command_display"] != "pnpm run dev" || created["spec_hash"] == "" {
		t.Fatalf("created %#v", created)
	}
	actions, _ := created["my_actions"].([]any)
	if strings.Join(anyStrings(t, actions), ",") != "run,stop,restart,logs,status" {
		t.Fatalf("owner actions %#v", actions)
	}
	spec, _ := created["spec"].(map[string]any)
	if spec["exec"] != "pnpm" || spec["restart"] != "on-failure" || spec["run_as"] != "joe" {
		t.Fatalf("spec %#v", spec)
	}
	status, env = w.do(tok, http.MethodPost, path, programBody("tra", "pnpm", false))
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")
	adminTok := w.token(admin.ID)
	extraTok := w.token(extra.ID)
	for _, tc := range []struct {
		who, method, url, body string
		status                 int
		code, msg              string
	}{
		{adminTok, http.MethodPost, path, programBody("zz", "pnpm", false), http.StatusForbidden, "forbidden", "forbidden"},
		{extraTok, http.MethodPost, path, programBody("zz", "pnpm", false), http.StatusNotFound, "not_found", "not found"},
		{adminTok, http.MethodPut, path + "/tra", programBody("", "pnpm", false), http.StatusForbidden, "forbidden", "forbidden"},
		{extraTok, http.MethodPut, path + "/tra", programBody("", "pnpm", false), http.StatusNotFound, "not_found", "not found"},
		{adminTok, http.MethodDelete, path + "/tra", "", http.StatusForbidden, "forbidden", "forbidden"},
		{extraTok, http.MethodDelete, path + "/tra", "", http.StatusNotFound, "not_found", "not found"},
		{adminTok, http.MethodPut, path + "/tra/permissions", `{"grants":[]}`, http.StatusForbidden, "forbidden", "forbidden"},
		{extraTok, http.MethodPut, path + "/tra/permissions", `{"grants":[]}`, http.StatusNotFound, "not_found", "not found"},
	} {
		status, env = w.do(tc.who, tc.method, tc.url, tc.body)
		mustHTTP(t, status, env, tc.status, tc.code, tc.msg)
	}
	status, env = w.do(tok, http.MethodPost, path, programBody("ld", "LD_PRELOAD=/tmp/x.so pnpm start", false))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "this variable changes what the program runs")
	status, env = w.do(tok, http.MethodPost, path, programBodyEnv("nodeopt", "NODE_OPTIONS", "--require /x"))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "this variable changes what the program runs")

	status, env = w.do(tok, http.MethodPut, path+"/tra", `{"name":"tra","kind":"program","command":"pnpm","shell":false,"dir":"/home/joe/app","run_as":"joe"}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid json")

	parse := "/v1/projects/" + sc.project.ID.String() + "/catalog/parse"
	status, env = w.do(w.token(admin.ID), http.MethodPost, parse, `{"command":"pnpm","shell":false}`)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env = w.do(tok, http.MethodPost, parse, `{"command":"pnpm run dev | cat","shell":false}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "pipe is not allowed")
	status, env = w.do(tok, http.MethodPost, parse, `{"command":"cd /tmp && pnpm","shell":true}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	got := objectPayload(t, env)
	if got["exec"] != "/bin/sh" || got["command_display"] != "cd /tmp && pnpm" {
		t.Fatalf("shell parse %#v", got)
	}
}

func TestCatalogPermissionsMatrix(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("admin@ex.com", "Admin")
	viewer := w.user("viewer@ex.com", "Viewer")
	spare := w.user("spare@ex.com", "Spare")
	extra := w.user("extra@ex.com", "Extra")
	sc := w.scene(owner, admin, viewer, spare, extra)
	tok := w.token(owner.ID)
	entry := createProgram(t, w, tok, sc.project.ID, "tra", "pnpm run dev", false)
	grants := `/v1/projects/` + sc.project.ID.String() + `/catalog/tra/permissions`
	body := `{"grants":[` +
		`{"subject":"role:admin","actions":["run","stop","restart","logs"]},` +
		`{"subject":"role:viewer","actions":["logs"]},` +
		`{"subject":"user:` + spare.ID.String() + `","actions":["stop"]}]}`
	status, env := w.do(w.token(viewer.ID), http.MethodPut, grants, body)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env = w.do(tok, http.MethodPut, grants, body)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	stored := objectPayload(t, env)["grants"].([]any)
	if len(stored) != 3 {
		t.Fatalf("grants %#v", stored)
	}

	actors := []struct {
		name  string
		tok   string
		allow map[string]bool
	}{
		{"owner", tok, map[string]bool{"run": true, "stop": true, "restart": true, "logs": true, "status": true}},
		{"admin", w.token(admin.ID), map[string]bool{"run": true, "stop": true, "restart": true, "logs": true, "status": true}},
		{"viewer", w.token(viewer.ID), map[string]bool{"logs": true, "status": true}},
		{"user", w.token(spare.ID), map[string]bool{"stop": true, "logs": true, "status": true}},
		{"nonmember", w.token(extra.ID), nil},
	}
	host := sc.host.ID.String()
	for _, actor := range actors {
		for _, action := range []string{"run", "stop", "restart", "logs", "status"} {
			status, env := postAct(w, actor.tok, sc.project.ID.String(), "tra", action, host, "k-"+actor.name+"-"+action, nil)
			if actor.allow == nil {
				mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
				continue
			}
			if actor.allow[action] {
				mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "host does not allow programs")
				continue
			}
			mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
		}
	}
	status, env = postAct(w, tok, sc.project.ID.String(), "missing", "run", host, "k-missing", nil)
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")

	status, env = w.do(w.token(viewer.ID), http.MethodGet, "/v1/projects/"+sc.project.ID.String()+"/catalog/tra", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if strings.Join(anyStrings(t, objectPayload(t, env)["my_actions"].([]any)), ",") != "logs,status" {
		t.Fatalf("viewer actions %#v", env.Payload)
	}
	status, env = w.do(w.token(viewer.ID), http.MethodGet, "/v1/projects/"+sc.project.ID.String()+"/catalog", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if len(listItems(t, env)) != 1 {
		t.Fatalf("viewer list %#v", env.Payload)
	}
	_ = entry

	createProgram(t, w, tok, sc.project.ID, "quiet", "pnpm run dev", false)
	quietGrants := `/v1/projects/` + sc.project.ID.String() + `/catalog/quiet/permissions`
	onlyStop := `{"grants":[{"subject":"user:` + spare.ID.String() + `","actions":["stop"]}]}`
	status, env = w.do(tok, http.MethodPut, quietGrants, onlyStop)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	quietAllow := map[string]map[string]bool{
		"spare":  {"stop": true, "status": true},
		"admin":  {},
		"viewer": {},
	}
	for name, allow := range quietAllow {
		who := w.token(spare.ID)
		if name == "admin" {
			who = w.token(admin.ID)
		}
		if name == "viewer" {
			who = w.token(viewer.ID)
		}
		for _, action := range []string{"run", "stop", "restart", "logs", "status"} {
			status, env := postAct(w, who, sc.project.ID.String(), "quiet", action, host, "q-"+name+"-"+action, nil)
			if allow[action] {
				mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "host does not allow programs")
				continue
			}
			mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
		}
	}
	status, env = w.do(w.token(viewer.ID), http.MethodGet, "/v1/projects/"+sc.project.ID.String()+"/catalog/quiet", "")
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env = w.do(w.token(admin.ID), http.MethodGet, "/v1/projects/"+sc.project.ID.String()+"/catalog/quiet", "")
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env = w.do(w.token(spare.ID), http.MethodGet, "/v1/projects/"+sc.project.ID.String()+"/catalog/quiet", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if strings.Join(anyStrings(t, objectPayload(t, env)["my_actions"].([]any)), ",") != "stop,status" {
		t.Fatalf("spare actions %#v", env.Payload)
	}
	status, env = w.do(w.token(viewer.ID), http.MethodGet, "/v1/projects/"+sc.project.ID.String()+"/catalog", "")
	if len(listItems(t, env)) != 1 {
		t.Fatalf("viewer still sees quiet %#v", env.Payload)
	}
	status, env = w.do(w.token(admin.ID), http.MethodGet, "/v1/projects/"+sc.project.ID.String()+"/catalog", "")
	if len(listItems(t, env)) != 1 {
		t.Fatalf("admin sees quiet %#v", env.Payload)
	}
	status, env = w.do(w.token(extra.ID), http.MethodGet, "/v1/projects/"+sc.project.ID.String()+"/catalog/quiet", "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	rawRun := `{"host_id":"` + host + `"}`
	status, env = w.do(w.token(viewer.ID), http.MethodPost, "/v1/projects/"+sc.project.ID.String()+"/catalog/tra/run", rawRun)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env = w.do(tok, http.MethodPost, "/v1/projects/"+sc.project.ID.String()+"/catalog/tra/run", rawRun)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid idempotency_key")
	foundGrantDeny := false
	for _, row := range auditRows(t, w, sc.project.ID) {
		if row.Action != "program.run" || row.Decision != "denied" || row.Result == nil || *row.Result != "forbidden" || row.HostID == nil {
			continue
		}
		var detail map[string]any
		if json.Unmarshal(row.Detail, &detail) != nil {
			t.Fatal("detail")
		}
		if detail["entry"] == "tra" && detail["reason"] == "forbidden" && *row.HostID == sc.host.ID {
			foundGrantDeny = true
		}
	}
	if !foundGrantDeny {
		t.Fatal("grant denial omitted entry or host")
	}
	if auditCount(auditRows(t, w, sc.project.ID), "program.logs", "denied") != 0 {
		t.Fatal("logs denial was audited")
	}
}

func TestCatalogHostRelation(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("admin@ex.com", "Admin")
	viewer := w.user("viewer@ex.com", "Viewer")
	spare := w.user("spare@ex.com", "Spare")
	extra := w.user("extra@ex.com", "Extra")
	sc := w.scene(owner, admin, viewer, spare, extra)
	boxOwner := w.user("box@ex.com", "Box")
	boxAdmin := w.user("boxadmin@ex.com", "BoxAdmin")
	boxViewer := w.user("boxview@ex.com", "BoxView")
	box, err := w.mem.CreateProject(ctx, boxOwner.ID, "Box", "box", w.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, box.ID, boxAdmin.ID, "admin", boxOwner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, box.ID, boxViewer.ID, "viewer", boxOwner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, sc.project.ID, boxOwner.ID, "viewer", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	boxHost, _, _ := enrollAgentHost(t, w, box, boxOwner.ID, "boxpi")
	tok := w.token(owner.ID)
	entry := createProgram(t, w, tok, sc.project.ID, "tra", "pnpm run dev", false)
	entryID, _ := entry["id"].(string)
	hash, _ := entry["spec_hash"].(string)
	approvals := "/v1/hosts/" + boxHost.ID.String() + "/catalog-approvals"

	status, env := w.do(w.token(extra.ID), http.MethodGet, approvals, "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	status, env = w.do(w.token(admin.ID), http.MethodGet, approvals, "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	status, env = w.do(w.token(boxViewer.ID), http.MethodGet, approvals, "")
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env = w.do(w.token(boxViewer.ID), http.MethodPost, approvals, `{"entry_id":"`+entryID+`","spec_hash":"`+hash+`"}`)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env = w.do(w.token(boxAdmin.ID), http.MethodGet, approvals, "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if len(listItems(t, env)) != 0 {
		t.Fatalf("approvals %#v", env.Payload)
	}
	status, env = w.do(tok, http.MethodGet, "/v1/hosts/"+uuid.New().String()+"/catalog-approvals", "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")

	if err := w.mem.SetHostPrograms(ctx, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, PolicyHash: "abc"}); err != nil {
		t.Fatal(err)
	}
	status, env = postAct(w, tok, sc.project.ID.String(), "tra", "run", sc.host.ID.String(), "own-1", nil)
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "host unavailable")

	status, env = postAct(w, tok, sc.project.ID.String(), "tra", "run", boxHost.ID.String(), "rel-unrelated", nil)
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")

	share := "/v1/hosts/" + boxHost.ID.String() + "/shares/" + sc.project.ID.String()
	status, env = w.do(w.token(boxOwner.ID), http.MethodPut, share, `{"level":"metrics"}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env = postAct(w, tok, sc.project.ID.String(), "tra", "run", boxHost.ID.String(), "rel-metrics", nil)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env = w.do(w.token(boxAdmin.ID), http.MethodGet, approvals, "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if len(listItems(t, env)) != 0 {
		t.Fatalf("metrics created an approval %#v", env.Payload)
	}

	status, env = w.do(w.token(boxOwner.ID), http.MethodPut, share, `{"level":"deploy"}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if err := w.mem.SetHostPrograms(ctx, boxHost.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, PolicyHash: "abc"}); err != nil {
		t.Fatal(err)
	}
	status, env = postAct(w, tok, sc.project.ID.String(), "tra", "run", boxHost.ID.String(), "rel-wait", nil)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "waiting for the host owner's approval")
	status, env = w.do(w.token(boxAdmin.ID), http.MethodGet, approvals, "")
	items := listItems(t, env)
	if len(items) != 1 || items[0]["status"] != "pending" || items[0]["spec_hash"] != hash || items[0]["requested_by"] != owner.ID.String() {
		t.Fatalf("pending %#v", items)
	}

	status, env = w.do(w.token(boxAdmin.ID), http.MethodPost, approvals, `{"entry_id":"`+entryID+`","spec_hash":"`+hash+`"}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	approved := objectPayload(t, env)
	if approved["status"] != "approved" || approved["requested_by"] != owner.ID.String() || approved["approved_by"] != boxAdmin.ID.String() || approved["exec"] != "pnpm" {
		t.Fatalf("approved %#v", approved)
	}
	approvedArgs, _ := approved["args"].([]any)
	approvedEnv, _ := approved["env"].(map[string]any)
	if len(approvedArgs) != 2 || approvedArgs[0] != "run" || approvedEnv == nil {
		t.Fatalf("approval spec %#v", approved)
	}
	status, env = w.do(tok, http.MethodPut, "/v1/projects/"+sc.project.ID.String()+"/catalog/tra", `{"kind":"program","command":"pnpm run dev","shell":false,"dir":"/home/joe/app","run_as":"joe"}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env = w.do(w.token(boxAdmin.ID), http.MethodGet, approvals, "")
	kept := listItems(t, env)
	if len(kept) != 1 || kept[0]["status"] != "approved" || kept[0]["spec_hash"] != hash {
		t.Fatalf("same hash voided %#v", kept)
	}
	entryUUID, err := uuid.Parse(entryID)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.mem.UpsertPendingApproval(ctx, entryUUID, boxHost.ID, hash, owner.ID, w.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	status, env = w.do(w.token(boxAdmin.ID), http.MethodGet, approvals, "")
	kept = listItems(t, env)
	if len(kept) != 1 || kept[0]["status"] != "approved" || kept[0]["requested_by"] != owner.ID.String() {
		t.Fatalf("upsert cleared approval %#v", kept)
	}
	status, env = postAct(w, tok, sc.project.ID.String(), "tra", "run", boxHost.ID.String(), "rel-go", nil)
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "host unavailable")

	status, env = w.do(tok, http.MethodPut, "/v1/projects/"+sc.project.ID.String()+"/catalog/tra", `{"kind":"program","command":"pnpm run start","shell":false,"dir":"/home/joe/app","run_as":"joe"}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	newHash, _ := objectPayload(t, env)["spec_hash"].(string)
	if newHash == hash {
		t.Fatal("spec hash did not change")
	}
	status, env = w.do(w.token(boxAdmin.ID), http.MethodGet, approvals, "")
	if len(listItems(t, env)) != 0 {
		t.Fatalf("void left %#v", env.Payload)
	}
	status, env = w.do(w.token(boxAdmin.ID), http.MethodPost, approvals, `{"entry_id":"`+entryID+`","spec_hash":"`+hash+`"}`)
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")
	status, env = w.do(w.token(boxAdmin.ID), http.MethodGet, approvals, "")
	if len(listItems(t, env)) != 0 {
		t.Fatalf("stale approve stored %#v", env.Payload)
	}
	status, env = postAct(w, tok, sc.project.ID.String(), "tra", "run", boxHost.ID.String(), "rel-void", nil)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "waiting for the host owner's approval")
	status, env = w.do(w.token(boxAdmin.ID), http.MethodGet, approvals, "")
	items = listItems(t, env)
	if len(items) != 1 || items[0]["status"] != "pending" || items[0]["spec_hash"] != newHash {
		t.Fatalf("pending after void %#v", items)
	}
	status, env = w.do(w.token(boxOwner.ID), http.MethodDelete, approvals+"/"+entryID, "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env = w.do(w.token(boxViewer.ID), http.MethodDelete, approvals+"/"+entryID, "")
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
}

func TestCatalogPolicy(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	createProgram(t, w, tok, sc.project.ID, "tra", "pnpm run dev", false)
	createProgram(t, w, tok, sc.project.ID, "sh", "echo hi", true)
	host := sc.host.ID.String()
	project := sc.project.ID.String()

	status, env := postAct(w, tok, project, "tra", "run", host, "p-null", nil)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "host does not allow programs")
	status, env = postAct(w, tok, project, "tra", "status", host, "", nil)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "host does not allow programs")

	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: false, RunAs: []string{"joe"}, PolicyHash: "abc"})
	status, env = postAct(w, tok, project, "tra", "run", host, "p-off", nil)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "programs are disabled on this host")

	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"other"}, PolicyHash: "abc"})
	status, env = postAct(w, tok, project, "tra", "stop", host, "p-user", nil)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "run_as is not allowed on this host")

	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, AllowShell: false, PolicyHash: "abc"})
	status, env = postAct(w, tok, project, "sh", "logs", host, "", nil)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "shell is not allowed on this host")
	createProgram(t, w, tok, sc.project.ID, "shbin", "/bin/sh -c 'echo hi'", false)
	status, env = postAct(w, tok, project, "shbin", "logs", host, "", nil)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "shell is not allowed on this host")
	status, env = postAct(w, tok, project, "tra", "restart", host, "p-offline", nil)
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "host unavailable")
	setPrograms(t, w, sc.host.ID, &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, AllowShell: true, PolicyHash: "abc"})
	status, env = postAct(w, tok, project, "shbin", "logs", host, "", nil)
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "host unavailable")

	status, env = postAct(w, tok, project, "tra", "logs", host, "", intPtr(0))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid lines")
	status, env = postAct(w, tok, project, "tra", "logs", host, "", intPtr(1001))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid lines")
	status, env = postAct(w, tok, project, "tra", "run", host, "bad key", nil)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid idempotency_key")
	status, env = postAct(w, tok, project, "tra", "run", host, strings.Repeat("a", 129), nil)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid idempotency_key")
	status, env = postAct(w, tok, project, "tra", "run", host, strings.Repeat("b", 128), nil)
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "host unavailable")
}

func TestCatalogConfirmationAndIdempotency(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	other := w.user("other@ex.com", "Other")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), other)
	tok := w.token(owner.ID)
	createProgram(t, w, tok, sc.project.ID, "tra", "pnpm run dev", false)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowPrograms(false), nil)
	log := watchTasks(t, conn, succeededTask)
	project := sc.project.ID.String()
	host := sc.host.ID.String()

	status, env := postAct(w, tok, project, "tra", "run", host, "console-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if objectPayload(t, env)["unit"] != "deploybot-proj-tra.service" {
		t.Fatalf("payload %#v", env.Payload)
	}
	if log.count() != 1 {
		t.Fatalf("console tasks %d", log.count())
	}
	first := log.raw(0)
	if first["kind"] != "program_start" || first["service"] != nil {
		t.Fatalf("task %#v", first)
	}
	spec, _ := first["spec"].(map[string]any)
	args, _ := spec["args"].([]any)
	envMap, _ := spec["env"].(map[string]any)
	if spec["project"] != "proj" || spec["entry"] != "tra" || spec["exec"] != "pnpm" || spec["run_as"] != "joe" || spec["shell"] != false || spec["dir"] != "/home/joe/app" || spec["restart"] != "on-failure" || len(args) != 2 || args[0] != "run" || args[1] != "dev" || len(envMap) != 0 {
		t.Fatalf("spec %#v", spec)
	}

	status, env = postAct(w, tok, project, "tra", "run", host, "console-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 1 || objectPayload(t, env)["unit"] != "deploybot-proj-tra.service" {
		t.Fatalf("replay tasks %d payload %#v", log.count(), env.Payload)
	}
	secondHost, cred, credID := enrollAgentHost(t, w, sc.project, owner.ID, "pi5")
	conn2 := helloAgent(t, w, secondHost, cred, credID, allowPrograms(false), nil)
	log2 := watchTasks(t, conn2, succeededTask)
	status, env = postAct(w, tok, project, "tra", "run", secondHost.ID.String(), "console-1", nil)
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")
	if log.count() != 1 || log2.count() != 0 {
		t.Fatalf("conflict dispatched %d %d", log.count(), log2.count())
	}

	delegated := tokenKind(t, w, owner.ID, store.KindDelegated)
	status, env = postAct(w, delegated, project, "tra", "restart", host, "del-1", nil)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	pending := objectPayload(t, env)
	id, _ := pending["confirmation_id"].(string)
	if len(id) != 43 || pending["plan"] != "will restart program tra (pnpm run dev, as joe) on pi4" || pending["expires_at"] != "2026-10-13T12:05:00Z" {
		t.Fatalf("confirmation %#v", pending)
	}
	if log.count() != 1 {
		t.Fatalf("confirmation dispatched %d", log.count())
	}
	status, env = postAct(w, delegated, project, "tra", "restart", host, "del-1", nil)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	if objectPayload(t, env)["confirmation_id"] != id || log.count() != 1 {
		t.Fatalf("replay minted another confirmation %#v tasks %d", env.Payload, log.count())
	}
	status, env = postAct(w, delegated, project, "tra", "restart", secondHost.ID.String(), "del-1", nil)
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")

	status, env = w.do(w.token(other.ID), http.MethodPost, "/v1/confirmations/"+id, confirmBody("del-1"))
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	status, env = w.do(delegated, http.MethodPost, "/v1/confirmations/"+id, confirmBody("del-1"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 2 || objectPayload(t, env)["unit"] != "deploybot-proj-tra.service" {
		t.Fatalf("confirm %#v tasks %d", env.Payload, log.count())
	}
	if log.raw(1)["kind"] != "program_restart" {
		t.Fatalf("confirm task %#v", log.raw(1))
	}
	status, env = w.do(delegated, http.MethodPost, "/v1/confirmations/"+id, confirmBody("del-1"))
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	status, env = postAct(w, delegated, project, "tra", "restart", host, "del-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 2 {
		t.Fatalf("stored result replayed as a new task %d", log.count())
	}

	status, env = postAct(w, delegated, project, "tra", "logs", host, "", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 3 || log.raw(2)["kind"] != "program_logs" {
		t.Fatalf("logs %#v", log.raw(2))
	}
	lines, _ := log.raw(2)["spec"].(map[string]any)["lines"].(float64)
	if lines != 200 {
		t.Fatalf("default lines %v", log.raw(2)["spec"])
	}
	rows := auditRows(t, w, sc.project.ID)
	if auditCount(rows, "program.confirmation_issued", "allowed") != 1 || auditVia(t, rows, "program.confirmation_issued") != "mcp" {
		t.Fatalf("confirmation audit %#v", rows)
	}
	if !auditHasResult(rows, "program.restart", "allowed", "succeeded", "mcp") {
		t.Fatalf("restart audit %#v", rows)
	}
	if auditCount(rows, "program.run", "allowed") != 1 || auditVia(t, rows, "program.run") != "console" {
		t.Fatalf("run audit %#v", rows)
	}
	for _, row := range rows {
		if strings.Contains(string(row.Detail), id) {
			t.Fatalf("audit kept confirmation id %s", row.Action)
		}
	}

	status, env = postAct(w, tok, project, "tra", "stop", host, "console-stop", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	stopTask := log.raw(log.count() - 1)
	stopSpec, _ := stopTask["spec"].(map[string]any)
	if stopTask["kind"] != "program_stop" || len(stopSpec) != 2 || stopSpec["project"] != "proj" || stopSpec["entry"] != "tra" {
		t.Fatalf("stop %#v", stopTask)
	}
	if !auditHasResult(auditRows(t, w, sc.project.ID), "program.stop", "allowed", "succeeded", "console") {
		t.Fatal("stop audit")
	}
	beforeStop := log.count()
	status, env = postAct(w, tok, project, "tra", "status", host, "", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	statusTask := log.raw(log.count() - 1)
	statusSpec, _ := statusTask["spec"].(map[string]any)
	if statusTask["kind"] != "program_status" || len(statusSpec) != 2 || statusSpec["project"] != "proj" || statusSpec["entry"] != "tra" || log.count() != beforeStop+1 {
		t.Fatalf("status %#v count %d", statusTask, log.count())
	}
	status, env = w.do(tok, http.MethodPut, "/v1/projects/"+project+"/catalog/tra", `{"kind":"program","command":"pnpm run start","shell":false,"dir":"/home/joe/app","run_as":"joe"}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	tasks := log.count()
	status, env = postAct(w, tok, project, "tra", "run", host, "console-1", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != tasks || objectPayload(t, env)["unit"] != "deploybot-proj-tra.service" {
		t.Fatalf("spec change replay tasks %d payload %#v", log.count(), env.Payload)
	}
}

func TestCatalogConfirmationEdges(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	other := w.user("other@ex.com", "Other")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), other)
	tok := w.token(owner.ID)
	createProgram(t, w, tok, sc.project.ID, "tra", "pnpm run dev", false)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowPrograms(false), nil)
	log := watchTasks(t, conn, succeededTask)
	delegated := tokenKind(t, w, owner.ID, store.KindDelegated)
	project := sc.project.ID.String()
	host := sc.host.ID.String()

	status, env := postAct(w, delegated, project, "tra", "stop", host, "edge-expire", nil)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	expiredID, _ := objectPayload(t, env)["confirmation_id"].(string)
	w.srv.Now = func() time.Time { return time.Date(2026, 10, 13, 12, 6, 0, 0, time.UTC) }
	status, env = w.do(delegated, http.MethodPost, "/v1/confirmations/"+expiredID, confirmBody("edge-expire"))
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	if log.count() != 0 {
		t.Fatalf("expired dispatched %d", log.count())
	}
	w.srv.Now = func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) }

	status, env = postAct(w, delegated, project, "tra", "stop", host, "edge-hash", nil)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, _ := objectPayload(t, env)["confirmation_id"].(string)
	status, env = w.do(tok, http.MethodPut, "/v1/projects/"+project+"/catalog/tra", `{"kind":"program","command":"pnpm run start","shell":false,"dir":"/home/joe/app","run_as":"joe"}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env = w.do(delegated, http.MethodPost, "/v1/confirmations/"+id, confirmBody("edge-hash"))
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")
	status, env = w.do(delegated, http.MethodPost, "/v1/confirmations/"+id, confirmBody("edge-hash"))
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")
	if log.count() != 0 {
		t.Fatalf("spec conflict dispatched %d", log.count())
	}
	row, err := w.mem.GetConfirmation(context.Background(), secret.Hash(id))
	if err != nil || row.UsedAt != nil {
		t.Fatalf("confirmation consumed %+v %v", row, err)
	}
}

func TestCatalogOutcomes(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	createProgram(t, w, tok, sc.project.ID, "tra", "FOO=super-secret-env-value pnpm run dev", false)
	project := sc.project.ID.String()
	host := sc.host.ID.String()
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowPrograms(false), nil)

	replies := []func(map[string]any) map[string]any{
		func(msg map[string]any) map[string]any {
			return map[string]any{"v": 1, "type": "task_reject", "task_id": msg["task_id"], "error_code": "policy_denied"}
		},
		func(msg map[string]any) map[string]any {
			return map[string]any{"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "failed", "error_code": "policy_denied"}
		},
		func(msg map[string]any) map[string]any {
			return map[string]any{"v": 1, "type": "task_reject", "task_id": msg["task_id"], "error_code": "bad_spec"}
		},
		func(msg map[string]any) map[string]any {
			return map[string]any{
				"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "failed", "error_code": "start_failed",
				"payload": map[string]any{"unit": "u", "lines": []string{"password=hunter2"}},
			}
		},
	}
	n := 0
	taskLog := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		fn := replies[n]
		n++
		return fn(msg)
	})
	status, env := postAct(w, tok, project, "tra", "run", host, "out-1", nil)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	started := taskLog.raw(0)
	startSpec, _ := started["spec"].(map[string]any)
	startEnv, _ := startSpec["env"].(map[string]any)
	if startEnv["FOO"] != "super-secret-env-value" {
		t.Fatalf("start env %#v", startSpec["env"])
	}
	if taskLog.count() != 1 {
		t.Fatalf("tasks %d", taskLog.count())
	}
	status, env = postAct(w, tok, project, "tra", "run", host, "out-1", nil)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	if taskLog.count() != 1 {
		t.Fatalf("error replay dispatched %d", taskLog.count())
	}
	status, env = postAct(w, tok, project, "tra", "run", host, "out-2", nil)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env = postAct(w, tok, project, "tra", "run", host, "out-3", nil)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "bad request")
	status, env = postAct(w, tok, project, "tra", "run", host, "out-4", nil)
	mustHTTP(t, status, env, http.StatusInternalServerError, "error", "start_failed")
	payload := objectPayload(t, env)
	if payload["unit"] != "u" {
		t.Fatalf("payload %#v", env.Payload)
	}
	lines, _ := payload["lines"].([]any)
	line, _ := lines[0].(string)
	if len(lines) != 1 || strings.Contains(line, "hunter2") || !strings.Contains(line, "[REDACTED]") {
		t.Fatalf("lines %#v", payload["lines"])
	}
	tasks := taskLog.count()
	status, env = postAct(w, tok, project, "tra", "run", host, "out-4", nil)
	mustHTTP(t, status, env, http.StatusInternalServerError, "error", "start_failed")
	replayLines, _ := objectPayload(t, env)["lines"].([]any)
	replayLine, _ := replayLines[0].(string)
	if taskLog.count() != tasks || strings.Contains(replayLine, "hunter2") {
		t.Fatalf("failed replay %#v tasks %d", env.Payload, taskLog.count())
	}
	for _, row := range auditRows(t, w, sc.project.ID) {
		if strings.Contains(string(row.Detail), "super-secret-env-value") {
			t.Fatalf("audit leaked env on %s", row.Action)
		}
	}
	before := len(auditRows(t, w, sc.project.ID))
	conn2 := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowPrograms(false), nil)
	watchTasks(t, conn2, succeededTask)
	status, env = postAct(w, tok, project, "tra", "logs", host, "", intPtr(7))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if len(auditRows(t, w, sc.project.ID)) != before {
		t.Fatal("logs wrote an audit row")
	}
}

func TestHelloProgramsAndOwnedIngest(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	appOwner := w.user("app@ex.com", "App")
	app, err := w.mem.CreateProject(ctx, appOwner.ID, "App", "appproj", w.now)
	if err != nil {
		t.Fatal(err)
	}
	createProgram(t, w, w.token(appOwner.ID), app.ID, "tra", "pnpm run dev", false)
	unit := "deploybot-missing-nope.service"
	scope := "system"
	services := []any{
		map[string]any{"name": "not-the-entry", "kind": "systemd", "ports": []int{3031}, "systemd_unit": unit, "systemd_scope": scope, "owner": map[string]any{"kind": "program", "project": "appproj", "entry": "tra"}},
		map[string]any{"name": "other", "kind": "systemd", "ports": []int{9}, "systemd_unit": unit, "systemd_scope": scope, "owner": map[string]any{"kind": "program", "project": "missing", "entry": "nope"}},
		map[string]any{"name": "imgd", "kind": "process", "ports": []int{1}, "owner": map[string]any{"kind": "image", "project": "appproj", "entry": "tra"}},
		map[string]any{"name": "reported", "kind": "systemd", "ports": []int{4}, "systemd_unit": "deploybot-appproj-absent.service", "systemd_scope": scope, "owner": map[string]any{"kind": "program", "project": "appproj", "entry": "no-such"}},
	}
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowPrograms(true), services)
	tok := w.token(owner.ID)
	status, env := w.do(tok, http.MethodGet, "/v1/hosts/"+sc.host.ID.String(), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	programs, _ := objectPayload(t, env)["programs"].(map[string]any)
	if programs["enabled"] != true || programs["allow_shell"] != true {
		t.Fatalf("programs %#v", programs)
	}
	items := serviceItems(t, w, tok, sc.host.ID)
	owned := findMap(t, items, "name", "tra")
	if owned["source"] != "owned" || owned["catalog_entry"] != "tra" || owned["project_id"] != app.ID.String() {
		t.Fatalf("owned %#v", owned)
	}
	if findMap(t, items, "name", "not-the-entry") != nil {
		t.Fatal("reported name was stored beside the entry")
	}
	miss := findMap(t, items, "name", unit)
	if miss["source"] != "discovered" || miss["catalog_entry"] != nil || miss["project_id"] != sc.project.ID.String() {
		t.Fatalf("fallback %#v", miss)
	}
	img := findMap(t, items, "name", "imgd")
	if img["source"] != "discovered" || img["catalog_entry"] != nil {
		t.Fatalf("image owner %#v", img)
	}
	wrong := findMap(t, items, "name", "deploybot-appproj-absent.service")
	if wrong["source"] != "discovered" || wrong["catalog_entry"] != nil || wrong["project_id"] != sc.project.ID.String() {
		t.Fatalf("wrong entry %#v", wrong)
	}
	writeFrame(t, conn, map[string]any{"v": 1, "type": "services", "services": []any{
		map[string]any{"name": "plain", "kind": "process", "ports": []int{2}},
	}})
	waitService(t, w, tok, sc.host.ID, "plain")
	status, env = w.do(tok, http.MethodGet, "/v1/hosts/"+sc.host.ID.String(), "")
	programs, _ = objectPayload(t, env)["programs"].(map[string]any)
	if programs["enabled"] != true {
		t.Fatalf("services cleared programs %#v", programs)
	}

	helloAgent(t, w, sc.host, sc.credPlain, sc.credID, map[string]any{"enabled": true, "dirs": []string{"/tmp"}}, nil)
	status, env = w.do(tok, http.MethodGet, "/v1/hosts/"+sc.host.ID.String(), "")
	programs, _ = objectPayload(t, env)["programs"].(map[string]any)
	runAs, _ := programs["run_as"].([]any)
	if programs["enabled"] != false || len(runAs) != 0 {
		t.Fatalf("invalid programs %#v", programs)
	}
	helloAgent(t, w, sc.host, sc.credPlain, sc.credID, nil, nil)
	status, env = w.do(tok, http.MethodGet, "/v1/hosts/"+sc.host.ID.String(), "")
	if objectPayload(t, env)["programs"] != nil {
		t.Fatalf("programs not cleared %#v", env.Payload)
	}
}

func TestCatalogAuditRows(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	entry := createProgram(t, w, tok, sc.project.ID, "tra", "pnpm run dev", false)
	status, env := w.do(tok, http.MethodPut, "/v1/projects/"+sc.project.ID.String()+"/catalog/tra", `{"kind":"program","command":"pnpm run start","shell":false,"dir":"/home/joe/app","run_as":"joe"}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	newHash, _ := objectPayload(t, env)["spec_hash"].(string)
	status, env = w.do(tok, http.MethodPut, "/v1/projects/"+sc.project.ID.String()+"/catalog/tra/permissions", `{"grants":[{"subject":"role:viewer","actions":["logs"]}]}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	boxOwner := w.user("box@ex.com", "Box")
	box, err := w.mem.CreateProject(ctx, boxOwner.ID, "Box", "boxaudit", w.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, box.ID, owner.ID, "admin", boxOwner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	host, _, _ := enrollAgentHost(t, w, box, boxOwner.ID, "auditpi")
	entryID, _ := entry["id"].(string)
	approvals := "/v1/hosts/" + host.ID.String() + "/catalog-approvals"
	status, env = w.do(tok, http.MethodPost, approvals, `{"entry_id":"`+entryID+`","spec_hash":"`+newHash+`"}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env = w.do(tok, http.MethodDelete, approvals+"/"+entryID, "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env = w.do(tok, http.MethodDelete, "/v1/projects/"+sc.project.ID.String()+"/catalog/tra", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")

	rows := auditRows(t, w, sc.project.ID)
	for _, action := range []string{"catalog.create", "catalog.update", "catalog.permissions", "catalog.delete"} {
		if auditCount(rows, action, "allowed") != 1 || auditVia(t, rows, action) != "console" {
			t.Fatalf("missing %s in %#v", action, rows)
		}
	}
	updated := auditOne(t, rows, "catalog.update", "allowed")
	detail := map[string]any{}
	if err := json.Unmarshal(updated.Detail, &detail); err != nil {
		t.Fatal(err)
	}
	if detail["old_spec_hash"] == "" || detail["spec_hash"] != newHash || detail["old_spec_hash"] == detail["spec_hash"] {
		t.Fatalf("update detail %#v", detail)
	}
	boxRows := auditRows(t, w, box.ID)
	if auditCount(boxRows, "catalog.approve", "allowed") != 1 || auditCount(boxRows, "catalog.approval_revoke", "allowed") != 1 {
		t.Fatalf("approval audit %#v", boxRows)
	}
}

func TestCatalogConfirmationNotConsumed(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("admin@ex.com", "Admin")
	sc := w.scene(owner, admin, w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	createProgram(t, w, tok, sc.project.ID, "tra", "pnpm run dev", false)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowPrograms(false), nil)
	log := watchTasks(t, conn, succeededTask)
	delegated := tokenKind(t, w, admin.ID, store.KindDelegated)
	project := sc.project.ID.String()
	host := sc.host.ID.String()
	grants := "/v1/projects/" + project + "/catalog/tra/permissions"

	status, env := postAct(w, delegated, project, "tra", "stop", host, "hold", nil)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, _ := objectPayload(t, env)["confirmation_id"].(string)
	status, env = w.do(delegated, http.MethodPost, "/v1/confirmations/"+id, `{}`)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid idempotency_key")
	status, env = w.do(delegated, http.MethodPost, "/v1/confirmations/"+id, confirmBody("other-key"))
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "idempotency_key does not match the request that issued this confirmation")
	status, env = w.do(tok, http.MethodPut, grants, `{"grants":[{"subject":"role:viewer","actions":["logs"]}]}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env = w.do(delegated, http.MethodPost, "/v1/confirmations/"+id, confirmBody("hold"))
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env = w.do(tok, http.MethodPut, grants, `{"grants":[{"subject":"role:admin","actions":["run","stop","restart","logs"]},{"subject":"role:viewer","actions":["logs"]}]}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	w.srv.Now = func() time.Time { return time.Date(2026, 10, 13, 12, 2, 0, 0, time.UTC) }
	status, env = w.do(delegated, http.MethodPost, "/v1/confirmations/"+id, confirmBody("hold"))
	mustHTTP(t, status, env, http.StatusServiceUnavailable, "unavailable", "host unavailable")
	w.srv.Now = func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) }
	if log.count() != 0 {
		t.Fatalf("confirmation dispatched %d", log.count())
	}
	row, err := w.mem.GetConfirmation(context.Background(), secret.Hash(id))
	if err != nil || row.UsedAt != nil {
		t.Fatalf("confirmation consumed %+v %v", row, err)
	}
}

func TestCatalogIdempotencyUsersAndProgress(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("admin@ex.com", "Admin")
	sc := w.scene(owner, admin, w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	createProgram(t, w, tok, sc.project.ID, "tra", "pnpm run dev", false)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowPrograms(false), nil)
	release := make(chan struct{})
	log := watchTasks(t, conn, func(msg map[string]any) map[string]any {
		<-release
		return succeededTask(msg)
	})
	project := sc.project.ID.String()
	host := sc.host.ID.String()
	type result struct {
		status int
		env    envelope
	}
	done := make(chan result, 1)
	go func() {
		status, env := postAct(w, tok, project, "tra", "run", host, "race", nil)
		done <- result{status, env}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for log.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if log.count() != 1 {
		t.Fatal("first task was not sent")
	}
	status, env := postAct(w, tok, project, "tra", "run", host, "race", nil)
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "request in progress")
	if log.count() != 1 {
		t.Fatalf("second call dispatched %d", log.count())
	}
	close(release)
	select {
	case first := <-done:
		mustHTTP(t, first.status, first.env, http.StatusOK, "ok", "ok")
	case <-time.After(3 * time.Second):
		t.Fatal("first request did not finish")
	}
	if log.count() != 1 {
		t.Fatalf("tasks %d", log.count())
	}
	status, env = postAct(w, w.token(admin.ID), project, "tra", "run", host, "race", nil)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if log.count() != 2 {
		t.Fatalf("other user reused the key, tasks %d", log.count())
	}
}

func TestCatalogGrantRules(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("admin@ex.com", "Admin")
	sc := w.scene(owner, admin, w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	createProgram(t, w, tok, sc.project.ID, "tra", "pnpm run dev", false)
	path := "/v1/projects/" + sc.project.ID.String() + "/catalog/tra/permissions"
	outsider := uuid.New()
	cases := []struct{ name, body, msg string }{
		{"missing", `{}`, "grants required"},
		{"null", `{"grants":null}`, "grants required"},
		{"owner", `{"grants":[{"subject":"user:` + owner.ID.String() + `","actions":["logs"]}]}`, "owner cannot be a subject"},
		{"outsider", `{"grants":[{"subject":"user:` + outsider.String() + `","actions":["logs"]}]}`, "subject is not a member"},
		{"duplicate", `{"grants":[{"subject":"role:viewer","actions":["logs"]},{"subject":"role:viewer","actions":["run"]}]}`, "duplicate subject"},
		{"status", `{"grants":[{"subject":"role:viewer","actions":["status"]}]}`, "invalid actions"},
		{"empty", `{"grants":[{"subject":"role:viewer","actions":[]}]}`, "invalid actions"},
		{"dup action", `{"grants":[{"subject":"role:viewer","actions":["logs","logs"]}]}`, "invalid actions"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, env := w.do(tok, http.MethodPut, path, tc.body)
			mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", tc.msg)
		})
	}
	var many []map[string]any
	for i := 0; i < 101; i++ {
		many = append(many, map[string]any{"subject": "role:viewer", "actions": []string{"logs"}})
	}
	raw, err := json.Marshal(map[string]any{"grants": many})
	if err != nil {
		t.Fatal(err)
	}
	status, env := w.do(tok, http.MethodPut, path, string(raw))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "too many grants")
	status, env = w.do(tok, http.MethodGet, path, "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	got := objectPayload(t, env)["grants"].([]any)
	if len(got) != 2 {
		t.Fatalf("grants changed %#v", got)
	}
}

func confirmBody(key string) string {
	raw, _ := json.Marshal(map[string]string{"idempotency_key": key})
	return string(raw)
}

func programBody(name, command string, shell bool) string {
	raw, _ := json.Marshal(map[string]any{
		"name": name, "kind": "program", "command": command, "shell": shell,
		"dir": "/home/joe/app", "run_as": "joe",
	})
	return string(raw)
}

func programBodyDir(name, command, dir string) string {
	raw, _ := json.Marshal(map[string]any{
		"name": name, "kind": "program", "command": command, "shell": false,
		"dir": dir, "run_as": "joe",
	})
	return string(raw)
}

func programBodyRun(name, runAs string) string {
	raw, _ := json.Marshal(map[string]any{
		"name": name, "kind": "program", "command": "pnpm", "shell": false,
		"dir": "/home/joe/app", "run_as": runAs,
	})
	return string(raw)
}

func programBodyEnv(name, key, val string) string {
	raw, _ := json.Marshal(map[string]any{
		"name": name, "kind": "program", "command": "pnpm", "shell": false,
		"dir": "/home/joe/app", "run_as": "joe", "env": map[string]string{key: val},
	})
	return string(raw)
}

func programBodyPort(name string, port int) string {
	raw, _ := json.Marshal(map[string]any{
		"name": name, "kind": "program", "command": "pnpm", "shell": false,
		"dir": "/home/joe/app", "run_as": "joe", "port": port,
	})
	return string(raw)
}

func programBodyRestart(name, restart string) string {
	raw, _ := json.Marshal(map[string]any{
		"name": name, "kind": "program", "command": "pnpm", "shell": false,
		"dir": "/home/joe/app", "run_as": "joe", "restart": restart,
	})
	return string(raw)
}

func envKey(i int) string {
	return "K" + strings.Repeat("A", 2) + string(rune('A'+i/26)) + string(rune('A'+i%26))
}

func createProgram(t *testing.T, w *world, tok string, project uuid.UUID, name, command string, shell bool) map[string]any {
	t.Helper()
	status, env := w.do(tok, http.MethodPost, "/v1/projects/"+project.String()+"/catalog", programBody(name, command, shell))
	mustHTTP(t, status, env, http.StatusCreated, "ok", "ok")
	return objectPayload(t, env)
}

func postAct(w *world, tok, project, name, action, hostID, key string, lines *int) (int, envelope) {
	body := map[string]any{"host_id": hostID}
	switch action {
	case "logs":
		if lines != nil {
			body["lines"] = *lines
		}
	case "status":
	default:
		body["idempotency_key"] = key
	}
	raw, _ := json.Marshal(body)
	return w.do(tok, http.MethodPost, "/v1/projects/"+project+"/catalog/"+name+"/"+action, string(raw))
}

func mustHTTP(t *testing.T, status int, env envelope, wantStatus int, code, msg string) {
	t.Helper()
	if status != wantStatus || env.Code != code || env.Msg != msg {
		t.Fatalf("status %d code %s msg %q, want %d %s %q", status, env.Code, env.Msg, wantStatus, code, msg)
	}
}

func anyStrings(t *testing.T, items []any) []string {
	t.Helper()
	out := make([]string, len(items))
	for i, item := range items {
		s, ok := item.(string)
		if !ok {
			t.Fatalf("item %T", item)
		}
		out[i] = s
	}
	return out
}

func intPtr(n int) *int { return &n }

func allowPrograms(shell bool) map[string]any {
	return map[string]any{"enabled": true, "run_as": []string{"joe"}, "allow_shell": shell, "policy_hash": "abc"}
}

func setPrograms(t *testing.T, w *world, hostID uuid.UUID, programs *store.HostPrograms) {
	t.Helper()
	if err := w.mem.SetHostPrograms(context.Background(), hostID, programs); err != nil {
		t.Fatal(err)
	}
}

func tokenKind(t *testing.T, w *world, userID uuid.UUID, kind string) string {
	t.Helper()
	plain, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.CreateSession(context.Background(), userID, hash, kind, w.now.Add(time.Hour), w.now); err != nil {
		t.Fatal(err)
	}
	return plain
}

func enrollAgentHost(t *testing.T, w *world, project store.Project, owner uuid.UUID, name string) (store.Host, string, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	_, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.CreateJoinToken(ctx, project.ID, hash, nil, owner, w.now.Add(time.Hour), w.now); err != nil {
		t.Fatal(err)
	}
	credPlain, credHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	credID := uuid.New()
	host, err := w.mem.ConsumeJoinToken(ctx, hash, store.EnrollInput{
		Name: name, NodeType: "pi", OS: "linux", Arch: "arm64", AlwaysOn: true, AgentVersion: "0.1.0",
	}, credID, credHash, w.now)
	if err != nil {
		t.Fatal(err)
	}
	return host, credPlain, credID
}

func helloAgent(t *testing.T, w *world, host store.Host, cred string, credID uuid.UUID, programs any, services any) *websocket.Conn {
	t.Helper()
	if services == nil {
		services = []any{}
	}
	c := w.dial(cred)
	frame := map[string]any{
		"v": 1, "type": "hello", "host_id": host.ID.String(), "credential_id": credID.String(),
		"agent_version": "0.1.0", "os": "linux", "arch": "arm64", "services": services,
	}
	if programs != nil {
		frame["programs"] = programs
	}
	writeFrame(t, c, frame)
	hello := readFrame(t, c)
	if hello["type"] != "hello_ok" {
		t.Fatalf("hello %#v", hello)
	}
	return c
}

type taskLog struct {
	mu    sync.Mutex
	tasks []map[string]any
}

func (l *taskLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.tasks)
}

func (l *taskLog) raw(i int) map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tasks[i]
}

func watchTasks(t *testing.T, c *websocket.Conn, reply func(map[string]any) map[string]any) *taskLog {
	t.Helper()
	log := &taskLog{}
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			_, b, err := c.Read(ctx)
			cancel()
			if err != nil {
				return
			}
			var msg map[string]any
			if json.Unmarshal(b, &msg) != nil || msg["type"] != "task" {
				continue
			}
			log.mu.Lock()
			log.tasks = append(log.tasks, msg)
			log.mu.Unlock()
			if reply == nil {
				continue
			}
			raw, err := json.Marshal(reply(msg))
			if err != nil {
				return
			}
			wctx, wcancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = c.Write(wctx, websocket.MessageText, raw)
			wcancel()
		}
	}()
	return log
}

func succeededTask(msg map[string]any) map[string]any {
	return map[string]any{
		"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "succeeded",
		"payload": map[string]any{
			"unit": "deploybot-proj-tra.service", "active_state": "active", "sub_state": "running",
			"main_pid": 1, "started_at": nil, "ports": []int{},
		},
	}
}

func auditRows(t *testing.T, w *world, projectID uuid.UUID) []store.AuditEntry {
	t.Helper()
	rows, _, err := w.mem.ListAudit(context.Background(), projectID, 200, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func auditCount(rows []store.AuditEntry, action, decision string) int {
	n := 0
	for _, row := range rows {
		if row.Action == action && row.Decision == decision {
			n++
		}
	}
	return n
}

func auditVia(t *testing.T, rows []store.AuditEntry, action string) string {
	t.Helper()
	for _, row := range rows {
		if row.Action == action {
			return row.Via
		}
	}
	t.Fatalf("no %s", action)
	return ""
}

func auditOne(t *testing.T, rows []store.AuditEntry, action, decision string) store.AuditEntry {
	t.Helper()
	for _, row := range rows {
		if row.Action == action && row.Decision == decision {
			return row
		}
	}
	t.Fatalf("no %s %s", action, decision)
	return store.AuditEntry{}
}

func auditHasResult(rows []store.AuditEntry, action, decision, result, via string) bool {
	for _, row := range rows {
		if row.Action == action && row.Decision == decision && row.Via == via && row.Result != nil && *row.Result == result {
			return true
		}
	}
	return false
}

func serviceItems(t *testing.T, w *world, tok string, hostID uuid.UUID) []map[string]any {
	t.Helper()
	status, env := w.do(tok, http.MethodGet, "/v1/hosts/"+hostID.String()+"/services", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	return listItems(t, env)
}

func waitService(t *testing.T, w *world, tok string, hostID uuid.UUID, name string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if findMap(t, serviceItems(t, w, tok, hostID), "name", name) != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("service %s did not appear", name)
}

func findMap(t *testing.T, items []map[string]any, key, val string) map[string]any {
	t.Helper()
	for _, item := range items {
		if item[key] == val {
			return item
		}
	}
	return nil
}
