package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const nginxSpec = `{"kind":"service","image":"nginx"}`

func TestDelegatedCatalogCreateConfirms(t *testing.T) {
	c := newCatalogCast(t)
	status, env, _ := mustCall(t, c.w, c.tok, http.MethodPost, catalogCollection(c.sc.project.ID), catalogImageBody("web", nginxSpec, "create-web"))
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, plan, exp := healthPlanOf(t, env)
	if len(id) != 43 {
		t.Fatalf("confirmation_id %q", id)
	}
	if plan != "will create image entry web in Proj: docker.io/library/nginx:latest, service" {
		t.Fatalf("plan %q", plan)
	}
	if exp != "2026-10-13T12:05:00Z" {
		t.Fatalf("expires_at %s", exp)
	}
	payload := objectPayload(t, env)
	if len(payload) != 3 {
		t.Fatalf("payload %#v", payload)
	}
	status, env = c.w.do(c.console, http.MethodGet, catalogItem(c.sc.project.ID, "web"), "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")

	status, env = c.w.do(c.tok, http.MethodPost, catalogCollection(c.sc.project.ID), catalogImageBody("web", nginxSpec, "create-web"))
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	if objectPayload(t, env)["confirmation_id"] != id {
		t.Fatal("replay minted a new confirmation")
	}

	status, env = c.w.do(c.tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("create-web"))
	mustHTTP(t, status, env, http.StatusCreated, "ok", "ok")
	created := objectPayload(t, env)
	if created["name"] != "web" || created["command_display"] != "docker.io/library/nginx:latest" {
		t.Fatalf("created %#v", created)
	}
	twin := createImage(t, c.w, c.console, c.sc.project.ID, "twin", nginxSpec)
	if twin["spec_hash"] != created["spec_hash"] || created["spec_hash"] == "" {
		t.Fatalf("hash delegated %v console %v", created["spec_hash"], twin["spec_hash"])
	}

	status, env = c.w.do(c.tok, http.MethodPost, catalogCollection(c.sc.project.ID), catalogImageBody("web", nginxSpec, "create-web"))
	mustHTTP(t, status, env, http.StatusCreated, "ok", "ok")
	if catalogNameCount(t, c, "web") != 1 {
		t.Fatal("replay created a second entry")
	}
	status, env = c.w.do(c.tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("create-web"))
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")

	rows := auditRows(t, c.w, c.sc.project.ID)
	if auditViaForName(t, rows, audit.ActionCatalogCreate, "web") != audit.ViaMCP {
		t.Fatal("applied create was not via mcp")
	}
	issued := issuedDetails(t, rows)
	if len(issued) != 1 || issued[0]["action"] != "create" || issued[0]["name"] != "web" || len(issued[0]) != 2 {
		t.Fatalf("issued %#v", issued)
	}
	if strings.Contains(auditBlob(t, c.w, c.sc.project.ID), id) {
		t.Fatal("audit stored the confirmation id")
	}
}

func TestDelegatedCatalogIdempotency(t *testing.T) {
	c := newCatalogCast(t)
	path := catalogCollection(c.sc.project.ID)
	for _, body := range []string{
		`{"name":"web","kind":"image","spec":{"kind":"service","image":"nginx"}}`,
		`{"name":"web","kind":"image","spec":{"kind":"service","image":"nginx"},"idempotency_key":""}`,
		`{"name":"web","kind":"image","spec":{"kind":"service","image":"nginx"},"idempotency_key":"bad key"}`,
	} {
		status, env := c.w.do(c.tok, http.MethodPost, path, body)
		mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid idempotency_key")
	}
	if catalogNameCount(t, c, "web") != 0 {
		t.Fatal("rejected key created an entry")
	}

	spaced := `{"name":"web","kind":"image","idempotency_key":"order-1","spec":{ "image" : "nginx", "kind" : "service" }}`
	status, env := c.w.do(c.tok, http.MethodPost, path, catalogImageBody("web", nginxSpec, "order-1"))
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, _, _ := healthPlanOf(t, env)
	status, env = c.w.do(c.tok, http.MethodPost, path, spaced)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	if objectPayload(t, env)["confirmation_id"] != id {
		t.Fatal("normalized spec did not replay")
	}

	status, env = c.w.do(c.tok, http.MethodPost, path, catalogImageBody("web", `{"kind":"service","image":"nginx:1.27"}`, "order-1"))
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")
	status, env = c.w.do(c.tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("other"))
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "idempotency_key does not match the request that issued this confirmation")
	status, env = c.w.do(c.tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("order-1"))
	mustHTTP(t, status, env, http.StatusCreated, "ok", "ok")
	if objectPayload(t, env)["command_display"] != "docker.io/library/nginx:latest" {
		t.Fatal("conflicting body was applied")
	}

	createImage(t, c.w, c.console, c.sc.project.ID, "taken", nginxSpec)
	status, env = c.w.do(c.tok, http.MethodPost, path, catalogImageBody("taken", nginxSpec, "fresh-key"))
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")
	status, env = c.w.do(c.tok, http.MethodPost, path, catalogImageBody("other", nginxSpec, "fresh-key"))
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")

	status, env, _ = mustCall(t, c.w, c.console, http.MethodPost, path, catalogImageBody("console-a", nginxSpec, "console-key"))
	mustHTTP(t, status, env, http.StatusCreated, "ok", "ok")
	if objectPayload(t, env)["name"] != "console-a" {
		t.Fatal("console create ignored its name")
	}
	status, env, _ = mustCall(t, c.w, c.console, http.MethodPost, path, catalogImageBody("console-b", nginxSpec, "console-key"))
	mustHTTP(t, status, env, http.StatusCreated, "ok", "ok")
	if objectPayload(t, env)["name"] != "console-b" {
		t.Fatal("console session replayed another entry for the same idempotency key")
	}
}

func TestDelegatedCatalogValidation(t *testing.T) {
	c := newCatalogCast(t)
	path := catalogCollection(c.sc.project.ID)
	cases := []struct{ spec, key, msg string }{
		{`{"kind":"service","image":"nginx","env_sets":["missing"]}`, "bad-set", "unknown env set"},
		{`{"kind":"service","image":"nginx","files":[{"file":"note.txt","target":"/etc/note"}]}`, "bad-file", "unknown file"},
		{`{"kind":"service","image":"nginx","volumes":[{"name":"Bad","target":"/data"}]}`, "bad-vol", "invalid volumes"},
		{`{"kind":"service","image":"nginx","env":{"API_KEY":"x"}}`, "bad-env", "use secret_env"},
	}
	for _, tc := range cases {
		status, env := c.w.do(c.tok, http.MethodPost, path, catalogImageBody("web", tc.spec, tc.key))
		mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", tc.msg)
		status, env = c.w.do(c.tok, http.MethodPost, path, catalogImageBody("web", nginxSpec, tc.key))
		mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	}
	if catalogNameCount(t, c, "web") != 0 {
		t.Fatal("validation failure created an entry")
	}
	rows := auditRows(t, c.w, c.sc.project.ID)
	if len(issuedDetails(t, rows)) != len(cases) {
		t.Fatal("a rejected body issued a plan, or a reused key did not")
	}
}

func TestDelegatedCatalogProgramForbidden(t *testing.T) {
	c := newCatalogCast(t)
	path := catalogCollection(c.sc.project.ID)
	body := programBody("batch", "pnpm start", false)
	status, env := c.w.do(c.tok, http.MethodPost, path, body)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", programEntriesConsole)
	if catalogNameCount(t, c, "batch") != 0 {
		t.Fatal("delegated program create wrote an entry")
	}
	status, env = c.w.do(c.console, http.MethodPost, path, body)
	mustHTTP(t, status, env, http.StatusCreated, "ok", "ok")

	status, env = c.w.do(c.tok, http.MethodPut, catalogItem(c.sc.project.ID, "batch"), catalogImagePutBody(nginxSpec, ""))
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", programEntriesConsole)
	status, env = c.w.do(c.console, http.MethodPut, catalogItem(c.sc.project.ID, "batch"), catalogImagePutBody(nginxSpec, "ignored"))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "kind must be program")
	status, env = c.w.do(c.tok, http.MethodDelete, catalogItem(c.sc.project.ID, "batch"), "")
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", programEntriesConsole)
	status, env = c.w.do(c.console, http.MethodGet, catalogItem(c.sc.project.ID, "batch"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env = c.w.do(c.console, http.MethodDelete, catalogItem(c.sc.project.ID, "batch"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")

	createImage(t, c.w, c.console, c.sc.project.ID, "web", nginxSpec)
	progPut := `{"kind":"program","command":"pnpm start","shell":false,"dir":"/home/joe/app","run_as":"joe"}`
	status, env = c.w.do(c.tok, http.MethodPut, catalogItem(c.sc.project.ID, "web"), progPut)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", programEntriesConsole)
	status, env = c.w.do(c.console, http.MethodPut, catalogItem(c.sc.project.ID, "web"), progPut)
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "kind must be image")
	if createImageGet(t, c.w, c.console, c.sc.project.ID, "web")["kind"] != "image" {
		t.Fatal("forbidden put changed the image")
	}
	rows := auditRows(t, c.w, c.sc.project.ID)
	requireDelegatedDenial(t, rows, audit.ActionCatalogCreate, 1)
	requireDelegatedDenial(t, rows, audit.ActionCatalogUpdate, 2)
	requireDelegatedDenial(t, rows, audit.ActionCatalogDelete, 1)
}

func TestDelegatedCatalogUpdate(t *testing.T) {
	c := newCatalogCast(t)
	web := createImage(t, c.w, c.console, c.sc.project.ID, "web", nginxSpec)
	approveEntry(t, c, web)
	status, env, _ := mustCall(t, c.w, c.tok, http.MethodPut, catalogItem(c.sc.project.ID, "web"), catalogImagePutBody(`{"kind":"service","image":"nginx:1.27"}`, "upd-1"))
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, plan, _ := healthPlanOf(t, env)
	want := "will update image entry web: image: docker.io/library/nginx:latest → docker.io/library/nginx:1.27; voids 1 host approval"
	if plan != want {
		t.Fatalf("plan %q", plan)
	}
	status, env = c.w.do(c.tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("upd-1"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if objectPayload(t, env)["command_display"] != "docker.io/library/nginx:1.27" {
		t.Fatalf("updated %#v", objectPayload(t, env))
	}
	if len(listApprovals(t, c.w, c.owner.ID, c.sc.host.ID)) != 0 {
		t.Fatal("confirm did not void the approval")
	}
	if auditViaForName(t, auditRows(t, c.w, c.sc.project.ID), audit.ActionCatalogUpdate, "web") != audit.ViaMCP {
		t.Fatal("applied update was not via mcp")
	}

	edge := createImage(t, c.w, c.console, c.sc.project.ID, "edge", nginxSpec)
	approveEntry(t, c, edge)
	status, env, _ = mustCall(t, c.w, c.tok, http.MethodPut, catalogItem(c.sc.project.ID, "edge"), catalogImagePutBody(nginxSpec, "upd-same"))
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	sameID, plan, _ := healthPlanOf(t, env)
	if plan != "will update image entry edge: voids 0 host approvals" {
		t.Fatalf("same plan %q", plan)
	}
	status, env = c.w.do(c.tok, http.MethodPost, "/v1/confirmations/"+sameID, confirmBody("upd-same"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if len(listApprovals(t, c.w, c.owner.ID, c.sc.host.ID)) != 1 {
		t.Fatal("same-hash confirm voided an approval")
	}

	old := createImage(t, c.w, c.console, c.sc.project.ID, "old", nginxSpec)
	approveEntry(t, c, old)
	status, env, _ = mustCall(t, c.w, c.tok, http.MethodPut, catalogItem(c.sc.project.ID, "old"), catalogImagePutBody(`{"kind":"service","image":"nginx:1.27"}`, "upd-stale"))
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	staleID, _, _ := healthPlanOf(t, env)
	replaced := createImagePut(t, c, "old", `{"kind":"service","image":"nginx:1.28"}`)
	if replaced["command_display"] != "docker.io/library/nginx:1.28" {
		t.Fatalf("console replace %#v", replaced["command_display"])
	}
	status, env = c.w.do(c.tok, http.MethodPost, "/v1/confirmations/"+staleID, confirmBody("upd-stale"))
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")
	status, env = c.w.do(c.tok, http.MethodPost, "/v1/confirmations/"+staleID, confirmBody("upd-stale"))
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")
	if createImageGet(t, c.w, c.console, c.sc.project.ID, "old")["command_display"] != "docker.io/library/nginx:1.28" {
		t.Fatal("conflict confirm applied the delegated spec")
	}
}

func TestDelegatedCatalogDelete(t *testing.T) {
	c := newCatalogCast(t)
	web := createImage(t, c.w, c.console, c.sc.project.ID, "web", nginxSpec)
	approveEntry(t, c, web)
	entryID, _ := web["id"].(string)
	status, env, _ := mustCall(t, c.w, c.console, http.MethodGet, catalogItem(c.sc.project.ID, "web")+"/permissions", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env, _ = mustCall(t, c.w, c.tok, http.MethodDelete, catalogItem(c.sc.project.ID, "web"), confirmBody("del-1"))
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, plan, _ := healthPlanOf(t, env)
	if plan != "will delete image entry web; 1 host approval and its grants are removed; running containers are not stopped" {
		t.Fatalf("plan %q", plan)
	}
	status, env = c.w.do(c.console, http.MethodGet, catalogItem(c.sc.project.ID, "web"), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env = c.w.do(c.tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("del-1"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env = c.w.do(c.console, http.MethodGet, catalogItem(c.sc.project.ID, "web"), "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	status, env = c.w.do(c.console, http.MethodGet, catalogItem(c.sc.project.ID, "web")+"/permissions", "")
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	if len(listApprovals(t, c.w, c.owner.ID, c.sc.host.ID)) != 0 {
		t.Fatal("delete left an approval")
	}
	svc, err := c.w.mem.GetService(context.Background(), c.sc.svc.ID, c.w.now)
	if err != nil || svc.Name != "api" {
		t.Fatalf("service %+v %v", svc, err)
	}
	status, env = c.w.do(c.tok, http.MethodDelete, catalogItem(c.sc.project.ID, "web"), confirmBody("del-1"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env = c.w.do(c.tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("del-1"))
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	rows := auditRows(t, c.w, c.sc.project.ID)
	if auditViaForName(t, rows, audit.ActionCatalogDelete, "web") != audit.ViaMCP {
		t.Fatal("applied delete was not via mcp")
	}
	if entryID == "" {
		t.Fatal("missing entry id")
	}
}

func TestDelegatedCatalogConfirmBounds(t *testing.T) {
	c := newCatalogCast(t)
	status, env, _ := mustCall(t, c.w, c.tok, http.MethodPost, catalogCollection(c.sc.project.ID), catalogImageBody("late", nginxSpec, "exp-1"))
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	expiredID, _, _ := healthPlanOf(t, env)
	c.w.srv.Now = func() time.Time { return time.Date(2026, 10, 13, 12, 6, 0, 0, time.UTC) }
	status, env = c.w.do(c.tok, http.MethodPost, "/v1/confirmations/"+expiredID, confirmBody("exp-1"))
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	if catalogNameCount(t, c, "late") != 0 {
		t.Fatal("expired confirm created an entry")
	}
	c.w.srv.Now = func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) }

	status, env, _ = mustCall(t, c.w, c.tok, http.MethodPost, catalogCollection(c.sc.project.ID), catalogImageBody("own", nginxSpec, "own-1"))
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, _, _ := healthPlanOf(t, env)
	other := tokenKind(t, c.w, c.admin.ID, store.KindDelegated)
	status, env = c.w.do(other, http.MethodPost, "/v1/confirmations/"+id, confirmBody("own-1"))
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	if err := c.w.mem.TransferOwnership(context.Background(), c.sc.project.ID, c.admin.ID); err != nil {
		t.Fatal(err)
	}
	status, env = c.w.do(c.tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("own-1"))
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	if catalogNameCount(t, c, "own") != 0 {
		t.Fatal("forbidden confirm created an entry")
	}
	if err := c.w.mem.TransferOwnership(context.Background(), c.sc.project.ID, c.owner.ID); err != nil {
		t.Fatal(err)
	}
	status, env = c.w.do(c.tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("own-1"))
	mustHTTP(t, status, env, http.StatusCreated, "ok", "ok")
}

func TestDelegatedCatalogPlanOmitsSecrets(t *testing.T) {
	c := newCatalogCast(t)
	c.w.srv.Secrets = testBox(t)
	project := c.sc.project.ID.String()
	putEnv(t, c.w, c.console, project, "svc", "TOKEN=super-secret-value-zz\nMODESET=env-set-value-zz")
	status, env, raw := putFile(t, c.w, c.console, project, "note.txt", "file-body-zz-unique", boolPtr(false))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if strings.Contains(raw, "file-body-zz-unique") {
		t.Fatal("file put returned content")
	}
	spec := `{"kind":"service","image":"nginx","env_sets":["svc"],"env":{"MODE":"plain-mode-value"},"secret_env":{"TOKEN":"svc.TOKEN"},"files":[{"file":"note.txt","target":"/etc/note"}]}`
	status, env, raw = mustCall(t, c.w, c.tok, http.MethodPost, catalogCollection(c.sc.project.ID), catalogImageBody("web", spec, "secret-plan"))
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, plan, _ := healthPlanOf(t, env)
	if !strings.Contains(plan, "TOKEN←svc.TOKEN") || !strings.Contains(plan, "MODE=plain-mode-value") || !strings.Contains(plan, "note.txt→/etc/note") || !strings.Contains(plan, "env sets svc") {
		t.Fatalf("plan %q", plan)
	}
	for _, secret := range []string{"super-secret-value-zz", "env-set-value-zz", "file-body-zz-unique"} {
		if strings.Contains(plan, secret) || strings.Contains(raw, secret) {
			t.Fatalf("plan leaked %s", secret)
		}
	}
	status, env, confirmRaw := mustCall(t, c.w, c.tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("secret-plan"))
	mustHTTP(t, status, env, http.StatusCreated, "ok", "ok")
	if !strings.Contains(confirmRaw, "plain-mode-value") {
		t.Fatal("confirm hid the inline env value")
	}
	blob := auditBlob(t, c.w, c.sc.project.ID)
	for _, secret := range []string{"super-secret-value-zz", "env-set-value-zz", "file-body-zz-unique", "plain-mode-value"} {
		if strings.Contains(blob, secret) {
			t.Fatalf("audit leaked %s", secret)
		}
	}
	for _, secret := range []string{"super-secret-value-zz", "env-set-value-zz", "file-body-zz-unique"} {
		if strings.Contains(confirmRaw, secret) {
			t.Fatalf("confirm leaked %s", secret)
		}
	}
}

func TestDelegatedCatalogConsoleOnly(t *testing.T) {
	c := newCatalogCast(t)
	web := createImage(t, c.w, c.console, c.sc.project.ID, "web", nginxSpec)
	entryID, _ := web["id"].(string)
	project := c.sc.project.ID.String()
	host := c.sc.host.ID.String()
	status, env, _ := mustCall(t, c.w, c.tok, http.MethodPut, catalogItem(c.sc.project.ID, "web")+"/permissions", `{"grants":[]}`)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env, _ = mustCall(t, c.w, c.tok, http.MethodPost, "/v1/hosts/"+host+"/catalog-approvals", `{"entry_id":"`+entryID+`","spec_hash":"`+web["spec_hash"].(string)+`"}`)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env, _ = mustCall(t, c.w, c.tok, http.MethodDelete, "/v1/hosts/"+host+"/catalog-approvals/"+entryID, "")
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env, _ = mustCall(t, c.w, c.tok, http.MethodPut, "/v1/projects/"+project+"/env-sets/svc", `{"dotenv":"TOKEN=super-secret-value-zz"}`)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env, _ = mustCall(t, c.w, c.tok, http.MethodGet, catalogItem(c.sc.project.ID, "web")+"/permissions", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env, _ = mustCall(t, c.w, c.tok, http.MethodGet, "/v1/hosts/"+host+"/catalog-approvals", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	outsider := tokenKind(t, c.w, c.extra.ID, store.KindDelegated)
	status, env, _ = mustCall(t, c.w, outsider, http.MethodPut, catalogItem(c.sc.project.ID, "web")+"/permissions", `{"grants":[]}`)
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	if len(listApprovals(t, c.w, c.owner.ID, c.sc.host.ID)) != 0 {
		t.Fatal("forbidden approval wrote a row")
	}
	rows := auditRows(t, c.w, c.sc.project.ID)
	requireDelegatedDenial(t, rows, audit.ActionCatalogPermissions, 1)
	requireDelegatedDenial(t, rows, audit.ActionCatalogApprove, 1)
	requireDelegatedDenial(t, rows, audit.ActionCatalogApprovalRevoke, 1)
}

func TestCatalogWriteConfirmedViaConsole(t *testing.T) {
	c := newCatalogCast(t)
	status, env, _ := mustCall(t, c.w, c.tok, http.MethodPost, catalogCollection(c.sc.project.ID), catalogImageBody("web", nginxSpec, "via-create"))
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, _, _ := healthPlanOf(t, env)
	status, env = c.w.do(c.console, http.MethodPost, "/v1/confirmations/"+id, confirmBody("via-create"))
	mustHTTP(t, status, env, http.StatusCreated, "ok", "ok")
	if auditViaForName(t, auditRows(t, c.w, c.sc.project.ID), audit.ActionCatalogCreate, "web") != audit.ViaMCP {
		t.Fatal("console confirm of create was not via mcp")
	}

	status, env, _ = mustCall(t, c.w, c.tok, http.MethodPut, catalogItem(c.sc.project.ID, "web"), catalogImagePutBody(`{"kind":"service","image":"nginx:1.27"}`, "via-upd"))
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, _, _ = healthPlanOf(t, env)
	status, env = c.w.do(c.console, http.MethodPost, "/v1/confirmations/"+id, confirmBody("via-upd"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if auditViaForName(t, auditRows(t, c.w, c.sc.project.ID), audit.ActionCatalogUpdate, "web") != audit.ViaMCP {
		t.Fatal("console confirm of update was not via mcp")
	}

	status, env, _ = mustCall(t, c.w, c.tok, http.MethodDelete, catalogItem(c.sc.project.ID, "web"), confirmBody("via-del"))
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, _, _ = healthPlanOf(t, env)
	status, env = c.w.do(c.console, http.MethodPost, "/v1/confirmations/"+id, confirmBody("via-del"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if auditViaForName(t, auditRows(t, c.w, c.sc.project.ID), audit.ActionCatalogDelete, "web") != audit.ViaMCP {
		t.Fatal("console confirm of delete was not via mcp")
	}
}

func TestDelegatedCatalogConfirmRechecks(t *testing.T) {
	c := newCatalogCast(t)
	c.w.srv.Secrets = testBox(t)
	project := c.sc.project.ID.String()
	putEnv(t, c.w, c.console, project, "svc", "TOKEN=super-secret-value-zz")
	status, env, _ := putFile(t, c.w, c.console, project, "note.txt", "file-body-zz-unique", boolPtr(false))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	spec := `{"kind":"service","image":"nginx","secret_env":{"TOKEN":"svc.TOKEN"},"files":[{"file":"note.txt","target":"/etc/note"}]}`
	status, env, _ = mustCall(t, c.w, c.tok, http.MethodPost, catalogCollection(c.sc.project.ID), catalogImageBody("web", spec, "recheck"))
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, _, _ := healthPlanOf(t, env)
	status, env, _ = mustCall(t, c.w, c.console, http.MethodDelete, "/v1/projects/"+project+"/env-sets/svc", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env = c.w.do(c.tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("recheck"))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "unknown env set")
	putEnv(t, c.w, c.console, project, "svc", "TOKEN=super-secret-value-zz")
	status, env, _ = mustCall(t, c.w, c.console, http.MethodDelete, "/v1/projects/"+project+"/files/note.txt", "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env = c.w.do(c.tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("recheck"))
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "unknown file")
	status, env, _ = putFile(t, c.w, c.console, project, "note.txt", "file-body-zz-unique", boolPtr(false))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env = c.w.do(c.tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("recheck"))
	mustHTTP(t, status, env, http.StatusCreated, "ok", "ok")
	if catalogNameCount(t, c, "web") != 1 {
		t.Fatal("recheck confirm did not create the entry")
	}
}

type catalogCast struct {
	w            *world
	owner, admin store.User
	extra        store.User
	sc           scene
	console, tok string
}

func newCatalogCast(t *testing.T) catalogCast {
	t.Helper()
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("a@ex.com", "A")
	extra := w.user("e@ex.com", "E")
	sc := w.scene(owner, admin, w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), extra)
	return catalogCast{
		w: w, owner: owner, admin: admin, extra: extra, sc: sc,
		console: w.token(owner.ID), tok: tokenKind(t, w, owner.ID, store.KindDelegated),
	}
}

func catalogCollection(project uuid.UUID) string {
	return "/v1/projects/" + project.String() + "/catalog"
}

func catalogItem(project uuid.UUID, name string) string {
	return catalogCollection(project) + "/" + name
}

func catalogImageBody(name, spec, key string) string {
	body := map[string]any{"name": name, "kind": "image", "spec": json.RawMessage(spec)}
	if key != "" {
		body["idempotency_key"] = key
	}
	raw, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func catalogImagePutBody(spec, key string) string {
	body := map[string]any{"kind": "image", "spec": json.RawMessage(spec)}
	if key != "" {
		body["idempotency_key"] = key
	}
	raw, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func createImagePut(t *testing.T, c catalogCast, name, spec string) map[string]any {
	t.Helper()
	status, env, _ := mustCall(t, c.w, c.console, http.MethodPut, catalogItem(c.sc.project.ID, name), catalogImagePutBody(spec, ""))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	return objectPayload(t, env)
}

func approveEntry(t *testing.T, c catalogCast, entry map[string]any) {
	t.Helper()
	id, _ := entry["id"].(string)
	hash, _ := entry["spec_hash"].(string)
	eid, err := uuid.Parse(id)
	if err != nil || hash == "" {
		t.Fatalf("entry id %q hash %q", id, hash)
	}
	if _, err := c.w.mem.ApproveCatalog(context.Background(), c.sc.host.ID, eid, hash, c.owner.ID, c.w.now); err != nil {
		t.Fatal(err)
	}
}

func catalogNameCount(t *testing.T, c catalogCast, name string) int {
	t.Helper()
	status, env, _ := mustCall(t, c.w, c.console, http.MethodGet, catalogCollection(c.sc.project.ID), "")
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	n := 0
	for _, item := range listItems(t, env) {
		if item["name"] == name {
			n++
		}
	}
	return n
}

func issuedDetails(t *testing.T, rows []store.AuditEntry) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, row := range rows {
		if row.Action != audit.ActionCatalogWriteConfirmation || row.Decision != audit.DecisionAllowed {
			continue
		}
		if row.Via != audit.ViaMCP {
			t.Fatalf("issued via %s", row.Via)
		}
		out = append(out, detailMap(t, row.Detail))
	}
	return out
}

func requireDelegatedDenial(t *testing.T, rows []store.AuditEntry, action string, want int) {
	t.Helper()
	n := 0
	for _, row := range rows {
		if row.Action != action || row.Decision != audit.DecisionDenied {
			continue
		}
		if row.ErrorCode == nil || *row.ErrorCode != "forbidden" {
			continue
		}
		if row.Via != audit.ViaMCP {
			t.Fatalf("%s denial via %s", action, row.Via)
		}
		n++
	}
	if n != want {
		t.Fatalf("%s denials %d, want %d", action, n, want)
	}
}

func auditViaForName(t *testing.T, rows []store.AuditEntry, action, name string) string {
	t.Helper()
	for _, row := range rows {
		if row.Action != action || row.Decision != audit.DecisionAllowed {
			continue
		}
		if detailMap(t, row.Detail)["name"] == name {
			return row.Via
		}
	}
	t.Fatalf("no %s for %s", action, name)
	return ""
}
