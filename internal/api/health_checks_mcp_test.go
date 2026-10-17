package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// Delegated health-check edits follow api-v1 v1.10: a plan, then the existing confirm route.

func TestDelegatedHealthPutPlans(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	swag := w.mem.PutDeclared(sc.host.ID, "swag", "process", []int{443, 8080}, w.now)
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	path := healthPath(swag.ID)

	status, env := w.do(tok, http.MethodPut, path, `{"checks":[{"protocol":"tcp","port":443},{"protocol":"http","port":8080,"path":"/health"}],"idempotency_key":"plan-two"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, plan, exp := healthPlanOf(t, env)
	if len(id) != 43 {
		t.Fatalf("confirmation_id %q", id)
	}
	if plan != `will set 2 health checks on "swag" (pi4): tcp 443, http 8080 "/health" every 60 s` {
		t.Fatalf("plan %q", plan)
	}
	if exp != "2026-10-13T12:05:00Z" {
		t.Fatalf("expires_at %s", exp)
	}
	if len(storedChecks(t, w, swag.ID)) != 0 {
		t.Fatal("delegated put replaced checks")
	}

	status, env = w.do(tok, http.MethodPut, path, `{"checks":[],"idempotency_key":"plan-empty"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	_, plan, _ = healthPlanOf(t, env)
	if plan != `will remove all health checks from "swag" (pi4)` {
		t.Fatalf("empty plan %q", plan)
	}

	status, env = w.do(tok, http.MethodPut, path, `{"checks":[{"protocol":"tcp","port":8080},{"protocol":"http","port":8080,"path":"/health","interval_sec":60}],"idempotency_key":"plan-redundant"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	_, plan, _ = healthPlanOf(t, env)
	if plan != `will set 2 health checks on "swag" (pi4): tcp 8080, http 8080 "/health" every 60 s (tcp 8080 is redundant with http 8080)` {
		t.Fatalf("redundant plan %q", plan)
	}

	status, env = w.do(tok, http.MethodPut, path, `{"checks":[{"protocol":"tcp","port":443},{"protocol":"http","port":443,"path":"/a","interval_sec":30},{"protocol":"tcp","port":8080},{"protocol":"http","port":8080,"path":"/b"}],"idempotency_key":"plan-ports"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	_, plan, _ = healthPlanOf(t, env)
	want := `will set 4 health checks on "swag" (pi4): tcp 443, http 443 "/a" every 30 s, tcp 8080, http 8080 "/b" every 60 s (tcp 443 is redundant with http 443) (tcp 8080 is redundant with http 8080)`
	if plan != want {
		t.Fatalf("ports plan %q", plan)
	}

	status, env = w.do(tok, http.MethodPut, path, `{"checks":[{"protocol":"tcp","port":443}],"idempotency_key":"plan-one"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	_, plan, _ = healthPlanOf(t, env)
	if plan != `will set 1 health check on "swag" (pi4): tcp 443` {
		t.Fatalf("singular plan %q", plan)
	}

	if _, err := w.mem.SetServiceDisplayName(context.Background(), swag.ID, strPtr("  Swag UI  "), w.now); err != nil {
		t.Fatal(err)
	}
	status, env = w.do(tok, http.MethodPut, path, `{"checks":[{"protocol":"tcp","port":443}],"idempotency_key":"plan-label"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	_, plan, _ = healthPlanOf(t, env)
	if plan != `will set 1 health check on "Swag UI" (pi4): tcp 443` {
		t.Fatalf("label plan %q", plan)
	}
	if _, err := w.mem.SetServiceDisplayName(context.Background(), swag.ID, strPtr("   "), w.now); err != nil {
		t.Fatal(err)
	}
	status, env = w.do(tok, http.MethodPut, path, `{"checks":[{"protocol":"http","port":8080,"path":"/health","interval_sec":90}],"idempotency_key":"plan-blank"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	_, plan, _ = healthPlanOf(t, env)
	if plan != `will set 1 health check on "swag" (pi4): http 8080 "/health" every 90 s` {
		t.Fatalf("blank label plan %q", plan)
	}

	if len(storedChecks(t, w, swag.ID)) != 0 {
		t.Fatal("plans replaced checks")
	}
	rows := auditRows(t, w, sc.project.ID)
	if auditCount(rows, audit.ActionHealthConfirmation, audit.DecisionAllowed) != 7 {
		t.Fatalf("issued %d", auditCount(rows, audit.ActionHealthConfirmation, audit.DecisionAllowed))
	}
	if auditCount(rows, audit.ActionHealthChecks, audit.DecisionAllowed) != 0 {
		t.Fatal("replace audited before confirm")
	}
	if auditVia(t, rows, audit.ActionHealthConfirmation) != audit.ViaMCP {
		t.Fatalf("via %s", auditVia(t, rows, audit.ActionHealthConfirmation))
	}
	blob := auditBlob(t, w, sc.project.ID)
	if strings.Contains(blob, "confirmation_id") || strings.Contains(blob, "/health") || strings.Contains(blob, id) {
		t.Fatalf("audit detail %s", blob)
	}
	for _, row := range rows {
		if row.Action != audit.ActionHealthConfirmation {
			continue
		}
		detail := detailMap(t, row.Detail)
		if detail["host"] != "pi4" || detail["count"] == nil {
			t.Fatalf("detail %#v", detail)
		}
	}
}

func TestDelegatedHealthPutRequiresKey(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	path := healthPath(sc.svc.ID)
	for _, body := range []string{
		`{"checks":[{"protocol":"tcp","port":8080}]}`,
		`{"checks":[{"protocol":"tcp","port":8080}],"idempotency_key":""}`,
		`{"checks":[{"protocol":"tcp","port":8080}],"idempotency_key":"not a key"}`,
		`{"checks":[{"protocol":"tcp","port":8080}],"idempotency_key":"has space"}`,
	} {
		status, env := w.do(tok, http.MethodPut, path, body)
		mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "invalid idempotency_key")
	}
	if len(storedChecks(t, w, sc.svc.ID)) != 0 {
		t.Fatal("rejected key replaced checks")
	}
	rows := auditRows(t, w, sc.project.ID)
	if auditCount(rows, audit.ActionHealthConfirmation, audit.DecisionAllowed) != 0 {
		t.Fatal("rejected key issued a plan")
	}
}

func TestDelegatedHealthPutValidatesBeforePlan(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	path := healthPath(sc.svc.ID)
	cases := []struct{ body, msg string }{
		{`{"idempotency_key":"valid-key"}`, "invalid json"},
		{`{"checks":[{"protocol":"http","port":8080,"path":"health"}],"idempotency_key":"valid-key"}`, "invalid path"},
		{`{"checks":[{"protocol":"nope","port":8080}]}`, "invalid protocol"},
		{`{"checks":[{"protocol":"tcp","port":9}],"idempotency_key":"other-key"}`, "port is not open on the service"},
	}
	for _, tc := range cases {
		status, env := w.do(tok, http.MethodPut, path, tc.body)
		mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", tc.msg)
	}
	var many strings.Builder
	many.WriteString(`{"idempotency_key":"too-many","checks":[`)
	for i := 0; i < 11; i++ {
		if i > 0 {
			many.WriteByte(',')
		}
		many.WriteString(`{"protocol":"tcp","port":8080}`)
	}
	many.WriteString(`]}`)
	status, env := w.do(tok, http.MethodPut, path, many.String())
	mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", "too many checks")

	status, env = w.do(tok, http.MethodPut, path, `{"checks":[{"protocol":"tcp","port":8080}],"idempotency_key":"valid-key"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	if len(storedChecks(t, w, sc.svc.ID)) != 0 {
		t.Fatal("validation failure still changed checks")
	}
}

func TestDelegatedHealthConfirmApplies(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	swag := w.mem.PutDeclared(sc.host.ID, "swag", "process", []int{443, 8080}, w.now)
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	conn := w.hello(sc)
	frames := make(chan map[string]any, 4)
	go readLoop(conn, frames)

	body := `{"checks":[{"protocol":"tcp","port":443},{"protocol":"http","port":443,"path":"/health"}],"idempotency_key":"apply-1"}`
	status, env := w.do(tok, http.MethodPut, healthPath(swag.ID), body)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, plan, _ := healthPlanOf(t, env)
	if !strings.Contains(plan, "(tcp 443 is redundant with http 443)") {
		t.Fatalf("plan %q", plan)
	}
	if len(storedChecks(t, w, swag.ID)) != 0 {
		t.Fatal("202 changed checks")
	}

	status, env = w.do(tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("apply-1"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	got := responseChecks(t, env)
	sort.Strings(got)
	if !reflect.DeepEqual(got, []string{"http 443 /health on", "tcp 443  on"}) {
		t.Fatalf("applied %#v", got)
	}
	frame := awaitFrame(t, frames)
	if !reflect.DeepEqual(frameSigs(t, frame), []string{"http 443 swag", "tcp 443 swag"}) {
		t.Fatalf("frame %#v", frame)
	}
	rows := auditRows(t, w, sc.project.ID)
	if auditCount(rows, audit.ActionHealthChecks, audit.DecisionAllowed) != 1 || auditVia(t, rows, audit.ActionHealthChecks) != audit.ViaMCP {
		t.Fatalf("replace audit via %s count %d", auditVia(t, rows, audit.ActionHealthChecks), auditCount(rows, audit.ActionHealthChecks, audit.DecisionAllowed))
	}
	if strings.Contains(auditBlob(t, w, sc.project.ID), "/health") {
		t.Fatalf("path in audit %s", auditBlob(t, w, sc.project.ID))
	}

	status, env = w.do(tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("apply-1"))
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")

	status, env = w.do(tok, http.MethodPut, healthPath(swag.ID), `{"checks":[],"idempotency_key":"apply-empty"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	emptyID, emptyPlan, _ := healthPlanOf(t, env)
	if emptyPlan != `will remove all health checks from "swag" (pi4)` {
		t.Fatalf("empty plan %q", emptyPlan)
	}
	status, env = w.do(tok, http.MethodPost, "/v1/confirmations/"+emptyID, confirmBody("apply-empty"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if payload, _ := env.Payload.(map[string]any); payload["checks"] == nil {
		t.Fatalf("empty confirm %#v", env.Payload)
	}
	if len(responseChecks(t, env)) != 0 || len(storedChecks(t, w, swag.ID)) != 0 {
		t.Fatal("empty confirm left checks")
	}
	cleared := awaitFrame(t, frames)
	if len(frameSigs(t, cleared)) != 0 {
		t.Fatalf("clear frame %#v", cleared)
	}
}

func TestDelegatedHealthConfirmExpired(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	status, env := w.do(tok, http.MethodPut, healthPath(sc.svc.ID), `{"checks":[{"protocol":"tcp","port":8080}],"idempotency_key":"exp-1"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, _, _ := healthPlanOf(t, env)
	w.srv.Now = func() time.Time { return time.Date(2026, 10, 13, 12, 6, 0, 0, time.UTC) }
	status, env = w.do(tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("exp-1"))
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	if len(storedChecks(t, w, sc.svc.ID)) != 0 {
		t.Fatal("expired confirm replaced checks")
	}
}

func TestDelegatedHealthConfirmForeignUser(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("a@ex.com", "A")
	sc := w.scene(owner, admin, w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	other := tokenKind(t, w, admin.ID, store.KindDelegated)
	status, env := w.do(tok, http.MethodPut, healthPath(sc.svc.ID), `{"checks":[{"protocol":"tcp","port":8080}],"idempotency_key":"own-1"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, _, _ := healthPlanOf(t, env)
	status, env = w.do(other, http.MethodPost, "/v1/confirmations/"+id, confirmBody("own-1"))
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
	if len(storedChecks(t, w, sc.svc.ID)) != 0 {
		t.Fatal("foreign confirm replaced checks")
	}
	status, env = w.do(tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("own-1"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if len(storedChecks(t, w, sc.svc.ID)) != 1 {
		t.Fatal("owner confirm did not apply")
	}
}

func TestDelegatedHealthConfirmSetChanged(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	console := w.token(owner.ID)
	conn := w.hello(sc)
	frames := make(chan map[string]any, 4)
	go readLoop(conn, frames)

	status, env := w.do(tok, http.MethodPut, healthPath(sc.svc.ID), `{"checks":[{"protocol":"tcp","port":8080}],"idempotency_key":"chg-1"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, _, _ := healthPlanOf(t, env)
	status, env = w.do(console, http.MethodPut, healthPath(sc.svc.ID), `{"checks":[{"protocol":"http","port":8080,"path":"/live"}]}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	pushed := awaitFrame(t, frames)
	if !reflect.DeepEqual(frameSigs(t, pushed), []string{"http 8080 api"}) {
		t.Fatalf("console frame %#v", pushed)
	}
	before := checkSigs(storedChecks(t, w, sc.svc.ID))
	status, env = w.do(tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("chg-1"))
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")
	if !reflect.DeepEqual(checkSigs(storedChecks(t, w, sc.svc.ID)), before) {
		t.Fatal("conflict replaced checks")
	}
	expectNoFrame(t, frames)
	status, env = w.do(tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("chg-1"))
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")
	if !reflect.DeepEqual(checkSigs(storedChecks(t, w, sc.svc.ID)), before) {
		t.Fatal("second conflict replaced checks")
	}
}

func TestConsoleHealthPutIgnoresKey(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	console := w.token(owner.ID)
	body := `{"checks":[{"protocol":"tcp","port":8080}],"idempotency_key":"console-key"}`
	status, env := w.do(console, http.MethodPut, healthPath(sc.svc.ID), body)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if status == http.StatusAccepted {
		t.Fatal("console put returned 202")
	}
	if len(storedChecks(t, w, sc.svc.ID)) != 1 {
		t.Fatal("console put did not replace")
	}
	rows := auditRows(t, w, sc.project.ID)
	if auditVia(t, rows, audit.ActionHealthChecks) != audit.ViaConsole {
		t.Fatalf("console via %s", auditVia(t, rows, audit.ActionHealthChecks))
	}
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	status, env = w.do(tok, http.MethodPut, healthPath(sc.svc.ID), body)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	if _, plan, _ := healthPlanOf(t, env); plan != `will set 1 health check on "api" (pi4): tcp 8080` {
		t.Fatalf("delegated plan %q", plan)
	}
}

func TestDelegatedHealthIdempotency(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	path := healthPath(sc.svc.ID)
	first := `{"idempotency_key":"same-key","checks":[{"protocol":"http","port":8080,"path":"/health","interval_sec":60}]}`
	again := `{"checks":[{"path":"/health","port":8080,"protocol":"http"}],"idempotency_key":"same-key"}`
	status, env := w.do(tok, http.MethodPut, path, first)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, _, _ := healthPlanOf(t, env)
	status, env = w.do(tok, http.MethodPut, path, again)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	if got, _, _ := healthPlanOf(t, env); got != id {
		t.Fatalf("replay id %s want %s", got, id)
	}
	status, env = w.do(tok, http.MethodPut, path, `{"checks":[{"protocol":"http","port":8080,"path":"/ready"}],"idempotency_key":"same-key"}`)
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")
	if len(storedChecks(t, w, sc.svc.ID)) != 0 {
		t.Fatal("conflicting replay replaced checks")
	}
	status, env = w.do(tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("same-key"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	ids := responseIDs(t, env)
	status, env = w.do(tok, http.MethodPut, path, first)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if !reflect.DeepEqual(responseIDs(t, env), ids) {
		t.Fatalf("replay after confirm %#v want %#v", responseIDs(t, env), ids)
	}
	if !reflect.DeepEqual(responseIDs(t, env), checkIDs(storedChecks(t, w, sc.svc.ID))) {
		t.Fatal("replay applied a second replace")
	}
}

func TestDelegatedHealthShareRules(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	viewer := w.user("v@ex.com", "V")
	sc := w.scene(owner, w.user("a@ex.com", "A"), viewer, w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	ctx := context.Background()
	metricsOwner := w.user("metrics-owner@ex.com", "MO")
	metricsAdmin := w.user("metrics-admin@ex.com", "MA")
	deployOwner := w.user("deploy-owner@ex.com", "DO")
	deployAdmin := w.user("deploy-admin@ex.com", "DA")
	deployViewer := w.user("deploy-viewer@ex.com", "DV")
	metrics, err := w.mem.CreateProject(ctx, metricsOwner.ID, "Metrics", "hcmetrics", w.now)
	if err != nil {
		t.Fatal(err)
	}
	deploy, err := w.mem.CreateProject(ctx, deployOwner.ID, "Deploy", "hcdeploy", w.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, metrics.ID, metricsAdmin.ID, "admin", metricsOwner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, deploy.ID, deployAdmin.ID, "admin", deployOwner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, deploy.ID, deployViewer.ID, "viewer", deployOwner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.mem.PutHostShare(ctx, sc.host.ID, metrics.ID, "metrics", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.mem.PutHostShare(ctx, sc.host.ID, deploy.ID, "deploy", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	own := w.mem.PutDeclared(sc.host.ID, "swag", "process", []int{443, 8080}, w.now)
	w.mem.SetServiceProject(own.ID, deploy.ID)

	metricsTok := tokenKind(t, w, metricsAdmin.ID, store.KindDelegated)
	viewerTok := tokenKind(t, w, viewer.ID, store.KindDelegated)
	deployViewTok := tokenKind(t, w, deployViewer.ID, store.KindDelegated)
	deployTok := tokenKind(t, w, deployAdmin.ID, store.KindDelegated)
	body := `{"checks":[{"protocol":"tcp","port":8080}],"idempotency_key":"share-put"}`
	status, env := w.do(metricsTok, http.MethodPut, healthPath(sc.svc.ID), body)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env = w.do(viewerTok, http.MethodPut, healthPath(sc.svc.ID), body)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env = w.do(deployViewTok, http.MethodPut, healthPath(own.ID), body)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	status, env = w.do(deployTok, http.MethodPut, healthPath(sc.svc.ID), `{"checks":[{"protocol":"tcp","port":8080}],"idempotency_key":"share-foreign"}`)
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	if len(storedChecks(t, w, sc.svc.ID)) != 0 || len(storedChecks(t, w, own.ID)) != 0 {
		t.Fatal("forbidden put replaced checks")
	}

	status, env = w.do(deployTok, http.MethodPut, healthPath(own.ID), `{"checks":[{"protocol":"tcp","port":8080}],"idempotency_key":"share-own"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, _, _ := healthPlanOf(t, env)
	if len(storedChecks(t, w, own.ID)) != 0 {
		t.Fatal("share plan replaced checks")
	}
	if _, _, err := w.mem.PutHostShare(ctx, sc.host.ID, deploy.ID, "metrics", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	status, env = w.do(deployTok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("share-own"))
	mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
	if len(storedChecks(t, w, own.ID)) != 0 {
		t.Fatal("forbidden confirm replaced checks")
	}
	if _, _, err := w.mem.PutHostShare(ctx, sc.host.ID, deploy.ID, "deploy", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	status, env = w.do(deployTok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("share-own"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if len(storedChecks(t, w, own.ID)) != 1 {
		t.Fatal("restored share did not confirm")
	}
	rows := auditRows(t, w, sc.project.ID)
	if auditCount(rows, audit.ActionHealthChecks, audit.DecisionAllowed) != 1 || auditVia(t, rows, audit.ActionHealthChecks) != audit.ViaMCP {
		t.Fatal("share confirm did not audit the owning project")
	}
}

func TestDelegatedHealthConfirmKeyMismatch(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	status, env := w.do(tok, http.MethodPut, healthPath(sc.svc.ID), `{"checks":[{"protocol":"tcp","port":8080}],"idempotency_key":"match-1"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, _, _ := healthPlanOf(t, env)
	status, env = w.do(tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("other-key"))
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "idempotency_key does not match the request that issued this confirmation")
	if len(storedChecks(t, w, sc.svc.ID)) != 0 {
		t.Fatal("mismatched key replaced checks")
	}
	status, env = w.do(tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("match-1"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
}

func TestDelegatedHealthConfirmUnknown(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	plain, _, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	status, env := w.do(tok, http.MethodPost, "/v1/confirmations/"+plain, confirmBody("unknown-1"))
	mustHTTP(t, status, env, http.StatusNotFound, "not_found", "not found")
}

func TestDelegatedHealthPlanDisabled(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	swag := w.mem.PutDeclared(sc.host.ID, "swag", "process", []int{443, 8080}, w.now)
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	body := `{"checks":[{"protocol":"tcp","port":443,"enabled":false},{"protocol":"http","port":8080,"path":"/health","enabled":false}],"idempotency_key":"plan-off"}`
	status, env := w.do(tok, http.MethodPut, healthPath(swag.ID), body)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	_, plan, _ := healthPlanOf(t, env)
	want := `will set 2 health checks on "swag" (pi4): tcp 443 (disabled), http 8080 "/health" every 60 s (disabled)`
	if plan != want {
		t.Fatalf("plan %q", plan)
	}
}

func TestDelegatedHealthPlanQuotesLabel(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	swag := w.mem.PutDeclared(sc.host.ID, "swag", "process", []int{443, 8080}, w.now)
	if _, err := w.mem.SetServiceDisplayName(context.Background(), swag.ID, strPtr(`say "hi"`), w.now); err != nil {
		t.Fatal(err)
	}
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	status, env := w.do(tok, http.MethodPut, healthPath(swag.ID), `{"checks":[{"protocol":"tcp","port":443}],"idempotency_key":"plan-quote"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	_, plan, _ := healthPlanOf(t, env)
	if plan != `will set 1 health check on "say \"hi\"" (pi4): tcp 443` {
		t.Fatalf("plan %q", plan)
	}
	if strings.Contains(plan, `"pi4"`) {
		t.Fatalf("host quoted %q", plan)
	}
	status, env = w.do(tok, http.MethodPut, healthPath(swag.ID), `{"checks":[],"idempotency_key":"plan-quote-empty"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	_, plan, _ = healthPlanOf(t, env)
	if plan != `will remove all health checks from "say \"hi\"" (pi4)` {
		t.Fatalf("empty plan %q", plan)
	}
}

func TestDelegatedHealthPlanQuotesPath(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	raw := "/a\u202e"
	body := `{"checks":[{"protocol":"http","port":8080,"path":"` + raw + `"}],"idempotency_key":"plan-rlo"}`
	status, env := w.do(tok, http.MethodPut, healthPath(sc.svc.ID), body)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, plan, _ := healthPlanOf(t, env)
	want := `will set 1 health check on "api" (pi4): http 8080 "/a\u202e" every 60 s`
	if plan != want {
		t.Fatalf("plan %q", plan)
	}
	if strings.Contains(plan, raw) {
		t.Fatal("plan contains the raw format character")
	}
	status, env = w.do(tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("plan-rlo"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	got := storedChecks(t, w, sc.svc.ID)
	if len(got) != 1 || got[0].Path == nil || *got[0].Path != raw {
		t.Fatalf("stored %#v", got)
	}
}

func TestDelegatedHealthConfirmFields(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	body := `{"checks":[{"protocol":"http","port":8080,"path":"/health","interval_sec":45,"expect_status_min":201,"expect_status_max":299,"enabled":false}],"idempotency_key":"fields-1"}`
	status, env := w.do(tok, http.MethodPut, healthPath(sc.svc.ID), body)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, _, _ := healthPlanOf(t, env)
	status, env = w.do(tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("fields-1"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	payload := objectPayload(t, env)
	raw, _ := payload["checks"].([]any)
	if len(raw) != 1 {
		t.Fatalf("checks %#v", payload["checks"])
	}
	item, _ := raw[0].(map[string]any)
	if item["protocol"] != "http" || item["port"] != float64(8080) || item["path"] != "/health" {
		t.Fatalf("identity %#v", item)
	}
	if item["interval_sec"] != float64(45) {
		t.Fatalf("interval_sec %#v", item["interval_sec"])
	}
	if item["expect_status_min"] != float64(201) {
		t.Fatalf("expect_status_min %#v", item["expect_status_min"])
	}
	if item["expect_status_max"] != float64(299) {
		t.Fatalf("expect_status_max %#v", item["expect_status_max"])
	}
	if item["enabled"] != false {
		t.Fatalf("enabled %#v", item["enabled"])
	}
	stored := storedChecks(t, w, sc.svc.ID)
	if len(stored) != 1 {
		t.Fatalf("stored %d", len(stored))
	}
	got := stored[0]
	if got.IntervalSec != 45 || got.ExpectStatusMin != 201 || got.ExpectStatusMax != 299 || got.Enabled {
		t.Fatalf("stored %+v", got)
	}
	if got.Path == nil || *got.Path != "/health" || got.Protocol != "http" || got.Port != 8080 {
		t.Fatalf("stored identity %+v", got)
	}
}

func TestDelegatedHealthKeyPerService(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	swag := w.mem.PutDeclared(sc.host.ID, "swag", "process", []int{443, 8080}, w.now)
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	body := `{"checks":[{"protocol":"tcp","port":8080}],"idempotency_key":"shared-key"}`
	status, env := w.do(tok, http.MethodPut, healthPath(sc.svc.ID), body)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	status, env = w.do(tok, http.MethodPut, healthPath(swag.ID), body)
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")
	if len(storedChecks(t, w, sc.svc.ID)) != 0 || len(storedChecks(t, w, swag.ID)) != 0 {
		t.Fatal("conflict replaced checks")
	}
}

func TestDelegatedHealthKeyBindsInterval(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	path := healthPath(sc.svc.ID)
	status, env := w.do(tok, http.MethodPut, path, `{"checks":[{"protocol":"http","port":8080,"path":"/health","interval_sec":60}],"idempotency_key":"iv-1"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	status, env = w.do(tok, http.MethodPut, path, `{"checks":[{"protocol":"http","port":8080,"path":"/health","interval_sec":90}],"idempotency_key":"iv-1"}`)
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")
	if len(storedChecks(t, w, sc.svc.ID)) != 0 {
		t.Fatal("interval conflict replaced checks")
	}
}

func TestDelegatedHealthConfirmStableSet(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	swag := w.mem.PutDeclared(sc.host.ID, "swag", "process", []int{443, 8080}, w.now)
	console := w.token(owner.ID)
	status, env := w.do(console, http.MethodPut, healthPath(swag.ID), `{"checks":[{"protocol":"http","port":8080,"path":"/b"},{"protocol":"tcp","port":443}]}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	if len(storedChecks(t, w, swag.ID)) != 2 {
		t.Fatal("seed did not store two checks")
	}
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	status, env = w.do(tok, http.MethodPut, healthPath(swag.ID), `{"checks":[{"protocol":"tcp","port":443}],"idempotency_key":"stable-1"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, _, _ := healthPlanOf(t, env)
	status, env = w.do(tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("stable-1"))
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	got := storedChecks(t, w, swag.ID)
	if len(got) != 1 || got[0].Protocol != "tcp" || got[0].Port != 443 {
		t.Fatalf("confirmed %#v", got)
	}
	pathB := "/b"
	forward := []store.HealthCheckInput{
		{Protocol: "http", Port: 8080, Path: &pathB, IntervalSec: 60, ExpectStatusMin: 200, ExpectStatusMax: 399, Enabled: true},
		{Protocol: "tcp", Port: 443, IntervalSec: 60, ExpectStatusMin: 200, ExpectStatusMax: 399, Enabled: true},
	}
	reverse := []store.HealthCheckInput{forward[1], forward[0]}
	if !bytes.Equal(store.HealthSetHash(forward), store.HealthSetHash(reverse)) {
		t.Fatal("set hash depends on input order")
	}
}

func TestDelegatedHealthAuditDetail(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	status, env := w.do(tok, http.MethodPut, healthPath(sc.svc.ID), `{"checks":[{"protocol":"tcp","port":8080},{"protocol":"http","port":8080,"path":"/health"}],"idempotency_key":"audit-1"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	var saw bool
	for _, row := range auditRows(t, w, sc.project.ID) {
		if row.Action != audit.ActionHealthConfirmation {
			continue
		}
		saw = true
		detail := detailMap(t, row.Detail)
		if detail["service"] != "api" {
			t.Fatalf("service %#v", detail["service"])
		}
		if detail["count"] != float64(2) {
			t.Fatalf("count %#v", detail["count"])
		}
	}
	if !saw {
		t.Fatal("no confirmation audit")
	}
}

func TestDelegatedHealthPutBounds(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	path := healthPath(sc.svc.ID)
	cases := []struct{ body, msg string }{
		{`{"checks":[{"protocol":"tcp","port":8080,"interval_sec":29}],"idempotency_key":"b29"}`, "invalid interval_sec"},
		{`{"checks":[{"protocol":"tcp","port":8080,"interval_sec":301}],"idempotency_key":"b301"}`, "invalid interval_sec"},
		{`{"checks":[{"protocol":"http","port":8080,"path":"/health","expect_status_min":199}],"idempotency_key":"b199"}`, "invalid expect status"},
		{`{"checks":[{"protocol":"http","port":8080,"path":"/health","expect_status_max":400}],"idempotency_key":"b400"}`, "invalid expect status"},
	}
	for _, tc := range cases {
		status, env := w.do(tok, http.MethodPut, path, tc.body)
		mustHTTP(t, status, env, http.StatusBadRequest, "bad_request", tc.msg)
	}
	rows := auditRows(t, w, sc.project.ID)
	if auditCount(rows, audit.ActionHealthConfirmation, audit.DecisionAllowed) != 0 {
		t.Fatal("rejected body issued a plan")
	}
	if len(storedChecks(t, w, sc.svc.ID)) != 0 {
		t.Fatal("rejected body replaced checks")
	}
	status, env := w.do(tok, http.MethodPut, path, `{"checks":[{"protocol":"tcp","port":8080}],"idempotency_key":"b29"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
}

func TestDelegatedHealthConfirmRacesConsole(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	console := w.token(owner.ID)
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	status, env := w.do(console, http.MethodPut, healthPath(sc.svc.ID), `{"checks":[{"protocol":"http","port":8080,"path":"/old"}]}`)
	mustHTTP(t, status, env, http.StatusOK, "ok", "ok")
	status, env = w.do(tok, http.MethodPut, healthPath(sc.svc.ID), `{"checks":[{"protocol":"tcp","port":8080}],"idempotency_key":"race-1"}`)
	mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
	id, _, _ := healthPlanOf(t, env)
	live := "/live"
	hook := &healthListHook{Store: w.srv.Store}
	hook.swap = func() {
		_, err := w.mem.ReplaceHealthChecks(context.Background(), sc.svc.ID, []store.HealthCheckInput{{
			Protocol: "http", Port: 8080, Path: &live,
			IntervalSec: 60, ExpectStatusMin: 200, ExpectStatusMax: 399, Enabled: true,
		}})
		if err != nil {
			t.Errorf("console replace %v", err)
		}
	}
	w.srv.Store = hook
	status, env = w.do(tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("race-1"))
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")
	got := storedChecks(t, w, sc.svc.ID)
	if len(got) != 1 || got[0].Protocol != "http" || got[0].Path == nil || *got[0].Path != "/live" {
		t.Fatalf("kept %#v", got)
	}
	status, env = w.do(tok, http.MethodPost, "/v1/confirmations/"+id, confirmBody("race-1"))
	mustHTTP(t, status, env, http.StatusConflict, "conflict", "conflict")
	got = storedChecks(t, w, sc.svc.ID)
	if len(got) != 1 || got[0].Path == nil || *got[0].Path != "/live" {
		t.Fatalf("second confirm %#v", got)
	}
}

// healthListHook returns the check set from before swap. Confirm's first
// read therefore still matches the plan. The locked replace re-reads.
type healthListHook struct {
	store.Store
	swap func()
}

func (h *healthListHook) ListHealthChecks(ctx context.Context, id uuid.UUID) ([]store.HealthCheck, error) {
	out, err := h.Store.ListHealthChecks(ctx, id)
	if err != nil || h.swap == nil {
		return out, err
	}
	h.swap()
	return out, nil
}

func healthPath(id uuid.UUID) string {
	return "/v1/services/" + id.String() + "/health-checks"
}

func healthPlanOf(t *testing.T, env envelope) (string, string, string) {
	t.Helper()
	payload := objectPayload(t, env)
	id, _ := payload["confirmation_id"].(string)
	plan, _ := payload["plan"].(string)
	exp, _ := payload["expires_at"].(string)
	if id == "" || plan == "" || exp == "" {
		t.Fatalf("plan payload %#v", payload)
	}
	return id, plan, exp
}

func storedChecks(t *testing.T, w *world, id uuid.UUID) []store.HealthCheck {
	t.Helper()
	checks, err := w.mem.ListHealthChecks(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return checks
}

func responseChecks(t *testing.T, env envelope) []string {
	t.Helper()
	payload := objectPayload(t, env)
	raw, _ := payload["checks"].([]any)
	out := make([]string, len(raw))
	for i, item := range raw {
		c, _ := item.(map[string]any)
		path, _ := c["path"].(string)
		en := "off"
		if c["enabled"] == true {
			en = "on"
		}
		out[i] = c["protocol"].(string) + " " + strconv.Itoa(int(c["port"].(float64))) + " " + path + " " + en
	}
	return out
}

func responseIDs(t *testing.T, env envelope) []string {
	t.Helper()
	payload := objectPayload(t, env)
	raw, _ := payload["checks"].([]any)
	out := make([]string, len(raw))
	for i, item := range raw {
		c, _ := item.(map[string]any)
		out[i], _ = c["id"].(string)
	}
	sort.Strings(out)
	return out
}

func checkIDs(checks []store.HealthCheck) []string {
	out := make([]string, len(checks))
	for i, c := range checks {
		out[i] = c.ID.String()
	}
	sort.Strings(out)
	return out
}

func checkSigs(checks []store.HealthCheck) []string {
	out := make([]string, len(checks))
	for i, c := range checks {
		path := ""
		if c.Path != nil {
			path = *c.Path
		}
		out[i] = c.ID.String() + " " + c.Protocol + " " + strconv.Itoa(c.Port) + " " + path
	}
	sort.Strings(out)
	return out
}

func frameSigs(t *testing.T, frame map[string]any) []string {
	t.Helper()
	if frame["type"] != "config_update" {
		t.Fatalf("frame %#v", frame)
	}
	cfg, _ := frame["config"].(map[string]any)
	raw, _ := cfg["health_checks"].([]any)
	out := make([]string, len(raw))
	for i, item := range raw {
		c, _ := item.(map[string]any)
		out[i] = c["protocol"].(string) + " " + strconv.Itoa(int(c["port"].(float64))) + " " + c["service"].(string)
	}
	sort.Strings(out)
	return out
}

func expectNoFrame(t *testing.T, frames <-chan map[string]any) {
	t.Helper()
	select {
	case frame := <-frames:
		t.Fatalf("unexpected frame %#v", frame)
	case <-time.After(500 * time.Millisecond):
	}
}

func detailMap(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var detail map[string]any
	if err := json.Unmarshal(raw, &detail); err != nil {
		t.Fatal(err)
	}
	return detail
}
