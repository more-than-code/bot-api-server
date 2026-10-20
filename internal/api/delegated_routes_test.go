package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// delegatedDenyPatterns is the explicit v1.12.1 deny list. A mutating
// route left at the zero value fails the guard unless it is named here.
var delegatedDenyPatterns = []string{
	"POST /v1/projects",
	"PATCH /v1/projects/{id}",
	"DELETE /v1/projects/{id}",
	"POST /v1/projects/{id}/members",
	"PATCH /v1/projects/{id}/members/{user_id}",
	"DELETE /v1/projects/{id}/members/{user_id}",
	"POST /v1/projects/{id}/transfer-ownership",
	"POST /v1/projects/{id}/join-tokens",
	"DELETE /v1/projects/{id}/join-tokens/{token_id}",
	"POST /v1/projects/{id}/invites",
	"DELETE /v1/projects/{id}/invites/{invite_id}",
	"DELETE /v1/hosts/{id}/credential",
	"PUT /v1/hosts/{id}/shares/{project_id}",
	"DELETE /v1/hosts/{id}/shares/{project_id}",
	"PATCH /v1/services/{id}",
	"PUT /v1/projects/{id}/env-sets/{set}/keys/{key}",
	"DELETE /v1/projects/{id}/env-sets/{set}/keys/{key}",
}

var delegatedAllowPatterns = []string{
	"POST /v1/hosts/{id}/snapshot",
	"POST /v1/services/{id}/probe",
	"POST /v1/projects/{id}/catalog/{name}/logs",
	"POST /v1/projects/{id}/catalog/{name}/status",
	"POST /v1/projects/{id}/catalog/parse",
	"POST /v1/auth/signout",
	"POST /v1/confirmations/{confirmation_id}",
}

func TestDelegatedWriteRoutesDenied(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("owner@ex.com", "Owner")
	admin := w.user("admin@ex.com", "Admin")
	spare := w.user("spare@ex.com", "Spare")
	extra := w.user("extra@ex.com", "Extra")
	sc := w.scene(owner, admin, w.user("viewer@ex.com", "Viewer"), spare, extra)
	other, err := w.mem.CreateProject(ctx, owner.ID, "Other", "other", w.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.mem.PutHostShare(ctx, sc.host.ID, other.ID, "metrics", owner.ID, w.now); err != nil {
		t.Fatal(err)
	}
	_, inviteHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	invite, err := w.mem.CreateInvite(ctx, sc.project.ID, inviteHash, "viewer", owner.ID, w.now.Add(time.Hour), w.now, 1)
	if err != nil {
		t.Fatal(err)
	}
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	project := sc.project.ID.String()
	host := sc.host.ID.String()

	cases := []struct {
		pattern string
		method  string
		path    string
		body    string
		read    func(t *testing.T) string
	}{
		{"POST /v1/projects", http.MethodPost, "/v1/projects", `{"name":"Nope"}`, func(t *testing.T) string {
			return projectNames(t, w, owner.ID)
		}},
		{"PATCH /v1/projects/{id}", http.MethodPatch, "/v1/projects/" + project, `{"name":"Renamed"}`, func(t *testing.T) string {
			return projectRow(t, w, sc.project.ID)
		}},
		{"DELETE /v1/projects/{id}", http.MethodDelete, "/v1/projects/" + project, "", func(t *testing.T) string {
			return projectRow(t, w, sc.project.ID)
		}},
		{"POST /v1/projects/{id}/members", http.MethodPost, "/v1/projects/" + project + "/members",
			`{"email":"` + extra.Email + `","role":"viewer"}`, func(t *testing.T) string {
				return memberRole(t, w, sc.project.ID, extra.ID)
			}},
		{"PATCH /v1/projects/{id}/members/{user_id}", http.MethodPatch, "/v1/projects/" + project + "/members/" + spare.ID.String(),
			`{"role":"admin"}`, func(t *testing.T) string {
				return memberRole(t, w, sc.project.ID, spare.ID)
			}},
		{"DELETE /v1/projects/{id}/members/{user_id}", http.MethodDelete, "/v1/projects/" + project + "/members/" + spare.ID.String(),
			"", func(t *testing.T) string {
				return memberRole(t, w, sc.project.ID, spare.ID)
			}},
		{"POST /v1/projects/{id}/transfer-ownership", http.MethodPost, "/v1/projects/" + project + "/transfer-ownership",
			`{"user_id":"` + admin.ID.String() + `"}`, func(t *testing.T) string {
				return memberRole(t, w, sc.project.ID, owner.ID) + " " + memberRole(t, w, sc.project.ID, admin.ID)
			}},
		{"POST /v1/projects/{id}/join-tokens", http.MethodPost, "/v1/projects/" + project + "/join-tokens", `{}`, func(t *testing.T) string {
			return joinState(t, w, sc.project.ID)
		}},
		{"DELETE /v1/projects/{id}/join-tokens/{token_id}", http.MethodDelete, "/v1/projects/" + project + "/join-tokens/" + sc.join.ID.String(),
			"", func(t *testing.T) string {
				return joinState(t, w, sc.project.ID)
			}},
		{"POST /v1/projects/{id}/invites", http.MethodPost, "/v1/projects/" + project + "/invites", `{"role":"viewer"}`, func(t *testing.T) string {
			return inviteState(t, w, sc.project.ID)
		}},
		{"DELETE /v1/projects/{id}/invites/{invite_id}", http.MethodDelete, "/v1/projects/" + project + "/invites/" + invite.ID.String(),
			"", func(t *testing.T) string {
				return inviteState(t, w, sc.project.ID)
			}},
		{"DELETE /v1/hosts/{id}/credential", http.MethodDelete, "/v1/hosts/" + host + "/credential", "", func(t *testing.T) string {
			return credState(t, w, sc)
		}},
		{"PUT /v1/hosts/{id}/shares/{project_id}", http.MethodPut, "/v1/hosts/" + host + "/shares/" + other.ID.String(),
			`{"level":"deploy"}`, func(t *testing.T) string {
				return shareState(t, w, sc.host.ID)
			}},
		{"DELETE /v1/hosts/{id}/shares/{project_id}", http.MethodDelete, "/v1/hosts/" + host + "/shares/" + other.ID.String(),
			"", func(t *testing.T) string {
				return shareState(t, w, sc.host.ID)
			}},
		{"PATCH /v1/services/{id}", http.MethodPatch, "/v1/services/" + sc.svc.ID.String(), `{"display_name":"Renamed"}`, func(t *testing.T) string {
			return displayName(t, w, sc.svc.ID)
		}},
		{"PUT /v1/projects/{id}/env-sets/{set}/keys/{key}", http.MethodPut, "/v1/projects/" + project + "/env-sets/svc/keys/TOKEN",
			`{"value":"nope"}`, func(t *testing.T) string {
				return envSnap(t, w, sc.project.ID, "svc")
			}},
		{"DELETE /v1/projects/{id}/env-sets/{set}/keys/{key}", http.MethodDelete, "/v1/projects/" + project + "/env-sets/svc/keys/TOKEN",
			"", func(t *testing.T) string {
				return envSnap(t, w, sc.project.ID, "svc")
			}},
	}
	if len(cases) != len(delegatedDenyPatterns) {
		t.Fatalf("cases %d, deny list %d", len(cases), len(delegatedDenyPatterns))
	}
	for i, tc := range cases {
		if tc.pattern != delegatedDenyPatterns[i] {
			t.Fatalf("case %d pattern %s, list %s", i, tc.pattern, delegatedDenyPatterns[i])
		}
		t.Run(tc.pattern, func(t *testing.T) {
			beforeSnap := tc.read(t)
			before := w.mem.AllAudits()
			status, env := w.do(tok, tc.method, tc.path, tc.body)
			mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
			if env.Payload != nil {
				t.Fatalf("payload %#v", env.Payload)
			}
			if got := tc.read(t); got != beforeSnap {
				t.Fatalf("target changed\nbefore %s\nafter  %s", beforeSnap, got)
			}
			rows := w.mem.AllAudits()
			if len(rows) != len(before)+1 {
				t.Fatalf("audit rows %d, want %d", len(rows), len(before)+1)
			}
			assertDelegatedDenied(t, rows[len(rows)-1], owner.ID, tc.pattern)
		})
	}
}

func TestDelegatedDenyUnknownProject(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("owner@ex.com", "Owner")
	extra := w.user("extra@ex.com", "Extra")
	sc := w.scene(owner, w.user("admin@ex.com", "Admin"), w.user("viewer@ex.com", "Viewer"), w.user("spare@ex.com", "Spare"), extra)
	foreign, err := w.mem.CreateProject(ctx, extra.ID, "Foreign", "foreign", w.now)
	if err != nil {
		t.Fatal(err)
	}
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	ownedPath := "/v1/projects/" + sc.project.ID.String()
	beforeName := projectRow(t, w, sc.project.ID)
	before := len(w.mem.AllAudits())
	ownedStatus, owned := w.do(tok, http.MethodPatch, ownedPath, `{"name":"Renamed"}`)
	mustHTTP(t, ownedStatus, owned, http.StatusForbidden, "forbidden", "forbidden")
	if projectRow(t, w, sc.project.ID) != beforeName {
		t.Fatal("owned project changed")
	}
	assertDelegatedDenied(t, w.mem.AllAudits()[before], owner.ID, "PATCH /v1/projects/{id}")

	cases := []struct {
		name string
		id   uuid.UUID
	}{
		{"random", uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")},
		{"non-member", foreign.ID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := len(w.mem.AllAudits())
			status, env := w.do(tok, http.MethodPatch, "/v1/projects/"+tc.id.String(), `{"name":"Renamed"}`)
			mustHTTP(t, status, env, ownedStatus, owned.Code, owned.Msg)
			if env.Payload != nil || owned.Payload != nil {
				t.Fatalf("payload owned %#v other %#v", owned.Payload, env.Payload)
			}
			rows := w.mem.AllAudits()
			if len(rows) != n+1 {
				t.Fatalf("audit rows %d, want %d", len(rows), n+1)
			}
			assertDelegatedDenied(t, rows[len(rows)-1], owner.ID, "PATCH /v1/projects/{id}")
		})
	}
}

func TestDelegatedAllowRoutes(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("admin@ex.com", "Admin"), w.user("viewer@ex.com", "Viewer"), w.user("spare@ex.com", "Spare"), w.user("extra@ex.com", "Extra"))
	answerTasks(w.hello(sc))
	project := sc.project.ID.String()
	host := sc.host.ID.String()
	// A missing catalog name or confirmation id is the handler's not_found.
	// Delegated logs and confirm already return 200 through Server.Handler()
	// in TestCatalogConfirmationAndIdempotency (catalog_http_test.go: the
	// del-1 confirm, then the logs call). Delegated status on a real entry
	// with that test's connected agent returns 200 in the same test.
	cases := []struct {
		name   string
		method string
		path   string
		body   string
		status int
		code   string
		msg    string
	}{
		{"signout", http.MethodPost, "/v1/auth/signout", "", http.StatusOK, "ok", "ok"},
		{"parse", http.MethodPost, "/v1/projects/" + project + "/catalog/parse", `{"command":"npm run dev","shell":false}`, http.StatusOK, "ok", "ok"},
		{"logs", http.MethodPost, "/v1/projects/" + project + "/catalog/missing/logs", `{"host_id":"` + host + `"}`, http.StatusNotFound, "not_found", "not found"},
		{"status", http.MethodPost, "/v1/projects/" + project + "/catalog/missing/status", `{"host_id":"` + host + `"}`, http.StatusNotFound, "not_found", "not found"},
		{"snapshot", http.MethodPost, "/v1/hosts/" + host + "/snapshot", "", http.StatusOK, "ok", "ok"},
		{"probe", http.MethodPost, "/v1/services/" + sc.svc.ID.String() + "/probe", `{"protocol":"http","port":8080,"path":"/"}`, http.StatusOK, "ok", "ok"},
		{"confirm", http.MethodPost, "/v1/confirmations/" + strings.Repeat("a", 43), confirmBody("allow-1"), http.StatusNotFound, "not_found", "not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := tokenKind(t, w, owner.ID, store.KindDelegated)
			status, env := w.do(tok, tc.method, tc.path, tc.body)
			mustHTTP(t, status, env, tc.status, tc.code, tc.msg)
			if denied := countAction(w.mem.AllAudits(), audit.ActionDelegatedDenied); denied != 0 {
				t.Fatalf("delegated.denied rows %d", denied)
			}
			if tc.name == "parse" && objectPayload(t, env)["exec"] != "npm" {
				t.Fatalf("parse payload %#v", env.Payload)
			}
			if tc.name == "signout" {
				again, env := w.do(tok, http.MethodGet, "/v1/me", "")
				mustHTTP(t, again, env, http.StatusUnauthorized, "unauthorized", "unauthorized")
			}
		})
	}
}

// TestDelegatedHandlerRoutes calls one delegatedHandler route of each class.
// The wrapper must not add a delegated.denied row. The handler keeps its own
// status and, where it writes one, its own audit action.
func TestDelegatedHandlerRoutes(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("admin@ex.com", "Admin"), w.user("viewer@ex.com", "Viewer"), w.user("spare@ex.com", "Spare"), w.user("extra@ex.com", "Extra"))
	createProgram(t, w, w.token(owner.ID), sc.project.ID, "tra", "pnpm run dev", false)
	conn := helloAgent(t, w, sc.host, sc.credPlain, sc.credID, allowPrograms(false), nil)
	watchTasks(t, conn, succeededTask)
	tok := tokenKind(t, w, owner.ID, store.KindDelegated)
	project := sc.project.ID.String()
	host := sc.host.ID.String()

	t.Run("d25 run", func(t *testing.T) {
		status, env := postAct(w, tok, project, "tra", "run", host, "handler-run", nil)
		mustHTTP(t, status, env, http.StatusAccepted, "ok", "ok")
		if id, _ := objectPayload(t, env)["confirmation_id"].(string); len(id) != 43 {
			t.Fatalf("confirmation %#v", env.Payload)
		}
		assertOwnAudit(t, w, audit.ActionProgramConfirmation, audit.DecisionAllowed, sc.project.ID)
		assertNoDelegatedDenied(t, w)
	})
	t.Run("refuseDelegated permissions", func(t *testing.T) {
		status, env := w.do(tok, http.MethodPut, "/v1/projects/"+project+"/catalog/tra/permissions", `{"grants":[]}`)
		mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
		assertOwnAudit(t, w, audit.ActionCatalogPermissions, audit.DecisionDenied, sc.project.ID)
		assertNoDelegatedDenied(t, w)
	})
	t.Run("requireConsole file put", func(t *testing.T) {
		before := len(w.mem.AllAudits())
		status, env := w.do(tok, http.MethodPut, "/v1/projects/"+project+"/files/note.txt", `{"content":"x","secret":false}`)
		mustHTTP(t, status, env, http.StatusForbidden, "forbidden", "forbidden")
		if len(w.mem.AllAudits()) != before {
			t.Fatalf("requireConsole wrote %d audit rows", len(w.mem.AllAudits())-before)
		}
		assertNoDelegatedDenied(t, w)
	})
	t.Run("consoleUser grant delete", func(t *testing.T) {
		before := len(w.mem.AllAudits())
		status, env := w.do(tok, http.MethodDelete, "/v1/me/grants/"+uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").String(), "")
		mustHTTP(t, status, env, http.StatusUnauthorized, "unauthorized", "unauthorized")
		if len(w.mem.AllAudits()) != before {
			t.Fatalf("consoleUser wrote %d audit rows", len(w.mem.AllAudits())-before)
		}
		assertNoDelegatedDenied(t, w)
	})
}

func TestDelegatedRouteGuard(t *testing.T) {
	if got := undeclaredDelegated(contractRoutes(), delegatedDenyPatterns); len(got) != 0 {
		t.Fatalf("mutating routes with no delegated decision: %s", strings.Join(got, ", "))
	}
	found := map[string]delegatedPolicy{}
	for _, rt := range contractRoutes() {
		found[rt.pattern] = rt.delegated
	}
	for _, pattern := range delegatedDenyPatterns {
		got, ok := found[pattern]
		if !ok {
			t.Fatalf("deny list names a route that is not registered: %s", pattern)
		}
		if got != delegatedDeny {
			t.Fatalf("%s policy %d, want deny", pattern, got)
		}
	}
	for _, pattern := range delegatedAllowPatterns {
		got, ok := found[pattern]
		if !ok {
			t.Fatalf("allow list names a route that is not registered: %s", pattern)
		}
		if got != delegatedAllow {
			t.Fatalf("%s policy %d, want allow", pattern, got)
		}
	}

	deny := []string{"POST /v1/projects"}
	cases := []struct {
		name    string
		pattern string
		policy  delegatedPolicy
		flag    bool
	}{
		{"zero value not on the deny list", "POST /v1/made-up", delegatedDeny, true},
		{"zero value on the deny list", "POST /v1/projects", delegatedDeny, false},
		{"explicit allow", "POST /v1/made-up", delegatedAllow, false},
		{"explicit handler", "PATCH /v1/made-up", delegatedHandler, false},
		{"get is not checked", "GET /v1/made-up", delegatedDeny, false},
		{"zero-value POST /oauth/token is flagged", "POST /oauth/token", delegatedDeny, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := undeclaredDelegated([]route{{pattern: tc.pattern, delegated: tc.policy}}, deny)
			flagged := len(got) == 1 && got[0] == tc.pattern
			if flagged != tc.flag {
				t.Fatalf("flagged %v, want %v (%v)", flagged, tc.flag, got)
			}
		})
	}
}

// undeclaredDelegated returns mutating patterns whose policy is the zero
// value and that are not on deny. Every mutating route needs an explicit
// value. A route added with no decision shows up here.
func undeclaredDelegated(routes []route, deny []string) []string {
	listed := map[string]bool{}
	for _, pattern := range deny {
		listed[pattern] = true
	}
	var out []string
	for _, rt := range routes {
		method, _, ok := strings.Cut(rt.pattern, " ")
		if !ok || !mutating(method) {
			continue
		}
		if rt.delegated != delegatedDeny || listed[rt.pattern] {
			continue
		}
		out = append(out, rt.pattern)
	}
	return out
}

func envSnap(t *testing.T, w *world, projectID uuid.UUID, name string) string {
	t.Helper()
	set, err := w.mem.GetEnvSet(context.Background(), projectID, name)
	if errors.Is(err, store.ErrNotFound) {
		return "missing"
	}
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(set.Keys)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func assertDelegatedDenied(t *testing.T, row store.AuditEntry, actor uuid.UUID, pattern string) {
	t.Helper()
	if row.Action != audit.ActionDelegatedDenied || row.Decision != audit.DecisionDenied || row.Via != audit.ViaMCP {
		t.Fatalf("audit action %s decision %s via %s", row.Action, row.Decision, row.Via)
	}
	if row.ErrorCode == nil || *row.ErrorCode != "forbidden" {
		t.Fatalf("error_code %#v", row.ErrorCode)
	}
	if row.ActorUserID == nil || *row.ActorUserID != actor {
		t.Fatalf("actor %#v", row.ActorUserID)
	}
	if row.ProjectID != nil || row.HostID != nil {
		t.Fatalf("project %#v host %#v", row.ProjectID, row.HostID)
	}
	var detail map[string]any
	if err := json.Unmarshal(row.Detail, &detail); err != nil {
		t.Fatal(err)
	}
	if detail["route"] != pattern || len(detail) != 1 {
		t.Fatalf("detail %#v", detail)
	}
}

func assertNoDelegatedDenied(t *testing.T, w *world) {
	t.Helper()
	if n := countAction(w.mem.AllAudits(), audit.ActionDelegatedDenied); n != 0 {
		t.Fatalf("delegated.denied rows %d", n)
	}
}

func assertOwnAudit(t *testing.T, w *world, action, decision string, projectID uuid.UUID) {
	t.Helper()
	var found *store.AuditEntry
	for _, row := range w.mem.AllAudits() {
		if row.Action != action {
			continue
		}
		if found != nil {
			t.Fatalf("more than one %s row", action)
		}
		cp := row
		found = &cp
	}
	if found == nil {
		t.Fatalf("no %s row", action)
	}
	if found.Decision != decision || found.Via != audit.ViaMCP {
		t.Fatalf("%s decision %s via %s", action, found.Decision, found.Via)
	}
	if found.ErrorCode != nil && decision != audit.DecisionDenied {
		t.Fatalf("%s error %#v", action, found.ErrorCode)
	}
	if decision == audit.DecisionDenied && (found.ErrorCode == nil || *found.ErrorCode != "forbidden") {
		t.Fatalf("%s error %#v", action, found.ErrorCode)
	}
	if found.ProjectID == nil || *found.ProjectID != projectID {
		t.Fatalf("%s project %#v", action, found.ProjectID)
	}
}

func countAction(rows []store.AuditEntry, action string) int {
	n := 0
	for _, row := range rows {
		if row.Action == action {
			n++
		}
	}
	return n
}

func projectNames(t *testing.T, w *world, userID uuid.UUID) string {
	t.Helper()
	items, err := w.mem.ListAllProjects(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(items))
	for i, item := range items {
		names[i] = item.Name
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

func projectRow(t *testing.T, w *world, id uuid.UUID) string {
	t.Helper()
	p, err := w.mem.GetProject(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%s deleted=%v", p.Name, p.DeletedAt != nil)
}

func memberRole(t *testing.T, w *world, projectID, userID uuid.UUID) string {
	t.Helper()
	role, err := w.mem.Role(context.Background(), projectID, userID)
	if errors.Is(err, store.ErrNotFound) {
		return "absent"
	}
	if err != nil {
		t.Fatal(err)
	}
	return role
}

func joinState(t *testing.T, w *world, projectID uuid.UUID) string {
	t.Helper()
	items, _, err := w.mem.ListJoinTokens(context.Background(), projectID, 50, nil)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID.String() < items[j].ID.String() })
	parts := make([]string, len(items))
	for i, item := range items {
		parts[i] = fmt.Sprintf("%s revoked=%v", item.ID, item.RevokedAt != nil)
	}
	return strings.Join(parts, ",")
}

func inviteState(t *testing.T, w *world, projectID uuid.UUID) string {
	t.Helper()
	items, _, err := w.mem.ListInvites(context.Background(), projectID, 50, nil)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID.String() < items[j].ID.String() })
	parts := make([]string, len(items))
	for i, item := range items {
		parts[i] = fmt.Sprintf("%s revoked=%v uses=%d", item.ID, item.RevokedAt != nil, item.Uses)
	}
	return strings.Join(parts, ",")
}

func credState(t *testing.T, w *world, sc scene) string {
	t.Helper()
	cred, host, err := w.mem.LookupCredential(context.Background(), secret.Hash(sc.credPlain))
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("cred=%v host=%v", cred.RevokedAt != nil, host.RevokedAt != nil)
}

func shareState(t *testing.T, w *world, hostID uuid.UUID) string {
	t.Helper()
	items, err := w.mem.ListHostShares(context.Background(), hostID)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ProjectID.String() < items[j].ProjectID.String() })
	parts := make([]string, len(items))
	for i, item := range items {
		parts[i] = item.ProjectID.String() + "=" + item.Level
	}
	return strings.Join(parts, ",")
}

func displayName(t *testing.T, w *world, id uuid.UUID) string {
	t.Helper()
	svc, err := w.mem.GetService(context.Background(), id, w.now)
	if err != nil {
		t.Fatal(err)
	}
	if svc.DisplayName == nil {
		return ""
	}
	return *svc.DisplayName
}
