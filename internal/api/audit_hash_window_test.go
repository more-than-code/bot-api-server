package api

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestAuditRows(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	viewer := w.user("viewer@ex.com", "Viewer")
	spare := w.user("spare@ex.com", "Spare")
	extra := w.user("extra@ex.com", "Extra")
	sc := w.scene(owner, w.user("admin@ex.com", "Admin"), viewer, spare, extra)
	ownerTok := w.token(owner.ID)
	viewerTok := w.token(viewer.ID)

	code, env := w.do(ownerTok, http.MethodPost, "/v1/projects", `{"name":"Alpha"}`)
	if code != http.StatusCreated || env.Code != "ok" {
		t.Fatalf("create %d %s", code, env.Code)
	}
	code, env = w.do(ownerTok, http.MethodPatch, "/v1/projects/"+sc.project.ID.String()+"/members/"+spare.ID.String(), `{"role":"admin"}`)
	if code != http.StatusOK {
		t.Fatalf("member %d %s", code, env.Code)
	}
	code, env = w.do(ownerTok, http.MethodPost, "/v1/projects/"+sc.project.ID.String()+"/join-tokens", `{}`)
	if code != http.StatusCreated {
		t.Fatalf("join %d %s", code, env.Code)
	}
	code, env = w.do(ownerTok, http.MethodPut, "/v1/services/"+sc.svc.ID.String()+"/health-checks",
		`{"checks":[{"protocol":"http","port":8080,"path":"/"}]}`)
	if code != http.StatusOK {
		t.Fatalf("health %d %s", code, env.Code)
	}
	answerTasks(w.hello(sc))
	code, env = w.do(ownerTok, http.MethodPost, "/v1/hosts/"+sc.host.ID.String()+"/snapshot", "")
	if code != http.StatusOK || env.Code != "ok" {
		t.Fatalf("snapshot %d %s", code, env.Code)
	}
	code, env = w.do(ownerTok, http.MethodDelete, "/v1/hosts/"+sc.host.ID.String()+"/credential", "")
	if code != http.StatusOK {
		t.Fatalf("revoke %d %s", code, env.Code)
	}
	code, env = w.do(viewerTok, http.MethodPatch, "/v1/projects/"+sc.project.ID.String(), `{"name":"Nope"}`)
	if code != http.StatusForbidden || env.Code != "forbidden" {
		t.Fatalf("denied %d %s", code, env.Code)
	}

	want := []struct{ action, decision, via string }{
		{audit.ActionProjectCreate, audit.DecisionAllowed, audit.ViaConsole},
		{audit.ActionMemberUpdate, audit.DecisionAllowed, audit.ViaConsole},
		{audit.ActionJoinCreate, audit.DecisionAllowed, audit.ViaConsole},
		{audit.ActionHostRevoke, audit.DecisionAllowed, audit.ViaConsole},
		{audit.ActionHealthChecks, audit.DecisionAllowed, audit.ViaConsole},
		{audit.ActionSnapshot, audit.DecisionAllowed, audit.ViaConsole},
		{audit.ActionProjectRename, audit.DecisionDenied, audit.ViaConsole},
	}
	rows := w.mem.AllAudits()
	for _, exp := range want {
		if !hasAudit(rows, exp.action, exp.decision, exp.via) {
			t.Fatalf("missing %s %s %s in %d rows", exp.action, exp.decision, exp.via, len(rows))
		}
	}
}

func hasAudit(rows []store.AuditEntry, action, decision, via string) bool {
	for _, row := range rows {
		if row.Action == action && row.Decision == decision && row.Via == via {
			return true
		}
	}
	return false
}

func TestHashesAtRest(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	owner := w.user("owner@ex.com", "Owner")
	dc, err := w.srv.Auth.StartDevice(ctx, "cli")
	if err != nil {
		t.Fatal(err)
	}
	if w.mem.HoldsPlaintext(dc.DeviceCode) {
		t.Fatal("device code stored in plaintext")
	}
	if _, err := w.mem.DeviceByHash(ctx, secret.Hash(dc.DeviceCode)); err != nil {
		t.Fatal(err)
	}
	if err := w.srv.Auth.ApproveDevice(ctx, dc.UserCode, owner.ID); err != nil {
		t.Fatal(err)
	}
	issued, err := w.srv.Auth.PollDevice(ctx, dc.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if w.mem.HoldsPlaintext(issued.Token) {
		t.Fatal("session token stored in plaintext")
	}
	if _, _, err := w.srv.Auth.Authenticate(ctx, "Bearer "+issued.Token); err != nil {
		t.Fatal(err)
	}

	tok := w.token(owner.ID)
	p, err := w.mem.CreateProject(ctx, owner.ID, "Proj", "proj", w.now)
	if err != nil {
		t.Fatal(err)
	}
	code, env := w.do(tok, http.MethodPost, "/v1/projects/"+p.ID.String()+"/join-tokens", `{}`)
	if code != http.StatusCreated {
		t.Fatalf("join %d %s", code, env.Code)
	}
	payload, _ := env.Payload.(map[string]any)
	plain, _ := payload["token"].(string)
	if plain == "" || w.mem.HoldsPlaintext(plain) {
		t.Fatal("join token stored in plaintext")
	}
	if _, err := w.mem.ConsumeJoinToken(ctx, secret.Hash(plain), store.EnrollInput{
		Name: "box", NodeType: "pi", OS: "linux", Arch: "arm64", AlwaysOn: true, AgentVersion: "0.1.0",
	}, uuid.New(), secret.Hash("not-the-credential"), w.now); err != nil {
		t.Fatal(err)
	}

	join := mustJoin(t, w, owner.ID)
	if w.mem.HoldsPlaintext(join) {
		t.Fatal("enroll join token stored in plaintext")
	}
	conn := w.dial("")
	writeFrame(t, conn, map[string]any{
		"v": 1, "type": "enroll", "join_token": join,
		"hostname": "pi5", "agent_version": "0.1.0", "os": "linux", "arch": "arm64", "always_on": true,
	})
	enrolled := readFrame(t, conn)
	cred, _ := enrolled["credential"].(string)
	if enrolled["type"] != "enrolled" || cred == "" || w.mem.HoldsPlaintext(cred) {
		t.Fatalf("credential plaintext: type %v holds %v", enrolled["type"], w.mem.HoldsPlaintext(cred))
	}
	if _, _, err := w.mem.LookupCredential(ctx, secret.Hash(cred)); err != nil {
		t.Fatal(err)
	}
}

func mustJoin(t *testing.T, w *world, owner uuid.UUID) string {
	t.Helper()
	ctx := context.Background()
	p, err := w.mem.CreateProject(ctx, owner, "Join", "join", w.now)
	if err != nil {
		t.Fatal(err)
	}
	code, env := w.do(w.token(owner), http.MethodPost, "/v1/projects/"+p.ID.String()+"/join-tokens", `{}`)
	if code != http.StatusCreated {
		t.Fatalf("join %d %s", code, env.Code)
	}
	payload, _ := env.Payload.(map[string]any)
	plain, _ := payload["token"].(string)
	if plain == "" {
		t.Fatal("empty join token")
	}
	return plain
}

func TestOneSidedWindows(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	base := "/v1/hosts/" + sc.host.ID.String() + "/metrics"
	now := "2026-10-13T12:00:00Z"
	hourAgo := "2026-10-13T11:00:00Z"

	q := url.Values{"m": {"cpu"}, "from": {hourAgo}}
	_, env := w.do(tok, http.MethodGet, base+"?"+q.Encode(), "")
	assertWindow(t, env, hourAgo, now)

	q = url.Values{"m": {"cpu"}, "to": {now}}
	_, env = w.do(tok, http.MethodGet, base+"?"+q.Encode(), "")
	assertWindow(t, env, hourAgo, now)

	_, env = w.do(tok, http.MethodGet, base+"?m=cpu", "")
	assertWindow(t, env, hourAgo, now)

	q = url.Values{"m": {"cpu"}, "from": {now}, "to": {hourAgo}}
	code, env := w.do(tok, http.MethodGet, base+"?"+q.Encode(), "")
	if code != http.StatusBadRequest || env.Code != "bad_request" {
		t.Fatalf("inverted window %d %s", code, env.Code)
	}
	q = url.Values{"m": {"cpu"}, "from": {now}, "to": {now}}
	code, env = w.do(tok, http.MethodGet, base+"?"+q.Encode(), "")
	if code != http.StatusBadRequest || env.Code != "bad_request" {
		t.Fatalf("equal window %d %s", code, env.Code)
	}
}

func assertWindow(t *testing.T, env envelope, from, to string) {
	t.Helper()
	if env.Code != "ok" {
		t.Fatalf("code %s", env.Code)
	}
	payload, _ := env.Payload.(map[string]any)
	if payload["from"] != from || payload["to"] != to {
		t.Fatalf("window from %v to %v", payload["from"], payload["to"])
	}
}
