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
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestServiceRenameMatrix(t *testing.T) {
	fx := newShareFixture(t)
	const (
		ok   = http.StatusOK
		no   = http.StatusForbidden
		miss = http.StatusNotFound
	)
	want := cellWant(no, ok, no, no, no, miss)
	for _, actor := range shareActors {
		if want[actor] == ok {
			continue
		}
		code, env := fx.do(actor, http.MethodPatch, fx.servicePath(fx.ownerSvc, ""), `{"display_name":"Stolen"}`)
		if code != want[actor] || env.Code != statusName(want[actor]) {
			t.Fatalf("%s %d %s", actor, code, env.Code)
		}
	}
	got, err := fx.w.mem.GetService(context.Background(), fx.ownerSvc.ID, fx.w.now)
	if err != nil || got.DisplayName != nil {
		t.Fatalf("denied rename stored %v %v", got.DisplayName, err)
	}
	for _, actor := range []string{actOwnerAdmin, actOwnerOwner} {
		code, env := fx.do(actor, http.MethodPatch, fx.servicePath(fx.ownerSvc, ""), `{"display_name":"Alpha"}`)
		if code != ok || env.Code != "ok" {
			t.Fatalf("%s %d %s", actor, code, env.Code)
		}
		payload := objectPayload(t, env)
		if payload["display_name"] != "Alpha" || payload["name"] != "api" {
			t.Fatalf("%s payload %#v", actor, payload["display_name"])
		}
		if _, wrapped := payload["health_checks"]; wrapped {
			t.Fatal("PATCH wraps health_checks")
		}
	}
	code, env := fx.do(actDeployAdmin, http.MethodPatch, fx.servicePath(fx.shareSvc, ""), `{"display_name":"Web"}`)
	if code != ok || objectPayload(t, env)["display_name"] != "Web" {
		t.Fatalf("deploy admin own service %d %#v", code, env.Code)
	}
	code, env = fx.do(actDeployAdmin, http.MethodPatch, fx.servicePath(fx.ownerSvc, ""), `{"display_name":"Stolen"}`)
	if code != no || env.Code != "forbidden" {
		t.Fatalf("deploy admin other service %d %s", code, env.Code)
	}
	got, err = fx.w.mem.GetService(context.Background(), fx.ownerSvc.ID, fx.w.now)
	if err != nil || got.DisplayName == nil || *got.DisplayName != "Alpha" {
		t.Fatalf("owner name after denials %v", got.DisplayName)
	}

	audits := []struct {
		decision string
		from, to any
	}{
		{audit.DecisionDenied, nil, "Stolen"},
		{audit.DecisionDenied, nil, "Stolen"},
		{audit.DecisionDenied, nil, "Stolen"},
		{audit.DecisionDenied, nil, "Stolen"},
		{audit.DecisionDenied, nil, "Stolen"},
		{audit.DecisionDenied, nil, "Stolen"},
		{audit.DecisionAllowed, nil, "Alpha"},
		{audit.DecisionAllowed, "Alpha", "Alpha"},
		{audit.DecisionAllowed, nil, "Web"},
		{audit.DecisionDenied, "Alpha", "Stolen"},
	}
	var rows []store.AuditEntry
	for _, row := range fx.w.mem.AllAudits() {
		if row.Action == audit.ActionServiceRename {
			rows = append(rows, row)
		}
	}
	if len(rows) != len(audits) {
		t.Fatalf("rename audits %d", len(rows))
	}
	for i, row := range rows {
		detail := decodeRename(t, row.Detail)
		if row.ProjectID == nil || *row.ProjectID != fx.home.ID || row.HostID == nil || *row.HostID != fx.sc.host.ID {
			t.Fatalf("audit target %+v", row)
		}
		if row.Decision != audits[i].decision || detail["from"] != audits[i].from || detail["to"] != audits[i].to {
			t.Fatalf("audit %d %#v", i, detail)
		}
		if row.Decision == audit.DecisionDenied && row.ErrorCode == nil {
			t.Fatal("deny audit missing error")
		}
	}
}

func TestServiceRenameValidation(t *testing.T) {
	fx := newShareFixture(t)
	path := fx.servicePath(fx.ownerSvc, "")
	before := len(fx.w.mem.AllAudits())
	code, env := fx.do(actOwnerViewer, http.MethodPatch, path, `{`)
	if code != http.StatusForbidden || env.Code != "forbidden" {
		t.Fatalf("auth wins %d %s %s", code, env.Code, env.Msg)
	}
	if row := lastRename(t, fx); row.Decision != audit.DecisionDenied {
		t.Fatalf("invalid body denial %s", row.Decision)
	} else if detail := decodeRename(t, row.Detail); detail["from"] != nil || detail["to"] != nil {
		t.Fatalf("invalid json denial %#v", detail)
	}
	code, env = fx.do(actOwnerViewer, http.MethodPatch, path, `{"display_name":""}`)
	if code != http.StatusForbidden || env.Code != "forbidden" {
		t.Fatalf("empty name denial %d %s", code, env.Code)
	}
	if detail := decodeRename(t, lastRename(t, fx).Detail); detail["from"] != nil || detail["to"] != nil {
		t.Fatalf("attempted value was audited %#v", detail)
	}

	bad := []struct{ body, msg string }{
		{`{}`, "invalid json"},
		{`{"display_name":"Ok","extra":1}`, "invalid json"},
		{`{"display_name":""}`, "invalid display_name"},
		{`{"display_name":"   "}`, "invalid display_name"},
		{`{"display_name":1}`, "invalid display_name"},
		{`{"display_name":"a\nb"}`, "invalid display_name"},
		{`{"display_name":"a` + "\u007f" + `b"}`, "invalid display_name"},
		{`{"display_name":"` + strings.Repeat("é", 65) + `"}`, "invalid display_name"},
	}
	for _, tc := range bad {
		code, env := fx.do(actOwnerAdmin, http.MethodPatch, path, tc.body)
		if code != http.StatusBadRequest || env.Code != "bad_request" || env.Msg != tc.msg {
			t.Fatalf("%s → %d %s %s", tc.body, code, env.Code, env.Msg)
		}
	}
	if len(fx.w.mem.AllAudits()) != before+2 {
		t.Fatal("validation wrote an audit")
	}
	long := strings.Repeat("é", 64)
	code, env = fx.do(actOwnerAdmin, http.MethodPatch, path, `{"display_name":"`+long+`"}`)
	if code != http.StatusOK || objectPayload(t, env)["display_name"] != long {
		t.Fatalf("64 runes %d %s", code, env.Msg)
	}
	code, env = fx.do(actOwnerAdmin, http.MethodPatch, path, `{"display_name":"  Hello  "}`)
	if code != http.StatusOK || objectPayload(t, env)["display_name"] != "Hello" {
		t.Fatalf("trim %#v", objectPayload(t, env)["display_name"])
	}
	code, env = fx.do(actOwnerAdmin, http.MethodPatch, path, `{"display_name":null}`)
	if code != http.StatusOK || objectPayload(t, env)["display_name"] != nil {
		t.Fatalf("clear %#v", objectPayload(t, env)["display_name"])
	}
	if detail := decodeRename(t, lastRename(t, fx).Detail); detail["from"] != "Hello" || detail["to"] != nil {
		t.Fatalf("clear audit %#v", detail)
	}
	if _, present := objectPayload(t, env)["display_name"]; !present {
		t.Fatal("display_name omitted")
	}

	code, env = fx.do(actOwnerAdmin, http.MethodPatch, path, `{"display_name":"Api"}`)
	if code != http.StatusOK {
		t.Fatal(env.Msg)
	}
	code, env = fx.do(actOwnerAdmin, http.MethodPatch, fx.servicePath(fx.shareSvc, ""), `{"display_name":"api"}`)
	if code != http.StatusConflict || env.Code != "conflict" {
		t.Fatalf("duplicate %d %s", code, env.Code)
	}
	share, err := fx.w.mem.GetService(context.Background(), fx.shareSvc.ID, fx.w.now)
	if err != nil || share.DisplayName != nil {
		t.Fatal("conflict stored a name")
	}
	code, env = fx.do(actOwnerAdmin, http.MethodPatch, path, `{"display_name":"api"}`)
	if code != http.StatusOK || objectPayload(t, env)["display_name"] != "api" {
		t.Fatalf("same row case %d %#v", code, objectPayload(t, env)["display_name"])
	}
	other := enrollAPIHost(t, fx.w, fx.home.ID, fx.home.CreatedBy, "other-host", true)
	peer := fx.w.mem.PutDeclared(other.ID, "peer", "process", nil, fx.w.now)
	code, env = fx.do(actOwnerAdmin, http.MethodPatch, "/v1/services/"+peer.ID.String(), `{"display_name":"api"}`)
	if code != http.StatusOK || objectPayload(t, env)["display_name"] != "api" {
		t.Fatalf("other host %d %s", code, env.Msg)
	}
}

func TestHostServiceListKeepsShape(t *testing.T) {
	fx := newShareFixture(t)
	user := "www-data"
	if err := fx.w.mem.UpsertDiscovered(context.Background(), fx.sc.host.ID, []store.Discovered{{
		Name: "api", Kind: "process", Ports: []int{8080}, OwnerUser: &user,
	}}, fx.w.now); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.w.mem.SetServiceDisplayName(context.Background(), fx.ownerSvc.ID, strPtr("Alpha"), fx.w.now); err != nil {
		t.Fatal(err)
	}
	code, env := fx.do(actOwnerAdmin, http.MethodGet, fx.hostPath("/services"), "")
	if code != http.StatusOK {
		t.Fatalf("list %d %s", code, env.Code)
	}
	payload := objectPayload(t, env)
	if _, ok := payload["total"]; ok {
		t.Fatal("host list gained total")
	}
	if _, ok := payload["prev_cursor"]; ok {
		t.Fatal("host list gained prev_cursor")
	}
	if _, ok := payload["next_cursor"]; !ok {
		t.Fatal("host list lost next_cursor")
	}
	item := findItem(t, listItems(t, env), "name", "api")
	if item["display_name"] != "Alpha" || item["owner_user"] != "www-data" {
		t.Fatalf("fields %#v %#v", item["display_name"], item["owner_user"])
	}
	if _, ok := item["host_name"]; ok {
		t.Fatal("host list gained host_name")
	}
	code, env = fx.do(actOwnerAdmin, http.MethodGet, fx.servicePath(fx.ownerSvc, ""), "")
	if code != http.StatusOK {
		t.Fatal(env.Code)
	}
	got := objectPayload(t, env)
	if got["display_name"] != "Alpha" || got["owner_user"] != "www-data" {
		t.Fatalf("get %#v %#v", got["display_name"], got["owner_user"])
	}
	checks, ok := got["health_checks"].([]any)
	if !ok || len(checks) != 0 {
		t.Fatalf("health_checks %#v", got["health_checks"])
	}
}

func lastRename(t *testing.T, fx *shareFixture) store.AuditEntry {
	t.Helper()
	rows := fx.w.mem.AllAudits()
	for i := len(rows) - 1; i >= 0; i-- {
		if rows[i].Action == audit.ActionServiceRename {
			return rows[i]
		}
	}
	t.Fatal("no rename audit")
	return store.AuditEntry{}
}

func decodeRename(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var detail map[string]any
	if err := json.Unmarshal(raw, &detail); err != nil {
		t.Fatal(err)
	}
	return detail
}

func statusName(code int) string {
	switch code {
	case http.StatusOK:
		return "ok"
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	default:
		return ""
	}
}

func strPtr(s string) *string { return &s }

func enrollAPIHost(t *testing.T, w *world, projectID, ownerID uuid.UUID, name string, always bool) store.Host {
	t.Helper()
	ctx := context.Background()
	_, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.mem.CreateJoinToken(ctx, projectID, hash, nil, ownerID, w.now.Add(time.Hour), w.now); err != nil {
		t.Fatal(err)
	}
	_, credHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	host, err := w.mem.ConsumeJoinToken(ctx, hash, store.EnrollInput{
		Name: name, NodeType: "pi", OS: "linux", Arch: "arm64", AlwaysOn: always, AgentVersion: "0.1.0",
	}, uuid.New(), credHash, w.now)
	if err != nil {
		t.Fatal(err)
	}
	return host
}
