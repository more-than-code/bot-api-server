package agentws

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/memstore"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestServicesCompleteParse(t *testing.T) {
	absent, err := parseFrame([]byte(`{"v":1,"type":"hello"}`))
	if err != nil || len(absent.ServicesComplete) != 0 || !servicesComplete(absent.ServicesComplete) {
		t.Fatalf("absent %q %v", absent.ServicesComplete, err)
	}
	nullField, err := parseFrame([]byte(`{"v":1,"type":"hello","services_complete":null}`))
	if err != nil || string(nullField.ServicesComplete) != "null" || servicesComplete(nullField.ServicesComplete) {
		t.Fatalf("null %q %v", nullField.ServicesComplete, err)
	}
	yes, err := parseFrame([]byte(`{"v":1,"type":"hello","services_complete":true}`))
	if err != nil || string(yes.ServicesComplete) != "true" || !servicesComplete(yes.ServicesComplete) {
		t.Fatalf("true %q %v", yes.ServicesComplete, err)
	}
	no, err := parseFrame([]byte(`{"v":1,"type":"hello","services_complete":false}`))
	if err != nil || string(no.ServicesComplete) != "false" || servicesComplete(no.ServicesComplete) {
		t.Fatalf("false %q %v", no.ServicesComplete, err)
	}
	for _, raw := range []string{
		`{"v":1,"type":"hello","services_complete":"true"}`,
		`{"v":1,"type":"hello","services_complete":1}`,
	} {
		if _, err := parseFrame([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestServicesCompleteHello(t *testing.T) {
	st, url, at := presenceHub(t)
	hostID, credID, cred := enrollAgent(t, st, url, at)
	alpha := st.PutDiscovered(hostID, "alpha", "process", []int{80}, nil, at)
	beta := st.PutDiscovered(hostID, "beta", "process", []int{81}, nil, at)

	conn := dial(t, url, cred)
	writeMsg(t, conn, helloFrame(hostID, credID, nil, []any{svcItem("alpha"), svcItem("beta")}))
	if hello := readMsg(t, conn); hello["type"] != "hello_ok" {
		t.Fatalf("hello %v", hello["type"])
	}
	if got := agentService(t, st, alpha.ID, at); got.GoneAt != nil {
		t.Fatal("complete hello marked alpha")
	}
	if got := agentService(t, st, beta.ID, at); got.GoneAt != nil {
		t.Fatal("complete hello marked beta")
	}
	conn.Close(websocket.StatusNormalClosure, "")

	incomplete := false
	conn = dial(t, url, cred)
	writeMsg(t, conn, helloFrame(hostID, credID, &incomplete, []any{svcItem("alpha"), svcItem("gamma")}))
	if hello := readMsg(t, conn); hello["type"] != "hello_ok" {
		t.Fatalf("incomplete hello %v", hello["type"])
	}
	if _, ok := agentNamed(t, st, hostID, "gamma", at); ok {
		t.Fatal("incomplete hello inserted gamma")
	}
	if got := agentService(t, st, alpha.ID, at); got.GoneAt != nil {
		t.Fatal("incomplete hello marked alpha")
	}
	if got := agentService(t, st, beta.ID, at); got.GoneAt != nil {
		t.Fatal("incomplete hello marked beta")
	}
	conn.Close(websocket.StatusNormalClosure, "")

	conn = dial(t, url, cred)
	writeMsg(t, conn, helloFrame(hostID, credID, nil, []any{svcItem("alpha")}))
	if hello := readMsg(t, conn); hello["type"] != "hello_ok" {
		t.Fatalf("partial hello %v", hello["type"])
	}
	if got := agentService(t, st, beta.ID, at); got.GoneAt == nil || !got.GoneAt.Equal(at) {
		t.Fatalf("omitted beta %v", got.GoneAt)
	}
	if got := agentService(t, st, alpha.ID, at); got.GoneAt != nil {
		t.Fatal("partial hello marked alpha")
	}

	writeMsg(t, conn, map[string]any{
		"v": 1, "type": "services", "services_complete": false,
		"services": []any{svcItem("alpha"), svcItem("beta")},
	})
	waitPresent(t, st, beta.ID, at)
	conn.Close(websocket.StatusNormalClosure, "")

	otherID, otherCredID, otherCred := enrollAgent(t, st, url, at)
	kept := st.PutDiscovered(otherID, "alpha", "process", []int{80}, nil, at)
	conn = dial(t, url, otherCred)
	writeMsg(t, conn, map[string]any{
		"v": 1, "type": "hello", "host_id": otherID.String(), "credential_id": otherCredID,
		"agent_version": "0.1.0", "os": "linux", "arch": "arm64",
	})
	if hello := readMsg(t, conn); hello["type"] != "hello_ok" {
		t.Fatalf("omitted services %v", hello["type"])
	}
	if got := agentService(t, st, kept.ID, at); got.GoneAt != nil {
		t.Fatal("hello without services marked alpha")
	}
	conn.Close(websocket.StatusNormalClosure, "")

	conn = dial(t, url, otherCred)
	writeMsg(t, conn, helloFrame(otherID, otherCredID, nil, []any{}))
	if hello := readMsg(t, conn); hello["type"] != "hello_ok" {
		t.Fatalf("empty hello %v", hello["type"])
	}
	if got := agentService(t, st, kept.ID, at); got.GoneAt == nil || !got.GoneAt.Equal(at) {
		t.Fatalf("empty hello %v", got.GoneAt)
	}
	conn.Close(websocket.StatusNormalClosure, "")

	conn = dial(t, url, cred)
	writeMsg(t, conn, helloFrame(hostID, credID, nil, []any{map[string]any{"name": "!!!"}}))
	if hello := readMsg(t, conn); hello["type"] != "hello_ok" {
		t.Fatalf("invalid services %v", hello["type"])
	}
	if got := agentService(t, st, alpha.ID, at); got.GoneAt != nil {
		t.Fatal("all-invalid hello marked alpha")
	}
	conn.Close(websocket.StatusNormalClosure, "")
}

func TestServicesCompleteRejectsWrongType(t *testing.T) {
	_, url, _ := presenceHub(t)
	for _, complete := range []any{"true", 1} {
		conn := dial(t, url, "")
		writeMsg(t, conn, map[string]any{
			"v": 1, "type": "hello", "services_complete": complete,
		})
		msg := readMsg(t, conn)
		if msg["type"] != "error" || msg["error_code"] != "bad_request" {
			t.Fatalf("%#v frame %#v", complete, msg)
		}
		expectClose(t, conn, websocket.StatusPolicyViolation)
	}
}

func TestServicesCompleteExplicitTrue(t *testing.T) {
	st, url, at := presenceHub(t)
	hostID, credID, cred := enrollAgent(t, st, url, at)
	alpha := st.PutDiscovered(hostID, "alpha", "process", []int{80}, nil, at)
	beta := st.PutDiscovered(hostID, "beta", "process", []int{81}, nil, at)
	complete := true
	conn := dial(t, url, cred)
	writeMsg(t, conn, helloFrame(hostID, credID, &complete, []any{svcItem("alpha")}))
	if hello := readMsg(t, conn); hello["type"] != "hello_ok" {
		t.Fatalf("hello %v", hello["type"])
	}
	if got := agentService(t, st, beta.ID, at); got.GoneAt == nil || !got.GoneAt.Equal(at) {
		t.Fatalf("explicit true left beta %v", got.GoneAt)
	}
	if got := agentService(t, st, alpha.ID, at); got.GoneAt != nil {
		t.Fatal("explicit true marked alpha")
	}
	conn.Close(websocket.StatusNormalClosure, "")

	conn = dial(t, url, cred)
	writeMsg(t, conn, helloFrame(hostID, credID, &complete, []any{svcItem("alpha"), svcItem("beta")}))
	if hello := readMsg(t, conn); hello["type"] != "hello_ok" {
		t.Fatalf("clear hello %v", hello["type"])
	}
	if got := agentService(t, st, beta.ID, at); got.GoneAt != nil {
		t.Fatalf("explicit true left beta gone %v", got.GoneAt)
	}
	conn.Close(websocket.StatusNormalClosure, "")
}

func TestServicesCompleteNull(t *testing.T) {
	st, url, at := presenceHub(t)
	hostID, credID, cred := enrollAgent(t, st, url, at)
	alpha := st.PutDiscovered(hostID, "alpha", "process", []int{80}, nil, at)
	beta := st.PutDiscovered(hostID, "beta", "process", []int{81}, nil, at)
	msg := helloFrame(hostID, credID, nil, []any{svcItem("alpha"), svcItem("gamma")})
	msg["services_complete"] = nil
	conn := dial(t, url, cred)
	writeMsg(t, conn, msg)
	if hello := readMsg(t, conn); hello["type"] != "hello_ok" {
		t.Fatalf("null hello %v", hello["type"])
	}
	if _, ok := agentNamed(t, st, hostID, "gamma", at); ok {
		t.Fatal("null services_complete inserted gamma")
	}
	if got := agentService(t, st, alpha.ID, at); got.GoneAt != nil {
		t.Fatal("null services_complete marked alpha")
	}
	if got := agentService(t, st, beta.ID, at); got.GoneAt != nil {
		t.Fatal("null services_complete marked beta")
	}
	conn.Close(websocket.StatusNormalClosure, "")
}

func TestServicesNullNotReport(t *testing.T) {
	st, url, at := presenceHub(t)
	hostID, credID, cred := enrollAgent(t, st, url, at)
	alpha := st.PutDiscovered(hostID, "alpha", "process", []int{80}, nil, at)
	conn := dial(t, url, cred)
	writeMsg(t, conn, helloFrame(hostID, credID, nil, nil))
	if hello := readMsg(t, conn); hello["type"] != "hello_ok" {
		t.Fatalf("null services %v", hello["type"])
	}
	if got := agentService(t, st, alpha.ID, at); got.GoneAt != nil {
		t.Fatal("null services marked alpha")
	}
	conn.Close(websocket.StatusNormalClosure, "")
}

func TestServicesMixedArray(t *testing.T) {
	st, url, at := presenceHub(t)
	hostID, credID, cred := enrollAgent(t, st, url, at)
	alpha := st.PutDiscovered(hostID, "alpha", "process", []int{80}, nil, at)
	beta := st.PutDiscovered(hostID, "beta", "process", []int{81}, nil, at)
	delta := st.PutDiscovered(hostID, "delta", "process", []int{82}, nil, at)
	conn := dial(t, url, cred)
	writeMsg(t, conn, helloFrame(hostID, credID, nil, []any{svcItem("alpha"), svcItem("beta")}))
	if hello := readMsg(t, conn); hello["type"] != "hello_ok" {
		t.Fatalf("seed hello %v", hello["type"])
	}
	if got := agentService(t, st, delta.ID, at); got.GoneAt == nil || !got.GoneAt.Equal(at) {
		t.Fatalf("seed left delta %v", got.GoneAt)
	}
	conn.Close(websocket.StatusNormalClosure, "")

	conn = dial(t, url, cred)
	writeMsg(t, conn, helloFrame(hostID, credID, nil, []any{svcItem("delta"), map[string]any{"name": "!!!"}}))
	if hello := readMsg(t, conn); hello["type"] != "hello_ok" {
		t.Fatalf("mixed hello %v", hello["type"])
	}
	if got := agentService(t, st, delta.ID, at); got.GoneAt != nil {
		t.Fatalf("mixed left delta gone %v", got.GoneAt)
	}
	if got := agentService(t, st, alpha.ID, at); got.GoneAt != nil {
		t.Fatal("mixed marked alpha")
	}
	if got := agentService(t, st, beta.ID, at); got.GoneAt != nil {
		t.Fatal("mixed marked beta")
	}
	conn.Close(websocket.StatusNormalClosure, "")
}

func presenceHub(t *testing.T) (*memstore.Mem, string, time.Time) {
	t.Helper()
	st := memstore.New()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return at }
	hub := New(st, audit.Writer{Store: st, Log: log, Now: now}, log, now)
	srv := httptest.NewServer(hub)
	t.Cleanup(func() {
		hub.CloseAll()
		srv.Close()
	})
	return st, "ws" + strings.TrimPrefix(srv.URL, "http"), at
}

func enrollAgent(t *testing.T, st *memstore.Mem, url string, at time.Time) (uuid.UUID, string, string) {
	t.Helper()
	ctx := context.Background()
	user, err := st.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: uuid.New().String(), Email: uuid.New().String() + "@ex.com", Name: "A", At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	project, err := st.CreateProject(ctx, user.ID, "P", "p"+strings.ReplaceAll(uuid.New().String(), "-", "")[:8], at)
	if err != nil {
		t.Fatal(err)
	}
	joinPlain, joinHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateJoinToken(ctx, project.ID, joinHash, nil, user.ID, at.Add(time.Hour), at); err != nil {
		t.Fatal(err)
	}
	conn := dial(t, url, "")
	writeMsg(t, conn, map[string]any{
		"v": 1, "type": "enroll", "join_token": joinPlain,
		"hostname":      "pi-" + strings.ReplaceAll(uuid.New().String(), "-", "")[:8],
		"agent_version": "0.1.0", "os": "linux", "arch": "arm64", "always_on": true,
	})
	enrolled := readMsg(t, conn)
	if enrolled["type"] != "enrolled" {
		t.Fatalf("enrolled %v", enrolled["type"])
	}
	expectClose(t, conn, websocket.StatusNormalClosure)
	hostID, err := uuid.Parse(enrolled["host_id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return hostID, enrolled["credential_id"].(string), enrolled["credential"].(string)
}

func helloFrame(hostID uuid.UUID, credID string, complete *bool, services []any) map[string]any {
	msg := map[string]any{
		"v": 1, "type": "hello", "host_id": hostID.String(), "credential_id": credID,
		"agent_version": "0.1.0", "os": "linux", "arch": "arm64",
		"services": services,
	}
	if complete != nil {
		msg["services_complete"] = *complete
	}
	return msg
}

func svcItem(name string) map[string]any {
	return map[string]any{"name": name, "kind": "process", "ports": []any{80}}
}

func agentService(t *testing.T, st *memstore.Mem, id uuid.UUID, at time.Time) store.Service {
	t.Helper()
	svc, err := st.GetService(context.Background(), id, at)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func agentNamed(t *testing.T, st *memstore.Mem, hostID uuid.UUID, name string, at time.Time) (store.Service, bool) {
	t.Helper()
	items, err := st.ListServices(context.Background(), hostID, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.Name == name {
			return item, true
		}
	}
	return store.Service{}, false
}

func waitPresent(t *testing.T, st *memstore.Mem, id uuid.UUID, at time.Time) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		svc := agentService(t, st, id, at)
		if svc.GoneAt == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("still gone %v", svc.GoneAt)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
