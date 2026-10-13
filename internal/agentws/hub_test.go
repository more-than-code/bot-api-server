package agentws

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
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

func TestAgentSequence(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	now := func() time.Time { return time.Now().UTC() }
	hub := New(st, audit.Writer{Store: st, Log: log, Now: now}, log, now)
	srv := httptest.NewServer(hub)
	t.Cleanup(func() {
		hub.CloseAll()
		srv.Close()
	})
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	user, err := st.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "sub", Email: "a@b.c", Name: "A", At: now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	project, err := st.CreateProject(ctx, user.ID, "P", "p", now())
	if err != nil {
		t.Fatal(err)
	}
	joinPlain, joinHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateJoinToken(ctx, project.ID, joinHash, nil, user.ID, now().Add(time.Hour), now()); err != nil {
		t.Fatal(err)
	}

	enrollConn := dial(t, url, "")
	writeMsg(t, enrollConn, map[string]any{
		"v": 1, "type": "enroll", "join_token": joinPlain,
		"hostname": "pi4", "agent_version": "0.1.0",
		"os": "linux", "arch": "arm64", "always_on": true,
	})
	enrolled := readMsg(t, enrollConn)
	if enrolled["type"] != "enrolled" {
		t.Fatalf("enrolled type %v", enrolled["type"])
	}
	expectClose(t, enrollConn, websocket.StatusNormalClosure)
	hostID, err := uuid.Parse(enrolled["host_id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	credID := enrolled["credential_id"].(string)
	credential := enrolled["credential"].(string)
	host, err := st.GetHost(ctx, hostID)
	if err != nil {
		t.Fatal(err)
	}
	if host.NodeType != "pi" || !host.AlwaysOn {
		t.Fatalf("host node %s always_on %v", host.NodeType, host.AlwaysOn)
	}

	conn := dial(t, url, credential)
	writeMsg(t, conn, map[string]any{
		"v": 1, "type": "hello", "host_id": hostID.String(), "credential_id": credID,
		"agent_version": "0.1.0", "os": "linux", "arch": "arm64",
		"services": []any{},
	})
	hello := readMsg(t, conn)
	if hello["type"] != "hello_ok" {
		t.Fatalf("hello type %v", hello["type"])
	}
	if hello["heartbeat_sec"] != float64(20) {
		t.Fatalf("heartbeat %v", hello["heartbeat_sec"])
	}

	batchID := uuid.New()
	sampleAt := time.Now().UTC().Truncate(time.Second)
	metrics := func() map[string]any {
		return map[string]any{
			"v": 1, "type": "metrics", "batch_id": batchID.String(),
			"samples": []any{map[string]any{
				"m": "cpu", "t": sampleAt.Format(time.RFC3339),
				"tags": map[string]any{"cpu": "cpu-total"},
				"f":    map[string]any{"usage_idle": 90.0},
			}},
		}
	}
	writeMsg(t, conn, metrics())
	ack := readMsg(t, conn)
	if ack["type"] != "metrics_ack" || ack["batch_id"] != batchID.String() {
		t.Fatalf("ack %#v", ack)
	}
	writeMsg(t, conn, metrics())
	ack = readMsg(t, conn)
	if ack["type"] != "metrics_ack" || ack["batch_id"] != batchID.String() {
		t.Fatalf("replay ack %#v", ack)
	}
	samples, err := st.LoadMetric(ctx, hostID, "cpu", sampleAt.Add(-time.Hour), sampleAt.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 {
		t.Fatalf("sample count %d", len(samples))
	}

	other := dial(t, url, credential)
	writeMsg(t, other, map[string]any{
		"v": 1, "type": "hello", "host_id": uuid.New().String(), "credential_id": credID,
		"agent_version": "0.1.0", "os": "linux", "arch": "arm64",
	})
	denied := readMsg(t, other)
	if denied["type"] != "error" || denied["error_code"] != "forbidden" {
		t.Fatalf("second hello %#v", denied)
	}
	expectClose(t, other, websocket.StatusPolicyViolation)
	writeMsg(t, conn, map[string]any{"v": 1, "type": "ping", "ts": sampleAt.Format(time.RFC3339)})
	pong := readMsg(t, conn)
	if pong["type"] != "pong" {
		t.Fatalf("pong after rejected hello %#v", pong)
	}

	snapCtx, snapCancel := context.WithTimeout(ctx, 5*time.Second)
	defer snapCancel()
	type snapOut struct {
		res LiveResult
		err error
	}
	snapCh := make(chan snapOut, 1)
	go func() {
		res, err := hub.Snapshot(snapCtx, host)
		snapCh <- snapOut{res, err}
	}()
	task := readMsg(t, conn)
	if task["type"] != "task" || task["kind"] != "host_snapshot" {
		t.Fatalf("task %#v", task)
	}
	spec, ok := task["spec"].(map[string]any)
	if !ok || len(spec) != 0 {
		t.Fatalf("spec %#v", task["spec"])
	}
	if task["service"] != nil {
		t.Fatalf("service %#v", task["service"])
	}
	taskID, _ := task["task_id"].(string)
	writeMsg(t, conn, map[string]any{
		"v": 1, "type": "task_result", "task_id": taskID, "state": "succeeded",
		"payload": map[string]any{"ok": true},
	})
	gotAck := readMsg(t, conn)
	if gotAck["type"] != "task_ack" || gotAck["task_id"] != taskID {
		t.Fatalf("task_ack %#v", gotAck)
	}
	select {
	case out := <-snapCh:
		if out.err != nil {
			t.Fatal(out.err)
		}
		if out.res.TaskID.String() != taskID {
			t.Fatalf("task id %s", out.res.TaskID)
		}
		var got, want any
		if err := json.Unmarshal(out.res.Payload, &got); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(`{"ok":true}`), &want); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("payload %s", out.res.Payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("snapshot hung")
	}

	writeMsg(t, conn, map[string]any{
		"v": 1, "type": "metrics", "batch_id": uuid.New().String(),
		"samples": []any{map[string]any{
			"m": "nope", "t": sampleAt.Format(time.RFC3339),
			"tags": map[string]any{}, "f": map[string]any{},
		}},
	})
	writeMsg(t, conn, map[string]any{"v": 1, "type": "ping"})
	next := readMsg(t, conn)
	if next["type"] != "pong" {
		t.Fatalf("after bad batch got %#v", next)
	}

	if err := st.RevokeHost(ctx, hostID, now()); err != nil {
		t.Fatal(err)
	}
	hub.CloseHost(hostID)
	closed := readMsg(t, conn)
	if closed["type"] != "error" || closed["error_code"] != "forbidden" {
		t.Fatalf("close frame %#v", closed)
	}
	expectClose(t, conn, websocket.StatusPolicyViolation)

	again := dial(t, url, credential)
	writeMsg(t, again, map[string]any{
		"v": 1, "type": "hello", "host_id": hostID.String(), "credential_id": credID,
		"agent_version": "0.1.0", "os": "linux", "arch": "arm64",
	})
	revokedHello := readMsg(t, again)
	if revokedHello["type"] != "error" || revokedHello["error_code"] != "forbidden" {
		t.Fatalf("revoked hello %#v", revokedHello)
	}
	expectClose(t, again, websocket.StatusPolicyViolation)

	join2, hash2, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateJoinToken(ctx, project.ID, hash2, nil, user.ID, now().Add(time.Hour), now()); err != nil {
		t.Fatal(err)
	}
	asleep := dial(t, url, "")
	writeMsg(t, asleep, map[string]any{
		"v": 1, "type": "enroll", "join_token": join2,
		"hostname": "pi5", "agent_version": "0.1.0",
		"os": "linux", "arch": "arm64", "always_on": true,
	})
	enrolled2 := readMsg(t, asleep)
	if enrolled2["type"] != "enrolled" {
		t.Fatalf("second enroll %#v", enrolled2["type"])
	}
	expectClose(t, asleep, websocket.StatusNormalClosure)
	host2ID := uuid.MustParse(enrolled2["host_id"].(string))
	host2, err := st.GetHost(ctx, host2ID)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	offCtx, offCancel := context.WithTimeout(ctx, 2*time.Second)
	defer offCancel()
	_, snapErr := hub.Snapshot(offCtx, host2)
	if time.Since(start) > time.Second {
		t.Fatalf("unavailable took %s", time.Since(start))
	}
	var ce *CallError
	if !errors.As(snapErr, &ce) || ce.Code != "unavailable" {
		t.Fatalf("snapshot err %#v", snapErr)
	}
}

func TestStatus(t *testing.T) {
	base := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	st := memstore.New()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	hub := New(st, audit.Writer{Store: st, Log: log, Now: func() time.Time { return base }}, log, func() time.Time { return base })
	srv := httptest.NewServer(hub)
	t.Cleanup(func() {
		hub.CloseAll()
		srv.Close()
	})
	ctx := context.Background()
	user, err := st.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "s2", Email: "b@b.c", Name: "B", At: base,
	})
	if err != nil {
		t.Fatal(err)
	}
	project, err := st.CreateProject(ctx, user.ID, "Q", "q", base)
	if err != nil {
		t.Fatal(err)
	}
	plain, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateJoinToken(ctx, project.ID, hash, nil, user.ID, base.Add(time.Hour), base); err != nil {
		t.Fatal(err)
	}
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	c := dial(t, url, "")
	writeMsg(t, c, map[string]any{
		"v": 1, "type": "enroll", "join_token": plain,
		"hostname": "box", "agent_version": "0.1.0",
		"os": "linux", "arch": "amd64", "always_on": false,
	})
	enrolled := readMsg(t, c)
	expectClose(t, c, websocket.StatusNormalClosure)
	hostID := uuid.MustParse(enrolled["host_id"].(string))
	cred := enrolled["credential"].(string)
	credID := enrolled["credential_id"].(string)
	live := dial(t, url, cred)
	defer live.Close(websocket.StatusNormalClosure, "")
	writeMsg(t, live, map[string]any{
		"v": 1, "type": "hello", "host_id": hostID.String(), "credential_id": credID,
		"agent_version": "0.1.0", "os": "linux", "arch": "amd64",
	})
	if hello := readMsg(t, live); hello["type"] != "hello_ok" {
		t.Fatalf("hello %#v", hello)
	}
	host, err := st.GetHost(ctx, hostID)
	if err != nil {
		t.Fatal(err)
	}
	if got := hub.Status(host, base); got != "online" {
		t.Fatalf("at hello %s", got)
	}
	if got := hub.Status(host, base.Add(60*time.Second)); got != "online" {
		t.Fatalf("at 60s %s", got)
	}
	if got := hub.Status(host, base.Add(60*time.Second+time.Nanosecond)); got != "asleep" {
		t.Fatalf("past 60s always_on false %s", got)
	}
	always := host
	always.AlwaysOn = true
	if got := hub.Status(always, base.Add(61*time.Second)); got != "offline" {
		t.Fatalf("stale always_on %s", got)
	}
	revAt := base
	revoked := host
	revoked.RevokedAt = &revAt
	if got := hub.Status(revoked, base); got != "revoked" {
		t.Fatalf("revoked %s", got)
	}
	missing := store.Host{ID: uuid.New(), AlwaysOn: false}
	if got := hub.Status(missing, base); got != "asleep" {
		t.Fatalf("no conn asleep %s", got)
	}
	missing.AlwaysOn = true
	if got := hub.Status(missing, base); got != "offline" {
		t.Fatalf("no conn offline %s", got)
	}
}

func dial(t *testing.T, url, cred string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var opts *websocket.DialOptions
	if cred != "" {
		opts = &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + cred}}}
	}
	c, _, err := websocket.Dial(ctx, url, opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writeMsg(t *testing.T, c *websocket.Conn, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func readMsg(t *testing.T, c *websocket.Conn) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typ, b, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if typ != websocket.MessageText {
		t.Fatalf("message type %d", typ)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func expectClose(t *testing.T, c *websocket.Conn, code websocket.StatusCode) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := c.Read(ctx)
	if websocket.CloseStatus(err) != code {
		t.Fatalf("close status %v err %v", websocket.CloseStatus(err), err)
	}
}
