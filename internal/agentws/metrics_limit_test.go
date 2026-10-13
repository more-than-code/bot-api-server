package agentws

import (
	"bytes"
	"context"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/memstore"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestMetricsFrameRateLimit(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	clk := &manualClock{t: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	hub := New(st, audit.Writer{Store: st, Log: log, Now: clk.Now}, log, clk.Now)
	srv := httptest.NewServer(hub)
	t.Cleanup(func() {
		hub.CloseAll()
		srv.Close()
	})
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	user, err := st.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "sub", Email: "a@b.c", Name: "A", At: clk.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	project, err := st.CreateProject(ctx, user.ID, "P", "p", clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	joinPlain, joinHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateJoinToken(ctx, project.ID, joinHash, nil, user.ID, clk.Now().Add(time.Hour), clk.Now()); err != nil {
		t.Fatal(err)
	}
	enrollConn := dial(t, wsURL, "")
	writeMsg(t, enrollConn, map[string]any{
		"v": 1, "type": "enroll", "join_token": joinPlain,
		"hostname": "pi4", "agent_version": "0.1.0",
		"os": "linux", "arch": "arm64", "always_on": true,
	})
	enrolled := readMsg(t, enrollConn)
	expectClose(t, enrollConn, websocket.StatusNormalClosure)
	hostID, _ := enrolled["host_id"].(string)
	credID, _ := enrolled["credential_id"].(string)
	credential, _ := enrolled["credential"].(string)
	conn := dial(t, wsURL, credential)
	t.Cleanup(func() { conn.Close(websocket.StatusNormalClosure, "") })
	writeMsg(t, conn, map[string]any{
		"v": 1, "type": "hello", "host_id": hostID, "credential_id": credID,
		"agent_version": "0.1.0", "os": "linux", "arch": "arm64",
	})
	if hello := readMsg(t, conn); hello["type"] != "hello_ok" {
		t.Fatalf("hello %#v", hello)
	}

	sampleAt := clk.Now().Format(time.RFC3339)
	send := func() string {
		t.Helper()
		id := uuid.New().String()
		writeMsg(t, conn, map[string]any{
			"v": 1, "type": "metrics", "batch_id": id,
			"samples": []any{map[string]any{
				"m": "cpu", "t": sampleAt,
				"tags": map[string]any{"cpu": "cpu-total"},
				"f":    map[string]any{"usage_idle": 90.0},
			}},
		})
		return id
	}
	for i := 0; i < metricsBurst; i++ {
		id := send()
		ack := readMsg(t, conn)
		if ack["type"] != "metrics_ack" || ack["batch_id"] != id {
			t.Fatalf("ack %d %#v", i, ack)
		}
	}
	denied := send()
	expectPong(t, conn)
	denied2 := send()
	expectPong(t, conn)
	logs := buf.String()
	if strings.Count(logs, "metrics rate limited") != 1 || strings.Contains(logs, denied) || strings.Contains(logs, denied2) {
		t.Fatalf("log %s", logs)
	}
	clk.Advance(time.Second)
	for i := 0; i < metricsPerSec; i++ {
		id := send()
		ack := readMsg(t, conn)
		if ack["type"] != "metrics_ack" || ack["batch_id"] != id {
			t.Fatalf("refilled ack %#v", ack)
		}
	}
	send()
	expectPong(t, conn)
	if strings.Count(buf.String(), "metrics rate limited") != 1 {
		t.Fatalf("logged again inside the minute: %s", buf.String())
	}
	// A minute later the bucket is full again. Drain it, then one excess logs a second time.
	clk.Advance(time.Minute - time.Second)
	for i := 0; i < metricsBurst; i++ {
		id := send()
		ack := readMsg(t, conn)
		if ack["type"] != "metrics_ack" || ack["batch_id"] != id {
			t.Fatalf("later ack %#v", ack)
		}
	}
	later := send()
	expectPong(t, conn)
	logs = buf.String()
	if strings.Count(logs, "metrics rate limited") != 2 || strings.Contains(logs, later) {
		t.Fatalf("log after a minute: %s", logs)
	}
	parsedHost, err := uuid.Parse(hostID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.LoadMetric(ctx, parsedHost, "cpu", clk.Now().Add(-2*time.Hour), clk.Now().Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != metricsBurst+metricsPerSec+metricsBurst {
		t.Fatalf("stored %d samples", len(got))
	}
}

func expectPong(t *testing.T, c *websocket.Conn) {
	t.Helper()
	writeMsg(t, c, map[string]any{"v": 1, "type": "ping"})
	msg := readMsg(t, c)
	if msg["type"] != "pong" {
		t.Fatalf("excess frame produced %#v", msg)
	}
}
