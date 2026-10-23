package agentws

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/memstore"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// countingStore counts the store reads an auto_action can cause.
type countingStore struct {
	store.Store
	targets atomic.Int64
	records atomic.Int64
	hosts   atomic.Int64
}

func (c *countingStore) AutoActionTarget(ctx context.Context, hostID uuid.UUID, slug, entry string) (store.AutoTarget, error) {
	c.targets.Add(1)
	return c.Store.AutoActionTarget(ctx, hostID, slug, entry)
}

func (c *countingStore) RecordAutoAction(ctx context.Context, in store.AutoAction) (store.ImageDeploy, bool, error) {
	c.records.Add(1)
	return c.Store.RecordAutoAction(ctx, in)
}

func (c *countingStore) GetHost(ctx context.Context, id uuid.UUID) (store.Host, error) {
	c.hosts.Add(1)
	return c.Store.GetHost(ctx, id)
}

func (c *countingStore) calls() int64 {
	return c.targets.Load() + c.records.Load() + c.hosts.Load()
}

// drainAcks sends a ping and counts auto_action_ack frames before the pong.
func drainAcks(t *testing.T, conn *websocket.Conn) int {
	t.Helper()
	writeMsg(t, conn, map[string]any{"v": 1, "type": "ping"})
	acks := 0
	for {
		got := readMsg(t, conn)
		switch got["type"] {
		case "pong":
			return acks
		case "auto_action_ack":
			acks++
		default:
			t.Fatalf("unexpected frame %#v", got)
		}
	}
}

func TestAutoActionThrottle(t *testing.T) {
	ctx := context.Background()
	mem := memstore.New()
	st := &countingStore{Store: mem}
	logBuf := &lockedBuf{}
	log := slog.New(slog.NewTextHandler(logBuf, nil))
	clock := &autoClock{at: time.Now().UTC().Truncate(time.Second)}
	hub := New(st, audit.Writer{Store: mem, Log: log, Now: clock.now}, log, clock.now)
	srv := httptest.NewServer(hub)
	t.Cleanup(func() {
		hub.CloseAll()
		srv.Close()
	})
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	user, err := mem.UpsertGoogleUser(ctx, store.GoogleSignIn{Subject: "sub", Email: "a@b.c", Name: "A", At: clock.now()})
	if err != nil {
		t.Fatal(err)
	}
	project, err := mem.CreateProject(ctx, user.ID, "P", "p", clock.now())
	if err != nil {
		t.Fatal(err)
	}
	joinPlain, joinHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mem.CreateJoinToken(ctx, project.ID, joinHash, nil, user.ID, clock.now().Add(time.Hour), clock.now()); err != nil {
		t.Fatal(err)
	}
	enrollConn := dial(t, url, "")
	writeMsg(t, enrollConn, map[string]any{
		"v": 1, "type": "enroll", "join_token": joinPlain,
		"hostname": "pi", "agent_version": "0.1.0", "os": "linux", "arch": "arm64", "always_on": true,
	})
	enrolled := readMsg(t, enrollConn)
	conn := dial(t, url, enrolled["credential"].(string))
	writeMsg(t, conn, map[string]any{
		"v": 1, "type": "hello", "host_id": enrolled["host_id"], "credential_id": enrolled["credential_id"],
		"agent_version": "0.2.6", "os": "linux", "arch": "arm64", "services": []any{},
		"programs": map[string]any{
			"enabled": true, "run_as": []string{"joe"}, "allow_shell": false, "policy_hash": "abc",
			"images": true, "docker": true, "healthcheck": true, "health_policy": true,
		},
	})
	if got := readMsg(t, conn); got["type"] != "hello_ok" {
		t.Fatalf("hello %#v", got)
	}
	// Each frame names an unknown entry: processed means one AutoActionTarget
	// read and an ack.
	burst := func(n int) {
		for i := 0; i < n; i++ {
			writeMsg(t, conn, autoFrame(uuid.New().String(), "p", "nope", "restart", "ok", nil, clock.now()))
		}
	}
	base := st.calls()
	burst(30)
	if acks := drainAcks(t, conn); acks != 10 {
		t.Fatalf("burst acks %d, want 10", acks)
	}
	if st.targets.Load() != 10 || st.calls()-base != 10 {
		t.Fatalf("store calls targets=%d total=%d, want 10", st.targets.Load(), st.calls()-base)
	}
	logs := logBuf.String()
	if strings.Count(logs, "reason=entry") != 1 || !strings.Contains(logs, "reason=entry host_id="+enrolled["host_id"].(string)+" dropped=1") {
		t.Fatalf("entry warn not deduplicated:\n%s", logs)
	}
	if strings.Count(logs, "reason=throttled") != 1 {
		t.Fatalf("throttle warn not deduplicated:\n%s", logs)
	}

	// Five seconds refill five tokens.
	clock.add(5 * time.Second)
	burst(7)
	if acks := drainAcks(t, conn); acks != 5 {
		t.Fatalf("refill acks %d, want 5", acks)
	}
	if st.targets.Load() != 15 {
		t.Fatalf("targets after refill %d", st.targets.Load())
	}
	logs = logBuf.String()
	if strings.Count(logs, "reason=entry") != 1 || strings.Count(logs, "reason=throttled") != 1 {
		t.Fatalf("warns repeated within the hour:\n%s", logs)
	}

	// An hour later the next drop logs again with the count since the last line.
	clock.add(time.Hour)
	burst(1)
	if acks := drainAcks(t, conn); acks != 1 {
		t.Fatalf("acks after an hour %d", acks)
	}
	logs = logBuf.String()
	if strings.Count(logs, "reason=entry") != 2 || !strings.Contains(logs, "dropped=15") {
		t.Fatalf("hourly warn with count missing:\n%s", logs)
	}
}
