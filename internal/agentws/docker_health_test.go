package agentws

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/memstore"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestDockerHealthGateAndConfig(t *testing.T) {
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
	user, err := st.UpsertGoogleUser(ctx, store.GoogleSignIn{Subject: "sub", Email: "a@b.c", Name: "A", At: now()})
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
		"hostname": "pi", "agent_version": "0.1.0", "os": "linux", "arch": "arm64", "always_on": true,
	})
	enrolled := readMsg(t, enrollConn)
	hostID, err := uuid.Parse(enrolled["host_id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	credID := enrolled["credential_id"].(string)
	credential := enrolled["credential"].(string)

	conn := dial(t, url, credential)
	writeMsg(t, conn, map[string]any{
		"v": 1, "type": "hello", "host_id": hostID.String(), "credential_id": credID,
		"agent_version": "0.1.0", "os": "linux", "arch": "arm64", "services": []any{},
		"programs": map[string]any{
			"enabled": true, "run_as": []string{"joe"}, "allow_shell": false, "policy_hash": "abc",
			"images": true, "docker": true,
		},
	})
	hello := readMsg(t, conn)
	cfg, _ := hello["config"].(map[string]any)
	if hello["type"] != "hello_ok" {
		t.Fatalf("hello %#v", hello)
	}
	if _, ok := cfg["docker_health"]; ok {
		t.Fatalf("ungated config %#v", cfg)
	}
	hub.PushConfig(ctx, hostID)
	pushed := readMsg(t, conn)
	pushedCfg, _ := pushed["config"].(map[string]any)
	if pushed["type"] != "config_update" {
		t.Fatalf("push %#v", pushed)
	}
	if _, ok := pushedCfg["docker_health"]; ok {
		t.Fatalf("ungated update %#v", pushedCfg)
	}

	at := time.Now().UTC().Format(time.RFC3339)
	dockerBatch := uuid.New().String()
	writeMsg(t, conn, map[string]any{
		"v": 1, "type": "metrics", "batch_id": dockerBatch,
		"samples": []any{map[string]any{
			"m": "health", "t": at,
			"tags": map[string]any{"service": "api", "protocol": "docker"},
			"f":    map[string]any{"result": "success", "http_status": nil, "latency_ms": nil},
		}},
	})
	writeMsg(t, conn, map[string]any{"v": 1, "type": "ping"})
	if got := readMsg(t, conn); got["type"] != "pong" {
		t.Fatalf("refused docker sample dropped the socket: %#v", got)
	}
	cpuBatch := uuid.New().String()
	writeMsg(t, conn, map[string]any{
		"v": 1, "type": "metrics", "batch_id": cpuBatch,
		"samples": []any{map[string]any{
			"m": "cpu", "t": at, "tags": map[string]any{"cpu": "cpu-total"}, "f": map[string]any{"usage_idle": 1},
		}},
	})
	ack := readMsg(t, conn)
	if ack["type"] != "metrics_ack" || ack["batch_id"] != cpuBatch {
		t.Fatalf("cpu ack %#v", ack)
	}

	next := dial(t, url, credential)
	writeMsg(t, next, map[string]any{
		"v": 1, "type": "hello", "host_id": hostID.String(), "credential_id": credID,
		"agent_version": "0.1.0", "os": "linux", "arch": "arm64", "services": []any{},
		"programs": map[string]any{
			"enabled": true, "run_as": []string{"joe"}, "allow_shell": false, "policy_hash": "abc",
			"images": true, "docker": true, "docker_health": true, "healthcheck": true,
		},
	})
	hello = readMsg(t, next)
	cfg, _ = hello["config"].(map[string]any)
	if cfg["docker_health"] != true {
		t.Fatalf("hello config %#v", cfg)
	}
	host, err := st.GetHost(ctx, hostID)
	if err != nil || host.Programs == nil || !host.Programs.DockerHealth || !host.Programs.Healthcheck {
		t.Fatalf("stored programs %#v %v", host.Programs, err)
	}
	hub.PushConfig(ctx, hostID)
	pushed = readMsg(t, next)
	pushedCfg, _ = pushed["config"].(map[string]any)
	if pushed["type"] != "config_update" || pushedCfg["docker_health"] != true {
		t.Fatalf("gated update %#v", pushed)
	}
	okBatch := uuid.New().String()
	writeMsg(t, next, map[string]any{
		"v": 1, "type": "metrics", "batch_id": okBatch,
		"samples": []any{map[string]any{
			"m": "health", "t": at,
			"tags": map[string]any{"service": "api", "protocol": "docker"},
			"f":    map[string]any{"result": "unhealthy", "http_status": nil, "latency_ms": nil},
		}},
	})
	ack = readMsg(t, next)
	if ack["type"] != "metrics_ack" || ack["batch_id"] != okBatch {
		t.Fatalf("docker ack %#v", ack)
	}
}
