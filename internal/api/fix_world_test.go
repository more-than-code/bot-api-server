package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/agentws"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/auth"
	"github.com/more-than-code/bot-api-server/internal/config"
	"github.com/more-than-code/bot-api-server/internal/memstore"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// world is one memstore behind the real REST mux and the agent socket.
type world struct {
	t      *testing.T
	mem    *memstore.Mem
	srv    *Server
	hub    *agentws.Hub
	http   *httptest.Server
	ws     *httptest.Server
	client *http.Client
	now    time.Time
}

func newWorld(t *testing.T) *world {
	t.Helper()
	mem := memstore.New()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	clk := func() time.Time { return now }
	cfg := config.Config{
		GoogleClientID:        "dummy-google-client-id",
		GoogleClientSecret:    "dummy-google-client-secret",
		GoogleIssuer:          "https://accounts.google.com",
		OAuthRedirectURIs:     []string{"http://127.0.0.1/callback"},
		DeviceVerificationURI: "http://127.0.0.1/device",
		AgentWSURL:            "ws://127.0.0.1/agent/v1/ws",
		MCPResource:           "http://127.0.0.1:8091",
	}
	hub := agentws.New(mem, audit.Writer{Store: mem, Log: log, Now: clk}, log, clk)
	ws := httptest.NewServer(hub)
	srv := &Server{
		Store:      mem,
		Auth:       auth.New(mem, cfg, clk),
		Hub:        hub,
		Audit:      audit.Writer{Store: mem, Log: log, Now: clk},
		AgentWSURL: cfg.AgentWSURL,
		Log:        log,
		Now:        clk,
	}
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { hub.CloseAll() })
	t.Cleanup(httpSrv.Close)
	t.Cleanup(ws.Close)
	return &world{
		t: t, mem: mem, srv: srv, hub: hub, http: httpSrv, ws: ws,
		client: &http.Client{Timeout: 10 * time.Second}, now: now,
	}
}

func (w *world) user(email, name string) store.User {
	w.t.Helper()
	u, err := w.mem.UpsertGoogleUser(context.Background(), store.GoogleSignIn{
		Subject: email, Email: email, Name: name, At: w.now,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return u
}

func (w *world) token(userID uuid.UUID) string {
	w.t.Helper()
	plain, hash, err := secret.NewToken()
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.mem.CreateSession(context.Background(), userID, hash, "console", w.now.Add(time.Hour), w.now); err != nil {
		w.t.Fatal(err)
	}
	return plain
}

type scene struct {
	project   store.Project
	host      store.Host
	svc       store.Service
	join      store.JoinToken
	spare     store.User
	extra     store.User
	credID    uuid.UUID
	credPlain string
}

func (w *world) scene(owner, admin, viewer, spare, extra store.User) scene {
	w.t.Helper()
	ctx := context.Background()
	p, err := w.mem.CreateProject(ctx, owner.ID, "Proj", "proj", w.now)
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, p.ID, admin.ID, "admin", owner.ID, w.now); err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, p.ID, viewer.ID, "viewer", owner.ID, w.now); err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.mem.AddMember(ctx, p.ID, spare.ID, "viewer", owner.ID, w.now); err != nil {
		w.t.Fatal(err)
	}
	joinPlain, joinHash, err := secret.NewToken()
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.mem.CreateJoinToken(ctx, p.ID, joinHash, nil, owner.ID, w.now.Add(time.Hour), w.now); err != nil {
		w.t.Fatal(err)
	}
	credPlain, credHash, err := secret.NewToken()
	if err != nil {
		w.t.Fatal(err)
	}
	credID := uuid.New()
	host, err := w.mem.ConsumeJoinToken(ctx, joinHash, store.EnrollInput{
		Name: "pi4", NodeType: "pi", OS: "linux", Arch: "arm64", AlwaysOn: true, AgentVersion: "0.1.0",
	}, credID, credHash, w.now)
	if err != nil {
		w.t.Fatal(err)
	}
	_ = joinPlain
	open, openHash, err := secret.NewToken()
	if err != nil {
		w.t.Fatal(err)
	}
	_ = open
	tok, err := w.mem.CreateJoinToken(ctx, p.ID, openHash, nil, owner.ID, w.now.Add(time.Hour), w.now)
	if err != nil {
		w.t.Fatal(err)
	}
	svc := w.mem.PutDeclared(host.ID, "api", "process", []int{8080}, w.now)
	return scene{
		project: p, host: host, svc: svc, join: tok, spare: spare, extra: extra,
		credID: credID, credPlain: credPlain,
	}
}

func (w *world) do(token, method, path, body string) (int, envelope) {
	w.t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, w.http.URL+path, rdr)
	if err != nil {
		w.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := w.client.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer res.Body.Close()
	var env envelope
	if err := json.NewDecoder(res.Body).Decode(&env); err != nil {
		w.t.Fatal(err)
	}
	return res.StatusCode, env
}

func (w *world) dial(cred string) *websocket.Conn {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(w.ws.URL, "http")
	var opts *websocket.DialOptions
	if cred != "" {
		opts = &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + cred}}}
	}
	c, _, err := websocket.Dial(ctx, url, opts)
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { c.Close(websocket.StatusNormalClosure, "") })
	return c
}

func writeFrame(t *testing.T, c *websocket.Conn, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
}

func readFrame(t *testing.T, c *websocket.Conn) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, b, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func (w *world) hello(sc scene) *websocket.Conn {
	w.t.Helper()
	c := w.dial(sc.credPlain)
	writeFrame(w.t, c, map[string]any{
		"v": 1, "type": "hello", "host_id": sc.host.ID.String(), "credential_id": sc.credID.String(),
		"agent_version": "0.1.0", "os": "linux", "arch": "arm64", "services": []any{},
	})
	hello := readFrame(w.t, c)
	if hello["type"] != "hello_ok" {
		w.t.Fatalf("hello %#v", hello)
	}
	return c
}

// answerTasks replies succeeded to every task so a live HTTP call can finish.
func answerTasks(c *websocket.Conn) {
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			_, b, err := c.Read(ctx)
			cancel()
			if err != nil {
				return
			}
			var msg map[string]any
			if json.Unmarshal(b, &msg) != nil || msg["type"] != "task" {
				continue
			}
			raw, err := json.Marshal(map[string]any{
				"v": 1, "type": "task_result", "task_id": msg["task_id"], "state": "succeeded",
				"payload": map[string]any{"ok": true},
			})
			if err != nil {
				return
			}
			wctx, wcancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = c.Write(wctx, websocket.MessageText, raw)
			wcancel()
		}
	}()
}
