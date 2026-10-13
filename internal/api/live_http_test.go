package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestHostRevokeClosesSocket(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	conn := w.hello(sc)
	code, env := w.do(w.token(owner.ID), http.MethodDelete, "/v1/hosts/"+sc.host.ID.String()+"/credential", "")
	if code != http.StatusOK || env.Code != "ok" {
		t.Fatalf("revoke %d %s", code, env.Code)
	}
	closed := readFrame(t, conn)
	if closed["type"] != "error" || closed["error_code"] != "forbidden" {
		t.Fatalf("close frame %#v", closed)
	}
	again := w.dial(sc.credPlain)
	writeFrame(t, again, map[string]any{
		"v": 1, "type": "hello", "host_id": sc.host.ID.String(), "credential_id": sc.credID.String(),
		"agent_version": "0.1.0", "os": "linux", "arch": "arm64",
	})
	denied := readFrame(t, again)
	if denied["type"] != "error" || denied["error_code"] != "forbidden" {
		t.Fatalf("reconnect %#v", denied)
	}
}

func TestConfigUpdateAfterHealthPut(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	conn := w.hello(sc)
	frames := make(chan map[string]any, 4)
	go readLoop(conn, frames)
	body := `{"checks":[{"protocol":"http","port":8080,"path":"/","expect_status_min":210,"expect_status_max":250}]}`
	code, env := w.do(w.token(owner.ID), http.MethodPut, "/v1/services/"+sc.svc.ID.String()+"/health-checks", body)
	if code != http.StatusOK || env.Code != "ok" {
		t.Fatalf("put %d %s", code, env.Code)
	}
	frame := awaitFrame(t, frames)
	if frame["type"] != "config_update" {
		t.Fatalf("frame %#v", frame)
	}
	cfg, _ := frame["config"].(map[string]any)
	checks, _ := cfg["health_checks"].([]any)
	if len(checks) != 1 {
		t.Fatalf("checks %#v", cfg)
	}
	check := checks[0].(map[string]any)
	if check["service"] != "api" || check["protocol"] != "http" || check["port"] != float64(8080) || check["path"] != "/" {
		t.Fatalf("check %#v", check)
	}
	if check["expect_status_min"] != float64(210) || check["expect_status_max"] != float64(250) {
		t.Fatalf("bounds %#v", check)
	}
}

func TestProbeHTTP(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	base := "/v1/services/" + sc.svc.ID.String() + "/probe"

	code, env := w.do(tok, http.MethodPost, base, `{"check_id":"11111111-1111-1111-1111-111111111111","protocol":"http","port":8080}`)
	if code != http.StatusBadRequest || env.Code != "bad_request" {
		t.Fatalf("xor both: %d %s", code, env.Code)
	}
	code, env = w.do(tok, http.MethodPost, base, `{}`)
	if code != http.StatusBadRequest || env.Code != "bad_request" {
		t.Fatalf("xor neither: %d %s", code, env.Code)
	}
	code, env = w.do(tok, http.MethodPost, base, `{"check_id":"22222222-2222-2222-2222-222222222222"}`)
	if code != http.StatusNotFound || env.Code != "not_found" {
		t.Fatalf("unknown check: %d %s", code, env.Code)
	}
	code, env = w.do(tok, http.MethodPost, base, `{"protocol":"http","port":9,"path":"/"}`)
	if code != http.StatusBadRequest || env.Code != "bad_request" || !strings.Contains(env.Msg, "port") {
		t.Fatalf("closed port: %d %s %s", code, env.Code, env.Msg)
	}

	put, putEnv := w.do(tok, http.MethodPut, "/v1/services/"+sc.svc.ID.String()+"/health-checks",
		`{"checks":[{"protocol":"http","port":8080,"path":"/","expect_status_min":210,"expect_status_max":250}]}`)
	if put != http.StatusOK {
		t.Fatalf("put %d %s", put, putEnv.Code)
	}
	payload, _ := putEnv.Payload.(map[string]any)
	checks, _ := payload["checks"].([]any)
	if len(checks) != 1 {
		t.Fatalf("stored checks %#v", putEnv.Payload)
	}
	checkID := checks[0].(map[string]any)["id"].(string)

	conn := w.hello(sc)
	tasks := make(chan map[string]any, 2)
	go readLoop(conn, tasks)

	wait, _, task := callLive(t, w, tok, base, `{"check_id":"`+checkID+`"}`, tasks)
	if task["kind"] != "probe_health" || task["service"] != "api" {
		t.Fatalf("task %#v", task)
	}
	spec := task["spec"].(map[string]any)
	if spec["protocol"] != "http" || spec["port"] != float64(8080) || spec["path"] != "/" {
		t.Fatalf("spec %#v", spec)
	}
	if spec["expect_status_min"] != float64(210) || spec["expect_status_max"] != float64(250) {
		t.Fatalf("stored bounds %#v", spec)
	}
	writeFrame(t, conn, map[string]any{
		"v": 1, "type": "task_result", "task_id": task["task_id"], "state": "succeeded",
		"payload": map[string]any{"result": "failure"},
	})
	got := <-wait
	if got.status != http.StatusOK || got.env.Code != "ok" {
		t.Fatalf("failed probe is still ok: %d %s", got.status, got.env.Code)
	}

	wait, _, task = callLive(t, w, tok, base, `{"protocol":"tcp","port":8080}`, tasks)
	if task["kind"] != "probe_health" {
		t.Fatalf("adhoc %#v", task)
	}
	spec = task["spec"].(map[string]any)
	if spec["protocol"] != "tcp" || spec["port"] != float64(8080) {
		t.Fatalf("adhoc spec %#v", spec)
	}
	if spec["expect_status_min"] != float64(200) || spec["expect_status_max"] != float64(399) {
		t.Fatalf("adhoc bounds %#v", spec)
	}
	if spec["path"] != nil {
		t.Fatalf("tcp path %#v", spec["path"])
	}
	writeFrame(t, conn, map[string]any{
		"v": 1, "type": "task_result", "task_id": task["task_id"], "state": "succeeded",
		"payload": map[string]any{"result": "success"},
	})
	got = <-wait
	if got.status != http.StatusOK || got.env.Code != "ok" {
		t.Fatalf("adhoc %d %s", got.status, got.env.Code)
	}
}

func TestLiveOutcomes(t *testing.T) {
	w := newWorld(t)
	owner := w.user("owner@ex.com", "Owner")
	sc := w.scene(owner, w.user("a@ex.com", "A"), w.user("v@ex.com", "V"), w.user("s@ex.com", "S"), w.user("e@ex.com", "E"))
	tok := w.token(owner.ID)
	path := "/v1/hosts/" + sc.host.ID.String() + "/snapshot"
	conn := w.hello(sc)
	tasks := make(chan map[string]any, 4)
	go readLoop(conn, tasks)

	cases := []struct {
		name   string
		reply  map[string]any
		status int
		code   string
	}{
		{"forbidden", map[string]any{"v": 1, "type": "task_reject", "error_code": "forbidden"}, http.StatusForbidden, "forbidden"},
		{"unknown_service", map[string]any{"v": 1, "type": "task_reject", "error_code": "unknown_service"}, http.StatusNotFound, "not_found"},
		{"bad_spec", map[string]any{"v": 1, "type": "task_reject", "error_code": "bad_spec"}, http.StatusBadRequest, "bad_request"},
		{"wrong_host", map[string]any{"v": 1, "type": "task_reject", "error_code": "wrong_host"}, http.StatusInternalServerError, "error"},
		{"expired", map[string]any{"v": 1, "type": "task_reject", "error_code": "expired"}, http.StatusInternalServerError, "error"},
		{"busy", map[string]any{"v": 1, "type": "task_reject", "error_code": "busy"}, http.StatusServiceUnavailable, "unavailable"},
		{"timed_out", map[string]any{"v": 1, "type": "task_result", "state": "timed_out"}, http.StatusGatewayTimeout, "timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wait, _, task := callLive(t, w, tok, path, "", tasks)
			reply := map[string]any{}
			for k, v := range tc.reply {
				reply[k] = v
			}
			reply["task_id"] = task["task_id"]
			writeFrame(t, conn, reply)
			got := <-wait
			if got.status != tc.status || got.env.Code != tc.code {
				t.Fatalf("%s: %d %s", tc.name, got.status, got.env.Code)
			}
		})
	}

	wait, _, task := callLive(t, w, tok, path, "", tasks)
	writeFrame(t, conn, map[string]any{
		"v": 1, "type": "task_result", "task_id": task["task_id"], "state": "failed",
		"error_code": "boom",
		"payload":    map[string]any{"cmdline": "app --token=sekret --ok", "n": 1},
	})
	got := <-wait
	if got.status != http.StatusInternalServerError || got.env.Code != "error" {
		t.Fatalf("failed: %d %s", got.status, got.env.Code)
	}
	raw, err := json.Marshal(got.env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "sekret") || !strings.Contains(string(raw), `"cmdline":"app --token=[REDACTED] --ok"`) {
		t.Fatalf("payload %s", raw)
	}
	if !strings.Contains(string(raw), `"n":1`) {
		t.Fatalf("number was not preserved: %s", raw)
	}
}

type httpResult struct {
	status int
	env    envelope
}

// callLive starts the HTTP call and returns the task the agent must answer.
func callLive(t *testing.T, w *world, token, path, body string, tasks <-chan map[string]any) (<-chan httpResult, envelope, map[string]any) {
	t.Helper()
	out := make(chan httpResult, 1)
	go func() {
		status, env := w.do(token, http.MethodPost, path, body)
		out <- httpResult{status, env}
	}()
	select {
	case task := <-tasks:
		return out, envelope{}, task
	case res := <-out:
		t.Fatalf("http finished before a task: %d %s", res.status, res.env.Code)
	case <-time.After(5 * time.Second):
		t.Fatal("no task")
	}
	return nil, envelope{}, nil
}

func readLoop(c *websocket.Conn, frames chan<- map[string]any) {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		_, b, err := c.Read(ctx)
		cancel()
		if err != nil {
			return
		}
		var msg map[string]any
		if json.Unmarshal(b, &msg) != nil {
			continue
		}
		if msg["type"] == "task_ack" {
			continue
		}
		frames <- msg
	}
}

func awaitFrame(t *testing.T, frames <-chan map[string]any) map[string]any {
	t.Helper()
	select {
	case frame := <-frames:
		return frame
	case <-time.After(5 * time.Second):
		t.Fatal("no frame")
	}
	return nil
}
