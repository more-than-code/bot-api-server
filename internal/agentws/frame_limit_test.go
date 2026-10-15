package agentws

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/memstore"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestMarshalFrameLimit(t *testing.T) {
	var buf bytes.Buffer
	ac := &agentConn{log: slog.New(slog.NewTextHandler(&buf, nil))}
	body, err := ac.marshalFrame(strings.Repeat("a", maxFrame-2))
	if err != nil || len(body) != maxFrame {
		t.Fatalf("exact limit: len %d err %v", len(body), err)
	}
	if buf.Len() != 0 {
		t.Fatalf("exact frame was logged: %s", buf.String())
	}
	const marker = "SENTINEL-OVERSIZE-BODY"
	_, err = ac.marshalFrame(strings.Repeat("b", maxFrame) + marker)
	if !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("oversize err %v", err)
	}
	logs := buf.String()
	if !strings.Contains(logs, "outbound frame too large") || !strings.Contains(logs, "bytes=") {
		t.Fatalf("log %q", logs)
	}
	if strings.Contains(logs, marker) {
		t.Fatalf("log contains frame body: %s", logs)
	}
}

func TestServerRefusesOversizeOutbound(t *testing.T) {
	const marker = "SENTINEL-OVERSIZE-BODY"

	t.Run("writeJSON", func(t *testing.T) {
		ac, c, logs := holdAgentConn(t)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := ac.writeJSON(ctx, map[string]any{"v": 1, "type": "config_update"}); err != nil {
			t.Fatal(err)
		}
		_, small, err := c.Read(ctx)
		if err != nil || !bytes.Contains(small, []byte(`"config_update"`)) {
			t.Fatalf("small frame: %v %s", err, small)
		}
		err = ac.writeJSON(ctx, map[string]string{"blob": strings.Repeat("a", maxFrame) + marker})
		if !errors.Is(err, errFrameTooLarge) {
			t.Fatalf("write err %v", err)
		}
		assertNoMarker(t, c, logs(), marker)
	})

	t.Run("fail", func(t *testing.T) {
		ac, c, logs := holdAgentConn(t)
		ac.fail(websocket.StatusPolicyViolation, "bad_request", strings.Repeat("b", maxFrame)+marker)
		assertNoMarker(t, c, logs(), marker)
	})

	t.Run("writeThenClose", func(t *testing.T) {
		ac, c, logs := holdAgentConn(t)
		err := ac.writeThenClose(map[string]string{"blob": strings.Repeat("c", maxFrame) + marker}, websocket.StatusNormalClosure, "bye")
		if !errors.Is(err, errFrameTooLarge) {
			t.Fatalf("err %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := ac.writeJSON(ctx, map[string]any{"v": 1, "type": "config_update"}); err != nil {
			t.Fatal(err)
		}
		_, msg, err := c.Read(ctx)
		if err != nil || bytes.Contains(msg, []byte(marker)) || !bytes.Contains(msg, []byte(`"config_update"`)) {
			t.Fatalf("socket after oversize close: %v %s", err, msg)
		}
		if !strings.Contains(logs(), "outbound frame too large") || strings.Contains(logs(), marker) {
			t.Fatalf("log %q", logs())
		}
	})
}

func TestLiveOversizeDoesNotClose(t *testing.T) {
	ac, c, _ := holdAgentConn(t)
	h := New(memstore.New(), audit.Writer{}, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now)
	id := uuid.New()
	ac.lastPing = time.Now()
	h.mu.Lock()
	h.conns[id] = ac
	h.mu.Unlock()
	host := store.Host{ID: id}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	blob := map[string]any{"blob": strings.Repeat("<", maxFrame)}
	_, err := h.Program(ctx, host, "program_start", blob)
	var call *CallError
	if !errors.As(err, &call) || call.Code != "bad_request" || call.Msg != "bad request" {
		t.Fatalf("program %v", err)
	}
	_, err = h.Image(ctx, host, "image_deploy", blob, 60)
	call = nil
	if !errors.As(err, &call) || call.Code != "bad_request" || call.Msg != EnvFrameTooLarge {
		t.Fatalf("image %v", err)
	}
	if err := ac.writeJSON(ctx, map[string]any{"v": 1, "type": "config_update"}); err != nil {
		t.Fatal(err)
	}
	_, msg, err := c.Read(ctx)
	if err != nil || !bytes.Contains(msg, []byte(`"config_update"`)) {
		t.Fatalf("socket closed: %v %s", err, msg)
	}
}

func TestWriteJSONBoundsWriteWait(t *testing.T) {
	ac, _, _ := holdAgentConn(t)
	payload := map[string]string{"blob": strings.Repeat("a", 512<<10)}
	parent, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	var blocked error
	for i := 0; i < 32; i++ {
		err := ac.writeJSON(parent, payload)
		if err != nil {
			blocked = err
			break
		}
	}
	elapsed := time.Since(start)
	if blocked == nil {
		t.Fatal("socket accepted every write")
	}
	if elapsed < 8*time.Second || elapsed > 15*time.Second {
		t.Fatalf("write returned in %s (%v), want about writeWait", elapsed, blocked)
	}
}

func assertNoMarker(t *testing.T, c *websocket.Conn, logs, marker string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, msg, err := c.Read(ctx)
	if err == nil || bytes.Contains(msg, []byte(marker)) {
		t.Fatalf("client received oversize frame: err=%v len=%d", err, len(msg))
	}
	if !strings.Contains(logs, "outbound frame too large") || strings.Contains(logs, marker) {
		t.Fatalf("log %q", logs)
	}
}

// holdAgentConn accepts one socket and returns it only after the client handshake has finished.
func holdAgentConn(t *testing.T) (*agentConn, *websocket.Conn, func() string) {
	t.Helper()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	got := make(chan *agentConn, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusInternalError, "")
		got <- &agentConn{ws: conn, parent: r.Context(), log: log}
		<-release
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(websocket.StatusNormalClosure, "") })
	c.SetReadLimit(int64(maxFrame) * 4)

	select {
	case ac := <-got:
		return ac, c, func() string { return buf.String() }
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	return nil, nil, nil
}
