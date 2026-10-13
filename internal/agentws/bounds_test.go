package agentws

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/memstore"
)

func TestUnauthenticatedSocketCap(t *testing.T) {
	hub := New(memstore.New(), audit.Writer{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	srv := httptest.NewServer(hub)
	t.Cleanup(func() {
		hub.CloseAll()
		srv.Close()
	})
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	var wg sync.WaitGroup
	errCh := make(chan error, maxUnauthConns)
	conns := make([]*websocket.Conn, maxUnauthConns)
	for i := 0; i < maxUnauthConns; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, _, err := websocket.Dial(ctx, url, nil)
			if err != nil {
				errCh <- err
				return
			}
			conns[i] = c
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, c := range conns {
			if c != nil {
				c.Close(websocket.StatusNormalClosure, "")
			}
		}
	})
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("65th connection: %d", resp.StatusCode)
	}
	var env map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if env["code"] != "unavailable" {
		t.Fatalf("body %#v", env)
	}
}

func TestFirstFrameTimeout(t *testing.T) {
	hub := New(memstore.New(), audit.Writer{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	srv := httptest.NewServer(hub)
	t.Cleanup(func() {
		hub.CloseAll()
		srv.Close()
	})
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn := dial(t, url, "")
	t.Cleanup(func() { conn.Close(websocket.StatusNormalClosure, "") })
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _, err := conn.Read(ctx)
	if err == nil || errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 14*time.Second {
		t.Fatalf("first frame still open after %s: %v", time.Since(start), err)
	}
}
