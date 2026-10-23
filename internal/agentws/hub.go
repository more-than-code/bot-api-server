// Package agentws is the phase-1 agent WebSocket hub.
package agentws

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/ingest"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const (
	heartbeatSec   = 20
	offlineAfter   = 60 * time.Second
	frameWait      = 90 * time.Second
	firstFrameWait = 10 * time.Second
	maxUnauthConns = 64
	writeWait      = 10 * time.Second
	maxFrame       = 1 << 20
	metricsPerSec  = 2
	metricsBurst   = 20
	autoPerSec     = 1
	autoBurst      = 10
	autoWarnEvery  = time.Hour
	taskTimeoutSec = 15
	taskTTL        = 60 * time.Second
	metricsEvery   = 10
	processEvery   = 60
)

// Hub tracks live agent sockets and serves /agent/v1/ws.
type Hub struct {
	st   store.Store
	aud  audit.Writer
	log  *slog.Logger
	now  func() time.Time
	seen *ingest.Seen

	mu      sync.Mutex
	conns   map[uuid.UUID]*agentConn
	waiters map[uuid.UUID]waiter
	unauth  int
	// autoWarned is the hourly-cap warn state per (entry, host), one line an hour.
	autoWarned map[string]*warnCount
}

type waiter struct {
	conn *agentConn
	ch   chan taskOut
}

type taskOut struct {
	res LiveResult
	err error
}

type agentConn struct {
	ws      *websocket.Conn
	parent  context.Context
	writeMu sync.Mutex
	done    bool

	hostID       uuid.UUID
	lastPing     time.Time
	sawFrame     bool
	log          *slog.Logger
	metricTokens float64
	metricAt     time.Time
	metricLogged time.Time
	// healthPolicy is this connection's hello programs.health_policy.
	healthPolicy bool
	// auto_action throttle and warn dedup, owned by the read loop.
	autoTokens float64
	autoAt     time.Time
	autoWarns  map[string]*warnCount
}

// errFrameTooLarge is returned when a serialized outbound frame exceeds maxFrame.
// The frame is not written.
var errFrameTooLarge = errors.New("outbound frame too large")

// EnvFrameTooLarge is the image deploy and rollback error when the task the
// API built exceeds maxFrame. No bytes are written and the socket stays up.
const EnvFrameTooLarge = "the resolved environment and files are too large for one task"

var _ http.Handler = (*Hub)(nil)

// New builds a hub. now may be nil, in which case time is UTC wall time.
func New(st store.Store, aud audit.Writer, log *slog.Logger, now func() time.Time) *Hub {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if log == nil {
		log = slog.Default()
	}
	h := &Hub{
		st:         st,
		aud:        aud,
		log:        log,
		now:        now,
		conns:      map[uuid.UUID]*agentConn{},
		waiters:    map[uuid.UUID]waiter{},
		autoWarned: map[string]*warnCount{},
	}
	h.seen = ingest.NewSeen(h.now)
	return h
}

// SetLog replaces the hub logger and the logger on live connections.
// Tests point it at the same buffer as the API log.
func (h *Hub) SetLog(log *slog.Logger) {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.log = log
	for _, ac := range h.conns {
		ac.log = log
	}
}

// Status reports revoked, online, asleep, or offline.
// Online requires a registered socket whose last ping is within 60s.
func (h *Hub) Status(host store.Host, now time.Time) string {
	if host.RevokedAt != nil {
		return "revoked"
	}
	h.mu.Lock()
	ac := h.conns[host.ID]
	online := ac != nil && now.Sub(ac.lastPing) <= offlineAfter
	h.mu.Unlock()
	if online {
		return "online"
	}
	if !host.AlwaysOn {
		return "asleep"
	}
	return "offline"
}

// PushConfig sends config_update to a connected host. A missing socket is a no-op.
func (h *Hub) PushConfig(ctx context.Context, hostID uuid.UUID) {
	cfg, err := h.agentConfig(ctx, hostID)
	if err != nil {
		h.log.Error("health checks failed", "host_id", hostID.String())
		return
	}
	h.mu.Lock()
	ac := h.conns[hostID]
	h.mu.Unlock()
	if ac == nil {
		return
	}
	frame := configUpdate{V: 1, Type: "config_update", Config: cfg}
	if err := ac.writeJSON(ctx, frame); err != nil {
		h.log.Error("config push failed", "host_id", hostID.String())
		go ac.close(websocket.StatusInternalError, "")
	}
}

// CloseHost writes forbidden and closes the host socket with 1008.
func (h *Hub) CloseHost(hostID uuid.UUID) {
	ac := h.take(hostID)
	if ac == nil {
		return
	}
	go ac.fail(websocket.StatusPolicyViolation, "forbidden", "forbidden")
}

// CloseAll closes every live socket.
func (h *Hub) CloseAll() {
	h.mu.Lock()
	all := h.conns
	h.conns = map[uuid.UUID]*agentConn{}
	var pending []waiter
	for id, w := range h.waiters {
		delete(h.waiters, id)
		pending = append(pending, w)
	}
	h.mu.Unlock()
	for _, w := range pending {
		w.ch <- taskOut{err: &CallError{Code: "unavailable", Msg: "host unavailable"}}
	}
	var wg sync.WaitGroup
	for _, ac := range all {
		wg.Add(1)
		go func(ac *agentConn) {
			defer wg.Done()
			ac.close(websocket.StatusGoingAway, "")
		}(ac)
	}
	wg.Wait()
}

func (h *Hub) register(ac *agentConn, hostID uuid.UUID) *agentConn {
	h.mu.Lock()
	defer h.mu.Unlock()
	var old *agentConn
	if prev := h.conns[hostID]; prev != nil && prev != ac {
		old = prev
	}
	ac.hostID = hostID
	ac.lastPing = h.now()
	h.conns[hostID] = ac
	return old
}

func (h *Hub) retire(old *agentConn) {
	if old == nil {
		return
	}
	h.mu.Lock()
	var pending []waiter
	for id, w := range h.waiters {
		if w.conn == old {
			delete(h.waiters, id)
			pending = append(pending, w)
		}
	}
	h.mu.Unlock()
	for _, w := range pending {
		w.ch <- taskOut{err: &CallError{Code: "unavailable", Msg: "host unavailable"}}
	}
	go old.close(websocket.StatusNormalClosure, "")
}

func (h *Hub) take(hostID uuid.UUID) *agentConn {
	h.mu.Lock()
	ac := h.conns[hostID]
	if ac != nil {
		delete(h.conns, hostID)
	}
	var pending []waiter
	if ac != nil {
		for id, w := range h.waiters {
			if w.conn == ac {
				delete(h.waiters, id)
				pending = append(pending, w)
			}
		}
	}
	h.mu.Unlock()
	for _, w := range pending {
		w.ch <- taskOut{err: &CallError{Code: "unavailable", Msg: "host unavailable"}}
	}
	return ac
}

func (h *Hub) unregister(ac *agentConn) {
	h.mu.Lock()
	if ac.hostID != uuid.Nil && h.conns[ac.hostID] == ac {
		delete(h.conns, ac.hostID)
	}
	h.mu.Unlock()
}

func (h *Hub) disconnect(ac *agentConn) {
	h.mu.Lock()
	if ac.hostID != uuid.Nil && h.conns[ac.hostID] == ac {
		delete(h.conns, ac.hostID)
	}
	var pending []waiter
	for id, w := range h.waiters {
		if w.conn == ac {
			delete(h.waiters, id)
			pending = append(pending, w)
		}
	}
	h.mu.Unlock()
	for _, w := range pending {
		w.ch <- taskOut{err: &CallError{Code: "unavailable", Msg: "host unavailable"}}
	}
}

func (h *Hub) notePing(ac *agentConn, at time.Time) {
	h.mu.Lock()
	if h.conns[ac.hostID] == ac {
		ac.lastPing = at
	}
	h.mu.Unlock()
}

func (h *Hub) agentConfig(ctx context.Context, hostID uuid.UUID) (configBody, error) {
	checks, err := h.st.HealthChecksForHost(ctx, hostID)
	if err != nil {
		return configBody{}, err
	}
	body := configBody{
		MetricsIntervalSec: metricsEvery,
		ProcessIntervalSec: processEvery,
		HealthChecks:       make([]checkJSON, 0, len(checks)),
	}
	for _, c := range checks {
		body.HealthChecks = append(body.HealthChecks, checkJSON{
			ID:              c.ID,
			Service:         c.Service,
			Protocol:        c.Protocol,
			Port:            c.Port,
			Path:            c.Path,
			IntervalSec:     c.IntervalSec,
			ExpectStatusMin: c.ExpectStatusMin,
			ExpectStatusMax: c.ExpectStatusMax,
		})
	}
	// A host lookup failure still sends the checks. The flag stays omitted.
	if host, err := h.st.GetHost(ctx, hostID); err == nil && host.Programs != nil && host.Programs.DockerHealth {
		body.DockerHealth = true
	}
	return body, nil
}

// marshalFrame serializes v and refuses a body larger than maxFrame.
// The log records the size only, never the body.
func (ac *agentConn) marshalFrame(v any) ([]byte, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(body) > maxFrame {
		if ac.log != nil {
			ac.log.Warn("outbound frame too large", "bytes", len(body), "limit", maxFrame)
		}
		return nil, errFrameTooLarge
	}
	return body, nil
}

// writeJSON bounds every socket write by writeWait, including when ctx is the
// longer task timeout. A cancelled parent still fails the write immediately.
func (ac *agentConn) writeJSON(ctx context.Context, v any) error {
	body, err := ac.marshalFrame(v)
	if err != nil {
		return err
	}
	parent := ctx
	if parent == nil {
		parent = context.Background()
	}
	wctx, cancel := context.WithTimeout(parent, writeWait)
	defer cancel()
	ac.writeMu.Lock()
	defer ac.writeMu.Unlock()
	return ac.ws.Write(wctx, websocket.MessageText, body)
}

func (ac *agentConn) write(v any) error {
	parent := ac.parent
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, writeWait)
	defer cancel()
	return ac.writeJSON(ctx, v)
}

func (ac *agentConn) fail(status websocket.StatusCode, code, msg string) {
	ac.writeMu.Lock()
	defer ac.writeMu.Unlock()
	if ac.done {
		return
	}
	ac.done = true
	if code != "" {
		ctx, cancel := context.WithTimeout(context.Background(), writeWait)
		body, err := ac.marshalFrame(errorFrame{V: 1, Type: "error", ErrorCode: code, Message: msg})
		if err == nil {
			_ = ac.ws.Write(ctx, websocket.MessageText, body)
		}
		cancel()
	}
	_ = ac.ws.Close(status, code)
}

func (ac *agentConn) close(status websocket.StatusCode, reason string) {
	ac.writeMu.Lock()
	defer ac.writeMu.Unlock()
	if ac.done {
		return
	}
	ac.done = true
	_ = ac.ws.Close(status, reason)
}

func (ac *agentConn) writeThenClose(v any, status websocket.StatusCode, reason string) error {
	body, err := ac.marshalFrame(v)
	if errors.Is(err, errFrameTooLarge) {
		return err
	}
	ac.writeMu.Lock()
	defer ac.writeMu.Unlock()
	if ac.done {
		return errClosed
	}
	ac.done = true
	ctx, cancel := context.WithTimeout(context.Background(), writeWait)
	defer cancel()
	if err != nil {
		_ = ac.ws.Close(websocket.StatusInternalError, "")
		return err
	}
	if err := ac.ws.Write(ctx, websocket.MessageText, body); err != nil {
		_ = ac.ws.Close(websocket.StatusInternalError, "")
		return err
	}
	return ac.ws.Close(status, reason)
}
