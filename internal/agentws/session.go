package agentws

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/ingest"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

var (
	hostnameRe = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)
	serviceRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
)

// ServeHTTP accepts one agent socket and blocks until it ends.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.acquireUnauth() {
		writeBusy(w)
		return
	}
	held := true
	defer func() {
		if held {
			h.releaseUnauth()
		}
	}()
	// Agents are not browsers; the Origin check is a browser CSRF control, not a TLS check.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	conn.SetReadLimit(maxFrame)
	ac := &agentConn{ws: conn, parent: r.Context(), log: h.log}
	defer func() {
		h.disconnect(ac)
		ac.close(websocket.StatusInternalError, "")
	}()

	token, hasBearer := bearerToken(r)
	authed := false
	for {
		typ, data, err := ac.readFrame()
		if err != nil {
			return
		}
		if typ != websocket.MessageText {
			ac.fail(websocket.StatusUnsupportedData, "bad_request", "text frames only")
			return
		}
		f, err := parseFrame(data)
		if err != nil || f.V != 1 || f.Type == "" {
			ac.fail(websocket.StatusPolicyViolation, "bad_request", "invalid frame")
			return
		}
		if !authed {
			if hasBearer {
				if f.Type != "hello" {
					ac.fail(websocket.StatusPolicyViolation, "unauthenticated", "unauthenticated")
					return
				}
				if !h.hello(ac, token, f) {
					return
				}
				h.releaseUnauth()
				held = false
				authed = true
				continue
			}
			if f.Type != "enroll" {
				ac.fail(websocket.StatusPolicyViolation, "unauthenticated", "unauthenticated")
				return
			}
			h.enroll(ac, f)
			return
		}
		if err := h.dispatch(ac, f); err != nil {
			return
		}
	}
}

func (ac *agentConn) readFrame() (websocket.MessageType, []byte, error) {
	// The first frame has 10s. Later frames keep a 90s budget, parented on the
	// request so shutdown cancels the read. Hijack means Server.ReadTimeout
	// does not apply to this connection.
	wait := frameWait
	if !ac.sawFrame {
		wait = firstFrameWait
	}
	ctx, cancel := context.WithTimeout(ac.parent, wait)
	defer cancel()
	typ, data, err := ac.ws.Read(ctx)
	if err == nil {
		ac.sawFrame = true
	}
	return typ, data, err
}

func (h *Hub) acquireUnauth() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.unauth >= maxUnauthConns {
		return false
	}
	h.unauth++
	return true
}

func (h *Hub) releaseUnauth() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.unauth > 0 {
		h.unauth--
	}
}

func writeBusy(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(`{"code":"unavailable","msg":"unavailable","payload":null}`))
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", false
	}
	scheme, rest, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	return strings.TrimSpace(rest), true
}

func (h *Hub) enroll(ac *agentConn, f frame) {
	if !hostnameRe.MatchString(f.Hostname) {
		ac.fail(websocket.StatusPolicyViolation, "bad_request", "invalid hostname")
		return
	}
	plain, credHash, err := secret.NewToken()
	if err != nil {
		ac.fail(websocket.StatusInternalError, "error", "unavailable")
		return
	}
	credID := uuid.New()
	nodeType := "pi"
	if !f.AlwaysOn {
		nodeType = "workstation"
	}
	host, err := h.st.ConsumeJoinToken(ac.parent, secret.Hash(f.JoinToken), store.EnrollInput{
		Name:         f.Hostname,
		NodeType:     nodeType,
		OS:           f.OS,
		Arch:         f.Arch,
		AlwaysOn:     f.AlwaysOn,
		AgentVersion: f.AgentVersion,
	}, credID, credHash, h.now())
	if err != nil {
		if errors.Is(err, store.ErrUnauthorized) {
			ac.fail(websocket.StatusPolicyViolation, "unauthenticated", "unauthenticated")
			return
		}
		h.log.Error("enroll failed")
		ac.fail(websocket.StatusInternalError, "error", "unavailable")
		return
	}
	projectID := host.ProjectID
	hostID := host.ID
	h.aud.Record(ac.parent, store.AuditRow{
		Via:       audit.ViaAgent,
		ProjectID: &projectID,
		HostID:    &hostID,
		Action:    audit.ActionHostEnroll,
		Decision:  audit.DecisionAllowed,
		Detail:    map[string]any{"name": f.Hostname},
	})
	err = ac.writeThenClose(enrolledFrame{
		V:            1,
		Type:         "enrolled",
		HostID:       host.ID,
		CredentialID: credID,
		Credential:   plain,
	}, websocket.StatusNormalClosure, "")
	if err != nil {
		h.log.Error("enroll write failed")
	}
}

func (h *Hub) hello(ac *agentConn, token string, f frame) bool {
	cred, host, err := h.st.LookupCredential(ac.parent, secret.Hash(token))
	if err != nil {
		if errors.Is(err, store.ErrUnauthorized) {
			ac.fail(websocket.StatusPolicyViolation, "unauthenticated", "unauthenticated")
			return false
		}
		h.log.Error("credential lookup failed")
		ac.fail(websocket.StatusInternalError, "error", "unavailable")
		return false
	}
	if cred.RevokedAt != nil || host.RevokedAt != nil {
		ac.fail(websocket.StatusPolicyViolation, "forbidden", "forbidden")
		return false
	}
	hostID, err := uuid.Parse(f.HostID)
	if err != nil || hostID != cred.HostID {
		ac.fail(websocket.StatusPolicyViolation, "forbidden", "forbidden")
		return false
	}
	if f.CredentialID != "" {
		credID, err := uuid.Parse(f.CredentialID)
		if err != nil || credID != cred.ID {
			ac.fail(websocket.StatusPolicyViolation, "forbidden", "forbidden")
			return false
		}
	}
	old := h.register(ac, host.ID)
	h.retire(old)
	if err := h.st.TouchHost(ac.parent, host.ID, h.now(), f.AgentVersion, f.OS, f.Arch); err != nil {
		h.unregister(ac)
		h.log.Error("touch host failed", "host_id", host.ID.String())
		ac.fail(websocket.StatusInternalError, "error", "unavailable")
		return false
	}
	h.upsertServices(ac, f.Services)
	cfg, err := h.agentConfig(ac.parent, host.ID)
	if err != nil {
		h.log.Error("health checks failed", "host_id", host.ID.String())
		cfg = configBody{MetricsIntervalSec: metricsEvery, ProcessIntervalSec: processEvery, HealthChecks: []checkJSON{}}
	}
	msg := helloOKFrame{
		V:            1,
		Type:         "hello_ok",
		HostID:       host.ID,
		HeartbeatSec: heartbeatSec,
		ServerTime:   h.now().UTC().Format(time.RFC3339),
		Config:       cfg,
	}
	if err := ac.write(msg); err != nil {
		h.unregister(ac)
		h.log.Error("hello_ok write failed", "host_id", host.ID.String())
		ac.close(websocket.StatusInternalError, "")
		return false
	}
	return true
}

func (h *Hub) dispatch(ac *agentConn, f frame) error {
	switch f.Type {
	case "enroll":
		ac.fail(websocket.StatusPolicyViolation, "unauthenticated", "unauthenticated")
		return errClosed
	case "ping":
		return h.onPing(ac)
	case "services":
		h.upsertServices(ac, f.Services)
		return nil
	case "metrics":
		return h.onMetrics(ac, f)
	case "task_result":
		return h.onTaskResult(ac, f)
	case "task_reject":
		h.onTaskReject(ac, f)
		return nil
	default:
		h.log.Info("ignored agent frame", "type", f.Type)
		return nil
	}
}

func (h *Hub) onPing(ac *agentConn) error {
	at := h.now()
	h.notePing(ac, at)
	if err := h.st.TouchHost(ac.parent, ac.hostID, at, "", "", ""); err != nil {
		h.log.Error("touch host failed", "host_id", ac.hostID.String())
	}
	return ac.write(map[string]any{
		"v":    1,
		"type": "pong",
		"ts":   at.UTC().Format(time.RFC3339),
	})
}

func (h *Hub) upsertServices(ac *agentConn, raw json.RawMessage) {
	items := h.discovered(raw)
	if len(items) == 0 {
		return
	}
	if err := h.st.UpsertDiscovered(ac.parent, ac.hostID, items, h.now()); err != nil {
		h.log.Error("services upsert failed", "host_id", ac.hostID.String())
	}
}

func (h *Hub) discovered(raw json.RawMessage) []store.Discovered {
	if len(strings.TrimSpace(string(raw))) == 0 || string(raw) == "null" {
		return nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		h.log.Warn("skip service", "name", "")
		return nil
	}
	out := make([]store.Discovered, 0, len(items))
	for _, item := range items {
		d, ok := h.oneService(item)
		if ok {
			out = append(out, d)
		}
	}
	return out
}

func (h *Hub) oneService(raw json.RawMessage) (store.Discovered, bool) {
	var peek struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(raw, &peek)
	var in struct {
		Name          string          `json:"name"`
		Kind          string          `json:"kind"`
		Ports         []int           `json:"ports"`
		SystemdUnit   *string         `json:"systemd_unit"`
		SystemdScope  *string         `json:"systemd_scope"`
		ContainerName *string         `json:"container_name"`
		ProcessName   *string         `json:"process_name"`
		User          json.RawMessage `json:"user"`
	}
	if err := json.Unmarshal(raw, &in); err != nil || !validService(in.Name, in.Kind, in.Ports, in.SystemdScope) {
		h.log.Warn("skip service", "name", clipName(peek.Name))
		return store.Discovered{}, false
	}
	ports := in.Ports
	if ports == nil {
		ports = []int{}
	}
	return store.Discovered{
		Name:          in.Name,
		Kind:          in.Kind,
		Ports:         ports,
		SystemdUnit:   in.SystemdUnit,
		SystemdScope:  in.SystemdScope,
		ContainerName: in.ContainerName,
		ProcessName:   in.ProcessName,
		OwnerUser:     ownerUser(in.User),
	}, true
}

// ownerUser reads Discovered.user. A missing, null, or non-string value
// becomes nil. The store drops strings that are not printable account names.
// A bad user does not drop the service.
func ownerUser(raw json.RawMessage) *string {
	if strings.TrimSpace(string(raw)) == "" || string(raw) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	return &s
}

func validService(name, kind string, ports []int, scope *string) bool {
	if !serviceRe.MatchString(name) {
		return false
	}
	if kind != "systemd" && kind != "process" {
		return false
	}
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return false
		}
	}
	if scope != nil && *scope != "system" && *scope != "user" {
		return false
	}
	return true
}

func clipName(name string) string {
	if len(name) > 128 {
		return name[:128]
	}
	return name
}

func (h *Hub) onMetrics(ac *agentConn, f frame) error {
	now := h.now()
	if !ac.allowMetrics(now) {
		if ac.metricLogged.IsZero() || now.Sub(ac.metricLogged) >= time.Minute {
			ac.metricLogged = now
			h.log.Warn("metrics rate limited", "host_id", ac.hostID.String())
		}
		return nil
	}
	id, samples, err := ingest.ValidateBatch(f.BatchID, f.Samples)
	if err != nil {
		reason := "invalid"
		var rej *ingest.Reject
		if errors.As(err, &rej) {
			reason = rej.Reason
		}
		h.log.Warn("metrics rejected", "reason", reason)
		return nil
	}
	if h.seen.Has(ac.hostID, id) {
		h.seen.Add(ac.hostID, id)
		return ac.write(metricsAck(id))
	}
	_, err = h.st.InsertBatch(ac.parent, ac.hostID, id, samples, h.now())
	if err != nil {
		h.log.Error("metrics insert failed")
		return nil
	}
	h.seen.Add(ac.hostID, id)
	return ac.write(metricsAck(id))
}

// allowMetrics is a token bucket: 2 frames per second, burst 20.
func (ac *agentConn) allowMetrics(now time.Time) bool {
	if ac.metricAt.IsZero() {
		ac.metricTokens = metricsBurst
	} else if elapsed := now.Sub(ac.metricAt); elapsed > 0 {
		ac.metricTokens += elapsed.Seconds() * metricsPerSec
		if ac.metricTokens > metricsBurst {
			ac.metricTokens = metricsBurst
		}
	}
	ac.metricAt = now
	if ac.metricTokens < 1 {
		return false
	}
	ac.metricTokens--
	return true
}

func metricsAck(id uuid.UUID) map[string]any {
	return map[string]any{
		"v":        1,
		"type":     "metrics_ack",
		"batch_id": id.String(),
	}
}
