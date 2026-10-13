package agentws

import (
	"context"
	"encoding/json"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/ingest"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// CallError is a live-task failure. Code is an API envelope code.
// Payload is set when the agent sent a failed result body.
type CallError struct {
	Code    string
	Msg     string
	Payload json.RawMessage
}

func (e *CallError) Error() string {
	if e == nil {
		return ""
	}
	return e.Code + ": " + e.Msg
}

// LiveResult is a succeeded task payload. Payload is the agent JSON value, or null.
type LiveResult struct {
	TaskID  uuid.UUID
	Payload json.RawMessage
}

// Snapshot asks a live host for a host_snapshot.
func (h *Hub) Snapshot(ctx context.Context, host store.Host) (LiveResult, error) {
	return h.live(ctx, host, "host_snapshot", nil, map[string]any{})
}

// Probe asks a live host to run probe_health for svc.
func (h *Hub) Probe(ctx context.Context, host store.Host, svc store.Service, spec map[string]any) (LiveResult, error) {
	name := svc.Name
	if spec == nil {
		spec = map[string]any{}
	}
	return h.live(ctx, host, "probe_health", &name, spec)
}

func (h *Hub) live(ctx context.Context, host store.Host, kind string, service *string, spec map[string]any) (LiveResult, error) {
	if host.RevokedAt != nil || h.Status(host, h.now()) != "online" {
		return LiveResult{}, &CallError{Code: "unavailable", Msg: "host unavailable"}
	}
	if spec == nil {
		spec = map[string]any{}
	}
	taskID := uuid.New()
	now := h.now()
	frame := taskFrame{
		V:          1,
		Type:       "task",
		TaskID:     taskID,
		HostID:     host.ID,
		Kind:       kind,
		Service:    service,
		ExpiresAt:  now.Add(taskTTL).UTC().Format(time.RFC3339),
		TimeoutSec: taskTimeoutSec,
		Spec:       spec,
	}
	ch := make(chan taskOut, 1)
	h.mu.Lock()
	ac := h.conns[host.ID]
	online := ac != nil && h.now().Sub(ac.lastPing) <= offlineAfter
	if !online || host.RevokedAt != nil {
		h.mu.Unlock()
		return LiveResult{}, &CallError{Code: "unavailable", Msg: "host unavailable"}
	}
	h.waiters[taskID] = waiter{conn: ac, ch: ch}
	h.mu.Unlock()

	if err := ac.writeJSON(ctx, frame); err != nil {
		h.dropWaiter(taskID)
		go ac.close(websocket.StatusInternalError, "")
		return LiveResult{}, &CallError{Code: "unavailable", Msg: "host unavailable"}
	}

	select {
	case <-ctx.Done():
		if out, ok := h.takeWaiter(taskID, ch); ok {
			return finishTask(taskID, out)
		}
		return LiveResult{}, &CallError{Code: "timeout", Msg: "timed out"}
	case out := <-ch:
		return finishTask(taskID, out)
	}
}

func finishTask(taskID uuid.UUID, out taskOut) (LiveResult, error) {
	if out.err != nil {
		return LiveResult{}, out.err
	}
	if out.res.TaskID == uuid.Nil {
		out.res.TaskID = taskID
	}
	if len(out.res.Payload) == 0 {
		out.res.Payload = json.RawMessage("null")
	}
	return out.res, nil
}

func (h *Hub) dropWaiter(id uuid.UUID) {
	h.mu.Lock()
	delete(h.waiters, id)
	h.mu.Unlock()
}

func (h *Hub) takeWaiter(id uuid.UUID, ch chan taskOut) (taskOut, bool) {
	h.mu.Lock()
	_, pending := h.waiters[id]
	if pending {
		delete(h.waiters, id)
	}
	h.mu.Unlock()
	if !pending {
		select {
		case out := <-ch:
			return out, true
		default:
			return taskOut{}, false
		}
	}
	select {
	case out := <-ch:
		return out, true
	default:
		return taskOut{}, false
	}
}

func (h *Hub) onTaskResult(ac *agentConn, f frame) error {
	id, err := uuid.Parse(f.TaskID)
	if err != nil {
		h.log.Warn("bad task_id")
		return nil
	}
	var out taskOut
	switch f.State {
	case "succeeded":
		out.res = LiveResult{TaskID: id, Payload: taskPayload(f.Payload)}
	case "timed_out":
		out.err = &CallError{Code: "timeout", Msg: "timed out"}
	case "failed":
		out.err = &CallError{Code: "error", Msg: jsonString(f.ErrorCode), Payload: taskPayload(f.Payload)}
	default:
		out.err = &CallError{Code: "error", Msg: jsonString(f.ErrorCode), Payload: taskPayload(f.Payload)}
	}
	h.deliver(id, out)
	return ac.write(map[string]any{
		"v":       1,
		"type":    "task_ack",
		"task_id": id.String(),
	})
}

func (h *Hub) onTaskReject(ac *agentConn, f frame) {
	id, err := uuid.Parse(f.TaskID)
	if err != nil {
		h.log.Warn("bad task_id")
		return
	}
	code, msg := rejectCode(jsonString(f.ErrorCode))
	h.deliver(id, taskOut{err: &CallError{Code: code, Msg: msg}})
	_ = ac
}

func rejectCode(code string) (string, string) {
	switch code {
	case "forbidden":
		return "forbidden", "forbidden"
	case "unknown_service":
		return "not_found", "not found"
	case "bad_spec":
		return "bad_request", "bad request"
	case "busy":
		return "unavailable", "host unavailable"
	default:
		return "error", "internal error"
	}
}

func taskPayload(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	return ingest.RedactPayload(raw)
}

func (h *Hub) deliver(id uuid.UUID, out taskOut) {
	h.mu.Lock()
	w, ok := h.waiters[id]
	if ok {
		delete(h.waiters, id)
	}
	h.mu.Unlock()
	if !ok {
		return
	}
	w.ch <- out
}
