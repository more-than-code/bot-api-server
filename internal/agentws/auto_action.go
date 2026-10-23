package agentws

import (
	"errors"
	"time"

	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/ingest"
	"github.com/more-than-code/bot-api-server/internal/store"
)

var autoAuditActions = map[string]string{
	"restart":  audit.ActionCatalogAutoRestart,
	"rollback": audit.ActionCatalogAutoRollback,
	"gave_up":  audit.ActionCatalogAutoGaveUp,
}

// onAutoAction stores one agent automatic action (agent-protocol v1.9 item 5,
// api-v1 v1.15 item 3 with the rev 2 amendments) and acknowledges it.
//
//   - A connection whose hello did not advertise programs.health_policy gets
//     no ack and nothing is read or stored. This check reads no database.
//   - A frame without a usable id gets no ack.
//   - A frame beyond the per-connection bucket (burst 10, 1 a second) is
//     dropped before any other check: no ack, no database read.
//   - A frame that fails the shape, container, entry, kind, policy, or
//     deployed checks, or is over the hourly cap, is acknowledged and dropped.
//     Warn lines are deduplicated to one an hour per (connection, reason),
//     and the cap to one an hour per (entry, host), each with a count.
//   - A replayed id is acknowledged without a second row.
//   - A store failure is not acknowledged, so the agent resends.
func (h *Hub) onAutoAction(ac *agentConn, f frame) error {
	now := h.now()
	if !ac.allowAuto(now) {
		// No ack: the agent keeps the frame and resends it after a reconnect.
		h.connWarn(ac, "throttled", now)
		return nil
	}
	if !ac.healthPolicy {
		h.log.Info("ignored agent frame", "type", f.Type)
		return nil
	}
	id, ok := ingest.ParseAutoActionID(f.Raw)
	if !ok {
		h.connWarn(ac, "id", now)
		return nil
	}
	ack := func() error { return ac.write(autoActionAck(id.String())) }
	drop := func(reason string) error {
		h.connWarn(ac, reason, now)
		return ack()
	}
	in, err := ingest.ValidateAutoAction(f.Raw)
	if err != nil {
		reason := "invalid"
		var rej *ingest.Reject
		if errors.As(err, &rej) {
			reason = rej.Reason
		}
		return drop(reason)
	}
	if in.Container != in.Project+"-"+in.Entry {
		return drop("container")
	}
	target, err := h.st.AutoActionTarget(ac.parent, ac.hostID, in.Project, in.Entry)
	if errors.Is(err, store.ErrNotFound) {
		return drop("entry")
	}
	if err != nil {
		h.log.Error("auto action lookup failed", "host_id", ac.hostID.String())
		return nil
	}
	img, err := catalog.ParseStored(target.ImageRaw)
	if err != nil || img.Kind != "service" {
		return drop("kind")
	}
	if !autoAllowed(img.HealthPolicy.Effective().OnUnhealthy, in) {
		return drop("policy")
	}
	if !target.Deployed {
		return drop("not deployed")
	}
	outcome, digest := in.Outcome, in.Digest
	if in.Result == "error" {
		outcome, digest = "auto_failed", nil
	}
	_, inserted, err := h.st.RecordAutoAction(ac.parent, store.AutoAction{
		ID:      in.ID,
		EntryID: target.EntryID,
		HostID:  ac.hostID,
		Outcome: outcome,
		Digest:  digest,
		At:      h.now(),
	})
	if errors.Is(err, store.ErrAutoActionLimit) {
		key := target.EntryID.String() + "/" + ac.hostID.String()
		h.mu.Lock()
		w := h.autoWarned[key]
		if w == nil {
			w = &warnCount{}
			h.autoWarned[key] = w
		}
		n, due := w.note(now)
		h.mu.Unlock()
		if due {
			h.log.Warn("auto action rejected", "reason", "rate", "host_id", ac.hostID.String(), "dropped", n)
		}
		return ack()
	}
	if err != nil {
		h.log.Error("auto action insert failed", "host_id", ac.hostID.String())
		return nil
	}
	if inserted {
		h.recordAutoAudit(ac, target, in)
	}
	return ack()
}

// autoAllowed is the rev 2 authority rule: an ok restart or rollback needs the
// entry's effective on_unhealthy to name that action; gave_up and an error
// result need any value other than none.
func autoAllowed(onUnhealthy string, in ingest.AutoAction) bool {
	if in.Action == "gave_up" || in.Result == "error" {
		return onUnhealthy != catalog.DefaultOnUnhealthy
	}
	return onUnhealthy == in.Action
}

// warnCount dedups one kind of warn line to one an hour. count is the
// number of events since the last line, including the one that logs.
type warnCount struct {
	last  time.Time
	count int
}

// note records one event and reports whether a line is due, with the count
// to print. The count resets when a line is logged.
func (w *warnCount) note(now time.Time) (int, bool) {
	w.count++
	if !w.last.IsZero() && now.Sub(w.last) < autoWarnEvery {
		return 0, false
	}
	n := w.count
	w.last = now
	w.count = 0
	return n, true
}

// connWarn logs an auto_action drop at most once an hour per (connection,
// reason), with the number dropped since the last line.
func (h *Hub) connWarn(ac *agentConn, reason string, now time.Time) {
	if ac.autoWarns == nil {
		ac.autoWarns = map[string]*warnCount{}
	}
	w := ac.autoWarns[reason]
	if w == nil {
		w = &warnCount{}
		ac.autoWarns[reason] = w
	}
	if n, due := w.note(now); due {
		h.log.Warn("auto action rejected", "reason", reason, "host_id", ac.hostID.String(), "dropped", n)
	}
}

// allowAuto is the per-connection auto_action token bucket: burst 10,
// refill 1 a second. It reads no database.
func (ac *agentConn) allowAuto(now time.Time) bool {
	if ac.autoAt.IsZero() {
		ac.autoTokens = autoBurst
	} else if elapsed := now.Sub(ac.autoAt); elapsed > 0 {
		ac.autoTokens += elapsed.Seconds() * autoPerSec
		if ac.autoTokens > autoBurst {
			ac.autoTokens = autoBurst
		}
	}
	ac.autoAt = now
	if ac.autoTokens < 1 {
		return false
	}
	ac.autoTokens--
	return true
}

func (h *Hub) recordAutoAudit(ac *agentConn, target store.AutoTarget, in ingest.AutoAction) {
	hostName := ""
	if host, err := h.st.GetHost(ac.parent, ac.hostID); err == nil {
		hostName = host.Name
	}
	projectID := target.ProjectID
	hostID := ac.hostID
	result := in.Result
	row := store.AuditRow{
		Via:       audit.ViaAgent,
		ProjectID: &projectID,
		HostID:    &hostID,
		Action:    autoAuditActions[in.Action],
		Decision:  audit.DecisionAllowed,
		Result:    &result,
		Detail: map[string]any{
			"entry":     in.Entry,
			"host":      hostName,
			"container": ingest.RedactCmdline(in.Container),
			"reason":    in.Reason,
			"result":    in.Result,
			"t":         in.At.Format(time.RFC3339),
		},
	}
	if result == "error" {
		row.ErrorCode = &result
	}
	h.aud.Record(ac.parent, row)
}

func autoActionAck(id string) map[string]any {
	return map[string]any{
		"v":    1,
		"type": "auto_action_ack",
		"id":   id,
	}
}
