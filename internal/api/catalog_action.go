package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/agentws"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/authz"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/ingest"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const (
	reasonNoPrograms = "host does not allow programs"
	reasonDisabled   = "programs are disabled on this host"
	reasonRunAs      = "run_as is not allowed on this host"
	reasonShell      = "shell is not allowed on this host"
	reasonWaiting    = "waiting for the host owner's approval"
	reasonInProgress = "request in progress"
)

// catalogAct is checks 1–6 for run, stop, restart, logs, and status.
// Membership was already checked. JSON and host_id are rejected before the
// grant. The idempotency key and lines are checked after the grant. The
// idempotency row is claimed after the host is online and before any agent
// call or confirmation.
func (s *Server) catalogAct(w http.ResponseWriter, r *http.Request, p principal, projectID uuid.UUID, action string) {
	hostID, key, lines, ok := s.catalogBody(w, r, action)
	if !ok {
		return
	}
	role, err := s.Store.Role(r.Context(), projectID, p.User.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	entry, err := s.catalogByName(r, projectID, r.PathValue("name"))
	if err != nil {
		s.fail(w, err)
		return
	}
	grants, err := s.Store.ListCatalogGrants(r.Context(), entry.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	held := heldActions(role, p.User.ID, grants)
	if !allowsAction(held, action) {
		s.programDeny(w, r, p, projectID, hostID, entry.Name, action, "forbidden", "forbidden")
		return
	}
	if !actionInputOK(w, action, key, lines) {
		return
	}
	host, rel, ok := s.programHost(w, r, p, projectID, hostID, entry, action)
	if !ok {
		return
	}
	if rel == "deploy" {
		approved, err := s.approvalCurrent(r.Context(), entry, host.ID)
		if err != nil {
			s.fail(w, err)
			return
		}
		if !approved {
			if err := s.Store.UpsertPendingApproval(r.Context(), entry.ID, host.ID, entry.SpecHash, p.User.ID, s.now()); err != nil {
				s.fail(w, err)
				return
			}
			s.programDeny(w, r, p, projectID, host.ID, entry.Name, action, "forbidden", reasonWaiting)
			return
		}
	}
	if msg := policyReason(host, entry.Spec.RunAs, entry.Spec.Exec, entry.Spec.Shell); msg != "" {
		s.programDeny(w, r, p, projectID, host.ID, entry.Name, action, "forbidden", msg)
		return
	}
	if s.hostStatus(host) != "online" {
		s.programUnavailable(w, r, p, projectID, host.ID, entry, action)
		return
	}
	hash := programRequestHash(action, projectID, host.ID, entry.Name)
	if action == "run" || action == "stop" || action == "restart" {
		if !s.claimOrReplay(w, r, p.User.ID, key, hash) {
			return
		}
		if p.Session.Kind == store.KindDelegated {
			s.issueConfirmation(w, r, p, projectID, host, entry, action, key, hash)
			return
		}
	}
	s.performProgram(w, r, p, projectID, host, entry, action, lines, key, hash)
}

func (s *Server) handleConfirmation(w http.ResponseWriter, r *http.Request) {
	p, ok := s.require(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, uuid.Nil, authz.CapSession); err != nil {
		s.writeAuth(w, err)
		return
	}
	var body struct {
		Key string `json:"idempotency_key"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if !catalog.ValidIdempotencyKey(body.Key) {
		writeCode(w, "bad_request", "invalid idempotency_key")
		return
	}
	token := r.PathValue("confirmation_id")
	hash := secret.Hash(token)
	c, err := s.Store.GetConfirmation(r.Context(), hash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeCode(w, "not_found", "not found")
			return
		}
		s.fail(w, err)
		return
	}
	now := s.now()
	if c.UserID != p.User.ID || c.UsedAt != nil || !c.ExpiresAt.After(now) {
		writeCode(w, "not_found", "not found")
		return
	}
	if body.Key != c.IdempotencyKey {
		writeCode(w, "conflict", "conflict")
		return
	}
	role, err := s.Store.Role(r.Context(), c.ProjectID, p.User.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeCode(w, "not_found", "not found")
			return
		}
		s.fail(w, err)
		return
	}
	entry, err := s.Store.GetCatalogEntry(r.Context(), c.ProjectID, c.EntryName)
	if err != nil {
		s.fail(w, err)
		return
	}
	grants, err := s.Store.ListCatalogGrants(r.Context(), entry.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if entry.ID != c.EntryID || !allowsAction(heldActions(role, p.User.ID, grants), c.Action) {
		s.programDeny(w, r, p, c.ProjectID, c.HostID, entry.Name, c.Action, "forbidden", "forbidden")
		return
	}
	host, rel, ok := s.programHost(w, r, p, c.ProjectID, c.HostID, entry, c.Action)
	if !ok {
		return
	}
	if rel == "deploy" {
		approved, err := s.approvalCurrent(r.Context(), entry, host.ID)
		if err != nil {
			s.fail(w, err)
			return
		}
		if !approved {
			if err := s.Store.UpsertPendingApproval(r.Context(), entry.ID, host.ID, entry.SpecHash, p.User.ID, now); err != nil {
				s.fail(w, err)
				return
			}
			s.programDeny(w, r, p, c.ProjectID, host.ID, entry.Name, c.Action, "forbidden", reasonWaiting)
			return
		}
	}
	if msg := policyReason(host, entry.Spec.RunAs, entry.Spec.Exec, entry.Spec.Shell); msg != "" {
		s.programDeny(w, r, p, c.ProjectID, host.ID, entry.Name, c.Action, "forbidden", msg)
		return
	}
	if s.hostStatus(host) != "online" {
		s.programUnavailable(w, r, p, c.ProjectID, host.ID, entry, c.Action)
		return
	}
	if entry.SpecHash != c.SpecHash {
		writeCode(w, "conflict", "conflict")
		return
	}
	if err := s.Store.MarkConfirmationUsed(r.Context(), hash, p.User.ID, now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeCode(w, "not_found", "not found")
			return
		}
		s.fail(w, err)
		return
	}
	s.performProgram(w, r, p, c.ProjectID, host, entry, c.Action, 0, c.IdempotencyKey, c.RequestHash)
}

func (s *Server) catalogBody(w http.ResponseWriter, r *http.Request, action string) (uuid.UUID, string, int, bool) {
	switch action {
	case "logs":
		var body struct {
			HostID string `json:"host_id"`
			Lines  *int   `json:"lines"`
		}
		if !decodeJSON(w, r, &body) {
			return uuid.Nil, "", 0, false
		}
		id, ok := parseHostID(w, body.HostID)
		if !ok {
			return uuid.Nil, "", 0, false
		}
		lines := 200
		if body.Lines != nil {
			lines = *body.Lines
		}
		return id, "", lines, true
	case "status":
		var body struct {
			HostID string `json:"host_id"`
		}
		if !decodeJSON(w, r, &body) {
			return uuid.Nil, "", 0, false
		}
		id, ok := parseHostID(w, body.HostID)
		if !ok {
			return uuid.Nil, "", 0, false
		}
		return id, "", 0, true
	default:
		var body struct {
			HostID string `json:"host_id"`
			Key    string `json:"idempotency_key"`
		}
		if !decodeJSON(w, r, &body) {
			return uuid.Nil, "", 0, false
		}
		id, ok := parseHostID(w, body.HostID)
		if !ok {
			return uuid.Nil, "", 0, false
		}
		return id, body.Key, 0, true
	}
}

func actionInputOK(w http.ResponseWriter, action, key string, lines int) bool {
	switch action {
	case "logs":
		if lines < 1 || lines > 1000 {
			writeCode(w, "bad_request", "invalid lines")
			return false
		}
	case "status":
	default:
		if !catalog.ValidIdempotencyKey(key) {
			writeCode(w, "bad_request", "invalid idempotency_key")
			return false
		}
	}
	return true
}

func parseHostID(w http.ResponseWriter, raw string) (uuid.UUID, bool) {
	id, err := uuid.Parse(raw)
	if err != nil {
		writeCode(w, "bad_request", "invalid id")
		return uuid.Nil, false
	}
	return id, true
}

func (s *Server) programHost(w http.ResponseWriter, r *http.Request, p principal, projectID, hostID uuid.UUID, entry store.CatalogEntry, action string) (store.Host, string, bool) {
	rel, err := s.Store.HostProjectRelation(r.Context(), projectID, hostID)
	if err != nil {
		s.fail(w, err)
		return store.Host{}, "", false
	}
	if rel == "" {
		writeCode(w, "not_found", "not found")
		return store.Host{}, "", false
	}
	if rel == "metrics" {
		s.programDeny(w, r, p, projectID, hostID, entry.Name, action, "forbidden", "forbidden")
		return store.Host{}, "", false
	}
	host, err := s.Store.GetHost(r.Context(), hostID)
	if err != nil {
		s.fail(w, err)
		return store.Host{}, "", false
	}
	return host, rel, true
}

func (s *Server) approvalCurrent(ctx context.Context, entry store.CatalogEntry, hostID uuid.UUID) (bool, error) {
	items, err := s.Store.ListCatalogApprovals(ctx, hostID)
	if err != nil {
		return false, err
	}
	for _, item := range items {
		if item.EntryID == entry.ID && item.Status == "approved" && item.SpecHash == entry.SpecHash {
			return true, nil
		}
	}
	return false, nil
}

func policyReason(host store.Host, runAs, exec string, shell bool) string {
	if host.Programs == nil {
		return reasonNoPrograms
	}
	if !host.Programs.Enabled {
		return reasonDisabled
	}
	found := false
	for _, name := range host.Programs.RunAs {
		if name == runAs {
			found = true
			break
		}
	}
	if !found {
		return reasonRunAs
	}
	if !host.Programs.AllowShell && (shell || shellExec(exec)) {
		return reasonShell
	}
	return ""
}

func shellExec(exec string) bool {
	base := exec
	if i := strings.LastIndex(exec, "/"); i >= 0 {
		base = exec[i+1:]
	}
	switch base {
	case "sh", "bash", "dash":
		return true
	default:
		return false
	}
}

// claimOrReplay reserves the idempotency key. false means the response was
// already written: a replay, a conflict, or an in-progress claim.
func (s *Server) claimOrReplay(w http.ResponseWriter, r *http.Request, userID uuid.UUID, key string, hash []byte) bool {
	rec, claimed, err := s.Store.ClaimIdempotency(r.Context(), userID, key, hash, s.now().UTC())
	if errors.Is(err, store.ErrPending) {
		writeCode(w, "conflict", reasonInProgress)
		return false
	}
	if errors.Is(err, store.ErrConflict) {
		writeCode(w, "conflict", "conflict")
		return false
	}
	if err != nil {
		s.fail(w, err)
		return false
	}
	if !claimed {
		writeJSON(w, rec.Status, rec.Body)
		return false
	}
	return true
}

func (s *Server) issueConfirmation(w http.ResponseWriter, r *http.Request, p principal, projectID uuid.UUID, host store.Host, entry store.CatalogEntry, action, key string, hash []byte) {
	plain, tokenHash, err := secret.NewToken()
	if err != nil {
		s.failClaimed(w, r, p.User.ID, key, err)
		return
	}
	now := s.now().UTC()
	expires := now.Add(store.ConfirmationTTL)
	if err := s.Store.PutConfirmation(r.Context(), tokenHash, store.CatalogConfirmation{
		UserID:         p.User.ID,
		ProjectID:      projectID,
		EntryID:        entry.ID,
		EntryName:      entry.Name,
		HostID:         host.ID,
		Action:         action,
		SpecHash:       entry.SpecHash,
		IdempotencyKey: key,
		RequestHash:    hash,
		CreatedAt:      now,
		ExpiresAt:      expires,
	}); err != nil {
		s.failClaimed(w, r, p.User.ID, key, err)
		return
	}
	payload := map[string]any{
		"confirmation_id": plain,
		"plan":            programPlan(action, entry.Name, entry.CommandDisplay, entry.Spec.RunAs, host.Name),
		"expires_at":      expires.Format(time.RFC3339),
	}
	body := envelopeRaw("ok", "ok", payload)
	s.finishIdempotency(r.Context(), p.User.ID, key, http.StatusAccepted, body)
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(projectID),
		HostID:    idPtr(host.ID),
		Action:    audit.ActionProgramConfirmation,
		Detail:    map[string]any{"entry": entry.Name, "action": action, "spec_hash": entry.SpecHash},
	})
	writeJSON(w, http.StatusAccepted, body)
}

func (s *Server) performProgram(w http.ResponseWriter, r *http.Request, p principal, projectID uuid.UUID, host store.Host, entry store.CatalogEntry, action string, lines int, key string, _ []byte) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res, callErr := s.dispatchProgram(ctx, projectID, host, entry, action, lines)
	var taskID *uuid.UUID
	if callErr == nil && res.TaskID != uuid.Nil {
		taskID = idPtr(res.TaskID)
	}
	status, body, _ := liveEnvelope(res, callErr)
	if key != "" {
		s.finishIdempotency(r.Context(), p.User.ID, key, status, body)
	}
	s.programOutcome(w, r, p, projectID, host.ID, entry, action, status, body, taskID, callErr)
}

func (s *Server) finishIdempotency(ctx context.Context, userID uuid.UUID, key string, status int, body []byte) {
	if err := s.Store.ReplaceIdempotencyResponse(ctx, userID, key, status, body); err != nil {
		s.logErr(err)
	}
}

func (s *Server) failClaimed(w http.ResponseWriter, r *http.Request, userID uuid.UUID, key string, err error) {
	status, body, _ := liveEnvelope(agentws.LiveResult{}, err)
	s.finishIdempotency(r.Context(), userID, key, status, body)
	writeJSON(w, status, body)
}

func (s *Server) dispatchProgram(ctx context.Context, projectID uuid.UUID, host store.Host, entry store.CatalogEntry, action string, lines int) (agentws.LiveResult, error) {
	if s.Hub == nil {
		return agentws.LiveResult{}, &agentws.CallError{Code: "error", Msg: "internal error"}
	}
	project, err := s.Store.GetProject(ctx, projectID)
	if err != nil {
		return agentws.LiveResult{}, err
	}
	kind, spec := programTask(project.Slug, entry, action, lines)
	return s.Hub.Program(ctx, host, kind, spec)
}

func programTask(slug string, entry store.CatalogEntry, action string, lines int) (string, map[string]any) {
	base := map[string]any{"project": slug, "entry": entry.Name}
	switch action {
	case "run":
		env := entry.Spec.Env
		if env == nil {
			env = map[string]string{}
		}
		args := entry.Spec.Args
		if args == nil {
			args = []string{}
		}
		return "program_start", map[string]any{
			"project": slug,
			"entry":   entry.Name,
			"dir":     entry.Spec.Dir,
			"exec":    entry.Spec.Exec,
			"args":    args,
			"shell":   entry.Spec.Shell,
			"run_as":  entry.Spec.RunAs,
			"env":     env,
			"restart": entry.Spec.Restart,
		}
	case "stop":
		return "program_stop", base
	case "restart":
		return "program_restart", base
	case "logs":
		out := map[string]any{"project": slug, "entry": entry.Name, "lines": lines}
		return "program_logs", out
	default:
		return "program_status", base
	}
}

// programUnavailable is the offline result. It is checked after policy and
// does not consume a confirmation.
func (s *Server) programUnavailable(w http.ResponseWriter, r *http.Request, p principal, projectID, hostID uuid.UUID, entry store.CatalogEntry, action string) {
	callErr := &agentws.CallError{Code: "unavailable", Msg: "host unavailable"}
	status, body, _ := liveEnvelope(agentws.LiveResult{}, callErr)
	s.programOutcome(w, r, p, projectID, hostID, entry, action, status, body, nil, callErr)
}

// programOutcome writes the task result that was already stored for
// idempotency. run, stop, and restart are audited. logs and status are not.
func (s *Server) programOutcome(w http.ResponseWriter, r *http.Request, p principal, projectID, hostID uuid.UUID, entry store.CatalogEntry, action string, status int, body []byte, taskID *uuid.UUID, callErr error) {
	if action == "run" || action == "stop" || action == "restart" {
		row := store.AuditRow{
			ProjectID: idPtr(projectID),
			HostID:    idPtr(hostID),
			Action:    programAction(action),
			Decision:  audit.DecisionAllowed,
			Detail:    map[string]any{"entry": entry.Name, "spec_hash": entry.SpecHash},
			TaskID:    taskID,
		}
		code := "ok"
		if callErr != nil {
			var call *agentws.CallError
			if errors.As(callErr, &call) {
				code = call.Code
			} else {
				code = "error"
			}
			row.Result = &code
			row.ErrorCode = &code
		} else {
			ok := "succeeded"
			row.Result = &ok
		}
		s.auditOK(r.Context(), p, row)
	}
	writeJSON(w, status, body)
}

func (s *Server) programDeny(w http.ResponseWriter, r *http.Request, p principal, projectID, hostID uuid.UUID, entryName, action, code, msg string) {
	if action == "run" || action == "stop" || action == "restart" {
		var host *uuid.UUID
		if hostID != uuid.Nil {
			host = idPtr(hostID)
		}
		result := code
		s.Audit.Record(r.Context(), store.AuditRow{
			ActorUserID: idPtr(p.User.ID),
			Via:         viaKind(p.Session.Kind),
			ProjectID:   idPtr(projectID),
			HostID:      host,
			Action:      programAction(action),
			Decision:    audit.DecisionDenied,
			Result:      &result,
			ErrorCode:   &result,
			Detail:      map[string]any{"reason": msg, "entry": entryName},
		})
	}
	writeCode(w, code, msg)
}

func programPlan(action, entry, display, runAs, host string) string {
	return fmt.Sprintf("will %s program %s (%s, as %s) on %s", action, entry, display, runAs, host)
}

func programRequestHash(action string, projectID, hostID uuid.UUID, entry string) []byte {
	raw := `{"action":` + jsonQuote(action) +
		`,"entry":` + jsonQuote(entry) +
		`,"host_id":` + jsonQuote(hostID.String()) +
		`,"project_id":` + jsonQuote(projectID.String()) + `}`
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

func jsonQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

func envelopeRaw(code, msg string, payload any) []byte {
	if msg == "" {
		msg = phrase(code)
	}
	raw, err := json.Marshal(envelope{Code: code, Msg: msg, Payload: payload})
	if err != nil {
		return []byte(`{"code":"error","msg":"internal error","payload":null}`)
	}
	return raw
}

func liveEnvelope(res agentws.LiveResult, err error) (int, []byte, string) {
	if err != nil {
		var call *agentws.CallError
		if errors.As(err, &call) {
			msg := call.Msg
			if msg == "" {
				msg = phrase(call.Code)
			}
			var payload any
			if call.Code == "error" && len(call.Payload) > 0 && json.Valid(call.Payload) && string(call.Payload) != "null" {
				payload = jsonRaw{redactProgramLines(call.Payload)}
			}
			return statusFor(call.Code), envelopeRaw(call.Code, msg, payload), call.Code
		}
		return http.StatusInternalServerError, envelopeRaw("error", "internal error", nil), "error"
	}
	payload := redactProgramLines(res.Payload)
	if len(payload) == 0 || !json.Valid(payload) {
		payload = []byte("null")
	}
	return http.StatusOK, envelopeRaw("ok", "ok", jsonRaw{payload}), "ok"
}

// redactProgramLines applies the v1.0.1 cmdline redactor to each journal
// line. Other fields are left as the agent sent them.
func redactProgramLines(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || !json.Valid(raw) {
		return raw
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	m, ok := v.(map[string]any)
	if !ok {
		return raw
	}
	lines, ok := m["lines"].([]any)
	if !ok {
		return raw
	}
	changed := false
	for i, item := range lines {
		s, ok := item.(string)
		if !ok {
			continue
		}
		next := ingest.RedactCmdline(s)
		if next != s {
			lines[i] = next
			changed = true
		}
	}
	if !changed {
		return raw
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}
