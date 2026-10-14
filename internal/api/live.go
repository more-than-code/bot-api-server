package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/agentws"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/authz"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	p, host, ok := s.fetchHost(w, r)
	if !ok {
		return
	}
	if _, ok := s.gateHost(w, r, p, host, authz.CapHostView, nil, nil, audit.ActionSnapshot); !ok {
		return
	}
	if s.Hub == nil {
		writeCode(w, "error", "internal error")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res, err := s.Hub.Snapshot(ctx, host)
	s.finishLive(w, r, p, host.ProjectID, host.ID, uuid.Nil, audit.ActionSnapshot, res, err)
}

func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) {
	p, svc, host, ok := s.fetchService(w, r)
	if !ok {
		return
	}
	if _, ok := s.gateHost(w, r, p, host, authz.CapServiceRead, &svc.ProjectID, idPtr(svc.ID), audit.ActionProbe); !ok {
		return
	}
	var body struct {
		CheckID  *string `json:"check_id"`
		Protocol *string `json:"protocol"`
		Port     *int    `json:"port"`
		Path     *string `json:"path"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	spec, msg, err := s.probeSpec(r, svc, body.CheckID, body.Protocol, body.Port, body.Path)
	if err != nil {
		s.fail(w, err)
		return
	}
	if msg != "" {
		if msg == "unknown check" {
			writeCode(w, "not_found", "unknown check")
			return
		}
		writeCode(w, "bad_request", msg)
		return
	}
	if s.Hub == nil {
		writeCode(w, "error", "internal error")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res, err := s.Hub.Probe(ctx, host, svc, spec)
	s.finishLive(w, r, p, host.ProjectID, host.ID, svc.ID, audit.ActionProbe, res, err)
}

func (s *Server) probeSpec(r *http.Request, svc store.Service, checkID, protocol *string, port *int, path *string) (map[string]any, string, error) {
	hasCheck := checkID != nil && *checkID != ""
	hasAdHoc := protocol != nil || port != nil || (path != nil && *path != "")
	if hasCheck == hasAdHoc {
		return nil, "invalid probe", nil
	}
	if hasCheck {
		id, err := uuid.Parse(*checkID)
		if err != nil {
			return nil, "invalid id", nil
		}
		checks, err := s.Store.ListHealthChecks(r.Context(), svc.ID)
		if err != nil {
			return nil, "", err
		}
		for _, c := range checks {
			if c.ID != id {
				continue
			}
			if !portOpen(svc.Ports, c.Port) {
				return nil, "port is not open on the service", nil
			}
			var p any
			if c.Path != nil {
				p = *c.Path
			}
			return map[string]any{
				"protocol":          c.Protocol,
				"port":              c.Port,
				"path":              p,
				"expect_status_min": c.ExpectStatusMin,
				"expect_status_max": c.ExpectStatusMax,
			}, "", nil
		}
		return nil, "unknown check", nil
	}
	item, msg := normalizeCheck(checkIn{Protocol: protocol, Port: port, Path: path}, svc.Ports)
	if msg != "" {
		return nil, msg, nil
	}
	var p any
	if item.Path != nil {
		p = *item.Path
	}
	return map[string]any{
		"protocol":          item.Protocol,
		"port":              item.Port,
		"path":              p,
		"expect_status_min": item.ExpectStatusMin,
		"expect_status_max": item.ExpectStatusMax,
	}, "", nil
}

func (s *Server) finishLive(w http.ResponseWriter, r *http.Request, p principal, projectID, hostID, serviceID uuid.UUID, action string, res agentws.LiveResult, err error) {
	row := store.AuditRow{
		ProjectID: idPtr(projectID),
		HostID:    idPtr(hostID),
		Action:    action,
		Decision:  audit.DecisionAllowed,
	}
	if serviceID != uuid.Nil {
		row.ServiceID = idPtr(serviceID)
	}
	if err != nil {
		var call *agentws.CallError
		if errors.As(err, &call) {
			row.Result = &call.Code
			row.ErrorCode = &call.Code
			s.auditOK(r.Context(), p, row)
			msg := call.Msg
			if msg == "" {
				msg = phrase(call.Code)
			}
			if call.Code == "error" && len(call.Payload) > 0 && json.Valid(call.Payload) && string(call.Payload) != "null" {
				write(w, statusFor(call.Code), call.Code, msg, jsonRaw{call.Payload})
				return
			}
			writeCode(w, call.Code, msg)
			return
		}
		s.fail(w, err)
		return
	}
	ok := "succeeded"
	row.Result = &ok
	if res.TaskID != uuid.Nil {
		row.TaskID = idPtr(res.TaskID)
	}
	s.auditOK(r.Context(), p, row)
	payload := res.Payload
	if len(payload) == 0 || !json.Valid(payload) {
		payload = []byte("null")
	}
	writeOK(w, http.StatusOK, jsonRaw{payload})
}

// jsonRaw embeds already-encoded JSON as the envelope payload.
type jsonRaw struct{ raw []byte }

func (j jsonRaw) MarshalJSON() ([]byte, error) {
	if len(j.raw) == 0 {
		return []byte("null"), nil
	}
	return j.raw, nil
}
