package api

import (
	"errors"
	"net/http"

	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/authz"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (s *Server) handleShareList(w http.ResponseWriter, r *http.Request) {
	p, host, ok := s.fetchHost(w, r)
	if !ok {
		return
	}
	if _, ok := s.gateHost(w, r, p, host, authz.CapHostAdmin, nil, nil, ""); !ok {
		return
	}
	items, err := s.Store.ListHostShares(r.Context(), host.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if items == nil {
		items = []store.HostShare{}
	}
	writeOK(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleSharePut(w http.ResponseWriter, r *http.Request) {
	p, host, ok := s.fetchHost(w, r)
	if !ok {
		return
	}
	target, ok := s.pathID(w, r, "project_id")
	if !ok {
		return
	}
	if _, ok := s.gateHost(w, r, p, host, authz.CapHostAdmin, nil, nil, audit.ActionHostShare); !ok {
		return
	}
	var body struct {
		Level *string `json:"level"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Level == nil || !store.ValidShareLevel(*body.Level) {
		writeCode(w, "bad_request", "invalid level")
		return
	}
	if target == host.ProjectID {
		writeCode(w, "bad_request", "cannot share with the owning project")
		return
	}
	if _, err := s.Store.Role(r.Context(), target, p.User.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeCode(w, "not_found", "not found")
			return
		}
		s.fail(w, err)
		return
	}
	share, created, err := s.Store.PutHostShare(r.Context(), host.ID, target, *body.Level, p.User.ID, s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	action := audit.ActionHostShare
	if !created {
		action = audit.ActionHostShareUpdate
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(host.ProjectID),
		HostID:    idPtr(host.ID),
		Action:    action,
		Detail: map[string]any{
			"project_id":   share.ProjectID.String(),
			"project_name": share.ProjectName,
			"level":        share.Level,
		},
	})
	writeOK(w, http.StatusOK, share)
}

func (s *Server) handleShareDelete(w http.ResponseWriter, r *http.Request) {
	p, host, ok := s.fetchHost(w, r)
	if !ok {
		return
	}
	target, ok := s.pathID(w, r, "project_id")
	if !ok {
		return
	}
	rel, err := authz.HostRelation(r.Context(), p.User.ID, host.ID)
	if err != nil {
		var denied *authz.Denied
		if errors.As(err, &denied) {
			s.deny(w, r, p, idPtr(host.ProjectID), idPtr(host.ID), nil, audit.ActionHostUnshare, err)
			return
		}
		if errors.Is(err, store.ErrNotFound) {
			writeCode(w, "not_found", "not found")
			return
		}
		s.fail(w, err)
		return
	}
	targetRole := ""
	targetMember := false
	role, err := s.Store.Role(r.Context(), target, p.User.ID)
	if err == nil {
		targetRole = role
		targetMember = true
	} else if !errors.Is(err, store.ErrNotFound) {
		s.fail(w, err)
		return
	}
	if err := authz.AuthorizeUnshare(rel, target, targetRole, targetMember); err != nil {
		s.deny(w, r, p, idPtr(host.ProjectID), idPtr(host.ID), nil, audit.ActionHostUnshare, err)
		return
	}
	reassign, ok := reassignOwner(w, r)
	if !ok {
		return
	}
	removed, err := s.Store.DeleteHostShare(r.Context(), host.ID, target, reassign)
	if err != nil {
		s.fail(w, err)
		return
	}
	detail := map[string]any{
		"project_id":   removed.ProjectID.String(),
		"project_name": removed.ProjectName,
		"level":        removed.Level,
	}
	if reassign {
		detail["reassign"] = "owner"
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(host.ProjectID),
		HostID:    idPtr(host.ID),
		Action:    audit.ActionHostUnshare,
		Detail:    detail,
	})
	writeOK(w, http.StatusOK, nil)
}

func reassignOwner(w http.ResponseWriter, r *http.Request) (bool, bool) {
	switch r.URL.Query().Get("reassign") {
	case "":
		return false, true
	case "owner":
		return true, true
	default:
		writeCode(w, "bad_request", "invalid reassign")
		return false, false
	}
}
