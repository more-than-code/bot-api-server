package api

import (
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/authz"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (s *Server) handleProjectCreate(w http.ResponseWriter, r *http.Request) {
	p, ok := s.require(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, uuid.Nil, authz.CapSession); err != nil {
		s.deny(w, r, p, nil, nil, nil, audit.ActionProjectCreate, err)
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	name, ok := cleanName(w, body.Name)
	if !ok {
		return
	}
	project, err := s.Store.CreateProject(r.Context(), p.User.ID, name, store.Slug(name), s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(project.ID),
		Action:    audit.ActionProjectCreate,
		Detail:    map[string]any{"slug": project.Slug},
	})
	writeOK(w, http.StatusCreated, project)
}

func (s *Server) handleProjectList(w http.ResponseWriter, r *http.Request) {
	p, ok := s.require(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, uuid.Nil, authz.CapSession); err != nil {
		s.deny(w, r, p, nil, nil, nil, "", err)
		return
	}
	limit, ok := s.limit(w, r)
	if !ok {
		return
	}
	cur, ok := s.cursor(w, r)
	if !ok {
		return
	}
	items, next, err := s.Store.ListProjects(r.Context(), p.User.ID, limit, cur)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeList(w, items, next)
}

func (s *Server) handleProjectGet(w http.ResponseWriter, r *http.Request) {
	p, ok := s.require(w, r)
	if !ok {
		return
	}
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapRead); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, "", err)
		return
	}
	project, err := s.Store.GetProject(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	role, err := s.Store.Role(r.Context(), id, p.User.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	project.Role = role
	writeOK(w, http.StatusOK, project)
}

func (s *Server) handleProjectPatch(w http.ResponseWriter, r *http.Request) {
	p, ok := s.require(w, r)
	if !ok {
		return
	}
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapProjectWrite); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, audit.ActionProjectRename, err)
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	name, ok := cleanName(w, body.Name)
	if !ok {
		return
	}
	project, err := s.Store.RenameProject(r.Context(), id, name)
	if err != nil {
		s.fail(w, err)
		return
	}
	project.Role = authz.RoleOwner
	s.auditOK(r.Context(), p, store.AuditRow{ProjectID: idPtr(id), Action: audit.ActionProjectRename})
	writeOK(w, http.StatusOK, project)
}

func (s *Server) handleProjectDelete(w http.ResponseWriter, r *http.Request) {
	p, ok := s.require(w, r)
	if !ok {
		return
	}
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapProjectWrite); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, audit.ActionProjectDelete, err)
		return
	}
	hosts, err := s.Store.DeleteProject(r.Context(), id, s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	if s.Hub != nil {
		for _, hostID := range hosts {
			s.Hub.CloseHost(hostID)
		}
	}
	s.auditOK(r.Context(), p, store.AuditRow{ProjectID: idPtr(id), Action: audit.ActionProjectDelete})
	for _, hostID := range hosts {
		hid := hostID
		s.auditOK(r.Context(), p, store.AuditRow{
			ProjectID: idPtr(id),
			HostID:    &hid,
			Action:    audit.ActionHostRevoke,
		})
	}
	writeOK(w, http.StatusOK, nil)
}

func (s *Server) handleMemberList(w http.ResponseWriter, r *http.Request) {
	p, ok := s.require(w, r)
	if !ok {
		return
	}
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapRead); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, "", err)
		return
	}
	limit, ok := s.limit(w, r)
	if !ok {
		return
	}
	cur, ok := s.cursor(w, r)
	if !ok {
		return
	}
	items, next, err := s.Store.ListMembers(r.Context(), id, limit, cur)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeList(w, items, next)
}

func (s *Server) handleMemberAdd(w http.ResponseWriter, r *http.Request) {
	p, ok := s.require(w, r)
	if !ok {
		return
	}
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapMembers); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, audit.ActionMemberAdd, err)
		return
	}
	var body struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(body.Email))
	if email == "" || len(email) > 320 || strings.ContainsAny(email, " \t\r\n") {
		writeCode(w, "bad_request", "invalid email")
		return
	}
	if body.Role != authz.RoleAdmin && body.Role != authz.RoleViewer {
		writeCode(w, "bad_request", "invalid role")
		return
	}
	user, err := s.Store.UserByEmail(r.Context(), email)
	if err != nil {
		s.fail(w, err)
		return
	}
	member, err := s.Store.AddMember(r.Context(), id, user.ID, body.Role, p.User.ID, s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(id),
		Action:    audit.ActionMemberAdd,
		Detail:    map[string]any{"user_id": user.ID.String(), "role": body.Role},
	})
	writeOK(w, http.StatusCreated, member)
}

func (s *Server) handleMemberPatch(w http.ResponseWriter, r *http.Request) {
	p, ok := s.require(w, r)
	if !ok {
		return
	}
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	userID, ok := s.pathID(w, r, "user_id")
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapMembers); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, audit.ActionMemberUpdate, err)
		return
	}
	var body struct {
		Role string `json:"role"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Role != authz.RoleAdmin && body.Role != authz.RoleViewer {
		writeCode(w, "bad_request", "invalid role")
		return
	}
	member, err := s.Store.UpdateMemberRole(r.Context(), id, userID, body.Role)
	if err != nil {
		s.ownerErr(w, r, p, idPtr(id), audit.ActionMemberUpdate, err)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(id),
		Action:    audit.ActionMemberUpdate,
		Detail:    map[string]any{"user_id": userID.String(), "role": body.Role},
	})
	writeOK(w, http.StatusOK, member)
}

func (s *Server) handleMemberDelete(w http.ResponseWriter, r *http.Request) {
	p, ok := s.require(w, r)
	if !ok {
		return
	}
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	userID, ok := s.pathID(w, r, "user_id")
	if !ok {
		return
	}
	err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapMembers)
	if err != nil && userID == p.User.ID {
		err = authz.Authorize(r.Context(), p.User.ID, id, authz.CapRead)
	}
	if err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, audit.ActionMemberRemove, err)
		return
	}
	if err := s.Store.RemoveMember(r.Context(), id, userID); err != nil {
		s.ownerErr(w, r, p, idPtr(id), audit.ActionMemberRemove, err)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(id),
		Action:    audit.ActionMemberRemove,
		Detail:    map[string]any{"user_id": userID.String()},
	})
	writeOK(w, http.StatusOK, nil)
}

func (s *Server) handleTransfer(w http.ResponseWriter, r *http.Request) {
	p, ok := s.require(w, r)
	if !ok {
		return
	}
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapProjectWrite); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, audit.ActionProjectTransfer, err)
		return
	}
	var body struct {
		UserID string `json:"user_id"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	userID, err := uuid.Parse(body.UserID)
	if err != nil {
		writeCode(w, "bad_request", "invalid id")
		return
	}
	if err := s.Store.TransferOwnership(r.Context(), id, userID); err != nil {
		s.fail(w, err)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(id),
		Action:    audit.ActionProjectTransfer,
		Detail:    map[string]any{"user_id": userID.String()},
	})
	writeOK(w, http.StatusOK, nil)
}

func cleanName(w http.ResponseWriter, name string) (string, bool) {
	name = strings.TrimSpace(name)
	if !store.ValidName(name) || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		writeCode(w, "bad_request", "invalid name")
		return "", false
	}
	if utf8.RuneCountInString(name) < 1 {
		writeCode(w, "bad_request", "invalid name")
		return "", false
	}
	return name, true
}
