package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/authz"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/store"
)

type catalogBody struct {
	Name    string            `json:"name"`
	Kind    string            `json:"kind"`
	Command string            `json:"command"`
	Shell   bool              `json:"shell"`
	Dir     string            `json:"dir"`
	RunAs   string            `json:"run_as"`
	Env     map[string]string `json:"env"`
	Port    *int              `json:"port"`
	Restart string            `json:"restart"`
	Spec    json.RawMessage   `json:"spec"`
}

type catalogReplaceBody struct {
	Kind    string            `json:"kind"`
	Command string            `json:"command"`
	Shell   bool              `json:"shell"`
	Dir     string            `json:"dir"`
	RunAs   string            `json:"run_as"`
	Env     map[string]string `json:"env"`
	Port    *int              `json:"port"`
	Restart string            `json:"restart"`
	Spec    json.RawMessage   `json:"spec"`
}

func (s *Server) handleCatalogList(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapRead); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, "", err)
		return
	}
	role, err := s.Store.Role(r.Context(), id, p.User.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	entries, err := s.Store.ListCatalogEntries(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	items := []store.CatalogEntry{}
	for _, entry := range entries {
		grants, err := s.Store.ListCatalogGrants(r.Context(), entry.ID)
		if err != nil {
			s.fail(w, err)
			return
		}
		held := heldActions(entry.Kind, role, p.User.ID, grants)
		if len(held) == 0 {
			continue
		}
		entry.MyActions = myActions(held)
		items = append(items, entry)
	}
	writeOK(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleCatalogParse(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapProjectWrite); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, "", err)
		return
	}
	var body struct {
		Command string `json:"command"`
		Shell   bool   `json:"shell"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	split, err := catalog.Preview(body.Command, body.Shell)
	if err != nil {
		s.writeField(w, err)
		return
	}
	writeOK(w, http.StatusOK, map[string]any{
		"exec":            split.Exec,
		"args":            split.Args,
		"env":             split.Env,
		"command_display": split.Display,
	})
}

func (s *Server) handleCatalogCreate(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapProjectWrite); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, audit.ActionCatalogCreate, err)
		return
	}
	raw, ok := readLimited(w, r)
	if !ok {
		return
	}
	if s.rejectUnimplemented(w, raw) {
		return
	}
	var body catalogBody
	if !decodeRaw(w, raw, &body) {
		return
	}
	if body.Kind == "image" {
		if programFieldsSet(body.Command, body.Dir, body.RunAs, body.Restart, body.Shell, body.Env, body.Port) {
			writeCode(w, "bad_request", "invalid json")
			return
		}
		s.writeImage(w, r, p, id, body.Name, body.Spec, false)
		return
	}
	if specPresent(body.Spec) {
		writeCode(w, "bad_request", "invalid json")
		return
	}
	if body.Kind != "program" {
		writeCode(w, "bad_request", "kind must be program")
		return
	}
	if !catalog.ValidName(body.Name) {
		writeCode(w, "bad_request", "invalid name")
		return
	}
	prog, ok := s.buildProgram(w, body.Command, body.Shell, body.Dir, body.RunAs, body.Env, body.Port, body.Restart)
	if !ok {
		return
	}
	entry, err := s.Store.CreateCatalogEntry(r.Context(), id, store.CatalogWrite{
		Name:           body.Name,
		Spec:           specOf(prog),
		SpecHash:       catalog.SpecHash(prog),
		CommandDisplay: prog.Display,
		Actor:          p.User.ID,
		At:             s.now(),
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	entry.MyActions = myActions(heldActions(entry.Kind, authz.RoleOwner, p.User.ID, nil))
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(id),
		Action:    audit.ActionCatalogCreate,
		Detail:    map[string]any{"name": entry.Name, "spec_hash": entry.SpecHash},
	})
	writeOK(w, http.StatusCreated, entry)
}

func (s *Server) handleCatalogGet(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapRead); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, "", err)
		return
	}
	entry, _, ok := s.visibleEntry(w, r, p, id, r.PathValue("name"))
	if !ok {
		return
	}
	writeOK(w, http.StatusOK, entry)
}

func (s *Server) handleCatalogPut(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapProjectWrite); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, audit.ActionCatalogUpdate, err)
		return
	}
	name := r.PathValue("name")
	if !catalog.ValidName(name) {
		writeCode(w, "not_found", "not found")
		return
	}
	raw, ok := readLimited(w, r)
	if !ok {
		return
	}
	if s.rejectUnimplemented(w, raw) {
		return
	}
	var body catalogReplaceBody
	if !decodeRaw(w, raw, &body) {
		return
	}
	existing, err := s.Store.GetCatalogEntry(r.Context(), id, name)
	if err != nil {
		s.fail(w, err)
		return
	}
	if body.Kind != existing.Kind {
		writeCode(w, "bad_request", "kind must be "+existing.Kind)
		return
	}
	if existing.Kind == "image" {
		if programFieldsSet(body.Command, body.Dir, body.RunAs, body.Restart, body.Shell, body.Env, body.Port) {
			writeCode(w, "bad_request", "invalid json")
			return
		}
		s.writeImage(w, r, p, id, name, body.Spec, true)
		return
	}
	if specPresent(body.Spec) {
		writeCode(w, "bad_request", "invalid json")
		return
	}
	prog, ok := s.buildProgram(w, body.Command, body.Shell, body.Dir, body.RunAs, body.Env, body.Port, body.Restart)
	if !ok {
		return
	}
	old, entry, err := s.Store.ReplaceCatalogEntry(r.Context(), id, name, store.CatalogWrite{
		Spec:           specOf(prog),
		SpecHash:       catalog.SpecHash(prog),
		CommandDisplay: prog.Display,
		Actor:          p.User.ID,
		At:             s.now(),
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	entry.MyActions = myActions(heldActions(entry.Kind, authz.RoleOwner, p.User.ID, nil))
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(id),
		Action:    audit.ActionCatalogUpdate,
		Detail:    map[string]any{"name": entry.Name, "old_spec_hash": old, "spec_hash": entry.SpecHash},
	})
	writeOK(w, http.StatusOK, entry)
}

func (s *Server) handleCatalogDelete(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapProjectWrite); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, audit.ActionCatalogDelete, err)
		return
	}
	name := r.PathValue("name")
	if !catalog.ValidName(name) {
		writeCode(w, "not_found", "not found")
		return
	}
	entry, err := s.Store.DeleteCatalogEntry(r.Context(), id, name)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(id),
		Action:    audit.ActionCatalogDelete,
		Detail:    map[string]any{"name": entry.Name, "spec_hash": entry.SpecHash},
	})
	writeOK(w, http.StatusOK, nil)
}

func (s *Server) handleCatalogPermGet(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapProjectWrite); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, "", err)
		return
	}
	entry, err := s.catalogByName(r, id, r.PathValue("name"))
	if err != nil {
		s.fail(w, err)
		return
	}
	grants, err := s.Store.ListCatalogGrants(r.Context(), entry.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeOK(w, http.StatusOK, map[string]any{"grants": grants})
}

func (s *Server) handleCatalogPermPut(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapProjectWrite); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, audit.ActionCatalogPermissions, err)
		return
	}
	name := r.PathValue("name")
	entry, err := s.catalogByName(r, id, name)
	if err != nil {
		s.fail(w, err)
		return
	}
	var body struct {
		Grants []store.CatalogGrant `json:"grants"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	grants, msg, err := s.normalizeGrants(r, id, body.Grants)
	if err != nil {
		s.fail(w, err)
		return
	}
	if msg != "" {
		writeCode(w, "bad_request", msg)
		return
	}
	if err := s.Store.ReplaceCatalogGrants(r.Context(), id, name, grants); err != nil {
		s.fail(w, err)
		return
	}
	stored, err := s.Store.ListCatalogGrants(r.Context(), entry.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(id),
		Action:    audit.ActionCatalogPermissions,
		Detail:    map[string]any{"name": name},
	})
	writeOK(w, http.StatusOK, map[string]any{"grants": stored})
}

func (s *Server) handleCatalogApprovals(w http.ResponseWriter, r *http.Request) {
	p, host, ok := s.loadCatalogHost(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, host.ProjectID, authz.CapMembers); err != nil {
		s.deny(w, r, p, idPtr(host.ProjectID), idPtr(host.ID), nil, "", err)
		return
	}
	items, err := s.Store.ListCatalogApprovals(r.Context(), host.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeOK(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleCatalogApprove(w http.ResponseWriter, r *http.Request) {
	p, host, ok := s.loadCatalogHost(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, host.ProjectID, authz.CapMembers); err != nil {
		s.deny(w, r, p, idPtr(host.ProjectID), idPtr(host.ID), nil, audit.ActionCatalogApprove, err)
		return
	}
	var body struct {
		EntryID  string `json:"entry_id"`
		SpecHash string `json:"spec_hash"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	entryID, err := uuid.Parse(body.EntryID)
	if err != nil {
		writeCode(w, "bad_request", "invalid id")
		return
	}
	item, err := s.Store.ApproveCatalog(r.Context(), host.ID, entryID, body.SpecHash, p.User.ID, s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(host.ProjectID),
		HostID:    idPtr(host.ID),
		Action:    audit.ActionCatalogApprove,
		Detail:    map[string]any{"entry_id": entryID.String(), "spec_hash": body.SpecHash},
	})
	writeOK(w, http.StatusOK, item)
}

func (s *Server) handleCatalogApprovalDelete(w http.ResponseWriter, r *http.Request) {
	p, host, ok := s.loadCatalogHost(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, host.ProjectID, authz.CapMembers); err != nil {
		s.deny(w, r, p, idPtr(host.ProjectID), idPtr(host.ID), nil, audit.ActionCatalogApprovalRevoke, err)
		return
	}
	entryID, err := uuid.Parse(r.PathValue("entry_id"))
	if err != nil {
		writeCode(w, "bad_request", "invalid id")
		return
	}
	if err := s.Store.DeleteCatalogApproval(r.Context(), host.ID, entryID); err != nil {
		s.fail(w, err)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(host.ProjectID),
		HostID:    idPtr(host.ID),
		Action:    audit.ActionCatalogApprovalRevoke,
		Detail:    map[string]any{"entry_id": entryID.String()},
	})
	writeOK(w, http.StatusOK, nil)
}

func (s *Server) handleCatalogRun(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapRead); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, audit.ActionProgramRun, err)
		return
	}
	s.catalogAct(w, r, p, id, "run")
}

func (s *Server) handleCatalogStop(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapRead); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, audit.ActionProgramStop, err)
		return
	}
	s.catalogAct(w, r, p, id, "stop")
}

func (s *Server) handleCatalogRestart(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapRead); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, audit.ActionProgramRestart, err)
		return
	}
	s.catalogAct(w, r, p, id, "restart")
}

func (s *Server) handleCatalogLogs(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapRead); err != nil {
		s.writeAuth(w, err)
		return
	}
	s.catalogAct(w, r, p, id, "logs")
}

func (s *Server) handleCatalogStatus(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapRead); err != nil {
		s.writeAuth(w, err)
		return
	}
	s.catalogAct(w, r, p, id, "status")
}

func (s *Server) catalogProject(w http.ResponseWriter, r *http.Request) (principal, uuid.UUID, bool) {
	p, ok := s.require(w, r)
	if !ok {
		return principal{}, uuid.Nil, false
	}
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return principal{}, uuid.Nil, false
	}
	return p, id, true
}

func (s *Server) loadCatalogHost(w http.ResponseWriter, r *http.Request) (principal, store.Host, bool) {
	p, ok := s.require(w, r)
	if !ok {
		return principal{}, store.Host{}, false
	}
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return principal{}, store.Host{}, false
	}
	host, err := s.Store.GetHost(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return principal{}, store.Host{}, false
	}
	return p, host, true
}

func (s *Server) visibleEntry(w http.ResponseWriter, r *http.Request, p principal, projectID uuid.UUID, name string) (store.CatalogEntry, string, bool) {
	role, err := s.Store.Role(r.Context(), projectID, p.User.ID)
	if err != nil {
		s.fail(w, err)
		return store.CatalogEntry{}, "", false
	}
	entry, err := s.catalogByName(r, projectID, name)
	if err != nil {
		s.fail(w, err)
		return store.CatalogEntry{}, "", false
	}
	grants, err := s.Store.ListCatalogGrants(r.Context(), entry.ID)
	if err != nil {
		s.fail(w, err)
		return store.CatalogEntry{}, "", false
	}
	held := heldActions(entry.Kind, role, p.User.ID, grants)
	if len(held) == 0 {
		writeCode(w, "forbidden", "forbidden")
		return store.CatalogEntry{}, "", false
	}
	entry.MyActions = myActions(held)
	return entry, role, true
}

func (s *Server) catalogByName(r *http.Request, projectID uuid.UUID, name string) (store.CatalogEntry, error) {
	if !catalog.ValidName(name) {
		return store.CatalogEntry{}, store.ErrNotFound
	}
	return s.Store.GetCatalogEntry(r.Context(), projectID, name)
}

func (s *Server) buildProgram(w http.ResponseWriter, command string, shell bool, dir, runAs string, env map[string]string, port *int, restart string) (catalog.Program, bool) {
	prog, err := catalog.BuildProgram(catalog.ProgramInput{
		Command: command,
		Shell:   shell,
		Dir:     dir,
		RunAs:   runAs,
		Env:     env,
		Port:    port,
		Restart: restart,
	})
	if err != nil {
		s.writeField(w, err)
		return catalog.Program{}, false
	}
	return prog, true
}

func (s *Server) writeField(w http.ResponseWriter, err error) {
	var fe *catalog.FieldError
	if errors.As(err, &fe) {
		writeCode(w, fe.Code, fe.Msg)
		return
	}
	s.fail(w, err)
}

func (s *Server) writeAuth(w http.ResponseWriter, err error) {
	var denied *authz.Denied
	if errors.As(err, &denied) {
		writeCode(w, denied.Code, phrase(denied.Code))
		return
	}
	s.fail(w, err)
}

func (s *Server) rejectUnimplemented(w http.ResponseWriter, raw []byte) bool {
	err := peekUnimplemented(raw)
	if err == nil {
		return false
	}
	s.writeField(w, err)
	return true
}

func peekUnimplemented(raw []byte) error {
	var peek map[string]json.RawMessage
	if err := json.Unmarshal(raw, &peek); err != nil {
		return nil
	}
	_, secretEnv := peek["secret_env"]
	kind := ""
	if v, ok := peek["kind"]; ok {
		_ = json.Unmarshal(v, &kind)
	}
	return catalog.RejectKind(kind, secretEnv)
}

func readLimited(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	return readLimitedN(w, r, 1<<20)
}

func readLimitedN(w http.ResponseWriter, r *http.Request, n int64) ([]byte, bool) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, n))
	if err != nil {
		writeCode(w, "bad_request", "invalid json")
		return nil, false
	}
	return raw, true
}

func decodeRaw(w http.ResponseWriter, raw []byte, dst any) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeCode(w, "bad_request", "invalid json")
		return false
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		writeCode(w, "bad_request", "invalid json")
		return false
	}
	return true
}

func specOf(p catalog.Program) store.ProgramSpec {
	args := p.Args
	if args == nil {
		args = []string{}
	}
	env := p.Env
	if env == nil {
		env = map[string]string{}
	}
	return store.ProgramSpec{
		Dir: p.Dir, Exec: p.Exec, Args: args, Shell: p.Shell,
		RunAs: p.RunAs, Env: env, Port: p.Port, Restart: p.Restart,
	}
}

var grantActionOrder = []string{"run", "stop", "restart", "logs", "deploy"}

func heldActions(kind, role string, userID uuid.UUID, grants []store.CatalogGrant) map[string]bool {
	held := map[string]bool{}
	if role == authz.RoleOwner {
		admin, _ := store.DefaultGrantActions(kind)
		for _, action := range admin {
			held[action] = true
		}
		return held
	}
	for _, g := range grants {
		if g.Subject != "role:"+role && g.Subject != "user:"+userID.String() {
			continue
		}
		for _, action := range g.Actions {
			held[action] = true
		}
	}
	return held
}

func myActions(held map[string]bool) []string {
	if len(held) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(grantActionOrder)+1)
	for _, action := range grantActionOrder {
		if held[action] {
			out = append(out, action)
		}
	}
	out = append(out, "status")
	return out
}

func allowsAction(held map[string]bool, action string) bool {
	if action == "status" {
		return len(held) > 0
	}
	return held[action]
}

func (s *Server) normalizeGrants(r *http.Request, projectID uuid.UUID, grants []store.CatalogGrant) ([]store.CatalogGrant, string, error) {
	if grants == nil {
		return nil, "grants required", nil
	}
	if len(grants) > 100 {
		return nil, "too many grants", nil
	}
	seen := map[string]bool{}
	out := make([]store.CatalogGrant, 0, len(grants))
	for _, g := range grants {
		subject, msg, err := s.grantSubject(r, projectID, g.Subject)
		if err != nil || msg != "" {
			return nil, msg, err
		}
		if seen[subject] {
			return nil, "duplicate subject", nil
		}
		seen[subject] = true
		actions, msg := canonicalActions(g.Actions)
		if msg != "" {
			return nil, msg, nil
		}
		out = append(out, store.CatalogGrant{Subject: subject, Actions: actions})
	}
	return out, "", nil
}

func (s *Server) grantSubject(r *http.Request, projectID uuid.UUID, subject string) (string, string, error) {
	switch subject {
	case "role:admin", "role:viewer":
		return subject, "", nil
	}
	if !strings.HasPrefix(subject, "user:") {
		return "", "invalid subject", nil
	}
	id, err := uuid.Parse(strings.TrimPrefix(subject, "user:"))
	if err != nil {
		return "", "invalid subject", nil
	}
	role, err := s.Store.Role(r.Context(), projectID, id)
	if errors.Is(err, store.ErrNotFound) {
		return "", "subject is not a member", nil
	}
	if err != nil {
		return "", "", err
	}
	if role == authz.RoleOwner {
		return "", "owner cannot be a subject", nil
	}
	return "user:" + id.String(), "", nil
}

func canonicalActions(in []string) ([]string, string) {
	if len(in) == 0 || len(in) > 5 {
		return nil, "invalid actions"
	}
	have := map[string]bool{}
	for _, action := range in {
		if have[action] {
			return nil, "invalid actions"
		}
		switch action {
		case "run", "stop", "restart", "logs", "deploy":
			have[action] = true
		default:
			return nil, "invalid actions"
		}
	}
	out := make([]string, 0, len(have))
	for _, action := range grantActionOrder {
		if have[action] {
			out = append(out, action)
		}
	}
	return out, ""
}

func programFieldsSet(command, dir, runAs, restart string, shell bool, env map[string]string, port *int) bool {
	return command != "" || dir != "" || runAs != "" || restart != "" || shell || port != nil || len(env) > 0
}

func specPresent(raw json.RawMessage) bool {
	s := bytes.TrimSpace(raw)
	return len(s) > 0 && string(s) != "null"
}

func programAction(action string) string {
	switch action {
	case "run":
		return audit.ActionProgramRun
	case "stop":
		return audit.ActionProgramStop
	case "restart":
		return audit.ActionProgramRestart
	default:
		return ""
	}
}
