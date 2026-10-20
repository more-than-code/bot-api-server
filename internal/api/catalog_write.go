package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/authz"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const programEntriesConsole = "program entries are edited in the console"

// imageSpecForBuild drops the zero field that SpecJSON always writes for the
// other kind. BuildImage treats a present timeout_sec as set, and a service
// rejects that, including 0. A job rejects a present healthy_after_sec.
// The stored body keeps both keys. Confirm removes only that zero before
// validating again.
func imageSpecForBuild(body []byte) []byte {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		return body
	}
	var kind string
	if raw, ok := fields["kind"]; ok {
		if json.Unmarshal(raw, &kind) != nil {
			return body
		}
	}
	switch kind {
	case "service":
		if bytes.Equal(bytes.TrimSpace(fields["timeout_sec"]), []byte("0")) {
			delete(fields, "timeout_sec")
		}
	case "job":
		if bytes.Equal(bytes.TrimSpace(fields["healthy_after_sec"]), []byte("0")) {
			delete(fields, "healthy_after_sec")
		}
	}
	out, err := json.Marshal(fields)
	if err != nil {
		return body
	}
	return out
}

func digestMap(names map[string][]string, img catalog.Image) map[string]string {
	digests := map[string]string{}
	for _, set := range catalog.ReferencedSets(img) {
		digests[set] = catalog.EnvKeyDigest(names[set])
	}
	return digests
}

// catalogWriteRequestHash binds the action, project, entry name, and
// normalized spec. Delete uses spec null. The idempotency key and the
// base spec hash are not part of the hash.
func catalogWriteRequestHash(action string, projectID uuid.UUID, name string, spec []byte) []byte {
	specJSON := "null"
	if action != "delete" && len(spec) > 0 {
		specJSON = string(spec)
	}
	raw := `{"action":` + jsonQuote(action) +
		`,"name":` + jsonQuote(name) +
		`,"project_id":` + jsonQuote(projectID.String()) +
		`,"spec":` + specJSON + `}`
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

func (s *Server) refuseDelegated(w http.ResponseWriter, r *http.Request, p principal, projectID, hostID *uuid.UUID, action string) bool {
	if p.Session.Kind != store.KindDelegated {
		return false
	}
	s.auditDelegatedDenial(r, p, projectID, hostID, action)
	writeCode(w, "forbidden", "forbidden")
	return true
}

func (s *Server) forbidProgram(w http.ResponseWriter, r *http.Request, p principal, projectID uuid.UUID, action string) {
	s.auditDelegatedDenial(r, p, idPtr(projectID), nil, action)
	writeCode(w, "forbidden", programEntriesConsole)
}

func (s *Server) auditDelegatedDenial(r *http.Request, p principal, projectID, hostID *uuid.UUID, action string) {
	code := "forbidden"
	s.Audit.Record(r.Context(), store.AuditRow{
		ActorUserID: idPtr(p.User.ID),
		Via:         audit.ViaMCP,
		ProjectID:   projectID,
		HostID:      hostID,
		Action:      action,
		Decision:    audit.DecisionDenied,
		ErrorCode:   &code,
	})
}

// issueCatalogImage validates the idempotency key and stores a plan.
// The image was already built. Nothing is written to the catalog.
func (s *Server) issueCatalogImage(w http.ResponseWriter, r *http.Request, p principal, projectID uuid.UUID, name string, img catalog.Image, hash, key string, replace bool) {
	action := "create"
	var base string
	var oldImg catalog.Image
	voids := 0
	if replace {
		action = "update"
		existing, err := s.Store.GetCatalogEntry(r.Context(), projectID, name)
		if err != nil {
			s.fail(w, err)
			return
		}
		if existing.Kind != "image" {
			s.forbidProgram(w, r, p, projectID, audit.ActionCatalogUpdate)
			return
		}
		parsed, err := catalog.ParseStored(existing.ImageRaw)
		if err != nil {
			s.fail(w, err)
			return
		}
		oldImg = parsed
		base = existing.SpecHash
		if hash != existing.SpecHash {
			voids, err = s.Store.CountEntryApprovals(r.Context(), projectID, name)
			if err != nil {
				s.fail(w, err)
				return
			}
		}
	} else {
		_, err := s.Store.GetCatalogEntry(r.Context(), projectID, name)
		if err == nil {
			// Confirm already created the entry. The same key replays the
			// stored response. A key that was never claimed stays free.
			reqHash := catalogWriteRequestHash("create", projectID, name, []byte(catalog.SpecJSON(img)))
			if s.replayStoredIdempotency(w, r, p.User.ID, key, reqHash) {
				return
			}
			writeCode(w, "conflict", "conflict")
			return
		}
		if !errors.Is(err, store.ErrNotFound) {
			s.fail(w, err)
			return
		}
	}
	if !catalog.ValidIdempotencyKey(key) {
		writeCode(w, "bad_request", "invalid idempotency_key")
		return
	}
	spec := []byte(catalog.SpecJSON(img))
	var plan string
	if replace {
		plan = catalogUpdatePlan(name, oldImg, img, voids)
	} else {
		project, err := s.Store.GetProject(r.Context(), projectID)
		if err != nil {
			s.fail(w, err)
			return
		}
		plan = catalogCreatePlan(project.Name, name, img)
	}
	reqHash := catalogWriteRequestHash(action, projectID, name, spec)
	if !s.claimOrReplay(w, r, p.User.ID, key, reqHash) {
		return
	}
	s.storeCatalogWritePlan(w, r, p, projectID, action, name, base, spec, key, reqHash, plan)
}

func (s *Server) issueCatalogDelete(w http.ResponseWriter, r *http.Request, p principal, projectID uuid.UUID, name string) {
	entry, err := s.Store.GetCatalogEntry(r.Context(), projectID, name)
	if errors.Is(err, store.ErrNotFound) {
		// Confirm already removed the entry. Replay only when this key
		// already holds the delete. An unknown name claims nothing, and a
		// missing or invalid body stays not_found.
		if s.replayDeletedCatalogWrite(w, r, p.User.ID, projectID, name) {
			return
		}
		s.fail(w, err)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if entry.Kind != "image" {
		s.forbidProgram(w, r, p, projectID, audit.ActionCatalogDelete)
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
	n, err := s.Store.CountEntryApprovals(r.Context(), projectID, name)
	if err != nil {
		s.fail(w, err)
		return
	}
	plan := catalogDeletePlan(entry.Name, n)
	reqHash := catalogWriteRequestHash("delete", projectID, name, nil)
	if !s.claimOrReplay(w, r, p.User.ID, body.Key, reqHash) {
		return
	}
	s.storeCatalogWritePlan(w, r, p, projectID, "delete", entry.Name, entry.SpecHash, nil, body.Key, reqHash, plan)
}

// replayStoredIdempotency writes a response that this key already stored.
// It does not claim. false means the key is invalid or has no record, so
// the caller keeps its own status and still does not claim.
func (s *Server) replayStoredIdempotency(w http.ResponseWriter, r *http.Request, userID uuid.UUID, key string, hash []byte) bool {
	if !catalog.ValidIdempotencyKey(key) {
		return false
	}
	rec, err := s.Store.GetIdempotency(r.Context(), userID, key, s.now().UTC())
	if errors.Is(err, store.ErrNotFound) {
		return false
	}
	if err != nil {
		s.fail(w, err)
		return true
	}
	if rec.Pending {
		writeCode(w, "conflict", reasonInProgress)
		return true
	}
	if !secret.Equal(rec.RequestHash, hash) {
		writeCode(w, "conflict", "conflict")
		return true
	}
	writeJSON(w, rec.Status, rec.Body)
	return true
}

// replayDeletedCatalogWrite reads a delete body without reporting a decode
// error. A bad body on a missing name is not_found, not bad_request.
func (s *Server) replayDeletedCatalogWrite(w http.ResponseWriter, r *http.Request, userID, projectID uuid.UUID, name string) bool {
	key, ok := idempotencyKeyQuiet(r)
	if !ok {
		return false
	}
	return s.replayStoredIdempotency(w, r, userID, key, catalogWriteRequestHash("delete", projectID, name, nil))
}

func idempotencyKeyQuiet(r *http.Request) (string, bool) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return "", false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var body struct {
		Key string `json:"idempotency_key"`
	}
	if err := dec.Decode(&body); err != nil {
		return "", false
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		return "", false
	}
	if !catalog.ValidIdempotencyKey(body.Key) {
		return "", false
	}
	return body.Key, true
}

func (s *Server) storeCatalogWritePlan(w http.ResponseWriter, r *http.Request, p principal, projectID uuid.UUID, action, name, base string, spec []byte, key string, reqHash []byte, plan string) {
	plain, tokenHash, err := secret.NewToken()
	if err != nil {
		s.failClaimed(w, r, p.User.ID, key, err)
		return
	}
	now := s.now().UTC()
	expires := now.Add(store.ConfirmationTTL)
	row := store.CatalogWriteConfirmation{
		UserID: p.User.ID, ProjectID: projectID, Action: action, EntryName: name,
		BaseSpecHash: base, Body: spec, RequestHash: reqHash, IdempotencyKey: key,
		CreatedAt: now, ExpiresAt: expires,
	}
	if err := s.Store.PutCatalogWriteConfirmation(r.Context(), tokenHash, row); err != nil {
		s.failClaimed(w, r, p.User.ID, key, err)
		return
	}
	payload := map[string]any{
		"confirmation_id": plain,
		"plan":            plan,
		"expires_at":      expires.Format(time.RFC3339),
	}
	body := envelopeRaw("ok", "ok", payload)
	s.finishIdempotency(r.Context(), p.User.ID, key, http.StatusAccepted, body)
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(projectID),
		Action:    audit.ActionCatalogWriteConfirmation,
		Detail:    map[string]any{"action": action, "name": name},
	})
	writeJSON(w, http.StatusAccepted, body)
}

// confirmCatalogWrite runs when the id is neither a catalog action nor a
// health-check confirmation. The name or spec_hash check, the mark, and
// the catalog write commit together. A conflict leaves the plan unused.
func (s *Server) confirmCatalogWrite(w http.ResponseWriter, r *http.Request, p principal, hash []byte, key string) {
	c, err := s.Store.GetCatalogWriteConfirmation(r.Context(), hash)
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
	if key != c.IdempotencyKey {
		writeCode(w, "conflict", "idempotency_key does not match the request that issued this confirmation")
		return
	}
	auditAction := audit.ActionCatalogCreate
	switch c.Action {
	case "update":
		auditAction = audit.ActionCatalogUpdate
	case "delete":
		auditAction = audit.ActionCatalogDelete
	}
	if err := authz.Authorize(r.Context(), p.User.ID, c.ProjectID, authz.CapProjectWrite); err != nil {
		s.deny(w, r, p, idPtr(c.ProjectID), nil, nil, auditAction, err)
		return
	}
	in := store.CatalogWrite{Name: c.EntryName, Actor: p.User.ID, At: now}
	if c.Action != "delete" {
		built, err := s.rebuildCatalogWrite(r.Context(), c.ProjectID, c.EntryName, c.Body, p.User.ID, now)
		if err != nil {
			s.writeField(w, err)
			return
		}
		in = built
	}
	old, entry, err := s.Store.CommitCatalogWrite(r.Context(), hash, p.User.ID, now, in)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			writeCode(w, "conflict", "conflict")
		case errors.Is(err, store.ErrNotFound):
			writeCode(w, "not_found", "not found")
		default:
			s.fail(w, err)
		}
		return
	}
	status := http.StatusOK
	var payload any
	detail := map[string]any{"name": entry.Name, "spec_hash": entry.SpecHash}
	switch c.Action {
	case "create":
		status = http.StatusCreated
		entry.MyActions = myActions(heldActions(entry.Kind, authz.RoleOwner, p.User.ID, nil))
		payload = entry
	case "update":
		entry.MyActions = myActions(heldActions(entry.Kind, authz.RoleOwner, p.User.ID, nil))
		payload = entry
		detail["old_spec_hash"] = old
	default:
		payload = nil
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(c.ProjectID), Action: auditAction, Via: audit.ViaMCP, Detail: detail,
	})
	body := envelopeRaw("ok", "ok", payload)
	s.finishIdempotency(r.Context(), p.User.ID, c.IdempotencyKey, status, body)
	writeJSON(w, status, body)
}

func (s *Server) rebuildCatalogWrite(ctx context.Context, projectID uuid.UUID, name string, body []byte, actor uuid.UUID, at time.Time) (store.CatalogWrite, error) {
	names, err := s.Store.ListEnvKeyNames(ctx, projectID)
	if err != nil {
		return store.CatalogWrite{}, err
	}
	if names == nil {
		names = map[string][]string{}
	}
	known, err := s.projectFileNames(ctx, projectID)
	if err != nil {
		return store.CatalogWrite{}, err
	}
	img, err := catalog.BuildImage(name, imageSpecForBuild(body), names, known)
	if err != nil {
		return store.CatalogWrite{}, err
	}
	return store.CatalogWrite{
		Name: name, Kind: "image", ImageRaw: json.RawMessage(catalog.SpecJSON(img)),
		SpecHash: catalog.ImageHash(img, digestMap(names, img)), CommandDisplay: img.Image,
		Actor: actor, At: at,
	}, nil
}
