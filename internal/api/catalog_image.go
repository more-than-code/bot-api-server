package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/agentws"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/authz"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/ingest"
	"github.com/more-than-code/bot-api-server/internal/seal"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const (
	reasonNoContainers = "this host does not run containers"
	invalidAgentResult = "invalid agent result"
	settleTimeout      = 5 * time.Second
	staleGraceSec      = 120
	maxAgentLines      = 50
	maxLogLines        = 2000
	maxAgentLineBytes  = 2048
	maxAgentLineTotal  = 64 << 10
	maxStatusBytes     = 2048
	secretRedactMin    = 6
)

var (
	errSecretsKey = errors.New("secrets key not configured")
	errDecrypt    = errors.New("decrypt failed")
)

func (s *Server) handleCatalogDeploy(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapRead); err != nil {
		s.writeAuth(w, err)
		return
	}
	s.imageMutate(w, r, "deploy")
}

func (s *Server) handleCatalogRollback(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapRead); err != nil {
		s.writeAuth(w, err)
		return
	}
	s.imageMutate(w, r, "rollback")
}

func (s *Server) handleCatalogRemove(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapRead); err != nil {
		s.writeAuth(w, err)
		return
	}
	s.imageMutate(w, r, "remove")
}

func (s *Server) handleCatalogDeploys(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapRead); err != nil {
		s.writeAuth(w, err)
		return
	}
	p, projectID, ok := s.catalogRead(w, r)
	if !ok {
		return
	}
	hostID, ok := parseHostID(w, r.URL.Query().Get("host_id"))
	if !ok {
		return
	}
	entry, grants, ok := s.imageEntry(w, r, projectID, p)
	if !ok {
		return
	}
	if entry.Kind != "image" {
		writeCode(w, "bad_request", "kind must be image")
		return
	}
	role, err := s.Store.Role(r.Context(), projectID, p.User.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if len(heldActions(entry.Kind, role, p.User.ID, grants)) == 0 {
		writeCode(w, "forbidden", "forbidden")
		return
	}
	items, err := s.Store.ListImageDeploys(r.Context(), entry.ID, hostID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if items == nil {
		items = []store.ImageDeploy{}
	}
	writeOK(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) imageMutate(w http.ResponseWriter, r *http.Request, action string) {
	p, projectID, ok := s.catalogRead(w, r)
	if !ok {
		return
	}
	body, ok := s.imageBody(w, r, action)
	if !ok {
		return
	}
	entry, grants, ok := s.imageEntry(w, r, projectID, p)
	if !ok {
		return
	}
	role, err := s.Store.Role(r.Context(), projectID, p.User.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !allowsAction(heldActions(entry.Kind, role, p.User.ID, grants), "deploy") {
		s.imageDeny(w, r, p, projectID, body.HostID, "", entry.Name, action, "forbidden", "forbidden")
		return
	}
	if entry.Kind != "image" {
		writeCode(w, "bad_request", "kind must be image")
		return
	}
	if !catalog.ValidIdempotencyKey(body.Key) {
		writeCode(w, "bad_request", "invalid idempotency_key")
		return
	}
	if action == "rollback" && !catalog.ValidDigest(body.Digest) {
		writeCode(w, "bad_request", "invalid digest")
		return
	}
	host, rel, ok := s.programHost(w, r, p, projectID, body.HostID, entry, action, true)
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
			s.imageDeny(w, r, p, projectID, host.ID, host.Name, entry.Name, action, "forbidden", reasonWaiting)
			return
		}
	}
	if !containersReady(host) {
		s.imageDeny(w, r, p, projectID, host.ID, host.Name, entry.Name, action, "bad_request", reasonNoContainers)
		return
	}
	if s.hostStatus(host) != "online" {
		s.imageDeny(w, r, p, projectID, host.ID, host.Name, entry.Name, action, "unavailable", "host unavailable")
		return
	}
	img, err := catalog.ParseStored(entry.ImageRaw)
	if err != nil {
		s.fail(w, err)
		return
	}
	if action == "rollback" && !s.digestAllowed(w, r, entry.ID, host.ID, body.Digest) {
		return
	}
	if action != "remove" {
		needs, err := s.imageNeedsKey(r.Context(), projectID, img)
		if err != nil {
			s.fail(w, err)
			return
		}
		if needs && s.Secrets == nil {
			s.imageDeny(w, r, p, projectID, host.ID, host.Name, entry.Name, action, "unavailable", errSecretsKey.Error())
			return
		}
	}
	var force *bool
	digest := ""
	if action == "deploy" {
		force = &body.Force
	}
	if action == "rollback" {
		digest = body.Digest
	}
	hash := imageRequestHash(action, projectID, host.ID, entry.Name, body.Force, digest)
	if !s.claimOrReplay(w, r, p.User.ID, body.Key, hash) {
		return
	}
	if p.Session.Kind == store.KindDelegated {
		s.issueConfirmation(w, r, p, projectID, host, entry, action, body.Key, hash, digest, force)
		return
	}
	s.performImage(w, r, p, projectID, host, entry, img, action, body.Force, digest, 0, body.Key)
}

func (s *Server) finishImageShort(w http.ResponseWriter, r *http.Request, p principal, projectID uuid.UUID, host store.Host, entry store.CatalogEntry, action, key string, lines int) {
	if !containersReady(host) {
		writeCode(w, "bad_request", reasonNoContainers)
		return
	}
	if s.hostStatus(host) != "online" {
		writeCode(w, "unavailable", "host unavailable")
		return
	}
	img, err := catalog.ParseStored(entry.ImageRaw)
	if err != nil {
		s.fail(w, err)
		return
	}
	hash := programRequestHash(action, projectID, host.ID, entry.Name)
	if action == "run" || action == "stop" || action == "restart" {
		if !s.claimOrReplay(w, r, p.User.ID, key, hash) {
			return
		}
		if p.Session.Kind == store.KindDelegated {
			s.issueConfirmation(w, r, p, projectID, host, entry, action, key, hash, "", nil)
			return
		}
	}
	s.performImage(w, r, p, projectID, host, entry, img, action, false, "", lines, key)
}

func (s *Server) confirmImage(w http.ResponseWriter, r *http.Request, p principal, c store.CatalogConfirmation, entry store.CatalogEntry) {
	host, rel, ok := s.programHost(w, r, p, c.ProjectID, c.HostID, entry, c.Action, true)
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
			s.imageDeny(w, r, p, c.ProjectID, host.ID, host.Name, entry.Name, c.Action, "forbidden", reasonWaiting)
			return
		}
	}
	if !containersReady(host) {
		s.imageDeny(w, r, p, c.ProjectID, host.ID, host.Name, entry.Name, c.Action, "bad_request", reasonNoContainers)
		return
	}
	if s.hostStatus(host) != "online" {
		s.imageDeny(w, r, p, c.ProjectID, host.ID, host.Name, entry.Name, c.Action, "unavailable", "host unavailable")
		return
	}
	img, err := catalog.ParseStored(entry.ImageRaw)
	if err != nil {
		s.fail(w, err)
		return
	}
	digest := ""
	if c.ImageDigest != nil {
		digest = *c.ImageDigest
	}
	if c.Action == "rollback" && !s.digestAllowed(w, r, entry.ID, host.ID, digest) {
		return
	}
	if c.Action == "deploy" || c.Action == "rollback" {
		needs, err := s.imageNeedsKey(r.Context(), c.ProjectID, img)
		if err != nil {
			s.fail(w, err)
			return
		}
		if needs && s.Secrets == nil {
			s.imageDeny(w, r, p, c.ProjectID, host.ID, host.Name, entry.Name, c.Action, "unavailable", errSecretsKey.Error())
			return
		}
	}
	if entry.SpecHash != c.SpecHash {
		writeCode(w, "conflict", "conflict")
		return
	}
	if err := s.Store.MarkConfirmationUsed(r.Context(), secretHash(r), p.User.ID, s.now()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeCode(w, "not_found", "not found")
			return
		}
		s.fail(w, err)
		return
	}
	force := c.ImageForce != nil && *c.ImageForce
	s.performImage(w, r, p, c.ProjectID, host, entry, img, c.Action, force, digest, 0, c.IdempotencyKey)
}

// secretHash is the confirmation token hash already checked by the caller.
// confirmImage receives the request so it can mark that row used.
func secretHash(r *http.Request) []byte {
	return secret.Hash(r.PathValue("confirmation_id"))
}

func (s *Server) performImage(w http.ResponseWriter, r *http.Request, p principal, projectID uuid.UUID, host store.Host, entry store.CatalogEntry, img catalog.Image, action string, force bool, digest string, lines int, key string) {
	timeout := imageTimeout(action, img)
	if s.imageBudget > 0 {
		timeout = s.imageBudget
	}
	ctx, cancel := imageCtx(r, action, timeout)
	defer cancel()
	mutate := action == "deploy" || action == "rollback" || action == "remove"
	var opID uuid.UUID
	hold := false
	if mutate {
		at := s.now()
		until := at.Add(time.Duration(timeout+staleGraceSec) * time.Second)
		row, err := s.Store.BeginImageOp(ctx, entry.ID, host.ID, entry.SpecHash, p.User.ID, viaKind(p.Session.Kind), at, until)
		if err != nil {
			s.imageFail(ctx, w, p.User.ID, key, err, nil)
			return
		}
		opID = row.ID
		hold = true
		defer func() {
			if hold {
				_ = s.settle(func(c context.Context) error {
					return s.Store.ReleaseImageOp(c, opID)
				})
			}
		}()
	}
	spec, secrets, err := s.imageTask(ctx, projectID, entry, img, action, force, digest, lines)
	if err != nil {
		s.auditDecrypt(ctx, p, projectID, host, entry.Name, action, err)
		s.imageFail(ctx, w, p.User.ID, key, err, secretForms(secrets))
		return
	}
	// Deploy and rollback already returned the values they put in the frame.
	// Other actions keep that frame and use the values only for redaction.
	if action != "deploy" && action != "rollback" {
		secrets = s.redactValues(ctx, projectID, img)
	}
	forms := secretForms(secrets)
	if s.Hub == nil {
		s.imageFail(ctx, w, p.User.ID, key, &agentws.CallError{Code: "error", Msg: "internal error"}, forms)
		return
	}
	res, callErr := s.Hub.Image(ctx, host, imageKind(action), spec, timeout)
	got := takeImage(action, res, callErr, forms)
	if action == "remove" && got.request && got.code == "timeout" {
		hold = false
		_ = s.settle(func(c context.Context) error {
			return s.Store.ReleaseImageOp(c, opID)
		})
		s.auditImageOK(ctx, p, projectID, host, entry.Name, action, "timeout", nil, forms)
		s.imageFail(ctx, w, p.User.ID, key, &agentws.CallError{Code: "timeout", Msg: phrase("timeout")}, forms)
		return
	}
	if got.request {
		// An oversized deploy frame is not a deploy. The row is released by the defer.
		if got.msg != agentws.EnvFrameTooLarge {
			s.auditImageDeny(ctx, p, projectID, host, entry.Name, action, got.code, got.msg, forms)
		}
		s.imageFail(ctx, w, p.User.ID, key, &agentws.CallError{Code: got.code, Msg: got.msg}, forms)
		return
	}
	if action == "logs" {
		s.imageDone(w, p.User.ID, "", got.logs, forms)
		return
	}
	if action == "run" || action == "stop" || action == "restart" || action == "status" {
		s.imageDone(w, p.User.ID, key, got.status, forms)
		return
	}
	if action == "remove" {
		hold = false
		_ = s.settle(func(c context.Context) error {
			return s.Store.ReleaseImageOp(c, opID)
		})
		s.auditImageOK(ctx, p, projectID, host, entry.Name, action, got.outcome, nil, forms)
		s.imageDone(w, p.User.ID, key, map[string]any{"status": got.status}, forms)
		return
	}
	var finished store.ImageDeploy
	err = s.settle(func(c context.Context) error {
		var ferr error
		finished, ferr = s.Store.FinishImageDeploy(c, opID, got.outcome, got.digest, got.exit, s.now())
		return ferr
	})
	if err != nil {
		s.imageFail(ctx, w, p.User.ID, key, err, forms)
		return
	}
	hold = false
	s.auditImageOK(ctx, p, projectID, host, entry.Name, action, finished.Outcome, finished.Digest, forms)
	s.imageDone(w, p.User.ID, key, map[string]any{
		"deploy": finished,
		"status": got.status,
		"lines":  got.lines,
	}, forms)
}

func (s *Server) writeImage(w http.ResponseWriter, r *http.Request, p principal, projectID uuid.UUID, name string, raw json.RawMessage, replace bool) {
	names, err := s.Store.ListEnvKeyNames(r.Context(), projectID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if names == nil {
		names = map[string][]string{}
	}
	img, err := catalog.BuildImage(name, raw, names)
	if err != nil {
		s.writeField(w, err)
		return
	}
	digests := map[string]string{}
	for _, set := range catalog.ReferencedSets(img) {
		digests[set] = catalog.EnvKeyDigest(names[set])
	}
	hash := catalog.ImageHash(img, digests)
	in := store.CatalogWrite{
		Name: name, Kind: "image", ImageRaw: json.RawMessage(catalog.SpecJSON(img)),
		SpecHash: hash, CommandDisplay: img.Image, Actor: p.User.ID, At: s.now(),
	}
	var entry store.CatalogEntry
	var old string
	if replace {
		old, entry, err = s.Store.ReplaceCatalogEntry(r.Context(), projectID, name, in)
	} else {
		entry, err = s.Store.CreateCatalogEntry(r.Context(), projectID, in)
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	entry.MyActions = myActions(heldActions(entry.Kind, authz.RoleOwner, p.User.ID, nil))
	detail := map[string]any{"name": entry.Name, "spec_hash": entry.SpecHash}
	action := audit.ActionCatalogCreate
	status := http.StatusCreated
	if replace {
		action = audit.ActionCatalogUpdate
		status = http.StatusOK
		detail["old_spec_hash"] = old
	}
	s.auditOK(r.Context(), p, store.AuditRow{ProjectID: idPtr(projectID), Action: action, Detail: detail})
	writeOK(w, status, entry)
}

type imageActBody struct {
	HostID uuid.UUID
	Key    string
	Force  bool
	Digest string
}

func (s *Server) imageBody(w http.ResponseWriter, r *http.Request, action string) (imageActBody, bool) {
	switch action {
	case "deploy":
		var body struct {
			HostID string `json:"host_id"`
			Force  bool   `json:"force"`
			Key    string `json:"idempotency_key"`
		}
		if !decodeJSON(w, r, &body) {
			return imageActBody{}, false
		}
		id, ok := parseHostID(w, body.HostID)
		if !ok {
			return imageActBody{}, false
		}
		return imageActBody{HostID: id, Key: body.Key, Force: body.Force}, true
	case "rollback":
		var body struct {
			HostID string `json:"host_id"`
			Digest string `json:"digest"`
			Key    string `json:"idempotency_key"`
		}
		if !decodeJSON(w, r, &body) {
			return imageActBody{}, false
		}
		id, ok := parseHostID(w, body.HostID)
		if !ok {
			return imageActBody{}, false
		}
		return imageActBody{HostID: id, Key: body.Key, Digest: body.Digest}, true
	default:
		var body struct {
			HostID string `json:"host_id"`
			Key    string `json:"idempotency_key"`
		}
		if !decodeJSON(w, r, &body) {
			return imageActBody{}, false
		}
		id, ok := parseHostID(w, body.HostID)
		if !ok {
			return imageActBody{}, false
		}
		return imageActBody{HostID: id, Key: body.Key}, true
	}
}

func (s *Server) catalogRead(w http.ResponseWriter, r *http.Request) (principal, uuid.UUID, bool) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return principal{}, uuid.Nil, false
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapRead); err != nil {
		s.writeAuth(w, err)
		return principal{}, uuid.Nil, false
	}
	return p, id, true
}

func (s *Server) imageEntry(w http.ResponseWriter, r *http.Request, projectID uuid.UUID, _ principal) (store.CatalogEntry, []store.CatalogGrant, bool) {
	entry, err := s.catalogByName(r, projectID, r.PathValue("name"))
	if err != nil {
		s.fail(w, err)
		return store.CatalogEntry{}, nil, false
	}
	grants, err := s.Store.ListCatalogGrants(r.Context(), entry.ID)
	if err != nil {
		s.fail(w, err)
		return store.CatalogEntry{}, nil, false
	}
	return entry, grants, true
}

func (s *Server) digestAllowed(w http.ResponseWriter, r *http.Request, entryID, hostID uuid.UUID, digest string) bool {
	items, err := s.Store.RollbackDigests(r.Context(), entryID, hostID)
	if err != nil {
		s.fail(w, err)
		return false
	}
	for _, item := range items {
		if item == digest {
			return true
		}
	}
	writeCode(w, "bad_request", "invalid digest")
	return false
}

func (s *Server) imageNeedsKey(ctx context.Context, projectID uuid.UUID, img catalog.Image) (bool, error) {
	if img.ReferencesEnv() {
		return true, nil
	}
	_, err := s.Store.GetRegistryMaterial(ctx, projectID, img.RegistryHost)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Server) imageTask(ctx context.Context, projectID uuid.UUID, entry store.CatalogEntry, img catalog.Image, action string, force bool, digest string, lines int) (map[string]any, []string, error) {
	project, err := s.Store.GetProject(ctx, projectID)
	if err != nil {
		return nil, nil, err
	}
	switch action {
	case "deploy", "rollback":
		env, err := s.mergeEnv(ctx, projectID, img)
		if err != nil {
			return nil, nil, err
		}
		spec, err := storedSpec(img)
		if err != nil {
			return nil, nil, err
		}
		reg, err := s.registryAuth(ctx, projectID, img.RegistryHost)
		if err != nil {
			return nil, nil, err
		}
		secrets := make([]string, 0, len(env)+1)
		for _, v := range env {
			secrets = append(secrets, v)
		}
		if regMap, ok := reg.(map[string]any); ok {
			if tok, ok := regMap["token"].(string); ok {
				secrets = append(secrets, tok)
			}
		}
		out := map[string]any{
			"project":       project.Slug,
			"entry":         entry.Name,
			"spec":          spec,
			"env":           env,
			"registry_auth": reg,
			"force":         force,
			"spec_hash":     entry.SpecHash,
		}
		if action == "rollback" {
			out["digest"] = digest
		}
		return out, secrets, nil
	case "logs":
		return map[string]any{"project": project.Slug, "entry": entry.Name, "lines": lines}, nil, nil
	default:
		return map[string]any{"project": project.Slug, "entry": entry.Name}, nil, nil
	}
}

// redactValues loads the entry's env values and the matching registry token
// only so a response can hide them. The task frame is not changed. A missing
// key returns nothing. A decrypt failure logs once, with no value, and returns
// nothing so the caller keeps the keyword rule and still answers.
func (s *Server) redactValues(ctx context.Context, projectID uuid.UUID, img catalog.Image) []string {
	if s.Secrets == nil {
		return nil
	}
	env, err := s.mergeEnv(ctx, projectID, img)
	if err != nil {
		if errors.Is(err, errDecrypt) {
			s.logger().Error("decrypt failed")
		}
		return nil
	}
	reg, err := s.registryAuth(ctx, projectID, img.RegistryHost)
	if err != nil {
		if errors.Is(err, errDecrypt) {
			s.logger().Error("decrypt failed")
		}
		return nil
	}
	secrets := make([]string, 0, len(env)+1)
	for _, v := range env {
		secrets = append(secrets, v)
	}
	if regMap, ok := reg.(map[string]any); ok {
		if tok, ok := regMap["token"].(string); ok {
			secrets = append(secrets, tok)
		}
	}
	return secrets
}

func (s *Server) mergeEnv(ctx context.Context, projectID uuid.UUID, img catalog.Image) (map[string]string, error) {
	out := map[string]string{}
	for _, set := range img.EnvSets {
		mats, err := s.Store.ListEnvMaterial(ctx, projectID, set)
		if err != nil {
			return nil, err
		}
		for _, m := range mats {
			val, err := s.openEnv(projectID, set, m)
			if err != nil {
				return nil, err
			}
			out[m.Key] = val
		}
	}
	for key, ref := range img.SecretEnv {
		set, name, ok := strings.Cut(ref, ".")
		if !ok {
			return nil, errDecrypt
		}
		mats, err := s.Store.ListEnvMaterial(ctx, projectID, set)
		if err != nil {
			return nil, err
		}
		found := false
		for _, m := range mats {
			if m.Key != name {
				continue
			}
			val, err := s.openEnv(projectID, set, m)
			if err != nil {
				return nil, err
			}
			out[key] = val
			found = true
			break
		}
		if !found {
			return nil, errDecrypt
		}
	}
	for key, val := range img.Env {
		out[key] = val
	}
	return out, nil
}

func (s *Server) openEnv(projectID uuid.UUID, set string, m store.EnvMaterial) (string, error) {
	if !m.IsSecret {
		return m.Plain, nil
	}
	if s.Secrets == nil {
		return "", errSecretsKey
	}
	plain, err := s.Secrets.Open(seal.EnvAAD(projectID.String(), set, m.Key), m.Nonce, m.Ciphertext)
	if err != nil {
		return "", errDecrypt
	}
	return string(plain), nil
}

func (s *Server) registryAuth(ctx context.Context, projectID uuid.UUID, host string) (any, error) {
	mat, err := s.Store.GetRegistryMaterial(ctx, projectID, host)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if s.Secrets == nil {
		return nil, errSecretsKey
	}
	token, err := s.Secrets.Open(seal.RegistryAAD(projectID.String(), host), mat.Nonce, mat.Ciphertext)
	if err != nil {
		return nil, errDecrypt
	}
	return map[string]any{"host": host, "username": mat.Username, "token": string(token)}, nil
}

// storedSpec is the entry's ImageSpec as stored. Inline env, env_sets, and
// secret_env stay references. Resolved values travel only in the task's top-level env.
func storedSpec(img catalog.Image) (map[string]any, error) {
	var spec map[string]any
	if err := json.Unmarshal([]byte(catalog.SpecJSON(img)), &spec); err != nil {
		return nil, err
	}
	return spec, nil
}

func containersReady(host store.Host) bool {
	return host.Programs != nil && host.Programs.Images && host.Programs.Docker
}

func imageTimeout(action string, img catalog.Image) int {
	switch action {
	case "deploy":
		return catalog.DeployTimeoutSec(img)
	case "rollback":
		return catalog.RollbackTimeoutSec(img)
	default:
		return catalog.ShortTimeoutSec()
	}
}

func imageKind(action string) string {
	switch action {
	case "deploy":
		return "image_deploy"
	case "rollback":
		return "image_rollback"
	case "remove":
		return "image_remove"
	case "run":
		return "image_start"
	case "stop":
		return "image_stop"
	case "restart":
		return "image_restart"
	case "logs":
		return "image_logs"
	default:
		return "image_status"
	}
}

func imageCtx(r *http.Request, action string, timeoutSec int) (context.Context, context.CancelFunc) {
	parent := r.Context()
	if action == "deploy" || action == "rollback" || action == "remove" {
		parent = context.WithoutCancel(r.Context())
	}
	return context.WithTimeout(parent, time.Duration(timeoutSec)*time.Second)
}

func imageRequestHash(action string, projectID, hostID uuid.UUID, entry string, force bool, digest string) []byte {
	if action == "rollback" {
		raw := `{"action":` + jsonQuote(action) +
			`,"digest":` + jsonQuote(digest) +
			`,"entry":` + jsonQuote(entry) +
			`,"host_id":` + jsonQuote(hostID.String()) +
			`,"project_id":` + jsonQuote(projectID.String()) + `}`
		return hashBytes(raw)
	}
	if action == "deploy" {
		flag := "false"
		if force {
			flag = "true"
		}
		raw := `{"action":` + jsonQuote(action) +
			`,"entry":` + jsonQuote(entry) +
			`,"force":` + flag +
			`,"host_id":` + jsonQuote(hostID.String()) +
			`,"project_id":` + jsonQuote(projectID.String()) + `}`
		return hashBytes(raw)
	}
	return programRequestHash(action, projectID, hostID, entry)
}

func hashBytes(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

type imageStatusBody struct {
	Container    *string `json:"container"`
	State        string  `json:"state"`
	ExitCode     *int    `json:"exit_code"`
	RestartCount int     `json:"restart_count"`
	StartedAt    *string `json:"started_at"`
	FinishedAt   *string `json:"finished_at"`
	Digest       *string `json:"digest"`
	Ports        []int   `json:"ports"`
}

type imageLogsBody struct {
	Container *string  `json:"container"`
	Lines     []string `json:"lines"`
	Truncated bool     `json:"truncated"`
}

type imageCall struct {
	request bool
	code    string
	msg     string
	outcome string
	digest  *string
	exit    *int
	status  imageStatusBody
	lines   []string
	logs    imageLogsBody
}

func takeImage(action string, res agentws.LiveResult, err error, forms []string) imageCall {
	if action == "logs" {
		return takeLogs(res, err, forms)
	}
	if action == "run" || action == "stop" || action == "restart" || action == "status" || action == "remove" {
		return takeStatus(action == "remove", res, err, forms)
	}
	return takeDeploy(res, err, forms)
}

func takeDeploy(res agentws.LiveResult, err error, forms []string) imageCall {
	if err == nil {
		if got, ok := acceptedDeploy(res.Payload, forms); ok {
			return got
		}
		return failedFixed()
	}
	var call *agentws.CallError
	if !errors.As(err, &call) {
		return imageCall{request: true, code: "error", msg: "internal error"}
	}
	if hostRejection(call.Code) {
		return requestCall(call, forms)
	}
	if got, ok := acceptedDeploy(call.Payload, forms); ok {
		return got
	}
	if call.Code == "timeout" {
		return imageCall{outcome: "timeout", status: timeoutStatus(), lines: []string{}}
	}
	return failedFixed()
}

func takeStatus(remove bool, res agentws.LiveResult, err error, forms []string) imageCall {
	if err == nil {
		p, ok := parseAgentImage(res.Payload)
		st, stOK := normalizeStatus(p.Status)
		if !ok || !stOK {
			return imageCall{request: true, code: "error", msg: invalidAgentResult}
		}
		return imageCall{outcome: "succeeded", status: st, lines: []string{}}
	}
	var call *agentws.CallError
	if !errors.As(err, &call) {
		return imageCall{request: true, code: "error", msg: "internal error"}
	}
	if call.Code == "timeout" {
		return imageCall{request: true, code: "timeout", msg: phrase("timeout")}
	}
	if hostRejection(call.Code) {
		return requestCall(call, forms)
	}
	if p, ok := parseAgentImage(call.Payload); ok {
		if st, stOK := normalizeStatus(p.Status); stOK {
			outcome := "failed"
			if imageOutcomeOK(call.Msg) && call.Msg != "succeeded" {
				outcome = redactExact(call.Msg, forms)
			}
			return imageCall{outcome: outcome, status: st, lines: []string{}}
		}
	}
	return imageCall{request: true, code: "error", msg: invalidAgentResult}
}

func takeLogs(res agentws.LiveResult, err error, forms []string) imageCall {
	if err != nil {
		var call *agentws.CallError
		if !errors.As(err, &call) {
			return imageCall{request: true, code: "error", msg: "internal error"}
		}
		if call.Code == "timeout" {
			return imageCall{request: true, code: "timeout", msg: phrase("timeout")}
		}
		if hostRejection(call.Code) {
			return requestCall(call, forms)
		}
		return imageCall{request: true, code: "error", msg: invalidAgentResult}
	}
	p, ok := parseAgentImage(res.Payload)
	lines, linesOK := boundLines(p.Lines, maxLogLines)
	if !ok || !linesOK || !statusTextOK(p.Container) {
		return imageCall{request: true, code: "error", msg: invalidAgentResult}
	}
	return imageCall{logs: imageLogsBody{Container: p.Container, Lines: redactLines(lines, forms), Truncated: p.Truncated}}
}

func hostRejection(code string) bool {
	switch code {
	case "unavailable", "forbidden", "bad_request", "not_found":
		return true
	default:
		return false
	}
}

func requestCall(call *agentws.CallError, forms []string) imageCall {
	msg := call.Msg
	if msg == "" {
		msg = phrase(call.Code)
	}
	if redactExact(msg, forms) != msg {
		msg = phrase(call.Code)
	}
	code := call.Code
	if code == "" {
		code = "error"
	}
	return imageCall{request: true, code: code, msg: msg}
}

func acceptedDeploy(raw json.RawMessage, forms []string) (imageCall, bool) {
	p, ok := parseAgentImage(raw)
	if !ok || !imageOutcomeOK(p.Outcome) {
		return imageCall{}, false
	}
	st, stOK := normalizeStatus(p.Status)
	if !stOK {
		return imageCall{}, false
	}
	if p.Digest != nil && !catalog.ValidDigest(*p.Digest) {
		return imageCall{}, false
	}
	lines, linesOK := boundLines(p.Lines, maxAgentLines)
	if !linesOK {
		return imageCall{}, false
	}
	return imageCall{
		outcome: p.Outcome,
		digest:  cleanDigest(p.Digest),
		exit:    p.ExitCode,
		status:  st,
		lines:   redactLines(lines, forms),
	}, true
}

func failedFixed() imageCall {
	return imageCall{outcome: "failed", status: blankStatus(), lines: []string{invalidAgentResult}}
}

type agentImage struct {
	Outcome   string          `json:"outcome"`
	Digest    *string         `json:"digest"`
	ExitCode  *int            `json:"exit_code"`
	Status    json.RawMessage `json:"status"`
	Lines     []string        `json:"lines"`
	Container *string         `json:"container"`
	Truncated bool            `json:"truncated"`
}

func parseAgentImage(raw json.RawMessage) (agentImage, bool) {
	if len(raw) == 0 || !json.Valid(raw) || string(raw) == "null" {
		return agentImage{}, false
	}
	var p agentImage
	if err := json.Unmarshal(raw, &p); err != nil {
		return agentImage{}, false
	}
	return p, true
}

func imageOutcomeOK(s string) bool {
	switch s {
	case "succeeded", "unchanged", "failed", "timeout", "rolled_back", "rollback_failed", "image_unavailable", "forbidden_spec", "conflict":
		return true
	default:
		return false
	}
}

func cleanDigest(d *string) *string {
	if d == nil || !catalog.ValidDigest(*d) {
		return nil
	}
	cp := *d
	return &cp
}

func blankStatus() imageStatusBody {
	return imageStatusBody{Ports: []int{}}
}

// timeoutStatus is the deploy or rollback result when the task times out
// with no usable agent payload. The agent cannot report this state.
func timeoutStatus() imageStatusBody {
	return imageStatusBody{State: "unknown", Ports: []int{}}
}

// Agent results stay on the v1.8 enum. "unknown" is only timeoutStatus.
func statusStateOK(state string) bool {
	switch state {
	case "running", "exited", "created", "paused", "restarting", "dead", "missing":
		return true
	default:
		return false
	}
}

func normalizeStatus(raw json.RawMessage) (imageStatusBody, bool) {
	if len(raw) == 0 || string(raw) == "null" || !json.Valid(raw) {
		return imageStatusBody{}, false
	}
	var st imageStatusBody
	if err := json.Unmarshal(raw, &st); err != nil {
		return imageStatusBody{}, false
	}
	if !statusStateOK(st.State) {
		return imageStatusBody{}, false
	}
	if st.Ports == nil {
		st.Ports = []int{}
	}
	for _, port := range st.Ports {
		if port < 1 || port > 65535 {
			return imageStatusBody{}, false
		}
	}
	if len(st.Ports) > 64 {
		return imageStatusBody{}, false
	}
	if st.Digest != nil && !catalog.ValidDigest(*st.Digest) {
		return imageStatusBody{}, false
	}
	if !statusTextOK(st.Container) || !statusTextOK(st.StartedAt) || !statusTextOK(st.FinishedAt) {
		return imageStatusBody{}, false
	}
	if st.RestartCount < 0 {
		return imageStatusBody{}, false
	}
	return st, true
}

func statusTextOK(s *string) bool {
	if s == nil {
		return true
	}
	if len(*s) > maxStatusBytes {
		return false
	}
	for i := 0; i < len(*s); i++ {
		if (*s)[i] < 0x20 || (*s)[i] > 0x7e {
			return false
		}
	}
	return true
}

func boundLines(lines []string, maxCount int) ([]string, bool) {
	if lines == nil {
		return []string{}, true
	}
	if len(lines) > maxCount {
		return nil, false
	}
	total := 0
	for _, line := range lines {
		n := len(line)
		if n > maxAgentLineBytes {
			return nil, false
		}
		total += n
		if total > maxAgentLineTotal {
			return nil, false
		}
	}
	return lines, true
}

func redactLines(lines []string, forms []string) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = redactExact(line, forms)
	}
	return out
}

func secretForms(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0)
	add := func(form string) {
		if len(form) < secretRedactMin || seen[form] {
			return
		}
		seen[form] = true
		out = append(out, form)
	}
	for _, value := range values {
		if len(value) < secretRedactMin {
			continue
		}
		add(value)
		add(base64.StdEncoding.EncodeToString([]byte(value)))
		add(base64.RawStdEncoding.EncodeToString([]byte(value)))
		add(base64.URLEncoding.EncodeToString([]byte(value)))
		add(base64.RawURLEncoding.EncodeToString([]byte(value)))
		quoted, err := json.Marshal(value)
		if err == nil && len(quoted) >= 2 {
			add(string(quoted[1 : len(quoted)-1]))
		}
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

func redactExact(s string, forms []string) string {
	for _, form := range forms {
		if form == "" {
			continue
		}
		s = strings.ReplaceAll(s, form, "[redacted]")
	}
	return ingest.RedactCmdline(s)
}

// redactBody applies exact and keyword redaction to each JSON string.
// The keyword rule treats every following non-space byte as the value, so
// running it on the raw document would swallow the rest of the object.
func redactBody(body []byte, forms []string) []byte {
	if len(body) == 0 {
		return body
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return []byte(redactExact(string(body), forms))
	}
	out, err := json.Marshal(redactJSON(v, forms))
	if err != nil {
		return []byte(redactExact(string(body), forms))
	}
	return out
}

func redactJSON(v any, forms []string) any {
	switch t := v.(type) {
	case string:
		return redactExact(t, forms)
	case []any:
		for i := range t {
			t[i] = redactJSON(t[i], forms)
		}
		return t
	case map[string]any:
		for k, val := range t {
			t[k] = redactJSON(val, forms)
		}
		return t
	default:
		return v
	}
}

func redactDetail(detail map[string]any, forms []string) map[string]any {
	if len(forms) == 0 || detail == nil {
		return detail
	}
	out := make(map[string]any, len(detail))
	for k, v := range detail {
		s, ok := v.(string)
		if !ok {
			out[k] = v
			continue
		}
		out[k] = redactExact(s, forms)
	}
	return out
}

func (s *Server) settle(fn func(context.Context) error) error {
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), settleTimeout)
		err = fn(ctx)
		cancel()
		if err == nil {
			return nil
		}
	}
	return err
}

func (s *Server) finishImageKey(userID uuid.UUID, key string, status int, body []byte) {
	if key == "" {
		return
	}
	_ = s.settle(func(ctx context.Context) error {
		return s.Store.ReplaceIdempotencyResponse(ctx, userID, key, status, body)
	})
}

func (s *Server) recordAudit(ctx context.Context, row store.AuditRow) {
	write := func(c context.Context) error {
		s.Audit.Record(c, row)
		return nil
	}
	if ctx != nil && ctx.Err() == nil {
		_ = write(ctx)
		return
	}
	_ = s.settle(write)
}

func (s *Server) imageDone(w http.ResponseWriter, userID uuid.UUID, key string, payload any, forms []string) {
	body := redactBody(envelopeRaw("ok", "ok", payload), forms)
	s.finishImageKey(userID, key, http.StatusOK, body)
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) imageFail(ctx context.Context, w http.ResponseWriter, userID uuid.UUID, key string, err error, forms []string) {
	var call *agentws.CallError
	switch {
	case errors.Is(err, errDecrypt):
		s.logger().Error("decrypt failed")
		call = &agentws.CallError{Code: "error", Msg: "internal error"}
	case errors.Is(err, errSecretsKey):
		s.logger().Error("secrets key not configured")
		call = &agentws.CallError{Code: "unavailable", Msg: errSecretsKey.Error()}
	case errors.Is(err, store.ErrConflict):
		call = &agentws.CallError{Code: "conflict", Msg: "conflict"}
	case errors.Is(err, store.ErrNotFound):
		call = &agentws.CallError{Code: "not_found", Msg: "not found"}
	case !errors.As(err, &call):
		s.logErr(err)
		call = &agentws.CallError{Code: "error", Msg: "internal error"}
	}
	if call.Msg == "" {
		call.Msg = phrase(call.Code)
	}
	if redactExact(call.Msg, forms) != call.Msg {
		call.Msg = phrase(call.Code)
	}
	status, body, _ := liveEnvelope(agentws.LiveResult{}, call)
	body = redactBody(body, forms)
	s.finishImageKey(userID, key, status, body)
	writeJSON(w, status, body)
}

func (s *Server) imageDeny(w http.ResponseWriter, r *http.Request, p principal, projectID, hostID uuid.UUID, hostName, entryName, action, code, msg string) {
	s.auditImageDeny(r.Context(), p, projectID, store.Host{ID: hostID, Name: hostName}, entryName, action, code, msg, nil)
	writeCode(w, code, msg)
}

func (s *Server) auditDecrypt(ctx context.Context, p principal, projectID uuid.UUID, host store.Host, entry, action string, err error) {
	switch {
	case errors.Is(err, errDecrypt):
		s.auditImageDeny(ctx, p, projectID, host, entry, action, "error", "decrypt failed", nil)
	case errors.Is(err, errSecretsKey):
		s.auditImageDeny(ctx, p, projectID, host, entry, action, "unavailable", errSecretsKey.Error(), nil)
	}
}

func (s *Server) auditImageDeny(ctx context.Context, p principal, projectID uuid.UUID, host store.Host, entry, action, code, msg string, forms []string) {
	name := catalogActionName(action)
	if name == "" {
		return
	}
	result := code
	detail := map[string]any{"reason": redactExact(msg, forms), "entry": entry}
	if host.Name != "" {
		detail["host"] = host.Name
	}
	var hostID *uuid.UUID
	if host.ID != uuid.Nil {
		hostID = idPtr(host.ID)
	}
	s.recordAudit(ctx, store.AuditRow{
		ActorUserID: idPtr(p.User.ID),
		Via:         viaKind(p.Session.Kind),
		ProjectID:   idPtr(projectID),
		HostID:      hostID,
		Action:      name,
		Decision:    audit.DecisionDenied,
		Result:      &result,
		ErrorCode:   &result,
		Detail:      redactDetail(detail, forms),
	})
}

func (s *Server) auditImageOK(ctx context.Context, p principal, projectID uuid.UUID, host store.Host, entry, action, outcome string, digest *string, forms []string) {
	name := catalogActionName(action)
	if name == "" {
		return
	}
	result := outcome
	detail := map[string]any{
		"entry":   entry,
		"host":    host.Name,
		"outcome": outcome,
		"via":     viaKind(p.Session.Kind),
	}
	if digest != nil {
		detail["digest"] = *digest
	}
	s.recordAudit(ctx, store.AuditRow{
		ActorUserID: idPtr(p.User.ID),
		Via:         viaKind(p.Session.Kind),
		ProjectID:   idPtr(projectID),
		HostID:      idPtr(host.ID),
		Action:      name,
		Decision:    audit.DecisionAllowed,
		Result:      &result,
		Detail:      redactDetail(detail, forms),
	})
}

func catalogActionName(action string) string {
	switch action {
	case "deploy":
		return audit.ActionCatalogDeploy
	case "rollback":
		return audit.ActionCatalogRollback
	case "remove":
		return audit.ActionCatalogRemove
	default:
		return ""
	}
}

func (s *Server) sealValue(projectID uuid.UUID, set, key, plain string) (store.EnvSecret, error) {
	if s.Secrets == nil {
		return store.EnvSecret{}, errSecretsKey
	}
	nonce, ciphertext, err := s.Secrets.Seal(seal.EnvAAD(projectID.String(), set, key), []byte(plain))
	if err != nil {
		return store.EnvSecret{}, err
	}
	return store.EnvSecret{Key: key, Nonce: nonce, Ciphertext: ciphertext, KeyVersion: seal.KeyVersion}, nil
}
