package api

import (
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/authz"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/seal"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const (
	maxRegistryUser  = 255
	maxRegistryToken = 4096
	envPutLimit      = 2 << 20
)

var envKeyPathRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)

func (s *Server) handleEnvSetList(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapMembers); err != nil {
		s.writeAuth(w, err)
		return
	}
	if !requireConsole(w, p) {
		return
	}
	items, err := s.Store.ListEnvSets(r.Context(), id)
	if err != nil {
		s.writeErr(w, err, false)
		return
	}
	writeOK(w, http.StatusOK, map[string]any{"items": fillEnvSets(items)})
}

func (s *Server) handleEnvSetGet(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapMembers); err != nil {
		s.writeAuth(w, err)
		return
	}
	if !requireConsole(w, p) {
		return
	}
	name, ok := envSetName(w, r)
	if !ok {
		return
	}
	set, err := s.Store.GetEnvSet(r.Context(), id, name)
	if err != nil {
		s.writeErr(w, err, false)
		return
	}
	writeOK(w, http.StatusOK, fillEnvSet(set))
}

func (s *Server) handleEnvSetPut(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapMembers); err != nil {
		s.writeAuth(w, err)
		return
	}
	if !requireConsole(w, p) {
		return
	}
	name, ok := envSetName(w, r)
	if !ok {
		return
	}
	raw, ok := readLimitedN(w, r, envPutLimit)
	if !ok {
		return
	}
	var body struct {
		Dotenv string `json:"dotenv"`
	}
	if !decodeRaw(w, raw, &body) {
		return
	}
	pairs, err := catalog.ParseDotenv([]byte(body.Dotenv))
	if err != nil {
		s.writeField(w, err)
		return
	}
	if s.Secrets == nil {
		s.logger().Error("secrets key not configured")
		writeCode(w, "unavailable", errSecretsKey.Error())
		return
	}
	keys := make([]store.EnvSecret, 0, len(pairs))
	names := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		// Seal every key. PutEnvSet keeps an existing key's visibility
		// inside its transaction and stores this seal only when the key is secret.
		sealed, err := s.sealValue(id, name, pair.Key, pair.Value)
		if err != nil {
			s.secretWriteErr(w, err)
			return
		}
		sealed.Plain = pair.Value
		keys = append(keys, sealed)
		names = append(names, pair.Key)
	}
	set, err := s.Store.PutEnvSet(r.Context(), id, name, keys, p.User.ID, s.now())
	if err != nil {
		s.writeErr(w, err, false)
		return
	}
	sort.Strings(names)
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(id),
		Action:    audit.ActionEnvSetReplace,
		Detail:    map[string]any{"set": name, "keys": names},
	})
	writeOK(w, http.StatusOK, fillEnvSet(set))
}

func (s *Server) handleEnvSetDelete(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapMembers); err != nil {
		s.writeAuth(w, err)
		return
	}
	if !requireConsole(w, p) {
		return
	}
	name, ok := envSetName(w, r)
	if !ok {
		return
	}
	if err := s.Store.DeleteEnvSet(r.Context(), id, name); err != nil {
		s.writeErr(w, err, false)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(id),
		Action:    audit.ActionEnvSetDelete,
		Detail:    map[string]any{"set": name},
	})
	writeOK(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleEnvKeyPatch(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapMembers); err != nil {
		s.writeAuth(w, err)
		return
	}
	if !requireConsole(w, p) {
		return
	}
	name, ok := envSetName(w, r)
	if !ok {
		return
	}
	key, ok := envKeyName(w, r)
	if !ok {
		return
	}
	var body struct {
		IsSecret *bool `json:"is_secret"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.IsSecret == nil {
		writeCode(w, "bad_request", "invalid json")
		return
	}
	mats, err := s.Store.ListEnvMaterial(r.Context(), id, name)
	if err != nil {
		s.writeErr(w, err, false)
		return
	}
	var mat *store.EnvMaterial
	for i := range mats {
		if mats[i].Key == key {
			mat = &mats[i]
			break
		}
	}
	if mat == nil {
		writeCode(w, "not_found", "not found")
		return
	}
	want := *body.IsSecret
	patch := store.EnvKeyPatch{IsSecret: want}
	if mat.IsSecret == want {
		if want {
			patch.Nonce = mat.Nonce
			patch.Ciphertext = mat.Ciphertext
			patch.KeyVersion = mat.KeyVersion
		} else {
			patch.Plain = mat.Plain
		}
	} else if want {
		sealed, err := s.sealValue(id, name, key, mat.Plain)
		if err != nil {
			s.secretWriteErr(w, err)
			return
		}
		patch.Nonce = sealed.Nonce
		patch.Ciphertext = sealed.Ciphertext
		patch.KeyVersion = sealed.KeyVersion
	} else {
		plain, err := s.openEnv(id, name, *mat)
		if err != nil {
			s.secretWriteErr(w, err)
			return
		}
		patch.Plain = plain
	}
	set, err := s.Store.PatchEnvKey(r.Context(), id, name, key, patch, p.User.ID, s.now())
	if err != nil {
		s.writeErr(w, err, false)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(id),
		Action:    audit.ActionEnvSetVisibility,
		Detail:    map[string]any{"set": name, "key": key, "is_secret": want},
	})
	writeOK(w, http.StatusOK, fillEnvSet(set))
}

func (s *Server) handleRegistryList(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapMembers); err != nil {
		s.writeAuth(w, err)
		return
	}
	if !requireConsole(w, p) {
		return
	}
	items, err := s.Store.ListRegistries(r.Context(), id)
	if err != nil {
		s.writeErr(w, err, false)
		return
	}
	if items == nil {
		items = []store.Registry{}
	}
	writeOK(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleRegistryPut(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapMembers); err != nil {
		s.writeAuth(w, err)
		return
	}
	if !requireConsole(w, p) {
		return
	}
	host, ok := registryHost(w, r)
	if !ok {
		return
	}
	var body struct {
		Username string `json:"username"`
		Token    string `json:"token"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if !credentialOK(body.Username, maxRegistryUser) {
		writeCode(w, "bad_request", "invalid username")
		return
	}
	if !credentialOK(body.Token, maxRegistryToken) {
		writeCode(w, "bad_request", "invalid token")
		return
	}
	if s.Secrets == nil {
		s.logger().Error("secrets key not configured")
		writeCode(w, "unavailable", errSecretsKey.Error())
		return
	}
	nonce, ciphertext, err := s.Secrets.Seal(seal.RegistryAAD(id.String(), host), []byte(body.Token))
	if err != nil {
		s.logger().Error("encrypt failed")
		writeCode(w, "error", "internal error")
		return
	}
	reg, err := s.Store.PutRegistry(r.Context(), id, host, store.RegistryWrite{
		Username:   body.Username,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		KeyVersion: seal.KeyVersion,
	}, p.User.ID, s.now())
	if err != nil {
		s.writeErr(w, err, false)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(id),
		Action:    audit.ActionRegistryPut,
		Detail:    map[string]any{"host": host},
	})
	writeOK(w, http.StatusOK, reg)
}

func (s *Server) handleRegistryDelete(w http.ResponseWriter, r *http.Request) {
	p, id, ok := s.catalogProject(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapMembers); err != nil {
		s.writeAuth(w, err)
		return
	}
	if !requireConsole(w, p) {
		return
	}
	host, ok := registryHost(w, r)
	if !ok {
		return
	}
	if err := s.Store.DeleteRegistry(r.Context(), id, host); err != nil {
		s.writeErr(w, err, false)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(id),
		Action:    audit.ActionRegistryDelete,
		Detail:    map[string]any{"host": host},
	})
	writeOK(w, http.StatusOK, map[string]any{})
}

func requireConsole(w http.ResponseWriter, p principal) bool {
	if p.Session.Kind != store.KindConsole {
		writeCode(w, "forbidden", "forbidden")
		return false
	}
	return true
}

func envSetName(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("set")
	if !catalog.ValidName(name) {
		writeCode(w, "bad_request", "invalid name")
		return "", false
	}
	return name, true
}

func envKeyName(w http.ResponseWriter, r *http.Request) (string, bool) {
	key := r.PathValue("key")
	if !envKeyPathRe.MatchString(key) {
		writeCode(w, "bad_request", "invalid env key")
		return "", false
	}
	return key, true
}

func registryHost(w http.ResponseWriter, r *http.Request) (string, bool) {
	host := r.PathValue("host")
	if !catalog.ValidRegistryHost(host) {
		writeCode(w, "bad_request", "invalid host")
		return "", false
	}
	return host, true
}

func credentialOK(v string, max int) bool {
	return v != "" && len(v) <= max && !strings.ContainsAny(v, "\r\n\x00")
}

func (s *Server) secretWriteErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errSecretsKey):
		s.logger().Error("secrets key not configured")
		writeCode(w, "unavailable", errSecretsKey.Error())
	case errors.Is(err, errDecrypt):
		s.logger().Error("decrypt failed")
		writeCode(w, "error", "internal error")
	default:
		s.logger().Error("encrypt failed")
		writeCode(w, "error", "internal error")
	}
}

func fillEnvSets(items []store.EnvSet) []store.EnvSet {
	if items == nil {
		return []store.EnvSet{}
	}
	for i := range items {
		items[i] = fillEnvSet(items[i])
	}
	return items
}

func fillEnvSet(set store.EnvSet) store.EnvSet {
	if set.Keys == nil {
		set.Keys = []store.EnvKey{}
	}
	return set
}
