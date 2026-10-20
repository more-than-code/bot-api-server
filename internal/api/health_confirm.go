package api

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/authz"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const healthConfirmAction = "health_checks"

// issueHealthConfirmation validates the idempotency key, claims it, and
// returns 202. The checks were already validated. Nothing is replaced.
func (s *Server) issueHealthConfirmation(w http.ResponseWriter, r *http.Request, p principal, svc store.Service, host store.Host, inputs []store.HealthCheckInput, key string) {
	if !catalog.ValidIdempotencyKey(key) {
		writeCode(w, "bad_request", "invalid idempotency_key")
		return
	}
	current, err := s.Store.ListHealthChecks(r.Context(), svc.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	reqHash := store.HealthRequestHash(svc.ID, inputs)
	if !s.claimOrReplay(w, r, p.User.ID, key, reqHash) {
		return
	}
	plain, tokenHash, err := secret.NewToken()
	if err != nil {
		s.failClaimed(w, r, p.User.ID, key, err)
		return
	}
	now := s.now().UTC()
	expires := now.Add(store.ConfirmationTTL)
	row := store.ServiceConfirmation{
		UserID: p.User.ID, ProjectID: svc.ProjectID, ServiceID: svc.ID, Action: healthConfirmAction,
		RequestHash: reqHash, CurrentHash: store.HealthSetHash(store.HealthCheckInputs(current)), Checks: inputs,
		IdempotencyKey: key, CreatedAt: now, ExpiresAt: expires,
	}
	if err := s.Store.PutServiceConfirmation(r.Context(), tokenHash, row); err != nil {
		s.failClaimed(w, r, p.User.ID, key, err)
		return
	}
	payload := map[string]any{
		"confirmation_id": plain,
		"plan":            healthPlan(serviceLabel(svc), host.Name, inputs),
		"expires_at":      expires.Format(time.RFC3339),
	}
	body := envelopeRaw("ok", "ok", payload)
	s.finishIdempotency(r.Context(), p.User.ID, key, http.StatusAccepted, body)
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(host.ProjectID),
		HostID:    idPtr(host.ID),
		ServiceID: idPtr(svc.ID),
		Action:    audit.ActionHealthConfirmation,
		Detail: map[string]any{
			"service": serviceLabel(svc),
			"host":    host.Name,
			"count":   len(inputs),
		},
	})
	writeJSON(w, http.StatusAccepted, body)
}

// confirmServiceHealth runs when the id is not a catalog confirmation.
// Permission and share checks run again. The current-set compare, the
// mark, and the replace commit together. A changed check set is conflict
// and leaves the token unused. Unknown, used, expired, and foreign ids
// are not_found.
func (s *Server) confirmServiceHealth(w http.ResponseWriter, r *http.Request, p principal, hash []byte, key string) {
	c, err := s.Store.GetServiceConfirmation(r.Context(), hash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// v1.12: a miss of both earlier tables loads catalog_write_confirmations.
			s.confirmCatalogWrite(w, r, p, hash, key)
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
	svc, host, ok := s.healthConfirmTarget(w, r, p, c.ServiceID)
	if !ok {
		return
	}
	current, err := s.Store.ListHealthChecks(r.Context(), svc.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !secret.Equal(store.HealthSetHash(store.HealthCheckInputs(current)), c.CurrentHash) {
		writeCode(w, "conflict", "conflict")
		return
	}
	checks, err := s.Store.CommitHealthReplacement(r.Context(), hash, p.User.ID, now)
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
	checks = s.finishHealthReplace(r, p, host, svc, checks)
	body := envelopeRaw("ok", "ok", map[string]any{"checks": checks})
	s.finishIdempotency(r.Context(), p.User.ID, c.IdempotencyKey, http.StatusOK, body)
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) healthConfirmTarget(w http.ResponseWriter, r *http.Request, p principal, serviceID uuid.UUID) (store.Service, store.Host, bool) {
	svc, err := s.Store.GetService(r.Context(), serviceID, s.now())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeCode(w, "not_found", "not found")
			return store.Service{}, store.Host{}, false
		}
		s.fail(w, err)
		return store.Service{}, store.Host{}, false
	}
	host, err := s.Store.GetHost(r.Context(), svc.HostID)
	if err != nil {
		s.fail(w, err)
		return store.Service{}, store.Host{}, false
	}
	if _, ok := s.gateHost(w, r, p, host, authz.CapServiceWrite, &svc.ProjectID, idPtr(svc.ID), audit.ActionHealthChecks); !ok {
		return store.Service{}, store.Host{}, false
	}
	return svc, host, true
}

func (s *Server) replaceHealthChecks(r *http.Request, p principal, host store.Host, svc store.Service, inputs []store.HealthCheckInput) ([]store.HealthCheck, error) {
	checks, err := s.Store.ReplaceHealthChecks(r.Context(), svc.ID, inputs)
	if err != nil {
		return nil, err
	}
	return s.finishHealthReplace(r, p, host, svc, checks), nil
}

func (s *Server) finishHealthReplace(r *http.Request, p principal, host store.Host, svc store.Service, checks []store.HealthCheck) []store.HealthCheck {
	if s.Hub != nil {
		s.Hub.PushConfig(r.Context(), host.ID)
	}
	if checks == nil {
		checks = []store.HealthCheck{}
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(host.ProjectID),
		HostID:    idPtr(host.ID),
		ServiceID: idPtr(svc.ID),
		Action:    audit.ActionHealthChecks,
		Detail:    map[string]any{"count": len(checks)},
	})
	return checks
}

// healthPlan is the v1.10 sentence. The label and each HTTP path are
// Go-quoted. The host name is not. A tcp item is "tcp <port>". An http
// item is `http <port> <quoted path> every <interval> s`. A disabled check
// ends with " (disabled)". The example does not put an interval on tcp.
// A tcp check that shares a port with an http check adds
// "(tcp <port> is redundant with http <port>)" and is still kept.
func healthPlan(label, host string, checks []store.HealthCheckInput) string {
	quoted := strconv.Quote(label)
	if len(checks) == 0 {
		return "will remove all health checks from " + quoted + " (" + host + ")"
	}
	noun := "health checks"
	if len(checks) == 1 {
		noun = "health check"
	}
	parts := make([]string, len(checks))
	for i, c := range checks {
		var item string
		if c.Protocol == "http" {
			path := ""
			if c.Path != nil {
				path = *c.Path
			}
			item = "http " + strconv.Itoa(c.Port) + " " + strconv.Quote(path) + " every " + strconv.Itoa(c.IntervalSec) + " s"
		} else {
			item = "tcp " + strconv.Itoa(c.Port)
		}
		if !c.Enabled {
			item += " (disabled)"
		}
		parts[i] = item
	}
	plan := "will set " + strconv.Itoa(len(checks)) + " " + noun + " on " + quoted + " (" + host + "): " + strings.Join(parts, ", ")
	for _, port := range redundantPorts(checks) {
		plan += " (tcp " + strconv.Itoa(port) + " is redundant with http " + strconv.Itoa(port) + ")"
	}
	return plan
}

func redundantPorts(checks []store.HealthCheckInput) []int {
	tcp := map[int]bool{}
	httpSeen := map[int]bool{}
	for _, c := range checks {
		switch c.Protocol {
		case "tcp":
			tcp[c.Port] = true
		case "http":
			httpSeen[c.Port] = true
		}
	}
	var ports []int
	for port := range tcp {
		if httpSeen[port] {
			ports = append(ports, port)
		}
	}
	sort.Ints(ports)
	return ports
}

func serviceLabel(svc store.Service) string {
	if svc.DisplayName != nil {
		if name := strings.TrimSpace(*svc.DisplayName); name != "" {
			return name
		}
	}
	return svc.Name
}
