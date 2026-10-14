package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/auth"
	"github.com/more-than-code/bot-api-server/internal/authz"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const (
	inviteExpiresDefault = 604800
	inviteExpiresMin     = 3600
	inviteExpiresMax     = 2592000
	inviteUsesDefault    = 1
	inviteUsesMin        = 1
	inviteUsesMax        = 50
)

func (s *Server) handleInviteCreate(w http.ResponseWriter, r *http.Request) {
	p, ok := s.require(w, r)
	if !ok {
		return
	}
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapMembers); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, audit.ActionInviteCreate, err)
		return
	}
	var body struct {
		Role    string `json:"role"`
		Expires *int   `json:"expires_in_sec"`
		MaxUses *int   `json:"max_uses"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Role != "admin" && body.Role != "viewer" {
		writeCode(w, "bad_request", "invalid role")
		return
	}
	sec := inviteExpiresDefault
	if body.Expires != nil {
		sec = *body.Expires
	}
	if sec < inviteExpiresMin || sec > inviteExpiresMax {
		writeCode(w, "bad_request", "invalid expires_in_sec")
		return
	}
	uses := inviteUsesDefault
	if body.MaxUses != nil {
		uses = *body.MaxUses
	}
	if uses < inviteUsesMin || uses > inviteUsesMax {
		writeCode(w, "bad_request", "invalid max_uses")
		return
	}
	prefix, ok := inviteURLPrefix(s.ConsoleOrigin)
	if !ok {
		s.logger().Error("console origin is not configured")
		writeCode(w, "error", "internal error")
		return
	}
	plain, hash, err := secret.NewToken()
	if err != nil {
		s.failInvite(w, err)
		return
	}
	now := s.now()
	expiresAt := now.Add(time.Duration(sec) * time.Second)
	inv, err := s.Store.CreateInvite(r.Context(), id, hash, body.Role, p.User.ID, expiresAt, now, uses)
	if err != nil {
		s.failInvite(w, err)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(id),
		Action:    audit.ActionInviteCreate,
		Detail: map[string]any{
			"invite_id":  inv.ID.String(),
			"role":       inv.Role,
			"max_uses":   inv.MaxUses,
			"expires_at": inv.ExpiresAt,
		},
	})
	writeOK(w, http.StatusCreated, struct {
		store.Invite
		Token string `json:"token"`
		URL   string `json:"url"`
	}{
		Invite: inv,
		Token:  plain,
		URL:    prefix + plain,
	})
}

// inviteURLPrefix is "<origin>/invite/". A trailing slash on the origin is
// removed, matching the OAuth consent redirect. An empty origin is refused
// before a token is minted.
func inviteURLPrefix(origin string) (string, bool) {
	origin = strings.TrimRight(origin, "/")
	if origin == "" {
		return "", false
	}
	return origin + "/invite/", true
}

func (s *Server) handleInviteList(w http.ResponseWriter, r *http.Request) {
	p, ok := s.require(w, r)
	if !ok {
		return
	}
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapMembers); err != nil {
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
	items, next, err := s.Store.ListInvites(r.Context(), id, limit, cur)
	if err != nil {
		s.failInvite(w, err)
		return
	}
	writeList(w, items, next)
}

func (s *Server) handleInviteRevoke(w http.ResponseWriter, r *http.Request) {
	p, ok := s.require(w, r)
	if !ok {
		return
	}
	id, ok := s.pathID(w, r, "id")
	if !ok {
		return
	}
	inviteID, ok := s.pathID(w, r, "invite_id")
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, id, authz.CapMembers); err != nil {
		s.deny(w, r, p, idPtr(id), nil, nil, audit.ActionInviteRevoke, err)
		return
	}
	if err := s.Store.RevokeInvite(r.Context(), id, inviteID, s.now()); err != nil {
		s.failInvite(w, err)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(id),
		Action:    audit.ActionInviteRevoke,
		Detail:    map[string]any{"invite_id": inviteID.String()},
	})
	writeOK(w, http.StatusOK, nil)
}

func (s *Server) handleInviteLookup(w http.ResponseWriter, r *http.Request) {
	p, ok := s.consoleUser(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, uuid.Nil, authz.CapSession); err != nil {
		s.deny(w, r, p, nil, nil, nil, "", err)
		return
	}
	if !s.allowInvite(w, r, p) {
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	// Every presented string is hashed, including an empty or malformed one,
	// so those cases share the unknown-token not_found body.
	look, err := s.Store.LookupInvite(r.Context(), secret.Hash(body.Token), p.User.ID, s.now())
	if err != nil {
		s.failInvite(w, err)
		return
	}
	writeOK(w, http.StatusOK, struct {
		ProjectID     uuid.UUID `json:"project_id"`
		ProjectName   string    `json:"project_name"`
		Role          string    `json:"role"`
		AlreadyMember bool      `json:"already_member"`
	}{
		ProjectID:     look.ProjectID,
		ProjectName:   look.ProjectName,
		Role:          look.Role,
		AlreadyMember: look.AlreadyMember,
	})
}

func (s *Server) handleInviteAccept(w http.ResponseWriter, r *http.Request) {
	p, ok := s.consoleUser(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, uuid.Nil, authz.CapSession); err != nil {
		s.deny(w, r, p, nil, nil, nil, "", err)
		return
	}
	if !s.allowInvite(w, r, p) {
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	res, err := s.Store.AcceptInvite(r.Context(), secret.Hash(body.Token), p.User.ID, s.now())
	if err != nil {
		s.failInvite(w, err)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		ProjectID: idPtr(res.ProjectID),
		Action:    audit.ActionInviteAccept,
		Detail: map[string]any{
			"invite_id": res.InviteID.String(),
			"user_id":   p.User.ID.String(),
		},
	})
	writeOK(w, http.StatusOK, struct {
		ProjectID uuid.UUID `json:"project_id"`
		Role      string    `json:"role"`
	}{
		ProjectID: res.ProjectID,
		Role:      res.Role,
	})
}

func (s *Server) allowInvite(w http.ResponseWriter, r *http.Request, p principal) bool {
	if err := s.Auth.AllowInvite(p.User.ID.String(), s.clientIP(r)); err != nil {
		if errors.Is(err, auth.ErrRateLimited) {
			writeCode(w, "rate_limited", "")
			return false
		}
		s.failInvite(w, err)
		return false
	}
	return true
}
