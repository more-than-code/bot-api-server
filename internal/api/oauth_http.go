package api

import (
	"encoding/json"
	"errors"
	"html"
	"io"
	"mime"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/auth"
	"github.com/more-than-code/bot-api-server/internal/authz"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (s *Server) handleOAuthMetadata(w http.ResponseWriter, _ *http.Request) {
	doc, err := s.Auth.MetadataDocument()
	if err != nil {
		s.logErr(err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "server error", "")
		return
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "server error", "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) handleOAuthRegister(w http.ResponseWriter, r *http.Request) {
	if err := s.Auth.AllowOAuthRegister(s.clientIP(r)); errors.Is(err, auth.ErrRateLimited) {
		writeRateLimited(w)
		return
	}
	raw, ok := readJSONBody(w, r)
	if !ok {
		return
	}
	client, err := s.Auth.Register(r.Context(), raw)
	if err != nil {
		s.writeOAuthResult(w, err)
		return
	}
	s.Audit.Record(r.Context(), store.AuditRow{
		Via:      audit.ViaSystem,
		Action:   audit.ActionOAuthRegister,
		Decision: audit.DecisionAllowed,
		Detail:   map[string]any{"client_id": client.ClientID, "client_name": client.ClientName},
	})
	raw, err = json.Marshal(client)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "server error", "")
		return
	}
	writeJSON(w, http.StatusCreated, raw)
}

func (s *Server) handleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	if err := s.Auth.AllowOAuthAuthorize(s.clientIP(r)); errors.Is(err, auth.ErrRateLimited) {
		writeHTML(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	out, err := s.Auth.BeginAuthorize(r.Context(), r.URL.Query())
	if err != nil {
		s.logErr(err)
		writeHTML(w, http.StatusInternalServerError, "temporarily unavailable")
		return
	}
	if out.Location != "" {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Location", out.Location)
		w.WriteHeader(out.Status)
		return
	}
	writeHTML(w, out.Status, out.Page)
}

func (s *Server) handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	user, pass, hasBasic := basicAuth(r)
	if !s.Auth.TokenRateExempt(user, pass, hasBasic) {
		if err := s.Auth.AllowOAuthToken(s.clientIP(r)); errors.Is(err, auth.ErrRateLimited) {
			writeRateLimited(w)
			return
		}
	}
	form, ok := readForm(w, r)
	if !ok {
		return
	}
	tok, err := s.Auth.OAuthToken(r.Context(), form, user, pass, hasBasic)
	if err != nil {
		var reuse *auth.RefreshReuseError
		if errors.As(err, &reuse) {
			actor := reuse.UserID
			s.Audit.Record(r.Context(), store.AuditRow{
				ActorUserID: &actor,
				Via:         audit.ViaMCP,
				Action:      audit.ActionOAuthRefreshReuse,
				Decision:    audit.DecisionDenied,
				Detail:      map[string]any{"grant_id": reuse.GrantID.String(), "client_id": reuse.ClientID},
			})
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid grant", "")
			return
		}
		s.writeOAuthResult(w, err)
		return
	}
	raw, err := json.Marshal(tok)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "server error", "")
		return
	}
	writeJSON(w, http.StatusOK, raw)
}

func (s *Server) handleOAuthRevoke(w http.ResponseWriter, r *http.Request) {
	form, ok := readForm(w, r)
	if !ok {
		return
	}
	user, pass, hasBasic := basicAuth(r)
	res, err := s.Auth.Revoke(r.Context(), form, user, pass, hasBasic)
	if err != nil {
		s.writeOAuthResult(w, err)
		return
	}
	if res.Revoked {
		actor := res.UserID
		s.Audit.Record(r.Context(), store.AuditRow{
			ActorUserID: &actor,
			Via:         audit.ViaMCP,
			Action:      audit.ActionOAuthTokenRevoke,
			Decision:    audit.DecisionAllowed,
			Detail:      map[string]any{"grant_id": res.GrantID.String(), "client_id": res.ClientID},
		})
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleOAuthRequestGet(w http.ResponseWriter, r *http.Request) {
	p, ok := s.consoleUser(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, uuid.Nil, authz.CapSession); err != nil {
		s.deny(w, r, p, nil, nil, nil, "", err)
		return
	}
	view, err := s.Auth.Consent(r.Context(), r.PathValue("id"), p.User.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeOK(w, http.StatusOK, map[string]any{
		"id": view.ID,
		"client": map[string]any{
			"id":       view.ClientID,
			"name":     view.ClientName,
			"verified": false,
		},
		"redirect_host":  view.RedirectHost,
		"resource":       view.Resource,
		"remembered":     view.Remembered,
		"projects_count": view.ProjectsCount,
		"expires_at":     view.ExpiresAt,
	})
}

func (s *Server) handleOAuthRequestApprove(w http.ResponseWriter, r *http.Request) {
	p, ok := s.consoleUser(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, uuid.Nil, authz.CapSession); err != nil {
		s.deny(w, r, p, nil, nil, nil, "", err)
		return
	}
	res, err := s.Auth.ApproveConsent(r.Context(), r.PathValue("id"), p.User.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		Action: audit.ActionOAuthAuthorize,
		Detail: oauthAuditDetail(res),
	})
	writeOK(w, http.StatusOK, map[string]any{"redirect_to": res.RedirectTo})
}

func (s *Server) handleOAuthRequestDeny(w http.ResponseWriter, r *http.Request) {
	p, ok := s.consoleUser(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, uuid.Nil, authz.CapSession); err != nil {
		s.deny(w, r, p, nil, nil, nil, "", err)
		return
	}
	res, err := s.Auth.DenyConsent(r.Context(), r.PathValue("id"), p.User.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		Action:   audit.ActionOAuthAuthorize,
		Decision: audit.DecisionDenied,
		Detail:   oauthAuditDetail(res),
	})
	writeOK(w, http.StatusOK, map[string]any{"redirect_to": res.RedirectTo})
}

func (s *Server) handleGrantList(w http.ResponseWriter, r *http.Request) {
	p, ok := s.consoleUser(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, uuid.Nil, authz.CapSession); err != nil {
		s.deny(w, r, p, nil, nil, nil, "", err)
		return
	}
	grants, err := s.Auth.ListGrants(r.Context(), p.User.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	items := make([]map[string]any, 0, len(grants))
	for _, g := range grants {
		items = append(items, map[string]any{
			"id":            g.ID.String(),
			"client_name":   g.ClientName,
			"redirect_host": g.RedirectHost,
			"created_at":    g.CreatedAt,
			"last_used_at":  g.LastUsedAt,
			"kind":          g.Kind,
		})
	}
	writeOK(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleGrantDelete(w http.ResponseWriter, r *http.Request) {
	p, ok := s.consoleUser(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, uuid.Nil, authz.CapSession); err != nil {
		s.deny(w, r, p, nil, nil, nil, "", err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeCode(w, "not_found", "not found")
		return
	}
	grants, err := s.Auth.ListGrants(r.Context(), p.User.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	var clientID string
	found := false
	for _, g := range grants {
		if g.ID == id {
			clientID = g.ClientID
			found = true
			break
		}
	}
	if !found {
		writeCode(w, "not_found", "not found")
		return
	}
	if err := s.Auth.DeleteGrant(r.Context(), p.User.ID, id); err != nil {
		s.fail(w, err)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{
		Action: audit.ActionOAuthTokenRevoke,
		Detail: map[string]any{"grant_id": id.String(), "client_id": clientID},
	})
	writeOK(w, http.StatusOK, nil)
}

func (s *Server) consoleUser(w http.ResponseWriter, r *http.Request) (principal, bool) {
	p, ok := principalFrom(r.Context())
	if !ok {
		writeCode(w, "unauthorized", "unauthorized")
		return principal{}, false
	}
	if p.Session.Kind != store.KindConsole {
		writeCode(w, "unauthorized", "unauthorized")
		return principal{}, false
	}
	return p, true
}

func oauthAuditDetail(res auth.ConsentResult) map[string]any {
	detail := map[string]any{
		"client_id":     res.ClientID,
		"client_name":   res.ClientName,
		"redirect_host": res.RedirectHost,
	}
	if res.GrantID != uuid.Nil {
		detail["grant_id"] = res.GrantID.String()
	}
	return detail
}

func (s *Server) writeOAuthResult(w http.ResponseWriter, err error) {
	var oe *auth.OAuthError
	if errors.As(err, &oe) {
		writeOAuthError(w, oe.Status, oe.Code, oe.Desc, oe.Authenticate)
		return
	}
	s.logErr(err)
	writeOAuthError(w, http.StatusInternalServerError, "server_error", "server error", "")
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc, authenticate string) {
	if authenticate != "" {
		w.Header().Set("WWW-Authenticate", authenticate)
	}
	raw, err := json.Marshal(struct {
		Error string `json:"error"`
		Desc  string `json:"error_description"`
	}{Error: code, Desc: desc})
	if err != nil {
		raw = []byte(`{"error":"server_error","error_description":"server error"}`)
		status = http.StatusInternalServerError
	}
	writeJSON(w, status, raw)
}

func writeRateLimited(w http.ResponseWriter) {
	writeJSON(w, http.StatusTooManyRequests, []byte(`{"error":"rate_limited"}`))
}

func writeHTML(w http.ResponseWriter, status int, page string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte("<!DOCTYPE html><html><body>" + html.EscapeString(page) + "</body></html>"))
}

func readJSONBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid request", "")
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	raw, err := io.ReadAll(r.Body)
	if err != nil || len(raw) == 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid request", "")
		return nil, false
	}
	return raw, true
}

func readForm(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid request", "")
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid request", "")
		return nil, false
	}
	return r.PostForm, true
}

func basicAuth(r *http.Request) (user, pass string, ok bool) {
	user, pass, ok = r.BasicAuth()
	return user, pass, ok
}
