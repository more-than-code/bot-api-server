package api

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/auth"
	"github.com/more-than-code/bot-api-server/internal/authz"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func (s *Server) handleGoogleStart(w http.ResponseWriter, r *http.Request) {
	if err := s.Auth.AllowGoogleIP(s.clientIP(r)); err != nil {
		writeCode(w, "unavailable", "unavailable")
		return
	}
	redirect := r.URL.Query().Get("redirect_uri")
	out, err := s.Auth.StartGoogle(r.Context(), redirect)
	if err != nil {
		if errors.Is(err, auth.ErrRedirect) {
			writeCode(w, "bad_request", "redirect_uri is not allowed")
			return
		}
		if errors.Is(err, auth.ErrUnavailable) {
			writeCode(w, "unavailable", "unavailable")
			return
		}
		s.logErr(err)
		writeCode(w, "error", "internal error")
		return
	}
	writeOK(w, http.StatusOK, map[string]string{
		"authorize_url": out.AuthorizeURL,
		"state":         out.State,
	})
}

func (s *Server) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code     string `json:"code"`
		State    string `json:"state"`
		Redirect string `json:"redirect_uri"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Code == "" || body.State == "" || body.Redirect == "" {
		writeCode(w, "bad_request", "invalid json")
		return
	}
	out, err := s.Auth.FinishGoogle(r.Context(), body.Code, body.State, body.Redirect)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrUnverified):
			writeCode(w, "forbidden", "email is not verified")
		case errors.Is(err, auth.ErrRedirect), errors.Is(err, store.ErrState):
			writeCode(w, "bad_request", "invalid state")
		case errors.Is(err, store.ErrConflict):
			writeCode(w, "conflict", "conflict")
		default:
			s.logErr(err)
			writeCode(w, "error", "internal error")
		}
		return
	}
	s.Audit.Record(r.Context(), store.AuditRow{
		ActorUserID: idPtr(out.User.ID),
		Via:         audit.ViaConsole,
		Action:      audit.ActionSignIn,
		Decision:    audit.DecisionAllowed,
		Detail:      map[string]any{"provider": "google"},
	})
	writeOK(w, http.StatusOK, map[string]any{
		"token":      out.Token,
		"expires_at": out.ExpiresAt.UTC(),
		"user":       out.User,
	})
}

func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request) {
	p, ok := s.require(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, uuid.Nil, authz.CapSession); err != nil {
		s.deny(w, r, p, nil, nil, nil, "", err)
		return
	}
	if err := s.Auth.SignOut(r.Context(), p.Session.ID); err != nil {
		s.fail(w, err)
		return
	}
	writeOK(w, http.StatusOK, nil)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p, ok := s.require(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, uuid.Nil, authz.CapSession); err != nil {
		s.deny(w, r, p, nil, nil, nil, "", err)
		return
	}
	idents, err := s.Store.ListIdentities(r.Context(), p.User.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	projects, err := s.Store.ListAllProjects(r.Context(), p.User.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	view := make([]map[string]string, 0, len(idents))
	for _, idn := range idents {
		view = append(view, map[string]string{"provider": idn.Provider, "email": idn.Email})
	}
	if projects == nil {
		projects = []store.Project{}
	}
	writeOK(w, http.StatusOK, map[string]any{
		"user":       p.User,
		"identities": view,
		"projects":   projects,
	})
}

func remoteHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return addr
	}
	return host
}

// clientIP is the TCP peer. X-Forwarded-For is used only when that peer is
// TrustedProxy, and then only the rightmost address, which is the one the
// trusted proxy appended.
func (s *Server) clientIP(r *http.Request) string {
	host := remoteHost(r.RemoteAddr)
	if s.TrustedProxy == "" || host != s.TrustedProxy {
		return host
	}
	if ip := forwardedClient(r.Header.Get("X-Forwarded-For")); ip != "" {
		return ip
	}
	return host
}

func forwardedClient(header string) string {
	parts := strings.Split(header, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

func (s *Server) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ClientName string `json:"client_name"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	name := strings.TrimSpace(body.ClientName)
	if n := utf8.RuneCountInString(name); n < 1 || n > 100 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		writeCode(w, "bad_request", "invalid client_name")
		return
	}
	if err := s.Auth.AllowDeviceIP(s.clientIP(r)); err != nil {
		write(w, http.StatusTooManyRequests, "slow_down", "", nil)
		return
	}
	out, err := s.Auth.StartDevice(r.Context(), name)
	if err != nil {
		s.logErr(err)
		writeCode(w, "error", "internal error")
		return
	}
	writeOK(w, http.StatusOK, map[string]any{
		"device_code":               out.DeviceCode,
		"user_code":                 out.UserCode,
		"verification_uri":          out.VerificationURI,
		"verification_uri_complete": out.VerificationURIComplete,
		"expires_in":                out.ExpiresIn,
		"interval":                  out.Interval,
	})
}

func (s *Server) handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceCode string `json:"device_code"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.DeviceCode == "" {
		writeCode(w, "bad_request", "device_code is required")
		return
	}
	if err := s.Auth.AllowDeviceTokenIP(s.clientIP(r)); err != nil {
		write(w, http.StatusTooManyRequests, "slow_down", "", nil)
		return
	}
	out, err := s.Auth.PollDevice(r.Context(), body.DeviceCode)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrPending):
			writeCode(w, "authorization_pending", "")
		case errors.Is(err, auth.ErrSlowDown):
			writeCode(w, "slow_down", "")
		case errors.Is(err, auth.ErrExpiredToken):
			writeCode(w, "expired_token", "")
		case errors.Is(err, auth.ErrAccessDenied):
			writeCode(w, "access_denied", "")
		default:
			s.logErr(err)
			writeCode(w, "error", "internal error")
		}
		return
	}
	sess, user, err := s.Auth.Authenticate(r.Context(), out.Token)
	if err != nil {
		s.logErr(err)
		writeCode(w, "error", "internal error")
		return
	}
	s.Audit.Record(r.Context(), store.AuditRow{
		ActorUserID: idPtr(user.ID),
		Via:         audit.ViaMCP,
		Action:      audit.ActionSignIn,
		Decision:    audit.DecisionAllowed,
	})
	_ = sess
	writeOK(w, http.StatusOK, map[string]any{
		"token":      out.Token,
		"expires_at": out.ExpiresAt.UTC(),
	})
}

func (s *Server) handleDeviceGet(w http.ResponseWriter, r *http.Request) {
	p, ok := s.consoleUser(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, uuid.Nil, authz.CapSession); err != nil {
		s.deny(w, r, p, nil, nil, nil, "", err)
		return
	}
	st, err := s.Auth.DeviceStatus(r.Context(), r.PathValue("user_code"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeOK(w, http.StatusOK, map[string]any{
		"user_code":   st.UserCode,
		"client_name": st.ClientName,
		"expires_at":  st.ExpiresAt.UTC(),
		"status":      st.Status,
	})
}

func (s *Server) handleDeviceApprove(w http.ResponseWriter, r *http.Request) {
	p, ok := s.consoleUser(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, uuid.Nil, authz.CapSession); err != nil {
		s.deny(w, r, p, nil, nil, nil, audit.ActionDeviceApprove, err)
		return
	}
	s.finishDevice(w, r, p, true)
}

func (s *Server) handleDeviceDeny(w http.ResponseWriter, r *http.Request) {
	p, ok := s.consoleUser(w, r)
	if !ok {
		return
	}
	if err := authz.Authorize(r.Context(), p.User.ID, uuid.Nil, authz.CapSession); err != nil {
		s.deny(w, r, p, nil, nil, nil, audit.ActionDeviceDeny, err)
		return
	}
	s.finishDevice(w, r, p, false)
}

func (s *Server) finishDevice(w http.ResponseWriter, r *http.Request, p principal, approve bool) {
	code := r.PathValue("user_code")
	var err error
	action := audit.ActionDeviceDeny
	if approve {
		action = audit.ActionDeviceApprove
		err = s.Auth.ApproveDevice(r.Context(), code, p.User.ID)
	} else {
		err = s.Auth.DenyDevice(r.Context(), code, p.User.ID)
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.auditOK(r.Context(), p, store.AuditRow{Action: action})
	writeOK(w, http.StatusOK, nil)
}
