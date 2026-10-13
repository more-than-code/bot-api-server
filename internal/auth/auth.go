// Package auth implements Google OIDC sign-in, console sessions, and the device flow.
// Plaintext session tokens, device codes, and OAuth state stay out of the store.
package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/config"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
	"golang.org/x/oauth2"
)

const (
	oauthStateTTL     = 10 * time.Minute
	oauthSweepEvery   = time.Minute
	oauthStateCap     = 10000
	consoleSessionTTL = 7 * 24 * time.Hour
	mcpSessionTTL     = 30 * 24 * time.Hour
	sessionConsole    = "console"
	sessionMCP        = "mcp"
	deviceIPLimit     = 10
	tokenIPLimit      = 30
	googleIPLimit     = 20
	deviceIPWindow    = time.Minute
	pollCap           = 10000
)

var (
	ErrUnverified   = errors.New("unverified email")
	ErrPending      = errors.New("authorization_pending")
	ErrSlowDown     = errors.New("slow_down")
	ErrIPLimited    = errors.New("slow_down") // distinct from ErrSlowDown so HTTP can use 429
	ErrExpiredToken = errors.New("expired_token")
	ErrAccessDenied = errors.New("access_denied")
	ErrRedirect     = errors.New("redirect_uri not allowed")
	ErrUnavailable  = errors.New("unavailable")
)

// Service is the Google and device-flow authenticator.
type Service struct {
	st        store.Store
	cfg       config.Config
	clock     func() time.Time
	mu        sync.Mutex
	client    *http.Client
	prov      *oidc.Provider
	states    map[string]oauthState
	polls     map[string]pollRec
	ips       map[string][]time.Time
	tokenIPs  map[string][]time.Time
	googleIPs map[string][]time.Time
	lastSweep time.Time
}

type oauthState struct {
	verifier    string
	redirectURI string
	expires     time.Time
}

// GoogleStart is the authorization redirect and the single-use state.
type GoogleStart struct {
	AuthorizeURL string
	State        string
}

// SessionIssue is a new console session. Token is the plaintext bearer, returned once.
type SessionIssue struct {
	Token     string
	ExpiresAt time.Time
	User      store.User
	Session   store.Session
}

// New returns a service. A nil clock uses time.Now().UTC.
func New(st store.Store, cfg config.Config, now func() time.Time) *Service {
	return &Service{
		st:        st,
		cfg:       cfg,
		clock:     now,
		states:    map[string]oauthState{},
		polls:     map[string]pollRec{},
		ips:       map[string][]time.Time{},
		tokenIPs:  map[string][]time.Time{},
		googleIPs: map[string][]time.Time{},
	}
}

// SetHTTPClient sets the client used for discovery and token exchange.
func (s *Service) SetHTTPClient(c *http.Client) {
	s.mu.Lock()
	s.client = c
	s.mu.Unlock()
}

func (s *Service) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now().UTC()
}

func (s *Service) withClient(ctx context.Context) context.Context {
	s.mu.Lock()
	c := s.client
	s.mu.Unlock()
	if c == nil {
		return ctx
	}
	ctx = oidc.ClientContext(ctx, c)
	return context.WithValue(ctx, oauth2.HTTPClient, c)
}

func (s *Service) provider(ctx context.Context) (*oidc.Provider, error) {
	s.mu.Lock()
	p := s.prov
	s.mu.Unlock()
	if p != nil {
		return p, nil
	}
	p, err := oidc.NewProvider(s.withClient(ctx), s.cfg.GoogleIssuer)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prov != nil {
		return s.prov, nil
	}
	s.prov = p
	return p, nil
}

func (s *Service) oauthConf(p *oidc.Provider, redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.cfg.GoogleClientID,
		ClientSecret: s.cfg.GoogleClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  redirectURI,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
}

// StartGoogle begins an authorization-code flow when redirectURI is allowlisted.
// The in-memory state map is capped at 10 000 entries. A full map returns ErrUnavailable.
func (s *Service) StartGoogle(ctx context.Context, redirectURI string) (GoogleStart, error) {
	if !s.cfg.RedirectAllowed(redirectURI) {
		return GoogleStart{}, ErrRedirect
	}
	now := s.now()
	if err := s.reserveState(now); err != nil {
		return GoogleStart{}, err
	}
	p, err := s.provider(ctx)
	if err != nil {
		return GoogleStart{}, err
	}
	plain, _, err := secret.NewToken()
	if err != nil {
		return GoogleStart{}, err
	}
	verifier := oauth2.GenerateVerifier()
	if err := s.putState(plain, verifier, redirectURI); err != nil {
		return GoogleStart{}, err
	}
	u := s.oauthConf(p, redirectURI).AuthCodeURL(plain, oauth2.S256ChallengeOption(verifier))
	return GoogleStart{AuthorizeURL: u, State: plain}, nil
}

// reserveState sweeps expired entries and rejects a start when the map is full.
func (s *Service) reserveState(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if len(s.states) >= oauthStateCap {
		return ErrUnavailable
	}
	return nil
}

func (s *Service) putState(plain, verifier, redirectURI string) error {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if len(s.states) >= oauthStateCap {
		return ErrUnavailable
	}
	s.states[plain] = oauthState{
		verifier:    verifier,
		redirectURI: redirectURI,
		expires:     now.Add(oauthStateTTL),
	}
	return nil
}

// Sweep drops expired OAuth state, idle device-poll records, and old IP windows.
// It runs at most once a minute.
func (s *Service) Sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
}

func (s *Service) sweepLocked(now time.Time) {
	if !s.lastSweep.IsZero() && now.Sub(s.lastSweep) < oauthSweepEvery {
		return
	}
	s.lastSweep = now
	for key, st := range s.states {
		if !now.Before(st.expires) {
			delete(s.states, key)
		}
	}
	cut := now.Add(-deviceIPWindow)
	pruneIPBucket(s.ips, cut)
	pruneIPBucket(s.tokenIPs, cut)
	pruneIPBucket(s.googleIPs, cut)
	for key, rec := range s.polls {
		expired := !rec.expires.IsZero() && !now.Before(rec.expires)
		idle := rec.seen && !rec.last.IsZero() && now.Sub(rec.last) > 24*time.Hour
		if expired || idle {
			delete(s.polls, key)
		}
	}
}

func pruneIPBucket(bucket map[string][]time.Time, cut time.Time) {
	for ip, hits := range bucket {
		kept := make([]time.Time, 0, len(hits))
		for _, at := range hits {
			if at.After(cut) {
				kept = append(kept, at)
			}
		}
		if len(kept) == 0 {
			delete(bucket, ip)
			continue
		}
		bucket[ip] = kept
	}
}

// AllowDeviceIP counts one code request for ip. More than 10 in a minute returns ErrIPLimited.
func (s *Service) AllowDeviceIP(ip string) error {
	return s.hitIP(s.ips, ip, deviceIPLimit, ErrIPLimited)
}

// AllowDeviceTokenIP counts one token poll for ip. More than 30 in a minute returns ErrIPLimited.
func (s *Service) AllowDeviceTokenIP(ip string) error {
	return s.hitIP(s.tokenIPs, ip, tokenIPLimit, ErrIPLimited)
}

// AllowGoogleIP counts one authorization start for ip. More than 20 in a minute returns ErrUnavailable.
func (s *Service) AllowGoogleIP(ip string) error {
	return s.hitIP(s.googleIPs, ip, googleIPLimit, ErrUnavailable)
}

func (s *Service) hitIP(bucket map[string][]time.Time, ip string, limit int, over error) error {
	if ip == "" {
		ip = "unknown"
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	cut := now.Add(-deviceIPWindow)
	kept := make([]time.Time, 0, len(bucket[ip])+1)
	for _, at := range bucket[ip] {
		if at.After(cut) {
			kept = append(kept, at)
		}
	}
	if len(kept) >= limit {
		bucket[ip] = kept
		return over
	}
	bucket[ip] = append(kept, now)
	return nil
}

// FinishGoogle exchanges the code, checks the ID token, and issues a console session.
func (s *Service) FinishGoogle(ctx context.Context, code, state, redirectURI string) (SessionIssue, error) {
	verifier, err := s.takeState(state, redirectURI)
	if err != nil {
		return SessionIssue{}, err
	}
	p, err := s.provider(ctx)
	if err != nil {
		return SessionIssue{}, err
	}
	tok, err := s.oauthConf(p, redirectURI).Exchange(s.withClient(ctx), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return SessionIssue{}, err
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return SessionIssue{}, errors.New("id_token missing")
	}
	idt, err := p.Verifier(&oidc.Config{
		ClientID: s.cfg.GoogleClientID,
		Now:      s.now,
	}).Verify(ctx, raw)
	if err != nil {
		return SessionIssue{}, err
	}
	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := idt.Claims(&claims); err != nil {
		return SessionIssue{}, err
	}
	email := strings.ToLower(claims.Email)
	if email == "" || !claims.EmailVerified {
		return SessionIssue{}, ErrUnverified
	}
	at := s.now()
	user, err := s.st.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject:   claims.Sub,
		Email:     email,
		Name:      claims.Name,
		AvatarURL: claims.Picture,
		At:        at,
	})
	if err != nil {
		return SessionIssue{}, err
	}
	plain, hash, err := secret.NewToken()
	if err != nil {
		return SessionIssue{}, err
	}
	exp := at.Add(consoleSessionTTL)
	sess, err := s.st.CreateSession(ctx, user.ID, hash, sessionConsole, exp, at)
	if err != nil {
		return SessionIssue{}, err
	}
	return SessionIssue{
		Token:     plain,
		ExpiresAt: sess.ExpiresAt,
		User:      user,
		Session:   sess,
	}, nil
}

// takeState deletes the state. Missing, expired, used, or a redirect mismatch is store.ErrState.
func (s *Service) takeState(state, redirectURI string) (string, error) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.states[state]
	if !ok {
		return "", store.ErrState
	}
	delete(s.states, state)
	if !now.Before(st.expires) || st.redirectURI != redirectURI {
		return "", store.ErrState
	}
	return st.verifier, nil
}

// Authenticate resolves a session token. It does not touch last_seen.
func (s *Service) Authenticate(ctx context.Context, bearer string) (store.Session, store.User, error) {
	token := bearer
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}
	if token == "" {
		return store.Session{}, store.User{}, store.ErrUnauthorized
	}
	return s.st.GetSession(ctx, secret.Hash(token), s.now())
}

// SignOut deletes the session.
func (s *Service) SignOut(ctx context.Context, sessionID uuid.UUID) error {
	return s.st.DeleteSession(ctx, sessionID)
}
