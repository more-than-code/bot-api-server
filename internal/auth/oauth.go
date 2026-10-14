package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const (
	accessTTL     = time.Hour
	codeTTL       = 60 * time.Second
	requestTTL    = 5 * time.Minute
	delegatedTTL  = 5 * time.Minute
	grantRemember = 30 * 24 * time.Hour
	clientIdle    = 30 * 24 * time.Hour

	grantAuthorizationCode = "authorization_code"
	grantRefreshToken      = "refresh_token"
	grantTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
	subjectAccessToken     = "urn:ietf:params:oauth:token-type:access_token"
	scopeDeploybot         = "deploybot"
)

// OAuthError is an RFC 6749 token or registration error.
// Authenticate is a WWW-Authenticate value, or empty.
type OAuthError struct {
	Status       int
	Code         string
	Desc         string
	Authenticate string
}

func (e *OAuthError) Error() string { return e.Code }

func oauthErr(status int, code, desc, authenticate string) *OAuthError {
	return &OAuthError{Status: status, Code: code, Desc: desc, Authenticate: authenticate}
}

// RefreshReuseError is a rotated refresh token. The family is already revoked.
type RefreshReuseError struct {
	UserID   uuid.UUID
	GrantID  uuid.UUID
	ClientID string
}

func (e *RefreshReuseError) Error() string { return "invalid_grant" }

// Metadata is the authorization-server document (oauth-v1 §1).
type Metadata struct {
	Issuer          string   `json:"issuer"`
	Authorization   string   `json:"authorization_endpoint"`
	Token           string   `json:"token_endpoint"`
	Registration    string   `json:"registration_endpoint"`
	Revocation      string   `json:"revocation_endpoint"`
	ResponseTypes   []string `json:"response_types_supported"`
	GrantTypes      []string `json:"grant_types_supported"`
	ChallengeMethod []string `json:"code_challenge_methods_supported"`
	AuthMethods     []string `json:"token_endpoint_auth_methods_supported"`
	Scopes          []string `json:"scopes_supported"`
}

// RegisteredClient is the RFC 7591 response. There is no client_secret.
type RegisteredClient struct {
	ClientID      string   `json:"client_id"`
	IssuedAt      int64    `json:"client_id_issued_at"`
	ClientName    string   `json:"client_name"`
	RedirectURIs  []string `json:"redirect_uris"`
	GrantTypes    []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
	AuthMethod    string   `json:"token_endpoint_auth_method"`
}

// TokenResponse is an access token, and a refresh token when the grant has one.
type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	Scope           string `json:"scope,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
}

// AuthorizeOutcome is either an HTML page or a redirect. Location is unset for a page.
type AuthorizeOutcome struct {
	Status   int
	Page     string
	Location string
}

// ConsentView is the console payload for a pending request.
type ConsentView struct {
	ID            string
	ClientID      string
	ClientName    string
	RedirectHost  string
	Resource      string
	Remembered    bool
	ProjectsCount int
	ExpiresAt     time.Time
}

// ConsentResult is the browser redirect after allow or deny.
type ConsentResult struct {
	RedirectTo   string
	ClientID     string
	ClientName   string
	RedirectHost string
	GrantID      uuid.UUID
}

type registerBody struct {
	ClientName    string   `json:"client_name"`
	RedirectURIs  []string `json:"redirect_uris"`
	GrantTypes    []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
	AuthMethod    *string  `json:"token_endpoint_auth_method"`
}

// MetadataDocument builds the discovery document from BOT_API_PUBLIC_ORIGIN.
func (s *Service) MetadataDocument() (Metadata, error) {
	issuer := strings.TrimRight(s.cfg.PublicOrigin, "/")
	if issuer == "" {
		return Metadata{}, errors.New("public origin is not configured")
	}
	return Metadata{
		Issuer:          issuer,
		Authorization:   issuer + "/oauth/authorize",
		Token:           issuer + "/oauth/token",
		Registration:    issuer + "/oauth/register",
		Revocation:      issuer + "/oauth/revoke",
		ResponseTypes:   []string{"code"},
		GrantTypes:      []string{grantAuthorizationCode, grantRefreshToken, grantTokenExchange},
		ChallengeMethod: []string{"S256"},
		AuthMethods:     []string{"none", "client_secret_basic"},
		Scopes:          []string{scopeDeploybot},
	}, nil
}

// SetMCPClientSecret stores bot-mcp-server. plain is hashed and not kept.
func (s *Service) SetMCPClientSecret(ctx context.Context, plain string) error {
	if plain == "" {
		return errors.New("mcp client secret is empty")
	}
	sum := secret.Hash(plain)
	now := s.now()
	err := s.st.PutOAuthClient(ctx, store.OAuthClient{
		ID:            store.ClientMCP,
		Name:          store.ClientMCP,
		RedirectURIs:  []string{},
		GrantTypes:    []string{grantTokenExchange},
		ResponseTypes: []string{"code"},
		AuthMethod:    "client_secret_basic",
		SecretHash:    sum,
		Kind:          store.ClientInternal,
		CreatedAt:     now,
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.mcpSecret = sum
	s.mu.Unlock()
	return nil
}

func (s *Service) secretMatches(plain string) bool {
	sum := secret.Hash(plain)
	s.mu.Lock()
	want := append([]byte(nil), s.mcpSecret...)
	s.mu.Unlock()
	if len(want) != len(sum) {
		subtle.ConstantTimeCompare(sum, sum)
		return false
	}
	return subtle.ConstantTimeCompare(sum, want) == 1
}

// PurgeOAuthClients deletes public clients with no use for 30 days.
func (s *Service) PurgeOAuthClients(ctx context.Context) error {
	return s.st.DeleteStalePublicClients(ctx, s.now().Add(-clientIdle))
}

// Register creates a public client. Unknown JSON members are ignored.
func (s *Service) Register(ctx context.Context, raw []byte) (RegisteredClient, error) {
	if err := s.st.DeleteStalePublicClients(ctx, s.now().Add(-clientIdle)); err != nil {
		return RegisteredClient{}, err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	var body registerBody
	if err := dec.Decode(&body); err != nil {
		return RegisteredClient{}, oauthErr(http.StatusBadRequest, "invalid_request", "invalid request", "")
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		return RegisteredClient{}, oauthErr(http.StatusBadRequest, "invalid_request", "invalid request", "")
	}
	if !validRedirectList(body.RedirectURIs) {
		return RegisteredClient{}, oauthErr(http.StatusBadRequest, "invalid_redirect_uri", "invalid redirect uri", "")
	}
	if !validClientName(body.ClientName) {
		return RegisteredClient{}, oauthErr(http.StatusBadRequest, "invalid_client_metadata", "invalid client metadata", "")
	}
	grants, ok := normalizeGrants(body.GrantTypes)
	if !ok {
		return RegisteredClient{}, oauthErr(http.StatusBadRequest, "invalid_client_metadata", "invalid client metadata", "")
	}
	responses, ok := normalizeResponses(body.ResponseTypes)
	if !ok {
		return RegisteredClient{}, oauthErr(http.StatusBadRequest, "invalid_client_metadata", "invalid client metadata", "")
	}
	method, ok := normalizeAuth(body.AuthMethod)
	if !ok {
		return RegisteredClient{}, oauthErr(http.StatusBadRequest, "invalid_client_metadata", "invalid client metadata", "")
	}
	id, _, err := secret.NewToken()
	if err != nil {
		return RegisteredClient{}, err
	}
	now := s.now()
	client := store.OAuthClient{
		ID:            id,
		Name:          body.ClientName,
		RedirectURIs:  append([]string(nil), body.RedirectURIs...),
		GrantTypes:    grants,
		ResponseTypes: responses,
		AuthMethod:    method,
		Kind:          store.ClientPublic,
		CreatedAt:     now,
	}
	if err := s.st.PutOAuthClient(ctx, client); err != nil {
		return RegisteredClient{}, err
	}
	return RegisteredClient{
		ClientID:      id,
		IssuedAt:      now.Unix(),
		ClientName:    client.Name,
		RedirectURIs:  client.RedirectURIs,
		GrantTypes:    client.GrantTypes,
		ResponseTypes: client.ResponseTypes,
		AuthMethod:    method,
	}, nil
}

// BeginAuthorize validates a GET /oauth/authorize query and stores a pending request.
func (s *Service) BeginAuthorize(ctx context.Context, q url.Values) (AuthorizeOutcome, error) {
	rawRedirect := q.Get("redirect_uri")
	client, clientOK, err := s.publicClient(ctx, q.Get("client_id"))
	if err != nil {
		return AuthorizeOutcome{}, err
	}
	if !clientOK || !presentedRedirectOK(client, rawRedirect) {
		return AuthorizeOutcome{Status: http.StatusBadRequest, Page: invalidAuthorizationPage}, nil
	}
	hasState := q.Has("state")
	state := q.Get("state")
	fail := func(code, desc string) (AuthorizeOutcome, error) {
		loc, locErr := errorRedirect(rawRedirect, code, desc, state, hasState)
		if locErr != nil {
			return AuthorizeOutcome{Status: http.StatusBadRequest, Page: invalidAuthorizationPage}, nil
		}
		return AuthorizeOutcome{Status: http.StatusSeeOther, Location: loc}, nil
	}
	if q.Get("response_type") != "code" {
		return fail("unsupported_response_type", "unsupported response type")
	}
	if q.Get("code_challenge_method") != "S256" || !validChallenge(q.Get("code_challenge")) {
		return fail("invalid_request", "invalid request")
	}
	if q.Has("scope") && q.Get("scope") != scopeDeploybot {
		return fail("invalid_scope", "invalid scope")
	}
	if q.Get("resource") == "" || q.Get("resource") != s.cfg.MCPResource {
		return fail("invalid_target", "invalid target")
	}
	if hasState && (strings.Contains(state, "\x00") || utf8.RuneCountInString(state) > 512) {
		return fail("invalid_request", "invalid request")
	}
	if !hasGrant(client, grantAuthorizationCode) {
		return fail("unauthorized_client", "unauthorized client")
	}
	origin := strings.TrimRight(s.cfg.ConsoleOrigin, "/")
	if origin == "" {
		return AuthorizeOutcome{}, ErrUnavailable
	}
	id, _, err := secret.NewToken()
	if err != nil {
		return AuthorizeOutcome{}, err
	}
	now := s.now()
	scope := scopeDeploybot
	if q.Has("scope") {
		scope = q.Get("scope")
	}
	req := store.OAuthRequest{
		ID:          id,
		ClientID:    client.ID,
		RedirectURI: rawRedirect,
		Challenge:   q.Get("code_challenge"),
		State:       state,
		Resource:    q.Get("resource"),
		Scope:       scope,
		CreatedAt:   now,
		ExpiresAt:   now.Add(requestTTL),
	}
	if err := s.st.InsertOAuthRequest(ctx, req); err != nil {
		return AuthorizeOutcome{}, err
	}
	if err := s.st.TouchOAuthClient(ctx, client.ID, now); err != nil {
		return AuthorizeOutcome{}, err
	}
	loc := origin + "/oauth/consent?request=" + url.QueryEscape(id)
	return AuthorizeOutcome{Status: http.StatusSeeOther, Location: loc}, nil
}

func (s *Service) publicClient(ctx context.Context, id string) (store.OAuthClient, bool, error) {
	if id == "" {
		return store.OAuthClient{}, false, nil
	}
	client, err := s.st.GetOAuthClient(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.OAuthClient{}, false, nil
	}
	if err != nil {
		return store.OAuthClient{}, false, err
	}
	if client.Kind != store.ClientPublic {
		return store.OAuthClient{}, false, nil
	}
	return client, true, nil
}

func presentedRedirectOK(client store.OAuthClient, raw string) bool {
	if raw == "" || validateRedirectURI(raw) != nil {
		return false
	}
	return redirectMatchesAny(client.RedirectURIs, raw)
}

// OAuthToken implements the token endpoint. hasBasic is true when the
// Authorization scheme is Basic. The secret is compared even when the user is wrong.
func (s *Service) OAuthToken(ctx context.Context, form url.Values, basicUser, basicPass string, hasBasic bool) (TokenResponse, error) {
	client, confidential, err := s.tokenClient(ctx, form.Get("client_id"), basicUser, basicPass, hasBasic)
	if err != nil {
		return TokenResponse{}, err
	}
	switch form.Get("grant_type") {
	case "":
		return TokenResponse{}, oauthErr(http.StatusBadRequest, "invalid_request", "invalid request", "")
	case grantAuthorizationCode:
		return s.grantCode(ctx, client, confidential, form)
	case grantRefreshToken:
		return s.grantRefresh(ctx, client, confidential, form)
	case grantTokenExchange:
		return s.grantExchange(ctx, client, confidential, form)
	default:
		return TokenResponse{}, oauthErr(http.StatusBadRequest, "unsupported_grant_type", "unsupported grant type", "")
	}
}

func (s *Service) tokenClient(ctx context.Context, formClientID, basicUser, basicPass string, hasBasic bool) (store.OAuthClient, bool, error) {
	if hasBasic {
		match := s.secretMatches(basicPass)
		if basicUser != store.ClientMCP || !match {
			return store.OAuthClient{}, false, oauthErr(http.StatusUnauthorized, "invalid_client", "invalid client", "Basic")
		}
		client, err := s.st.GetOAuthClient(ctx, store.ClientMCP)
		if err != nil || client.Kind != store.ClientInternal {
			return store.OAuthClient{}, false, oauthErr(http.StatusUnauthorized, "invalid_client", "invalid client", "Basic")
		}
		return client, true, nil
	}
	if formClientID == "" {
		return store.OAuthClient{}, false, oauthErr(http.StatusBadRequest, "invalid_request", "invalid request", "")
	}
	client, err := s.st.GetOAuthClient(ctx, formClientID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (client.Kind != store.ClientPublic || client.AuthMethod != "none")) {
		return store.OAuthClient{}, false, oauthErr(http.StatusUnauthorized, "invalid_client", "invalid client", "")
	}
	if err != nil {
		return store.OAuthClient{}, false, err
	}
	return client, false, nil
}

func (s *Service) grantCode(ctx context.Context, client store.OAuthClient, confidential bool, form url.Values) (TokenResponse, error) {
	if confidential || !hasGrant(client, grantAuthorizationCode) {
		return TokenResponse{}, oauthErr(http.StatusBadRequest, "unauthorized_client", "unauthorized client", "")
	}
	code := form.Get("code")
	redirectURI := form.Get("redirect_uri")
	verifier := form.Get("code_verifier")
	resource := form.Get("resource")
	if code == "" || redirectURI == "" || verifier == "" {
		return TokenResponse{}, oauthErr(http.StatusBadRequest, "invalid_request", "invalid request", "")
	}
	peeked, err := s.st.PeekOAuthCode(ctx, secret.Hash(code))
	if errors.Is(err, store.ErrNotFound) {
		return TokenResponse{}, oauthErr(http.StatusBadRequest, "invalid_grant", "invalid grant", "")
	}
	if err != nil {
		return TokenResponse{}, err
	}
	now := s.now()
	if peeked.UsedAt != nil {
		return s.consumeUsedCode(ctx, peeked, client.ID, redirectURI, resource, now)
	}
	if peeked.Resource != resource {
		return TokenResponse{}, oauthErr(http.StatusBadRequest, "invalid_target", "invalid target", "")
	}
	if peeked.ClientID != client.ID || peeked.RedirectURI != redirectURI || !now.Before(peeked.ExpiresAt) || !s256Match(verifier, peeked.Challenge) {
		return TokenResponse{}, oauthErr(http.StatusBadRequest, "invalid_grant", "invalid grant", "")
	}
	accessPlain, accessHash, err := secret.NewToken()
	if err != nil {
		return TokenResponse{}, err
	}
	refreshPlain, refreshHash, err := secret.NewToken()
	if err != nil {
		return TokenResponse{}, err
	}
	_, _, err = s.st.RedeemOAuthCode(ctx, store.RedeemCode{
		Hash:           secret.Hash(code),
		ClientID:       client.ID,
		RedirectURI:    redirectURI,
		Resource:       resource,
		At:             now,
		AccessHash:     accessHash,
		AccessExpires:  now.Add(accessTTL),
		RefreshHash:    refreshHash,
		RefreshExpires: now.Add(mcpSessionTTL),
		Audience:       s.mcpAudience(peeked.Resource),
	})
	if errors.Is(err, store.ErrTarget) {
		return TokenResponse{}, oauthErr(http.StatusBadRequest, "invalid_target", "invalid target", "")
	}
	if err != nil {
		return TokenResponse{}, oauthErr(http.StatusBadRequest, "invalid_grant", "invalid grant", "")
	}
	return TokenResponse{
		AccessToken:  accessPlain,
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTTL / time.Second),
		RefreshToken: refreshPlain,
		Scope:        scopeDeploybot,
	}, nil
}

func (s *Service) consumeUsedCode(ctx context.Context, peeked store.OAuthCode, clientID, redirectURI, resource string, now time.Time) (TokenResponse, error) {
	_, _, err := s.st.RedeemOAuthCode(ctx, store.RedeemCode{
		Hash: peeked.Hash, ClientID: clientID, RedirectURI: redirectURI, Resource: resource, At: now,
		AccessHash: peeked.Hash, AccessExpires: now, RefreshHash: peeked.Hash, RefreshExpires: now,
		Audience: peeked.Resource,
	})
	if err != nil && !errors.Is(err, store.ErrReuse) && !errors.Is(err, store.ErrNotFound) {
		return TokenResponse{}, err
	}
	return TokenResponse{}, oauthErr(http.StatusBadRequest, "invalid_grant", "invalid grant", "")
}

func (s *Service) grantRefresh(ctx context.Context, client store.OAuthClient, confidential bool, form url.Values) (TokenResponse, error) {
	if confidential || !hasGrant(client, grantRefreshToken) {
		return TokenResponse{}, oauthErr(http.StatusBadRequest, "unauthorized_client", "unauthorized client", "")
	}
	token := form.Get("refresh_token")
	if token == "" {
		return TokenResponse{}, oauthErr(http.StatusBadRequest, "invalid_request", "invalid request", "")
	}
	now := s.now()
	accessPlain, accessHash, err := secret.NewToken()
	if err != nil {
		return TokenResponse{}, err
	}
	refreshPlain, refreshHash, err := secret.NewToken()
	if err != nil {
		return TokenResponse{}, err
	}
	ident, _, err := s.st.RotateRefresh(ctx, store.RotateRefresh{
		Hash:           secret.Hash(token),
		ClientID:       client.ID,
		Resource:       form.Get("resource"),
		ResourceSet:    form.Has("resource"),
		At:             now,
		AccessHash:     accessHash,
		AccessExpires:  now.Add(accessTTL),
		RefreshHash:    refreshHash,
		RefreshExpires: now.Add(mcpSessionTTL),
		Audience:       s.cfg.MCPResource,
	})
	if errors.Is(err, store.ErrReuse) {
		gid := uuid.Nil
		if ident.GrantID != nil {
			gid = *ident.GrantID
		}
		return TokenResponse{}, &RefreshReuseError{UserID: ident.UserID, GrantID: gid, ClientID: client.ID}
	}
	if errors.Is(err, store.ErrTarget) {
		return TokenResponse{}, oauthErr(http.StatusBadRequest, "invalid_target", "invalid target", "")
	}
	if err != nil {
		return TokenResponse{}, oauthErr(http.StatusBadRequest, "invalid_grant", "invalid grant", "")
	}
	return TokenResponse{
		AccessToken:  accessPlain,
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTTL / time.Second),
		RefreshToken: refreshPlain,
		Scope:        scopeDeploybot,
	}, nil
}

func (s *Service) grantExchange(ctx context.Context, client store.OAuthClient, confidential bool, form url.Values) (TokenResponse, error) {
	if !confidential || client.ID != store.ClientMCP {
		return TokenResponse{}, oauthErr(http.StatusBadRequest, "unauthorized_client", "unauthorized client", "")
	}
	if form.Get("subject_token") == "" || form.Get("subject_token_type") != subjectAccessToken {
		return TokenResponse{}, oauthErr(http.StatusBadRequest, "invalid_request", "invalid request", "")
	}
	issuer := strings.TrimRight(s.cfg.PublicOrigin, "/")
	if form.Get("resource") == "" || form.Get("resource") != issuer {
		return TokenResponse{}, oauthErr(http.StatusBadRequest, "invalid_target", "invalid target", "")
	}
	plain, hash, err := secret.NewToken()
	if err != nil {
		return TokenResponse{}, err
	}
	now := s.now()
	_, err = s.st.IssueDelegated(ctx, store.IssueDelegated{
		SubjectHash:     secret.Hash(form.Get("subject_token")),
		TokenHash:       hash,
		Audience:        issuer,
		SubjectAudience: s.cfg.MCPResource,
		ExpiresAt:       now.Add(delegatedTTL),
		At:              now,
	})
	if err != nil {
		if errors.Is(err, store.ErrUnauthorized) || errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrInvalid) {
			return TokenResponse{}, oauthErr(http.StatusBadRequest, "invalid_grant", "invalid grant", "")
		}
		return TokenResponse{}, err
	}
	return TokenResponse{
		AccessToken:     plain,
		TokenType:       "Bearer",
		ExpiresIn:       int(delegatedTTL / time.Second),
		IssuedTokenType: subjectAccessToken,
	}, nil
}

// Revoke revokes the grant family of an mcp_access or mcp_refresh token.
// Unknown tokens return a zero result and no error.
func (s *Service) Revoke(ctx context.Context, form url.Values, basicUser, basicPass string, hasBasic bool) (store.RevokeResult, error) {
	client, confidential, err := s.tokenClient(ctx, form.Get("client_id"), basicUser, basicPass, hasBasic)
	if err != nil {
		return store.RevokeResult{}, err
	}
	token := form.Get("token")
	if token == "" {
		return store.RevokeResult{}, oauthErr(http.StatusBadRequest, "invalid_request", "invalid request", "")
	}
	return s.st.RevokeTokenFamily(ctx, secret.Hash(token), s.now(), client.ID, confidential)
}

// Consent loads a pending request for a console user.
func (s *Service) Consent(ctx context.Context, id string, userID uuid.UUID) (ConsentView, error) {
	req, client, err := s.pending(ctx, id)
	if err != nil {
		return ConsentView{}, err
	}
	now := s.now()
	remembered := false
	grant, err := s.st.FindLiveGrant(ctx, userID, req.ClientID, req.Resource)
	if err == nil && now.Sub(grant.CreatedAt) < grantRemember {
		remembered = true
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return ConsentView{}, err
	}
	projects, err := s.st.ListAllProjects(ctx, userID)
	if err != nil {
		return ConsentView{}, err
	}
	return ConsentView{
		ID:            req.ID,
		ClientID:      client.ID,
		ClientName:    client.Name,
		RedirectHost:  redirectHost(req.RedirectURI),
		Resource:      req.Resource,
		Remembered:    remembered,
		ProjectsCount: len(projects),
		ExpiresAt:     req.ExpiresAt,
	}, nil
}

// ApproveConsent reuses a live grant even when it is older than 30 days.
func (s *Service) ApproveConsent(ctx context.Context, id string, userID uuid.UUID) (ConsentResult, error) {
	req, client, err := s.pending(ctx, id)
	if err != nil {
		return ConsentResult{}, err
	}
	plain, hash, err := secret.NewToken()
	if err != nil {
		return ConsentResult{}, err
	}
	now := s.now()
	host := redirectHost(req.RedirectURI)
	grant, err := s.st.ApproveOAuth(ctx, store.ApproveCode{
		RequestID:    id,
		UserID:       userID,
		At:           now,
		CodeHash:     hash,
		CodeExpires:  now.Add(codeTTL),
		RedirectHost: host,
	})
	if err != nil {
		return ConsentResult{}, err
	}
	loc, err := codeRedirect(req.RedirectURI, plain, req.State)
	if err != nil {
		return ConsentResult{}, err
	}
	return ConsentResult{
		RedirectTo:   loc,
		ClientID:     client.ID,
		ClientName:   client.Name,
		RedirectHost: host,
		GrantID:      grant.ID,
	}, nil
}

// DenyConsent marks the request denied and returns the client's error redirect.
func (s *Service) DenyConsent(ctx context.Context, id string, userID uuid.UUID) (ConsentResult, error) {
	req, client, err := s.pending(ctx, id)
	if err != nil {
		return ConsentResult{}, err
	}
	if _, err := s.st.DenyOAuth(ctx, id, userID, s.now()); err != nil {
		return ConsentResult{}, err
	}
	loc, err := errorRedirect(req.RedirectURI, "access_denied", "access denied", req.State, req.State != "")
	if err != nil {
		return ConsentResult{}, err
	}
	return ConsentResult{
		RedirectTo:   loc,
		ClientID:     client.ID,
		ClientName:   client.Name,
		RedirectHost: redirectHost(req.RedirectURI),
	}, nil
}

func (s *Service) pending(ctx context.Context, id string) (store.OAuthRequest, store.OAuthClient, error) {
	req, err := s.st.GetOAuthRequest(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.OAuthRequest{}, store.OAuthClient{}, store.ErrNotFound
	}
	if err != nil {
		return store.OAuthRequest{}, store.OAuthClient{}, err
	}
	if req.DecidedAt != nil || !s.now().Before(req.ExpiresAt) {
		return store.OAuthRequest{}, store.OAuthClient{}, store.ErrNotFound
	}
	client, err := s.st.GetOAuthClient(ctx, req.ClientID)
	if errors.Is(err, store.ErrNotFound) {
		return store.OAuthRequest{}, store.OAuthClient{}, store.ErrNotFound
	}
	if err != nil {
		return store.OAuthRequest{}, store.OAuthClient{}, err
	}
	return req, client, nil
}

// ListGrants returns the caller's live grants, newest first.
func (s *Service) ListGrants(ctx context.Context, userID uuid.UUID) ([]store.OAuthGrant, error) {
	return s.st.ListUserGrants(ctx, userID)
}

// DeleteGrant revokes one of the caller's grants. Another user's grant is not found.
func (s *Service) DeleteGrant(ctx context.Context, userID, grantID uuid.UUID) error {
	return s.st.RevokeUserGrant(ctx, userID, grantID, s.now())
}

func (s *Service) mcpAudience(resource string) string {
	if s.cfg.MCPResource != "" {
		return s.cfg.MCPResource
	}
	return resource
}

func hasGrant(client store.OAuthClient, grant string) bool {
	for _, item := range client.GrantTypes {
		if item == grant {
			return true
		}
	}
	return false
}

func validClientName(name string) bool {
	n := utf8.RuneCountInString(name)
	if n < 1 || n > 64 {
		return false
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func validRedirectList(uris []string) bool {
	if len(uris) < 1 || len(uris) > 5 {
		return false
	}
	for _, uri := range uris {
		if validateRedirectURI(uri) != nil {
			return false
		}
	}
	return true
}

func normalizeGrants(in []string) ([]string, bool) {
	if in == nil {
		return []string{grantAuthorizationCode, grantRefreshToken}, true
	}
	if len(in) == 0 {
		return nil, false
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, grant := range in {
		if seen[grant] || (grant != grantAuthorizationCode && grant != grantRefreshToken) {
			return nil, false
		}
		seen[grant] = true
		out = append(out, grant)
	}
	return out, true
}

func normalizeResponses(in []string) ([]string, bool) {
	if in == nil {
		return []string{"code"}, true
	}
	if len(in) != 1 || in[0] != "code" {
		return nil, false
	}
	return []string{"code"}, true
}

func normalizeAuth(in *string) (string, bool) {
	if in == nil || *in == "" || *in == "none" {
		return "none", true
	}
	return "", false
}

func validChallenge(s string) bool {
	if len(s) < 43 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !isBase64URL(r) {
			return false
		}
	}
	return true
}

func validVerifier(s string) bool {
	n := utf8.RuneCountInString(s)
	if n < 43 || n > 128 {
		return false
	}
	for _, r := range s {
		if !isUnreserved(r) {
			return false
		}
	}
	return true
}

func isBase64URL(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
}

func isUnreserved(r rune) bool {
	return isBase64URL(r) || r == '.' || r == '~'
}

func s256Match(verifier, challenge string) bool {
	if !validVerifier(verifier) {
		subtle.ConstantTimeCompare([]byte(challenge), []byte(challenge))
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	if len(got) != len(challenge) {
		subtle.ConstantTimeCompare([]byte(got), []byte(got))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}
