package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/auth"
	"github.com/more-than-code/bot-api-server/internal/config"
	"github.com/more-than-code/bot-api-server/internal/memstore"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const (
	oauthVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	oauthResource = "http://mcp.example"
	oauthIssuer   = "http://as.example"
	oauthConsole  = "http://console.example"
	oauthRedirect = "https://app.example/callback"
	mcpSecret     = "mcp-secret"
	exchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"
	exchangeType  = "urn:ietf:params:oauth:token-type:access_token"
)

type wall struct {
	mu sync.Mutex
	t  time.Time
}

func (w *wall) Now() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.t
}

func (w *wall) Advance(d time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.t = w.t.Add(d)
}

type oauthFX struct {
	mem      *memstore.Mem
	srv      *Server
	h        http.Handler
	clk      *wall
	ip       string
	lastCode string
}

func newOAuthFX(t *testing.T) *oauthFX {
	t.Helper()
	mem := memstore.New()
	clk := &wall{t: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	cfg := config.Config{
		PublicOrigin:          oauthIssuer,
		ConsoleOrigin:         oauthConsole,
		MCPResource:           oauthResource,
		GoogleClientID:        "dummy-google-client-id",
		GoogleClientSecret:    "dummy-google-client-secret",
		OAuthRedirectURIs:     []string{"http://127.0.0.1/callback"},
		DeviceVerificationURI: "http://127.0.0.1/device",
		AgentWSURL:            "ws://127.0.0.1/agent/v1/ws",
	}
	authn := auth.New(mem, cfg, clk.Now)
	if err := authn.SetMCPClientSecret(context.Background(), mcpSecret); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &Server{
		Store: mem,
		Auth:  authn,
		Audit: audit.Writer{Store: mem, Log: log, Now: clk.Now},
		Log:   log,
		Now:   clk.Now,
	}
	return &oauthFX{mem: mem, srv: srv, h: srv.Handler(), clk: clk}
}

func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (f *oauthFX) do(method, path, body, contentType, bearer string) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req.RemoteAddr = "192.0.2.1:1234"
	if f.ip != "" {
		req.RemoteAddr = f.ip
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func (f *oauthFX) user(t *testing.T, email string) store.User {
	t.Helper()
	u, err := f.mem.UpsertGoogleUser(context.Background(), store.GoogleSignIn{
		Subject: email, Email: email, Name: email, At: f.clk.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (f *oauthFX) console(t *testing.T, user store.User) string {
	t.Helper()
	plain, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.mem.CreateSession(context.Background(), user.ID, hash, store.KindConsole, f.clk.Now().Add(365*24*time.Hour), f.clk.Now()); err != nil {
		t.Fatal(err)
	}
	return plain
}

func (f *oauthFX) registerRaw(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	return f.do(http.MethodPost, "/oauth/register", body, "application/json", "")
}

func (f *oauthFX) register(t *testing.T, name, redirect string) auth.RegisteredClient {
	t.Helper()
	body := `{"client_name":"` + name + `","redirect_uris":["` + redirect + `"]}`
	rec := f.registerRaw(t, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register %d %s", rec.Code, rec.Body.String())
	}
	var client auth.RegisteredClient
	if err := json.Unmarshal(rec.Body.Bytes(), &client); err != nil {
		t.Fatal(err)
	}
	return client
}

func (f *oauthFX) authorize(clientID, redirect, state string) *httptest.ResponseRecorder {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirect)
	q.Set("code_challenge", s256Challenge(oauthVerifier))
	q.Set("code_challenge_method", "S256")
	q.Set("resource", oauthResource)
	if state != "" {
		q.Set("state", state)
	}
	return f.do(http.MethodGet, "/oauth/authorize?"+q.Encode(), "", "", "")
}

func requestID(t *testing.T, loc string) string {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	id := u.Query().Get("request")
	if id == "" || !strings.HasPrefix(loc, oauthConsole+"/oauth/consent?") {
		t.Fatalf("consent location %q", loc)
	}
	return id
}

func (f *oauthFX) approve(t *testing.T, bearer, id string) string {
	t.Helper()
	rec := f.do(http.MethodPost, "/v1/oauth/requests/"+id+"/approve", "", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve %d %s", rec.Code, rec.Body.String())
	}
	var env envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	payload, _ := env.Payload.(map[string]any)
	redirect, _ := payload["redirect_to"].(string)
	if redirect == "" {
		t.Fatalf("approve payload %#v", env.Payload)
	}
	return redirect
}

func codeFromRedirect(t *testing.T, redirect string) (code, state string) {
	t.Helper()
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("code"), u.Query().Get("state")
}

func (f *oauthFX) token(form url.Values, user, pass string) *httptest.ResponseRecorder {
	return f.postForm("/oauth/token", form, user, pass)
}

func (f *oauthFX) revoke(form url.Values, user, pass string) *httptest.ResponseRecorder {
	return f.postForm("/oauth/revoke", form, user, pass)
}

func (f *oauthFX) postForm(path string, form url.Values, user, pass string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func tokenPair(t *testing.T, rec *httptest.ResponseRecorder) (access, refresh string) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("token %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		Type    string `json:"token_type"`
		Expires int    `json:"expires_in"`
		Scope   string `json:"scope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Access == "" || body.Refresh == "" || body.Type != "Bearer" || body.Expires != 3600 || body.Scope != "deploybot" {
		t.Fatalf("token body %s", rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("token response is cacheable")
	}
	return body.Access, body.Refresh
}

func oauthErr(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status %d body %s, want %d %s", rec.Code, rec.Body.String(), status, code)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error != code {
		t.Fatalf("error %q want %q body %s", body.Error, code, rec.Body.String())
	}
}

func (f *oauthFX) issue(t *testing.T) (client auth.RegisteredClient, bearer, access, refresh, code, redirect string) {
	t.Helper()
	user := f.user(t, "owner@example.com")
	bearer = f.console(t, user)
	client = f.register(t, "Claude", oauthRedirect)
	loc := f.authorize(client.ClientID, oauthRedirect, "xyz").Header().Get("Location")
	redirect = f.approve(t, bearer, requestID(t, loc))
	code, state := codeFromRedirect(t, redirect)
	if state != "xyz" || code == "" {
		t.Fatalf("redirect %s", redirect)
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", oauthRedirect)
	form.Set("client_id", client.ClientID)
	form.Set("code_verifier", oauthVerifier)
	form.Set("resource", oauthResource)
	access, refresh = tokenPair(t, f.token(form, "", ""))
	return client, bearer, access, refresh, code, redirect
}

func (f *oauthFX) live(t *testing.T, plain string) bool {
	t.Helper()
	_, _, err := f.srv.Auth.Authenticate(context.Background(), "Bearer "+plain)
	return err == nil
}

func TestOAuthMetadata(t *testing.T) {
	f := newOAuthFX(t)
	rec := f.do(http.MethodGet, "/.well-known/oauth-authorization-server", "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "max-age=300" {
		t.Fatalf("cache %q", rec.Header().Get("Cache-Control"))
	}
	var doc auth.Metadata
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Issuer != oauthIssuer ||
		doc.Authorization != oauthIssuer+"/oauth/authorize" ||
		doc.Token != oauthIssuer+"/oauth/token" ||
		doc.Registration != oauthIssuer+"/oauth/register" ||
		doc.Revocation != oauthIssuer+"/oauth/revoke" ||
		strings.Join(doc.ResponseTypes, ",") != "code" ||
		strings.Join(doc.GrantTypes, ",") != "authorization_code,refresh_token,"+exchangeGrant ||
		strings.Join(doc.ChallengeMethod, ",") != "S256" ||
		strings.Join(doc.AuthMethods, ",") != "none,client_secret_basic" ||
		strings.Join(doc.Scopes, ",") != "deploybot" {
		t.Fatalf("metadata %#v", doc)
	}
}

func TestOAuthRegisterValidation(t *testing.T) {
	f := newOAuthFX(t)
	name := strings.Repeat("n", 64)
	accepted := []string{
		`{"client_name":"ok","redirect_uris":["https://example.com/cb"]}`,
		`{"client_name":"ok","redirect_uris":["https://example.com:8443/cb"]}`,
		`{"client_name":"ok","redirect_uris":["https://example.com/cb?x=1"]}`,
		`{"client_name":"ok","redirect_uris":["http://127.0.0.1/cb"]}`,
		`{"client_name":"ok","redirect_uris":["http://127.0.0.1:8080/cb"]}`,
		`{"client_name":"ok","redirect_uris":["http://localhost/cb"]}`,
		`{"client_name":"ok","redirect_uris":["http://localhost:1/cb"]}`,
		`{"client_name":"ok","redirect_uris":["http://[::1]/cb"]}`,
		`{"client_name":"ok","redirect_uris":["http://[::1]:9/cb"]}`,
		`{"client_name":"` + name + `","redirect_uris":["https://example.com/cb"]}`,
		`{"client_name":"a","redirect_uris":["https://example.com/cb"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","logo_uri":"https://ignored.example"}`,
		`{"client_name":"ok","redirect_uris":["https://example.com/cb"],"token_endpoint_auth_method":""}`,
	}
	for i, body := range accepted {
		f.ip = fmt.Sprintf("198.51.100.%d:1234", i+1)
		rec := f.registerRaw(t, body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("accepted %s -> %d %s", body, rec.Code, rec.Body.String())
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatal(err)
		}
		if _, ok := raw["client_secret"]; ok {
			t.Fatal("client_secret returned")
		}
		var client auth.RegisteredClient
		if err := json.Unmarshal(rec.Body.Bytes(), &client); err != nil {
			t.Fatal(err)
		}
		if len(client.ClientID) < 22 || client.AuthMethod != "none" || client.IssuedAt != f.clk.Now().Unix() {
			t.Fatalf("client %#v", client)
		}
		if client.ClientID == store.ClientMCP {
			t.Fatal("registration minted the internal client id")
		}
	}
	refusedURI := []string{
		`{"client_name":"ok","redirect_uris":[]}`,
		`{"client_name":"ok","redirect_uris":["http://example.com/cb"]}`,
		`{"client_name":"ok","redirect_uris":["http://127.0.0.2/cb"]}`,
		`{"client_name":"ok","redirect_uris":["http://127.0.0.1/cb#x"]}`,
		`{"client_name":"ok","redirect_uris":["https://user@example.com/cb"]}`,
		`{"client_name":"ok","redirect_uris":["https://*.example.com/cb"]}`,
		`{"client_name":"ok","redirect_uris":["https://example.com/cb*"]}`,
		`{"client_name":"ok","redirect_uris":["http://localhost/a","http://localhost/b","http://localhost/c","http://localhost/d","http://localhost/e","http://localhost/f"]}`,
		`{"client_name":"ok"}`,
	}
	for i, body := range refusedURI {
		f.ip = fmt.Sprintf("198.51.101.%d:1234", i+1)
		rec := f.registerRaw(t, body)
		oauthErr(t, rec, http.StatusBadRequest, "invalid_redirect_uri")
	}
	refusedMeta := []string{
		`{"client_name":"","redirect_uris":["https://example.com/cb"]}`,
		`{"client_name":"` + strings.Repeat("n", 65) + `","redirect_uris":["https://example.com/cb"]}`,
		`{"client_name":"bad\nname","redirect_uris":["https://example.com/cb"]}`,
		`{"client_name":"ok","redirect_uris":["https://example.com/cb"],"token_endpoint_auth_method":"client_secret_basic"}`,
		`{"client_name":"ok","redirect_uris":["https://example.com/cb"],"token_endpoint_auth_method":"client_secret_post"}`,
		`{"client_name":"ok","redirect_uris":["https://example.com/cb"],"grant_types":[]}`,
		`{"client_name":"ok","redirect_uris":["https://example.com/cb"],"grant_types":["client_credentials"]}`,
		`{"client_name":"ok","redirect_uris":["https://example.com/cb"],"response_types":["token"]}`,
		`{"client_name":"ok","redirect_uris":["https://example.com/cb"],"response_types":[]}`,
	}
	for i, body := range refusedMeta {
		f.ip = fmt.Sprintf("198.51.102.%d:1234", i+1)
		rec := f.registerRaw(t, body)
		oauthErr(t, rec, http.StatusBadRequest, "invalid_client_metadata")
	}
	f.ip = "198.51.103.1:1234"
	onlyRefresh := f.registerRaw(t, `{"client_name":"ok","redirect_uris":["https://example.com/cb"],"grant_types":["refresh_token"]}`)
	if onlyRefresh.Code != http.StatusCreated {
		t.Fatalf("refresh-only %d %s", onlyRefresh.Code, onlyRefresh.Body.String())
	}
}

func TestOAuthAuthorizeErrors(t *testing.T) {
	f := newOAuthFX(t)
	client := f.register(t, "Claude", oauthRedirect)
	loop := f.register(t, "Loop", "http://127.0.0.1/cb")
	query := f.register(t, "Query", "https://example.com/cb?x=1")
	httpsPort := f.register(t, "Port", "https://example.com/cb")
	refreshOnly := f.registerRaw(t, `{"client_name":"ro","redirect_uris":["https://example.com/cb"],"grant_types":["refresh_token"]}`)
	var ro auth.RegisteredClient
	if err := json.Unmarshal(refreshOnly.Body.Bytes(), &ro); err != nil {
		t.Fatal(err)
	}
	challenge := s256Challenge(oauthVerifier)
	base := func(id, redirect string) url.Values {
		q := url.Values{}
		q.Set("response_type", "code")
		q.Set("client_id", id)
		if redirect != "" {
			q.Set("redirect_uri", redirect)
		}
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
		q.Set("resource", oauthResource)
		q.Set("state", "st")
		return q
	}
	noRedirect := []url.Values{
		base("missing-client", oauthRedirect),
		func() url.Values { q := base(client.ClientID, ""); q.Del("redirect_uri"); return q }(),
		base(client.ClientID, "https://evil.example/cb"),
		base(client.ClientID, "https://app.example/callback#x"),
		base(httpsPort.ClientID, "https://example.com:8443/cb"),
		base(loop.ClientID, "http://127.0.0.1:9/other"),
		base(query.ClientID, "https://example.com/cb"),
	}
	for _, q := range noRedirect {
		rec := f.do(http.MethodGet, "/oauth/authorize?"+q.Encode(), "", "", "")
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), "invalid authorization request") {
			t.Fatalf("no-redirect %s -> %d %s location %q", q.Encode(), rec.Code, rec.Body.String(), rec.Header().Get("Location"))
		}
		if strings.Contains(rec.Body.String(), "http") {
			t.Fatalf("page reflects a uri: %s", rec.Body.String())
		}
	}
	redirectErr := []struct {
		q    url.Values
		code string
	}{
		{func() url.Values {
			q := base(client.ClientID, oauthRedirect)
			q.Set("response_type", "token")
			return q
		}(), "unsupported_response_type"},
		{func() url.Values { q := base(client.ClientID, oauthRedirect); q.Del("response_type"); return q }(), "unsupported_response_type"},
		{func() url.Values {
			q := base(client.ClientID, oauthRedirect)
			q.Set("code_challenge_method", "plain")
			return q
		}(), "invalid_request"},
		{func() url.Values {
			q := base(client.ClientID, oauthRedirect)
			q.Set("code_challenge", "short")
			return q
		}(), "invalid_request"},
		{func() url.Values { q := base(client.ClientID, oauthRedirect); q.Del("code_challenge"); return q }(), "invalid_request"},
		{func() url.Values { q := base(client.ClientID, oauthRedirect); q.Set("scope", "other"); return q }(), "invalid_scope"},
		{func() url.Values { q := base(client.ClientID, oauthRedirect); q.Del("resource"); return q }(), "invalid_target"},
		{func() url.Values {
			q := base(client.ClientID, oauthRedirect)
			q.Set("resource", "http://other.example")
			return q
		}(), "invalid_target"},
		{func() url.Values {
			q := base(client.ClientID, oauthRedirect)
			q.Set("state", strings.Repeat("s", 513))
			return q
		}(), "invalid_request"},
		{base(ro.ClientID, "https://example.com/cb"), "unauthorized_client"},
	}
	for _, tc := range redirectErr {
		rec := f.do(http.MethodGet, "/oauth/authorize?"+tc.q.Encode(), "", "", "")
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("%s status %d %s", tc.code, rec.Code, rec.Body.String())
		}
		loc := rec.Header().Get("Location")
		u, err := url.Parse(loc)
		if err != nil || u.Query().Get("error") != tc.code || u.Query().Get("state") == "" && tc.q.Get("state") != "" && utf8Len(tc.q.Get("state")) <= 512 {
			t.Fatalf("location %q want error %s", loc, tc.code)
		}
	}
	ok := f.authorize(loop.ClientID, "http://127.0.0.1:54321/cb", "st")
	if ok.Code != http.StatusSeeOther || !strings.HasPrefix(ok.Header().Get("Location"), oauthConsole+"/oauth/consent?request=") {
		t.Fatalf("loopback port: %d %s", ok.Code, ok.Header().Get("Location"))
	}
}

func utf8Len(s string) int { return len([]rune(s)) }

func TestOAuthCodeAndRefresh(t *testing.T) {
	f := newOAuthFX(t)
	client, _, access, refresh, code, _ := f.issue(t)
	if f.mem.HoldsPlaintext(code) || f.mem.HoldsPlaintext(access) || f.mem.HoldsPlaintext(refresh) || f.mem.HoldsPlaintext(oauthVerifier) {
		t.Fatal("plaintext secret at rest")
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", oauthRedirect)
	form.Set("client_id", client.ClientID)
	form.Set("code_verifier", oauthVerifier)
	form.Set("resource", oauthResource)
	if !f.live(t, refresh) {
		t.Fatal("refresh token was not live before code reuse")
	}
	oauthErr(t, f.token(form, "", ""), http.StatusBadRequest, "invalid_grant")
	if f.live(t, access) {
		t.Fatal("second code use left the first access token alive")
	}
	if f.live(t, refresh) {
		t.Fatal("second code use left the first refresh token alive")
	}

	f.clk.Advance(time.Minute)
	_, access2, refresh2 := f.redeemFresh(t, client.ClientID)
	rotated := f.refresh(t, client.ClientID, refresh2, "")
	if !f.live(t, rotated.access) || !f.live(t, rotated.refresh) {
		t.Fatal("rotated tokens were not live before code reuse")
	}
	delegated := delegatedToken(t, f.exchange(accessForm(rotated.access), store.ClientMCP, mcpSecret))
	if me := f.do(http.MethodGet, "/v1/me", "", "", delegated); me.Code != http.StatusOK {
		t.Fatalf("delegated token was not live before code reuse: %d %s", me.Code, me.Body.String())
	}
	form.Set("code", f.lastCode)
	oauthErr(t, f.token(form, "", ""), http.StatusBadRequest, "invalid_grant")
	if f.live(t, access2) {
		t.Fatal("second code use left the access token from that code alive")
	}
	if f.live(t, rotated.access) {
		t.Fatal("second code use left the rotated access token alive")
	}
	if f.live(t, rotated.refresh) {
		t.Fatal("second code use left the rotated refresh token alive")
	}
	deadDelegated := f.do(http.MethodGet, "/v1/me", "", "", delegated)
	if deadDelegated.Code != http.StatusUnauthorized || strings.Contains(deadDelegated.Body.String(), `"code":"invalid_token"`) || !strings.Contains(deadDelegated.Body.String(), `"code":"unauthorized"`) {
		t.Fatalf("second code use left the delegated token alive: %d %s", deadDelegated.Code, deadDelegated.Body.String())
	}
	_ = refresh2

	_, _, refresh3 := f.redeemFresh(t, client.ClientID)
	again := f.refresh(t, client.ClientID, refresh3, "")
	if !f.live(t, again.access) {
		t.Fatal("successor access was not live before refresh reuse")
	}
	if !f.live(t, again.refresh) {
		t.Fatal("successor refresh was not live before refresh reuse")
	}
	reuse := f.refreshRaw(client.ClientID, refresh3, "")
	oauthErr(t, reuse, http.StatusBadRequest, "invalid_grant")
	if f.live(t, again.access) {
		t.Fatal("refresh reuse left the successor access token alive")
	}
	if f.live(t, again.refresh) {
		t.Fatal("refresh reuse left the successor refresh token alive")
	}
	if !auditHas(f.mem.AllAudits(), audit.ActionOAuthRefreshReuse, audit.DecisionDenied, audit.ViaMCP) {
		t.Fatal("refresh reuse was not audited")
	}
}

func delegatedToken(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("exchange %d %s", rec.Code, rec.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	tok, _ := raw["access_token"].(string)
	if tok == "" {
		t.Fatalf("exchange body %s", rec.Body.String())
	}
	return tok
}

func (f *oauthFX) redeemFresh(t *testing.T, clientID string) (code, access, refresh string) {
	t.Helper()
	user := f.user(t, "second@example.com")
	bearer := f.console(t, user)
	loc := f.authorize(clientID, oauthRedirect, "s2").Header().Get("Location")
	redirect := f.approve(t, bearer, requestID(t, loc))
	code, _ = codeFromRedirect(t, redirect)
	f.lastCode = code
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", oauthRedirect)
	form.Set("client_id", clientID)
	form.Set("code_verifier", oauthVerifier)
	form.Set("resource", oauthResource)
	access, refresh = tokenPair(t, f.token(form, "", ""))
	return code, access, refresh
}

func (f *oauthFX) refresh(t *testing.T, clientID, token, resource string) tokenOut {
	t.Helper()
	rec := f.refreshRaw(clientID, token, resource)
	access, refresh := tokenPair(t, rec)
	return tokenOut{access: access, refresh: refresh}
}

func (f *oauthFX) refreshRaw(clientID, token, resource string) *httptest.ResponseRecorder {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", token)
	form.Set("client_id", clientID)
	if resource != "" {
		form.Set("resource", resource)
	}
	return f.token(form, "", "")
}

type tokenOut struct {
	access  string
	refresh string
}

func TestOAuthCodeEdges(t *testing.T) {
	f := newOAuthFX(t)
	client := f.register(t, "Claude", oauthRedirect)
	user := f.user(t, "edge@example.com")
	bearer := f.console(t, user)
	mint := func() string {
		t.Helper()
		loc := f.authorize(client.ClientID, oauthRedirect, "e").Header().Get("Location")
		redirect := f.approve(t, bearer, requestID(t, loc))
		code, _ := codeFromRedirect(t, redirect)
		return code
	}
	post := func(code, redirect, verifier, resource string) *httptest.ResponseRecorder {
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", redirect)
		form.Set("client_id", client.ClientID)
		form.Set("code_verifier", verifier)
		form.Set("resource", resource)
		return f.token(form, "", "")
	}
	badPKCE := mint()
	oauthErr(t, post(badPKCE, oauthRedirect, strings.Repeat("b", 43), oauthResource), http.StatusBadRequest, "invalid_grant")
	peek, err := f.mem.PeekOAuthCode(context.Background(), secret.Hash(badPKCE))
	if err != nil || peek.UsedAt != nil {
		t.Fatalf("pkce mismatch consumed the code: %v %+v", err, peek.UsedAt)
	}
	formOK := url.Values{}
	formOK.Set("grant_type", "authorization_code")
	formOK.Set("code", badPKCE)
	formOK.Set("redirect_uri", oauthRedirect)
	formOK.Set("client_id", client.ClientID)
	formOK.Set("code_verifier", oauthVerifier)
	formOK.Set("resource", oauthResource)
	if _, _ = tokenPair(t, f.token(formOK, "", "")); false {
		t.Fatal("unreachable")
	}

	badRedirect := mint()
	oauthErr(t, post(badRedirect, "https://app.example/other", oauthVerifier, oauthResource), http.StatusBadRequest, "invalid_grant")
	peek, err = f.mem.PeekOAuthCode(context.Background(), secret.Hash(badRedirect))
	if err != nil || peek.UsedAt != nil {
		t.Fatal("redirect mismatch consumed the code")
	}

	badResource := mint()
	oauthErr(t, post(badResource, oauthRedirect, oauthVerifier, "http://other.example"), http.StatusBadRequest, "invalid_target")
	peek, err = f.mem.PeekOAuthCode(context.Background(), secret.Hash(badResource))
	if err != nil || peek.UsedAt != nil {
		t.Fatal("resource mismatch consumed the code")
	}
	if _, _ = tokenPair(t, post(badResource, oauthRedirect, oauthVerifier, oauthResource)); false {
		t.Fatal("unreachable")
	}

	expiring := mint()
	f.clk.Advance(59 * time.Second)
	if _, _ = tokenPair(t, post(expiring, oauthRedirect, oauthVerifier, oauthResource)); false {
		t.Fatal("unreachable")
	}
	late := mint()
	f.clk.Advance(60 * time.Second)
	oauthErr(t, post(late, oauthRedirect, oauthVerifier, oauthResource), http.StatusBadRequest, "invalid_grant")
	peek, err = f.mem.PeekOAuthCode(context.Background(), secret.Hash(late))
	if err != nil || peek.UsedAt != nil {
		t.Fatal("expiry consumed the code")
	}
}

func TestOAuthTokenExchange(t *testing.T) {
	f := newOAuthFX(t)
	client, bearer, access, refresh, _, _ := f.issue(t)
	_ = bearer
	refused := []struct {
		name string
		tok  string
	}{
		{"console", f.console(t, f.user(t, "other@example.com"))},
		{"refresh", refresh},
		{"legacy", f.bound(t, store.KindLegacyMCP, oauthResource, nil)},
	}
	for _, tc := range refused {
		rec := f.exchange(accessForm(tc.tok), store.ClientMCP, mcpSecret)
		oauthErr(t, rec, http.StatusBadRequest, "invalid_grant")
	}
	wrongAud := f.bound(t, store.KindMCPAccess, "http://other.example", f.grantID(t))
	oauthErr(t, f.exchange(accessForm(wrongAud), store.ClientMCP, mcpSecret), http.StatusBadRequest, "invalid_grant")

	form := accessForm(access)
	form.Set("client_id", client.ClientID)
	oauthErr(t, f.token(form, "", ""), http.StatusBadRequest, "unauthorized_client")
	oauthErr(t, f.exchange(accessForm(access), store.ClientMCP, "wrong"), http.StatusUnauthorized, "invalid_client")
	badUser := f.exchange(accessForm(access), "not-mcp", mcpSecret)
	oauthErr(t, badUser, http.StatusUnauthorized, "invalid_client")
	if badUser.Header().Get("WWW-Authenticate") != "Basic" {
		t.Fatalf("www-authenticate %q", badUser.Header().Get("WWW-Authenticate"))
	}

	ok := f.exchange(accessForm(access), store.ClientMCP, mcpSecret)
	if ok.Code != http.StatusOK {
		t.Fatalf("exchange %d %s", ok.Code, ok.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(ok.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, has := raw["refresh_token"]; has {
		t.Fatal("delegated token is refreshable")
	}
	if raw["expires_in"] != float64(300) || raw["issued_token_type"] != exchangeType || raw["token_type"] != "Bearer" {
		t.Fatalf("exchange body %s", ok.Body.String())
	}
	delegated, _ := raw["access_token"].(string)
	sess, user, err := f.srv.Auth.Authenticate(context.Background(), "Bearer "+delegated)
	if err != nil || sess.Kind != store.KindDelegated || sess.Audience != oauthIssuer || !sess.ExpiresAt.Equal(f.clk.Now().Add(5*time.Minute)) {
		t.Fatalf("delegated session %+v %v", sess, err)
	}
	me := f.do(http.MethodGet, "/v1/me", "", "", delegated)
	if me.Code != http.StatusOK {
		t.Fatalf("delegated /v1/me %d %s", me.Code, me.Body.String())
	}
	created := f.do(http.MethodPost, "/v1/projects", `{"name":"From MCP"}`, "application/json", delegated)
	if created.Code != http.StatusCreated {
		t.Fatalf("delegated create %d %s", created.Code, created.Body.String())
	}
	if !auditHas(f.mem.AllAudits(), audit.ActionProjectCreate, audit.DecisionAllowed, audit.ViaMCP) {
		t.Fatal("delegated audit via is not mcp")
	}
	again := f.exchange(accessForm(delegated), store.ClientMCP, mcpSecret)
	oauthErr(t, again, http.StatusBadRequest, "invalid_grant")
	_ = user

	f.clk.Advance(61 * time.Minute)
	oauthErr(t, f.exchange(accessForm(access), store.ClientMCP, mcpSecret), http.StatusBadRequest, "invalid_grant")
}

func (f *oauthFX) exchange(form url.Values, user, pass string) *httptest.ResponseRecorder {
	return f.token(form, user, pass)
}

func accessForm(token string) url.Values {
	form := url.Values{}
	form.Set("grant_type", exchangeGrant)
	form.Set("subject_token", token)
	form.Set("subject_token_type", exchangeType)
	form.Set("resource", oauthIssuer)
	return form
}

func (f *oauthFX) grantID(t *testing.T) *uuid.UUID {
	t.Helper()
	grants, err := f.mem.ListUserGrants(context.Background(), f.onlyUser(t))
	if err != nil || len(grants) == 0 {
		t.Fatal(err)
	}
	id := grants[0].ID
	return &id
}

func (f *oauthFX) onlyUser(t *testing.T) uuid.UUID {
	t.Helper()
	u, err := f.mem.UserByEmail(context.Background(), "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func (f *oauthFX) bound(t *testing.T, kind, audience string, grant *uuid.UUID) string {
	t.Helper()
	plain, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	clientID := ""
	if grant != nil {
		clientID = "client"
	}
	if _, err := f.mem.CreateBoundSession(context.Background(), store.BoundSession{
		UserID: f.onlyUser(t), TokenHash: hash, Kind: kind, Audience: audience,
		ExpiresAt: f.clk.Now().Add(time.Hour), At: f.clk.Now(), GrantID: grant, ClientID: clientID,
	}); err != nil {
		t.Fatal(err)
	}
	return plain
}

func TestOAuthAudienceRule(t *testing.T) {
	f := newOAuthFX(t)
	_, consoleBearer, access, refresh, _, _ := f.issue(t)
	id := "11111111-1111-1111-1111-111111111111"
	for _, token := range []string{access, refresh} {
		for _, pattern := range Patterns() {
			if !strings.Contains(pattern, " /v1/") {
				continue
			}
			method, path, _ := strings.Cut(pattern, " ")
			path = strings.ReplaceAll(path, "{project_id}", id)
			path = strings.ReplaceAll(path, "{user_id}", id)
			path = strings.ReplaceAll(path, "{token_id}", id)
			path = strings.ReplaceAll(path, "{user_code}", "ABCD-EFGH")
			path = strings.ReplaceAll(path, "{id}", id)
			rec := f.do(method, path, `{}`, "application/json", token)
			var env envelope
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatalf("%s %s: %v", pattern, token[:4], err)
			}
			if rec.Code != http.StatusUnauthorized || env.Code != "invalid_token" {
				t.Fatalf("%s mcp audience: %d %s", pattern, rec.Code, rec.Body.String())
			}
		}
	}
	me := f.do(http.MethodGet, "/v1/me", "", "", consoleBearer)
	if me.Code != http.StatusOK {
		t.Fatalf("console /v1/me %d %s", me.Code, me.Body.String())
	}
	garbage := f.do(http.MethodPost, "/v1/auth/device/code", `{"client_name":"cli"}`, "application/json", "not-a-token")
	if garbage.Code == http.StatusUnauthorized {
		t.Fatalf("garbage bearer on a public route: %s", garbage.Body.String())
	}
	expiredPlain, expiredHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.mem.CreateBoundSession(context.Background(), store.BoundSession{
		UserID: f.onlyUser(t), TokenHash: expiredHash, Kind: store.KindMCPAccess, Audience: oauthResource,
		ExpiresAt: f.clk.Now().Add(-time.Second), At: f.clk.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	expired := f.do(http.MethodPost, "/v1/auth/device/code", `{"client_name":"cli"}`, "application/json", expiredPlain)
	if expired.Code == http.StatusUnauthorized {
		t.Fatalf("expired mcp token rejected a public route: %s", expired.Body.String())
	}
}

func TestLegacyMCPRejected(t *testing.T) {
	f := newOAuthFX(t)
	user := f.user(t, "owner@example.com")
	plain, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.mem.CreateSession(context.Background(), user.ID, hash, store.KindLegacyMCP, f.clk.Now().Add(24*time.Hour), f.clk.Now()); err != nil {
		t.Fatal(err)
	}
	rec := f.do(http.MethodGet, "/v1/me", "", "", plain)
	var env envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusUnauthorized || env.Code != "invalid_token" {
		t.Fatalf("legacy mcp /v1/me %d %s", rec.Code, rec.Body.String())
	}
}

func TestOAuthRevokeAndGrants(t *testing.T) {
	f := newOAuthFX(t)
	client, bearer, access, refresh, _, _ := f.issue(t)
	other := f.console(t, f.user(t, "other@example.com"))
	list := f.do(http.MethodGet, "/v1/me/grants", "", "", bearer)
	if list.Code != http.StatusOK {
		t.Fatalf("list %d %s", list.Code, list.Body.String())
	}
	var env envelope
	if err := json.Unmarshal(list.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	payload, _ := env.Payload.(map[string]any)
	items, _ := payload["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("grants %#v", payload)
	}
	row, _ := items[0].(map[string]any)
	id, _ := row["id"].(string)
	if row["client_name"] != "Claude" || row["kind"] != "oauth" || row["redirect_host"] != "app.example" {
		t.Fatalf("grant row %#v", row)
	}
	missing := f.do(http.MethodDelete, "/v1/me/grants/"+id, "", "", other)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("other user delete %d %s", missing.Code, missing.Body.String())
	}
	if !f.live(t, access) {
		t.Fatal("other user's delete revoked the grant")
	}
	form := url.Values{}
	form.Set("token", access)
	form.Set("client_id", "someone-else")
	oauthErr(t, f.revoke(form, "", ""), http.StatusUnauthorized, "invalid_client")
	form.Set("client_id", client.ClientID)
	form.Del("token")
	rec := f.revoke(form, "", "")
	oauthErr(t, rec, http.StatusBadRequest, "invalid_request")
	form.Set("token", "not-a-token")
	unknown := f.revoke(form, "", "")
	if unknown.Code != http.StatusOK || unknown.Body.Len() != 0 {
		t.Fatalf("unknown revoke %d %q", unknown.Code, unknown.Body.String())
	}
	form.Set("token", access)
	form.Set("client_id", client.ClientID)
	wrongClient := f.register(t, "Other", "https://other.example/cb")
	form.Set("client_id", wrongClient.ClientID)
	mismatch := f.revoke(form, "", "")
	if mismatch.Code != http.StatusOK || !f.live(t, access) {
		t.Fatal("client mismatch revoked the token")
	}
	form.Set("client_id", client.ClientID)
	form.Set("token", refresh)
	revoked := f.revoke(form, "", "")
	if revoked.Code != http.StatusOK || revoked.Body.Len() != 0 {
		t.Fatalf("revoke %d %q", revoked.Code, revoked.Body.String())
	}
	if f.live(t, access) || f.live(t, refresh) {
		t.Fatal("revoke left the family alive")
	}
	if !auditHas(f.mem.AllAudits(), audit.ActionOAuthTokenRevoke, audit.DecisionAllowed, audit.ViaMCP) {
		t.Fatal("revoke was not audited")
	}

	f2 := newOAuthFX(t)
	_, bearer2, access2, _, _, _ := f2.issue(t)
	list = f2.do(http.MethodGet, "/v1/me/grants", "", "", bearer2)
	if err := json.Unmarshal(list.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	payload, _ = env.Payload.(map[string]any)
	items, _ = payload["items"].([]any)
	row, _ = items[0].(map[string]any)
	id, _ = row["id"].(string)
	del := f2.do(http.MethodDelete, "/v1/me/grants/"+id, "", "", bearer2)
	if del.Code != http.StatusOK || !strings.Contains(del.Body.String(), `"payload":null`) {
		t.Fatalf("delete %d %s", del.Code, del.Body.String())
	}
	if f2.live(t, access2) {
		t.Fatal("grant delete left the access token alive")
	}
	if !auditHas(f2.mem.AllAudits(), audit.ActionOAuthTokenRevoke, audit.DecisionAllowed, audit.ViaConsole) {
		t.Fatal("console revoke was not audited as console")
	}
}

func TestOAuthConsent(t *testing.T) {
	f := newOAuthFX(t)
	user := f.user(t, "owner@example.com")
	if _, err := f.mem.CreateProject(context.Background(), user.ID, "One", "one", f.clk.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.mem.CreateProject(context.Background(), user.ID, "Two", "two", f.clk.Now()); err != nil {
		t.Fatal(err)
	}
	bearer := f.console(t, user)
	client := f.register(t, "Claude", oauthRedirect)
	loc := f.authorize(client.ClientID, oauthRedirect, "consent-state").Header().Get("Location")
	id := requestID(t, loc)
	anon := f.do(http.MethodGet, "/v1/oauth/requests/"+id, "", "", "")
	if anon.Code != http.StatusUnauthorized {
		t.Fatalf("anon %d", anon.Code)
	}
	mcpPlain, mcpHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.mem.CreateBoundSession(context.Background(), store.BoundSession{
		UserID: user.ID, TokenHash: mcpHash, Kind: store.KindMCPAccess, Audience: oauthResource,
		ExpiresAt: f.clk.Now().Add(time.Hour), At: f.clk.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	mcp := f.do(http.MethodGet, "/v1/oauth/requests/"+id, "", "", mcpPlain)
	var env envelope
	if err := json.Unmarshal(mcp.Body.Bytes(), &env); err != nil || mcp.Code != http.StatusUnauthorized || env.Code != "invalid_token" {
		t.Fatalf("mcp consent %d %s", mcp.Code, mcp.Body.String())
	}
	view := f.do(http.MethodGet, "/v1/oauth/requests/"+id, "", "", bearer)
	if view.Code != http.StatusOK {
		t.Fatalf("view %d %s", view.Code, view.Body.String())
	}
	if err := json.Unmarshal(view.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	payload, _ := env.Payload.(map[string]any)
	clientObj, _ := payload["client"].(map[string]any)
	if payload["remembered"] != false || payload["projects_count"] != float64(2) || payload["redirect_host"] != "app.example" || clientObj["verified"] != false || clientObj["name"] != "Claude" {
		t.Fatalf("view %#v", payload)
	}
	denyLoc := f.authorize(client.ClientID, oauthRedirect, "no").Header().Get("Location")
	deny := f.do(http.MethodPost, "/v1/oauth/requests/"+requestID(t, denyLoc)+"/deny", "", "", bearer)
	if err := json.Unmarshal(deny.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	denied, _ := env.Payload.(map[string]any)
	redirect, _ := denied["redirect_to"].(string)
	u, err := url.Parse(redirect)
	if err != nil || u.Query().Get("error") != "access_denied" || u.Query().Get("state") != "no" {
		t.Fatalf("deny redirect %s", redirect)
	}
	if !auditHas(f.mem.AllAudits(), audit.ActionOAuthAuthorize, audit.DecisionDenied, audit.ViaConsole) {
		t.Fatal("deny was not audited")
	}
	allowLoc := f.authorize(client.ClientID, oauthRedirect, "yes").Header().Get("Location")
	allow := f.approve(t, bearer, requestID(t, allowLoc))
	if _, state := codeFromRedirect(t, allow); state != "yes" || !strings.Contains(allow, "code=") {
		t.Fatalf("approve redirect %s", allow)
	}
	next := f.authorize(client.ClientID, oauthRedirect, "again").Header().Get("Location")
	again := f.do(http.MethodGet, "/v1/oauth/requests/"+requestID(t, next), "", "", bearer)
	if err := json.Unmarshal(again.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	payload, _ = env.Payload.(map[string]any)
	if payload["remembered"] != true {
		t.Fatalf("remembered %#v", payload)
	}
	f.approve(t, bearer, requestID(t, next))
	f.clk.Advance(31 * 24 * time.Hour)
	later := f.authorize(client.ClientID, oauthRedirect, "old").Header().Get("Location")
	old := f.do(http.MethodGet, "/v1/oauth/requests/"+requestID(t, later), "", "", bearer)
	if err := json.Unmarshal(old.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	payload, _ = env.Payload.(map[string]any)
	if payload["remembered"] != false {
		t.Fatalf("old grant remembered %#v", payload)
	}
	f.approve(t, bearer, requestID(t, later))
	listed := f.do(http.MethodGet, "/v1/me/grants", "", "", bearer)
	if err := json.Unmarshal(listed.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	payload, _ = env.Payload.(map[string]any)
	items, _ := payload["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("reused grant created a second row: %#v", items)
	}
}

func TestOAuthRateLimits(t *testing.T) {
	f := newOAuthFX(t)
	for i := 0; i < 10; i++ {
		rec := f.registerRaw(t, `{`)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("register limited at %d", i)
		}
	}
	limited := f.registerRaw(t, `{"client_name":"ok","redirect_uris":["https://example.com/cb"]}`)
	if limited.Code != http.StatusTooManyRequests || limited.Body.String() != `{"error":"rate_limited"}` {
		t.Fatalf("register limit %d %s", limited.Code, limited.Body.String())
	}
	f.clk.Advance(59 * time.Minute)
	inside := f.registerRaw(t, `{"client_name":"ok","redirect_uris":["https://example.com/cb"]}`)
	if inside.Code != http.StatusTooManyRequests {
		t.Fatalf("register hits inside the hour were dropped: %d", inside.Code)
	}
	f.clk.Advance(2 * time.Minute)
	reset := f.registerRaw(t, `{`)
	if reset.Code == http.StatusTooManyRequests {
		t.Fatal("register limit did not reset")
	}
	for i := 0; i < 60; i++ {
		rec := f.do(http.MethodGet, "/oauth/authorize", "", "", "")
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("authorize limited at %d", i)
		}
	}
	az := f.do(http.MethodGet, "/oauth/authorize", "", "", "")
	if az.Code != http.StatusTooManyRequests || !strings.Contains(az.Body.String(), "rate limited") {
		t.Fatalf("authorize limit %d %s", az.Code, az.Body.String())
	}
	f.clk.Advance(59 * time.Second)
	azInside := f.do(http.MethodGet, "/oauth/authorize", "", "", "")
	if azInside.Code != http.StatusTooManyRequests {
		t.Fatalf("authorize hits inside the minute were dropped: %d", azInside.Code)
	}
	f.clk.Advance(2 * time.Second)
	azReset := f.do(http.MethodGet, "/oauth/authorize", "", "", "")
	if azReset.Code == http.StatusTooManyRequests {
		t.Fatal("authorize limit did not reset")
	}
	for i := 0; i < 60; i++ {
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("grant_type=authorization_code"))
		req.RemoteAddr = "192.0.2.1:1234"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("token limited at %d", i)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("grant_type=authorization_code"))
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests || rec.Body.String() != `{"error":"rate_limited"}` {
		t.Fatalf("token limit %d %s", rec.Code, rec.Body.String())
	}
	f.clk.Advance(59 * time.Second)
	insideReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("grant_type=authorization_code"))
	insideReq.RemoteAddr = "192.0.2.1:1234"
	insideReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	insideRec := httptest.NewRecorder()
	f.h.ServeHTTP(insideRec, insideReq)
	if insideRec.Code != http.StatusTooManyRequests {
		t.Fatalf("token hits inside the minute were dropped: %d", insideRec.Code)
	}
	f.clk.Advance(2 * time.Second)
	resetReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("grant_type=authorization_code"))
	resetReq.RemoteAddr = "192.0.2.1:1234"
	resetReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resetRec := httptest.NewRecorder()
	f.h.ServeHTTP(resetRec, resetReq)
	if resetRec.Code == http.StatusTooManyRequests {
		t.Fatal("token limit did not reset")
	}
}

func TestOAuthTokenBasicNotLimited(t *testing.T) {
	f := newOAuthFX(t)
	form := accessForm("not-a-token")
	for i := 0; i < 61; i++ {
		rec := f.exchange(form, store.ClientMCP, mcpSecret)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("bot-mcp-server limited at %d", i)
		}
	}
	for i := 0; i < 60; i++ {
		rec := f.exchange(form, store.ClientMCP, "wrong-secret")
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("wrong secret limited at %d", i)
		}
		oauthErr(t, rec, http.StatusUnauthorized, "invalid_client")
	}
	limited := f.exchange(form, store.ClientMCP, "wrong-secret")
	if limited.Code != http.StatusTooManyRequests || limited.Body.String() != `{"error":"rate_limited"}` {
		t.Fatalf("wrong secret limit %d %s", limited.Code, limited.Body.String())
	}
}

func TestConsoleSessionRequired(t *testing.T) {
	f := newOAuthFX(t)
	_, _, access, _, _, _ := f.issue(t)
	delegated := delegatedToken(t, f.exchange(accessForm(access), store.ClientMCP, mcpSecret))
	routes := []struct{ method, path string }{
		{http.MethodGet, "/v1/oauth/requests/missing"},
		{http.MethodPost, "/v1/oauth/requests/missing/approve"},
		{http.MethodPost, "/v1/oauth/requests/missing/deny"},
		{http.MethodGet, "/v1/auth/device/ABCD-EFGH"},
		{http.MethodPost, "/v1/auth/device/ABCD-EFGH/approve"},
		{http.MethodPost, "/v1/auth/device/ABCD-EFGH/deny"},
	}
	for _, rt := range routes {
		rec := f.do(rt.method, rt.path, "", "", delegated)
		if rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), `"code":"invalid_token"`) || !strings.Contains(rec.Body.String(), `"code":"unauthorized"`) {
			t.Fatalf("%s %s delegated: %d %s", rt.method, rt.path, rec.Code, rec.Body.String())
		}
	}
}

func TestOAuthAuditRows(t *testing.T) {
	f := newOAuthFX(t)
	client, _, access, _, code, _ := f.issue(t)
	rows := f.mem.AllAudits()
	if !auditHas(rows, audit.ActionOAuthRegister, audit.DecisionAllowed, audit.ViaSystem) {
		t.Fatal("register audit missing")
	}
	if !auditHas(rows, audit.ActionOAuthAuthorize, audit.DecisionAllowed, audit.ViaConsole) {
		t.Fatal("allow audit missing")
	}
	blob := string(mustAudit(rows))
	for _, secretText := range []string{access, code, oauthVerifier, mcpSecret} {
		if strings.Contains(blob, secretText) {
			t.Fatal("audit detail contains a secret")
		}
	}
	if !strings.Contains(blob, client.ClientID) {
		t.Fatal("audit detail dropped the client id")
	}
}

func auditHas(rows []store.AuditEntry, action, decision, via string) bool {
	for _, row := range rows {
		if row.Action == action && row.Decision == decision && row.Via == via {
			return true
		}
	}
	return false
}

func mustAudit(rows []store.AuditEntry) []byte {
	var b strings.Builder
	for _, row := range rows {
		b.Write(row.Detail)
	}
	return []byte(b.String())
}

func TestOAuthExpiredRefreshDoesNotReuse(t *testing.T) {
	f := newOAuthFX(t)
	client, bearer, _, refresh, _, _ := f.issue(t)
	_ = bearer
	plain, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	grants, err := f.mem.ListUserGrants(context.Background(), f.onlyUser(t))
	if err != nil || len(grants) != 1 {
		t.Fatal(err)
	}
	gid := grants[0].ID
	if _, err := f.mem.CreateBoundSession(context.Background(), store.BoundSession{
		UserID: f.onlyUser(t), TokenHash: hash, Kind: store.KindMCPRefresh, Audience: oauthResource,
		ExpiresAt: f.clk.Now().Add(-time.Second), At: f.clk.Now().Add(-time.Hour), GrantID: &gid, ClientID: client.ClientID,
	}); err != nil {
		t.Fatal(err)
	}
	oauthErr(t, f.refreshRaw(client.ClientID, plain, ""), http.StatusBadRequest, "invalid_grant")
	if auditHas(f.mem.AllAudits(), audit.ActionOAuthRefreshReuse, audit.DecisionDenied, audit.ViaMCP) {
		t.Fatal("expired refresh was audited as reuse")
	}
	if !f.live(t, refresh) {
		t.Fatal("expired refresh revoked the family")
	}
	listed := f.do(http.MethodGet, "/v1/me/grants", "", "", bearer)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), grants[0].ID.String()) {
		t.Fatalf("grant disappeared: %s", listed.Body.String())
	}
}

func TestOAuthConfidentialCodeRejected(t *testing.T) {
	f := newOAuthFX(t)
	_, _, _, _, code, _ := f.issue(t)
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", oauthRedirect)
	form.Set("code_verifier", oauthVerifier)
	form.Set("resource", oauthResource)
	oauthErr(t, f.token(form, store.ClientMCP, mcpSecret), http.StatusBadRequest, "unauthorized_client")
}

func TestOAuthRevokedSubject(t *testing.T) {
	f := newOAuthFX(t)
	_, bearer, access, _, _, _ := f.issue(t)
	gid := f.grantID(t)
	list := f.do(http.MethodDelete, "/v1/me/grants/"+gid.String(), "", "", bearer)
	if list.Code != http.StatusOK {
		t.Fatal(list.Body.String())
	}
	plain, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.mem.CreateBoundSession(context.Background(), store.BoundSession{
		UserID: f.onlyUser(t), TokenHash: hash, Kind: store.KindMCPAccess, Audience: oauthResource,
		ExpiresAt: f.clk.Now().Add(time.Hour), At: f.clk.Now(), GrantID: gid, ClientID: store.ClientMCP,
	}); err != nil {
		t.Fatal(err)
	}
	_ = access
	oauthErr(t, f.exchange(accessForm(plain), store.ClientMCP, mcpSecret), http.StatusBadRequest, "invalid_grant")
}
