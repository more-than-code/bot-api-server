package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/api"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/auth"
	"github.com/more-than-code/bot-api-server/internal/config"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

const oauthVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"

func seedLegacyMCPSession(t *testing.T, d *DB, ctx context.Context) (uuid.UUID, bool) {
	t.Helper()
	var sessions *string
	if err := d.pool.QueryRow(ctx, `SELECT to_regclass('app.sessions')::text`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions == nil || *sessions == "" {
		return uuid.Nil, false
	}
	var mig *string
	if err := d.pool.QueryRow(ctx, `SELECT to_regclass('app.schema_migrations')::text`).Scan(&mig); err != nil {
		t.Fatal(err)
	}
	if mig != nil && *mig != "" {
		var n int
		if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM app.schema_migrations WHERE name = '0005_mcp_oauth.sql'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			return uuid.Nil, false
		}
	}
	at := time.Now().UTC()
	user, err := d.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "legacy-mcp-cutover",
		Email:   "legacy-mcp-cutover@example.com",
		Name:    "Legacy",
		At:      at,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	sess, err := d.CreateSession(ctx, user.ID, hash, store.KindLegacyMCP, at.Add(24*time.Hour), at)
	if err != nil {
		t.Fatal(err)
	}
	return sess.ID, true
}

func assertLegacyMCPExpired(t *testing.T, d *DB, ctx context.Context, id uuid.UUID) {
	t.Helper()
	var live bool
	if err := d.pool.QueryRow(ctx, `SELECT expires_at > now() FROM app.sessions WHERE id = $1::uuid`, id.String()).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live {
		t.Fatal("migration 0005 left a legacy mcp session unexpired")
	}
}

func replayMCPCutover(t *testing.T, d *DB, ctx context.Context) {
	t.Helper()
	at := time.Now().UTC()
	user, err := d.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "replay-mcp-cutover",
		Email:   "replay-mcp-cutover@example.com",
		Name:    "Replay",
		At:      at,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	sess, err := d.CreateSession(ctx, user.ID, hash, store.KindLegacyMCP, at.Add(24*time.Hour), at)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE deploybot_owner`); err != nil {
		t.Fatalf("set role: %v", err)
	}
	if _, err := tx.Exec(ctx, mcpCutoverSQL(t)); err != nil {
		t.Fatalf("cut-over: %v", err)
	}
	var expired bool
	if err := tx.QueryRow(ctx, `SELECT expires_at <= now() FROM app.sessions WHERE id = $1::uuid`, sess.ID.String()).Scan(&expired); err != nil {
		t.Fatal(err)
	}
	if !expired {
		t.Fatal("replayed cut-over left the mcp session unexpired")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func assertOAuthSchema(t *testing.T, d *DB, ctx context.Context) {
	t.Helper()
	for _, table := range []string{"oauth_clients", "oauth_grants", "oauth_requests", "oauth_codes"} {
		var reg *string
		if err := d.pool.QueryRow(ctx, `SELECT to_regclass($1)::text`, "app."+table).Scan(&reg); err != nil {
			t.Fatal(err)
		}
		if reg == nil || *reg == "" {
			t.Fatalf("missing app.%s", table)
		}
	}
	cols := map[string]bool{}
	rows, err := d.pool.Query(ctx, `
SELECT column_name FROM information_schema.columns
WHERE table_schema = 'app' AND table_name = 'sessions'
  AND column_name IN ('audience', 'grant_id', 'client_id', 'code_id', 'rotated_at')
`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		cols[name] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	for _, name := range []string{"audience", "grant_id", "client_id", "code_id", "rotated_at"} {
		if !cols[name] {
			t.Fatalf("sessions columns = %v", cols)
		}
	}
	var def string
	if err := d.pool.QueryRow(ctx, `
SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'sessions_kind_chk'
`).Scan(&def); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"console", "mcp", "mcp_access", "mcp_refresh", "api_delegated"} {
		if !strings.Contains(def, kind) {
			t.Fatalf("sessions_kind_chk = %s", def)
		}
	}
	grants := map[string]map[string]bool{}
	rows, err = d.pool.Query(ctx, `
SELECT table_name, privilege_type FROM information_schema.role_table_grants
WHERE grantee = 'deploybot_api' AND table_schema = 'app'
  AND table_name IN ('oauth_clients', 'oauth_grants', 'oauth_requests', 'oauth_codes')
`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var table, priv string
		if err := rows.Scan(&table, &priv); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if grants[table] == nil {
			grants[table] = map[string]bool{}
		}
		grants[table][priv] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	for _, table := range []string{"oauth_clients", "oauth_grants", "oauth_requests", "oauth_codes"} {
		for _, priv := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
			if !grants[table][priv] {
				t.Fatalf("deploybot_api grants on %s = %v", table, grants[table])
			}
		}
	}
	var kind, method string
	if err := d.pool.QueryRow(ctx, `
SELECT kind, token_endpoint_auth_method FROM app.oauth_clients WHERE id = 'deploybot-cli'
`).Scan(&kind, &method); err != nil {
		t.Fatal(err)
	}
	if kind != "internal" || method != "none" {
		t.Fatalf("deploybot-cli kind=%s auth=%s", kind, method)
	}
}

func oauthHTTPIntegration(t *testing.T, d *DB, ctx context.Context) {
	t.Helper()
	now := time.Now().UTC()
	clock := func() time.Time { return now }
	authn := auth.New(d, config.Config{
		Listen:                "127.0.0.1:0",
		GoogleClientID:        "dummy-google-client-id",
		GoogleClientSecret:    "dummy-google-client-secret",
		DeviceVerificationURI: "http://127.0.0.1/device",
		AgentWSURL:            "ws://127.0.0.1/agent/v1/ws",
		OAuthRedirectURIs:     []string{"http://127.0.0.1/callback"},
		PublicOrigin:          "http://as.example",
		ConsoleOrigin:         "http://console.example",
		MCPResource:           "http://mcp.example",
	}, clock)
	if err := authn.SetMCPClientSecret(ctx, "integration-mcp-secret"); err != nil {
		t.Fatalf("mcp client: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := (&api.Server{
		Store: d,
		Auth:  authn,
		Audit: audit.Writer{Store: d, Log: log, Now: clock},
		Log:   log,
		Now:   clock,
	}).Handler()
	user, err := d.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "oauth-http", Email: "oauth-http@example.com", Name: "OAuth", At: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	consolePlain, consoleHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateSession(ctx, user.ID, consoleHash, store.KindConsole, now.Add(24*time.Hour), now); err != nil {
		t.Fatal(err)
	}
	fx := oauthHTTP{t: t, h: h, ctx: ctx, d: d, console: consolePlain}
	clientID := fx.register()
	code, access, refresh := fx.issue(clientID)
	fx.assertCodeHash(code)
	fx.assertAudience(access, "invalid_token")
	fx.assertMe(refresh, "invalid_token")
	fx.redeemAgain(clientID, code)
	fx.assertMe(access, "unauthorized")
	fx.assertMe(refresh, "unauthorized")

	code2, access2, refresh2 := fx.issue(clientID)
	rotatedAccess, rotatedRefresh := fx.refresh(clientID, refresh2)
	fx.assertMe(rotatedAccess, "invalid_token")
	fx.assertMe(rotatedRefresh, "invalid_token")
	delegated := fx.exchange(rotatedAccess)
	fx.assertMe(delegated, "ok")
	fx.redeemAgain(clientID, code2)
	fx.assertMe(access2, "unauthorized")
	fx.assertMe(rotatedAccess, "unauthorized")
	fx.assertMe(rotatedRefresh, "unauthorized")
	fx.assertMe(delegated, "unauthorized")

	_, access3, refresh3 := fx.issue(clientID)
	nextAccess, nextRefresh := fx.refresh(clientID, refresh3)
	fx.assertMe(nextAccess, "invalid_token")
	fx.assertMe(nextRefresh, "invalid_token")
	fx.token(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh3},
		"client_id":     {clientID},
		"resource":      {"http://mcp.example"},
	}, http.StatusBadRequest, "invalid_grant")
	fx.assertMe(nextAccess, "unauthorized")
	fx.assertMe(nextRefresh, "unauthorized")
	fx.assertMe(access3, "unauthorized")
	legacyPlain, legacyHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateSession(ctx, user.ID, legacyHash, store.KindLegacyMCP, now.Add(24*time.Hour), now); err != nil {
		t.Fatal(err)
	}
	legacy := fx.do(http.MethodGet, "/v1/me", "", "", legacyPlain)
	if legacy.Code != http.StatusUnauthorized || !strings.Contains(legacy.Body.String(), `"code":"invalid_token"`) {
		t.Fatalf("legacy mcp /v1/me %d %s", legacy.Code, legacy.Body.String())
	}
	me := fx.do(http.MethodGet, "/v1/me", "", "", consolePlain)
	if me.Code != http.StatusOK {
		t.Fatalf("console /v1/me %d %s", me.Code, me.Body.String())
	}
}

type oauthHTTP struct {
	t       *testing.T
	h       http.Handler
	ctx     context.Context
	d       *DB
	console string
}

func (o oauthHTTP) do(method, path, body, contentType, bearer string) *httptest.ResponseRecorder {
	o.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "203.0.113.10:1234"
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	o.h.ServeHTTP(rec, req)
	return rec
}

func (o oauthHTTP) register() string {
	o.t.Helper()
	rec := o.do(http.MethodPost, "/oauth/register", `{"client_name":"Claude","redirect_uris":["https://app.example/callback"]}`, "application/json", "")
	if rec.Code != http.StatusCreated {
		o.t.Fatalf("register %d %s", rec.Code, rec.Body.String())
	}
	var client struct {
		ID string `json:"client_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &client); err != nil || client.ID == "" {
		o.t.Fatalf("client: %v %s", err, rec.Body.String())
	}
	return client.ID
}

func (o oauthHTTP) issue(clientID string) (code, access, refresh string) {
	o.t.Helper()
	sum := sha256.Sum256([]byte(oauthVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", "https://app.example/callback")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("resource", "http://mcp.example")
	q.Set("state", "xyz")
	rec := o.do(http.MethodGet, "/oauth/authorize?"+q.Encode(), "", "", "")
	if rec.Code != http.StatusSeeOther {
		o.t.Fatalf("authorize %d %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Query().Get("request") == "" {
		o.t.Fatalf("authorize location %q", rec.Header().Get("Location"))
	}
	approved := o.do(http.MethodPost, "/v1/oauth/requests/"+url.PathEscape(loc.Query().Get("request"))+"/approve", "", "", o.console)
	if approved.Code != http.StatusOK {
		o.t.Fatalf("approve %d %s", approved.Code, approved.Body.String())
	}
	var env struct {
		Payload struct {
			RedirectTo string `json:"redirect_to"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(approved.Body.Bytes(), &env); err != nil {
		o.t.Fatal(err)
	}
	redir, err := url.Parse(env.Payload.RedirectTo)
	if err != nil {
		o.t.Fatal(err)
	}
	code = redir.Query().Get("code")
	if code == "" || redir.Query().Get("state") != "xyz" {
		o.t.Fatalf("redirect_to %s", env.Payload.RedirectTo)
	}
	tok := o.token(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.example/callback"},
		"client_id":     {clientID},
		"code_verifier": {oauthVerifier},
		"resource":      {"http://mcp.example"},
	}, http.StatusOK, "")
	var body struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		Type    string `json:"token_type"`
		Expires int    `json:"expires_in"`
	}
	if err := json.Unmarshal(tok.Body.Bytes(), &body); err != nil {
		o.t.Fatal(err)
	}
	if body.Type != "Bearer" || body.Expires != 3600 || body.Access == "" || body.Refresh == "" {
		o.t.Fatalf("token body %s", tok.Body.String())
	}
	return code, body.Access, body.Refresh
}

func (o oauthHTTP) refresh(clientID, refresh string) (access, next string) {
	o.t.Helper()
	tok := o.token(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {clientID},
		"resource":      {"http://mcp.example"},
	}, http.StatusOK, "")
	var body struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		Expires int    `json:"expires_in"`
	}
	if err := json.Unmarshal(tok.Body.Bytes(), &body); err != nil {
		o.t.Fatal(err)
	}
	if body.Expires != 3600 || body.Access == "" || body.Refresh == "" {
		o.t.Fatalf("refresh body %s", tok.Body.String())
	}
	return body.Access, body.Refresh
}

func (o oauthHTTP) redeemAgain(clientID, code string) {
	o.t.Helper()
	o.token(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.example/callback"},
		"client_id":     {clientID},
		"code_verifier": {oauthVerifier},
		"resource":      {"http://mcp.example"},
	}, http.StatusBadRequest, "invalid_grant")
}

func (o oauthHTTP) exchange(subject string) string {
	o.t.Helper()
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", subject)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("resource", "http://as.example")
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(store.ClientMCP, "integration-mcp-secret")
	rec := httptest.NewRecorder()
	o.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		o.t.Fatalf("exchange %d %s", rec.Code, rec.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		o.t.Fatal(err)
	}
	tok, _ := raw["access_token"].(string)
	if tok == "" {
		o.t.Fatalf("exchange body %s", rec.Body.String())
	}
	return tok
}

func (o oauthHTTP) assertMe(bearer, want string) {
	o.t.Helper()
	rec := o.do(http.MethodGet, "/v1/me", "", "", bearer)
	var env struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	got := env.Code
	if rec.Code == http.StatusOK {
		got = "ok"
	}
	if got != want {
		o.t.Fatalf("/v1/me got %s (%d %s), want %s", got, rec.Code, rec.Body.String(), want)
	}
}

func (o oauthHTTP) token(form url.Values, status int, oauthCode string) *httptest.ResponseRecorder {
	o.t.Helper()
	rec := o.do(http.MethodPost, "/oauth/token", form.Encode(), "application/x-www-form-urlencoded", "")
	if rec.Code != status {
		o.t.Fatalf("token %d %s", rec.Code, rec.Body.String())
	}
	if oauthCode != "" && !strings.Contains(rec.Body.String(), `"error":"`+oauthCode+`"`) {
		o.t.Fatalf("token error %s", rec.Body.String())
	}
	return rec
}

func (o oauthHTTP) assertCodeHash(code string) {
	o.t.Helper()
	var stored []byte
	if err := o.d.pool.QueryRow(o.ctx, `
SELECT code_hash FROM app.oauth_codes ORDER BY created_at DESC LIMIT 1
`).Scan(&stored); err != nil {
		o.t.Fatal(err)
	}
	if !bytes.Equal(stored, secret.Hash(code)) {
		o.t.Fatal("code_hash is not secret.Hash(code)")
	}
	if bytes.Contains(stored, []byte(code)) {
		o.t.Fatal("code_hash contains the plaintext code")
	}
}

func (o oauthHTTP) assertAudience(access, want string) {
	o.t.Helper()
	id := "11111111-1111-1111-1111-111111111111"
	for _, pattern := range api.Patterns() {
		if !strings.Contains(pattern, " /v1/") {
			continue
		}
		method, path, _ := strings.Cut(pattern, " ")
		path = strings.ReplaceAll(path, "{project_id}", id)
		path = strings.ReplaceAll(path, "{id}", id)
		path = strings.ReplaceAll(path, "{user_id}", id)
		path = strings.ReplaceAll(path, "{token_id}", id)
		path = strings.ReplaceAll(path, "{user_code}", "ABCD-EFGH")
		rec := o.do(method, path, "", "", access)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"code":"`+want+`"`) {
			o.t.Fatalf("%s access %s: %d %s", pattern, want, rec.Code, rec.Body.String())
		}
	}
}
