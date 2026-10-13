package auth_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/more-than-code/bot-api-server/internal/api"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/auth"
	"github.com/more-than-code/bot-api-server/internal/config"
	"github.com/more-than-code/bot-api-server/internal/memstore"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestDeviceHTTPStatuses(t *testing.T) {
	mem := memstore.New()
	apiSrv := deviceServer(t, mem, "https://accounts.google.com")
	srv := httptest.NewServer(apiSrv.Handler())
	defer srv.Close()
	start := func(name string) (string, string) {
		t.Helper()
		res, err := http.Post(srv.URL+"/v1/auth/device/code", "application/json", bytes.NewReader([]byte(`{"client_name":"`+name+`"}`)))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var body struct {
			Code    string `json:"code"`
			Payload struct {
				DeviceCode string `json:"device_code"`
				UserCode   string `json:"user_code"`
			} `json:"payload"`
		}
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusOK || body.Code != "ok" || body.Payload.DeviceCode == "" {
			t.Fatalf("start %s: %d %#v", name, res.StatusCode, body)
		}
		return body.Payload.DeviceCode, body.Payload.UserCode
	}
	postToken := func(device string) (int, string) {
		t.Helper()
		res, err := http.Post(srv.URL+"/v1/auth/device/token", "application/json", bytes.NewReader([]byte(`{"device_code":"`+device+`"}`)))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var env struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(res.Body).Decode(&env); err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, env.Code
	}
	device, _ := start("cli")
	status, kind := postToken(device)
	if status != http.StatusBadRequest || kind != "authorization_pending" {
		t.Fatalf("pending %d %s", status, kind)
	}
	status, kind = postToken(device)
	if status != http.StatusBadRequest || kind != "slow_down" {
		t.Fatalf("slow_down %d %s", status, kind)
	}
	status, kind = postToken("missing-device-code")
	if status != http.StatusBadRequest || kind != "expired_token" {
		t.Fatalf("expired %d %s", status, kind)
	}
	deniedCode, userCode := start("cli-denied")
	user, err := mem.UpsertGoogleUser(context.Background(), store.GoogleSignIn{
		Subject: "sub", Email: "a@b.c", Name: "A", At: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := apiSrv.Auth.DenyDevice(context.Background(), userCode, user.ID); err != nil {
		t.Fatal(err)
	}
	status, kind = postToken(deniedCode)
	if status != http.StatusBadRequest || kind != "access_denied" {
		t.Fatalf("denied %d %s", status, kind)
	}
}

func TestDeviceIPLimit(t *testing.T) {
	mem := memstore.New()
	h := deviceServer(t, mem, "https://accounts.google.com").Handler()
	for i := 0; i < 10; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/device/code", bytes.NewReader([]byte(`{"client_name":"cli"}`)))
		req.RemoteAddr = "203.0.113.8:1234"
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/device/code", bytes.NewReader([]byte(`{"client_name":"cli"}`)))
	req.RemoteAddr = "203.0.113.8:9999"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests || !bytes.Contains(rec.Body.Bytes(), []byte(`"code":"slow_down"`)) {
		t.Fatalf("limit %d %s", rec.Code, rec.Body.String())
	}
	if mem.DeviceCount() != 10 {
		t.Fatalf("devices %d", mem.DeviceCount())
	}
}

func TestDeviceTokenIPLimit(t *testing.T) {
	h := deviceServer(t, memstore.New(), "https://accounts.google.com").Handler()
	post := func(addr, forwarded, code string) (int, string) {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/device/token", bytes.NewReader([]byte(`{"device_code":"`+code+`"}`)))
		req.RemoteAddr = addr
		if forwarded != "" {
			req.Header.Set("X-Forwarded-For", forwarded)
		}
		h.ServeHTTP(rec, req)
		var env struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		return rec.Code, env.Code
	}
	for i := 0; i < 30; i++ {
		status, kind := post("203.0.113.8:1000", fmt.Sprintf("198.51.100.%d", i%20), "unknown-code")
		if status != http.StatusBadRequest || kind != "expired_token" {
			t.Fatalf("poll %d: %d %s", i, status, kind)
		}
	}
	status, kind := post("203.0.113.8:1001", "198.51.100.99", "unknown-code")
	if status != http.StatusTooManyRequests || kind != "slow_down" {
		t.Fatalf("over limit: %d %s", status, kind)
	}
	status, kind = post("203.0.113.9:1000", "203.0.113.8", "unknown-code")
	if status != http.StatusBadRequest || kind != "expired_token" {
		t.Fatalf("other peer: %d %s", status, kind)
	}
}

func TestDeviceTokenTrustedProxy(t *testing.T) {
	srv := deviceServer(t, memstore.New(), "https://accounts.google.com")
	srv.TrustedProxy = "203.0.113.8"
	h := srv.Handler()
	post := func(addr, forwarded string) (int, string) {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/device/token", bytes.NewReader([]byte(`{"device_code":"unknown-code"}`)))
		req.RemoteAddr = addr
		req.Header.Set("X-Forwarded-For", forwarded)
		h.ServeHTTP(rec, req)
		var env struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		return rec.Code, env.Code
	}
	for i := 0; i < 30; i++ {
		status, kind := post("203.0.113.8:1000", "1.2.3.4, 198.51.100.9")
		if status != http.StatusBadRequest || kind != "expired_token" {
			t.Fatalf("client %d: %d %s", i, status, kind)
		}
	}
	status, kind := post("203.0.113.8:1000", "198.51.100.9")
	if status != http.StatusTooManyRequests || kind != "slow_down" {
		t.Fatalf("same client: %d %s", status, kind)
	}
	status, kind = post("203.0.113.8:1000", "1.2.3.4, 198.51.100.10")
	if status != http.StatusBadRequest || kind != "expired_token" {
		t.Fatalf("other client: %d %s", status, kind)
	}
	status, kind = post("198.51.100.50:9", "198.51.100.9")
	if status != http.StatusBadRequest || kind != "expired_token" {
		t.Fatalf("untrusted peer: %d %s", status, kind)
	}
}

func TestGoogleStartIPLimit(t *testing.T) {
	var oidcSrv *httptest.Server
	oidcSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, map[string]any{
			"issuer":                                oidcSrv.URL,
			"authorization_endpoint":                oidcSrv.URL + "/auth",
			"token_endpoint":                        oidcSrv.URL + "/token",
			"jwks_uri":                              oidcSrv.URL + "/keys",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	defer oidcSrv.Close()
	const redirect = "http://127.0.0.1/callback"
	apiSrv := newAPI(t, memstore.New(), config.Config{
		GoogleClientID:        "dummy-google-client-id",
		GoogleClientSecret:    "dummy-google-client-secret",
		GoogleIssuer:          oidcSrv.URL,
		OAuthRedirectURIs:     []string{redirect},
		DeviceVerificationURI: "http://127.0.0.1/device",
		AgentWSURL:            "ws://127.0.0.1/agent/v1/ws",
	}, nil)
	apiSrv.Auth.SetHTTPClient(oidcSrv.Client())
	h := apiSrv.Handler()
	start := func(addr string) int {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/google/start?redirect_uri="+redirect, nil)
		req.RemoteAddr = addr
		req.Header.Set("X-Forwarded-For", "198.51.100.20")
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < 20; i++ {
		if code := start("203.0.113.8:2000"); code != http.StatusOK {
			t.Fatalf("start %d: %d", i, code)
		}
	}
	if code := start("203.0.113.8:2001"); code != http.StatusServiceUnavailable {
		t.Fatalf("over limit: %d", code)
	}
	if code := start("203.0.113.9:2000"); code != http.StatusOK {
		t.Fatalf("other ip: %d", code)
	}
}

func TestGoogleCallbackHTTP(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "test-key"
	keys, err := jwksJSON(&key.PublicKey, kid)
	if err != nil {
		t.Fatal(err)
	}
	var oidcSrv *httptest.Server
	tokens := map[string]string{}
	oidcSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(t, w, map[string]any{
				"issuer":                                oidcSrv.URL,
				"authorization_endpoint":                oidcSrv.URL + "/auth",
				"token_endpoint":                        oidcSrv.URL + "/token",
				"jwks_uri":                              oidcSrv.URL + "/keys",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(keys)
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad", http.StatusBadRequest)
				return
			}
			code := r.Form.Get("code")
			if code == "noid" {
				writeJSON(t, w, map[string]any{"access_token": "x", "token_type": "Bearer"})
				return
			}
			writeJSON(t, w, map[string]any{
				"access_token": "x", "token_type": "Bearer", "id_token": tokens[code],
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer oidcSrv.Close()

	start := time.Date(2026, 10, 13, 15, 0, 0, 0, time.UTC)
	clk := &manualClock{t: start}
	sign := func(sub, email string, verified bool) string {
		t.Helper()
		raw, err := signRS256(key, kid, map[string]any{
			"iss": oidcSrv.URL, "sub": sub, "aud": "dummy-google-client-id",
			"exp": start.Add(time.Hour).Unix(), "iat": start.Unix(),
			"email": email, "email_verified": verified, "name": "Ada",
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	tokens["unverified"] = sign("sub-u", "ada@example.com", false)
	tokens["ok"] = sign("sub-1", "ada@example.com", true)
	tokens["other"] = sign("sub-2", "ada@example.com", true)

	mem := memstore.New()
	const redirect = "http://127.0.0.1/callback"
	apiSrv := newAPI(t, mem, config.Config{
		GoogleClientID:        "dummy-google-client-id",
		GoogleClientSecret:    "dummy-google-client-secret",
		GoogleIssuer:          oidcSrv.URL,
		OAuthRedirectURIs:     []string{redirect},
		DeviceVerificationURI: "http://127.0.0.1/device",
		AgentWSURL:            "ws://127.0.0.1/agent/v1/ws",
	}, clk.Now)
	apiSrv.Auth.SetHTTPClient(oidcSrv.Client())
	h := apiSrv.Handler()

	status, env := apiCall(t, h, http.MethodGet, "/v1/auth/google/start?redirect_uri=https://evil.example/cb", "")
	if status != http.StatusBadRequest || env.Code != "bad_request" {
		t.Fatalf("redirect %d %s", status, env.Code)
	}
	status, env = apiCall(t, h, http.MethodPost, "/v1/auth/google/callback", `{"code":"ok","state":"missing-state","redirect_uri":"`+redirect+`"}`)
	if status != http.StatusBadRequest || env.Code != "bad_request" {
		t.Fatalf("bad state %d %s", status, env.Code)
	}
	if mem.UserCount() != 0 {
		t.Fatal("bad state created a user")
	}

	state := googleState(t, h, redirect)
	status, env = apiCall(t, h, http.MethodPost, "/v1/auth/google/callback", `{"code":"unverified","state":"`+state+`","redirect_uri":"`+redirect+`"}`)
	if status != http.StatusForbidden || env.Code != "forbidden" {
		t.Fatalf("unverified %d %s", status, env.Code)
	}
	if mem.UserCount() != 0 {
		t.Fatal("unverified email created a user")
	}

	state = googleState(t, h, redirect)
	status, env = apiCall(t, h, http.MethodPost, "/v1/auth/google/callback", `{"code":"noid","state":"`+state+`","redirect_uri":"`+redirect+`"}`)
	if status != http.StatusInternalServerError || env.Code != "error" {
		t.Fatalf("missing id_token %d %s", status, env.Code)
	}

	state = googleState(t, h, redirect)
	status, env = apiCall(t, h, http.MethodPost, "/v1/auth/google/callback", `{"code":"ok","state":"`+state+`","redirect_uri":"`+redirect+`"}`)
	if status != http.StatusOK || env.Code != "ok" {
		t.Fatalf("sign-in %d %s", status, env.Code)
	}
	if !hasSignIn(mem.AllAudits()) {
		t.Fatal("sign-in was not audited")
	}

	state = googleState(t, h, redirect)
	status, env = apiCall(t, h, http.MethodPost, "/v1/auth/google/callback", `{"code":"other","state":"`+state+`","redirect_uri":"`+redirect+`"}`)
	if status != http.StatusConflict || env.Code != "conflict" {
		t.Fatalf("conflict %d %s", status, env.Code)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	defer bad.Close()
	broken := newAPI(t, memstore.New(), config.Config{
		GoogleClientID:        "dummy-google-client-id",
		GoogleClientSecret:    "dummy-google-client-secret",
		GoogleIssuer:          bad.URL,
		OAuthRedirectURIs:     []string{redirect},
		DeviceVerificationURI: "http://127.0.0.1/device",
		AgentWSURL:            "ws://127.0.0.1/agent/v1/ws",
	}, clk.Now)
	broken.Auth.SetHTTPClient(bad.Client())
	status, env = apiCall(t, broken.Handler(), http.MethodGet, "/v1/auth/google/start?redirect_uri="+redirect, "")
	if status != http.StatusInternalServerError || env.Code != "error" {
		t.Fatalf("provider %d %s", status, env.Code)
	}
}

func hasSignIn(rows []store.AuditEntry) bool {
	for _, row := range rows {
		if row.Action == audit.ActionSignIn && row.Decision == audit.DecisionAllowed && row.Via == audit.ViaConsole && row.ProjectID == nil {
			return true
		}
	}
	return false
}

func googleState(t *testing.T, h http.Handler, redirect string) string {
	t.Helper()
	status, env := apiCall(t, h, http.MethodGet, "/v1/auth/google/start?redirect_uri="+redirect, "")
	if status != http.StatusOK || env.Code != "ok" {
		t.Fatalf("start %d %s", status, env.Code)
	}
	payload, _ := env.Payload.(map[string]any)
	state, _ := payload["state"].(string)
	if state == "" {
		t.Fatal("empty state")
	}
	return state
}

type httpEnv struct {
	Code    string `json:"code"`
	Payload any    `json:"payload"`
}

func apiCall(t *testing.T, h http.Handler, method, path, body string) (int, httpEnv) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = bytes.NewReader([]byte(body))
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, rdr)
	h.ServeHTTP(rec, req)
	var env httpEnv
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode %d %s: %v", rec.Code, rec.Body.String(), err)
	}
	return rec.Code, env
}

func newAPI(t *testing.T, mem *memstore.Mem, cfg config.Config, now func() time.Time) *api.Server {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &api.Server{
		Store:      mem,
		Auth:       auth.New(mem, cfg, now),
		Audit:      audit.Writer{Store: mem, Log: log, Now: now},
		AgentWSURL: cfg.AgentWSURL,
		Log:        log,
		Now:        now,
	}
}

func deviceServer(t *testing.T, mem *memstore.Mem, issuer string) *api.Server {
	t.Helper()
	return newAPI(t, mem, config.Config{
		GoogleClientID:        "dummy-google-client-id",
		GoogleClientSecret:    "dummy-google-client-secret",
		GoogleIssuer:          issuer,
		OAuthRedirectURIs:     []string{"http://127.0.0.1/callback"},
		DeviceVerificationURI: "http://127.0.0.1/device",
		AgentWSURL:            "ws://127.0.0.1/agent/v1/ws",
	}, nil)
}
