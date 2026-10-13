package auth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/more-than-code/bot-api-server/internal/auth"
	"github.com/more-than-code/bot-api-server/internal/config"
	"github.com/more-than-code/bot-api-server/internal/memstore"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestGoogleOIDC(t *testing.T) {
	ctx := context.Background()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "test-key"
	keys, err := jwksJSON(&key.PublicKey, kid)
	if err != nil {
		t.Fatal(err)
	}

	var srv *httptest.Server
	var verifiers []string
	var redirects []string
	tokens := map[string]string{}
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(t, w, map[string]any{
				"issuer":                                srv.URL,
				"authorization_endpoint":                srv.URL + "/auth",
				"token_endpoint":                        srv.URL + "/token",
				"jwks_uri":                              srv.URL + "/keys",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			w.Header().Set("Content-Type", "application/json")
			if _, err := w.Write(keys); err != nil {
				t.Errorf("write jwks: %v", err)
			}
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse token form: %v", err)
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			verifiers = append(verifiers, r.Form.Get("code_verifier"))
			redirects = append(redirects, r.Form.Get("redirect_uri"))
			if r.Form.Get("code_verifier") == "" {
				t.Error("token endpoint received an empty code_verifier")
			}
			writeJSON(t, w, map[string]any{
				"access_token": "test-access",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"id_token":     tokens[r.Form.Get("code")],
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	start := time.Date(2026, 10, 13, 15, 0, 0, 0, time.UTC)
	clk := &manualClock{t: start}
	const (
		sub       = "google-sub-1"
		redirectA = "https://console.example/cb"
		redirectB = "https://console.example/alt"
		clientID  = "bot-client"
	)
	claims := func(email string, verified bool, name string) string {
		t.Helper()
		raw, err := signRS256(key, kid, map[string]any{
			"iss":            srv.URL,
			"sub":            sub,
			"aud":            clientID,
			"exp":            start.Add(2 * time.Hour).Unix(),
			"iat":            start.Unix(),
			"email":          email,
			"email_verified": verified,
			"name":           name,
			"picture":        "https://img.example/ada.png",
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	tokens["unverified"] = claims("Ada@Example.com", false, "Ada Lovelace")
	tokens["empty"] = claims("", true, "Ada Lovelace")
	tokens["ok"] = claims("Ada@Example.com", true, "Ada Lovelace")
	tokens["rename"] = claims("Other@Example.com", true, "Ada Lovelace II")

	mem := memstore.New()
	svc := auth.New(mem, config.Config{
		GoogleClientID:     clientID,
		GoogleClientSecret: "bot-secret",
		GoogleIssuer:       srv.URL,
		OAuthRedirectURIs:  []string{redirectA, redirectB},
	}, clk.Now)
	svc.SetHTTPClient(srv.Client())

	if _, err := svc.StartGoogle(ctx, "https://evil.example/cb"); !errors.Is(err, auth.ErrRedirect) {
		t.Fatalf("disallowed redirect: %v", err)
	}

	started, err := svc.StartGoogle(ctx, redirectA)
	if err != nil {
		t.Fatal(err)
	}
	authURL, err := url.Parse(started.AuthorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	if authURL.Scheme+"://"+authURL.Host+authURL.Path != srv.URL+"/auth" {
		t.Fatalf("authorize url %q", started.AuthorizeURL)
	}
	q := authURL.Query()
	if q.Get("state") != started.State || q.Get("redirect_uri") != redirectA {
		t.Fatalf("authorize query %v", q)
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("pkce query %v", q)
	}
	if strings.Contains(started.AuthorizeURL, "code_verifier=") {
		t.Fatal("code_verifier leaked into the authorize URL")
	}
	scope := q.Get("scope")
	for _, want := range []string{"openid", "email", "profile"} {
		if !strings.Contains(" "+scope+" ", " "+want+" ") {
			t.Fatalf("scope %q missing %s", scope, want)
		}
	}

	if _, err := svc.FinishGoogle(ctx, "ok", started.State, redirectB); !errors.Is(err, store.ErrState) {
		t.Fatalf("redirect mismatch: %v", err)
	}
	if _, err := svc.FinishGoogle(ctx, "ok", started.State, redirectA); !errors.Is(err, store.ErrState) {
		t.Fatalf("state reused after mismatch: %v", err)
	}
	if mem.UserCount() != 0 {
		t.Fatalf("mismatch created %d users", mem.UserCount())
	}

	started, err = svc.StartGoogle(ctx, redirectA)
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(10 * time.Minute)
	if _, err := svc.FinishGoogle(ctx, "ok", started.State, redirectA); !errors.Is(err, store.ErrState) {
		t.Fatalf("expired state: %v", err)
	}

	if _, err := svc.FinishGoogle(ctx, "ok", "missing-state", redirectA); !errors.Is(err, store.ErrState) {
		t.Fatalf("missing state: %v", err)
	}

	started, err = svc.StartGoogle(ctx, redirectA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.FinishGoogle(ctx, "unverified", started.State, redirectA); !errors.Is(err, auth.ErrUnverified) {
		t.Fatalf("unverified: %v", err)
	}
	started, err = svc.StartGoogle(ctx, redirectA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.FinishGoogle(ctx, "empty", started.State, redirectA); !errors.Is(err, auth.ErrUnverified) {
		t.Fatalf("empty email: %v", err)
	}
	if mem.UserCount() != 0 {
		t.Fatalf("rejected sign-in created %d users", mem.UserCount())
	}
	if len(verifiers) == 0 {
		t.Fatal("token endpoint was not called")
	}
	for i, v := range verifiers {
		if v == "" {
			t.Fatalf("verifier %d empty", i)
		}
		if redirects[i] != redirectA {
			t.Fatalf("token redirect %q", redirects[i])
		}
	}

	started, err = svc.StartGoogle(ctx, redirectA)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := svc.FinishGoogle(ctx, "ok", started.State, redirectA)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Token == "" || issued.User.Email != "ada@example.com" || issued.User.Name != "Ada Lovelace" {
		t.Fatalf("issue %+v", issued)
	}
	if issued.User.AvatarURL != "https://img.example/ada.png" {
		t.Fatalf("avatar %q", issued.User.AvatarURL)
	}
	if issued.Session.Kind != "console" || issued.Session.UserID != issued.User.ID {
		t.Fatalf("session %+v", issued.Session)
	}
	if !issued.ExpiresAt.Equal(clk.Now().Add(7*24*time.Hour)) || !issued.Session.ExpiresAt.Equal(issued.ExpiresAt) {
		t.Fatalf("expiry %s session %s", issued.ExpiresAt, issued.Session.ExpiresAt)
	}
	if mem.UserCount() != 1 {
		t.Fatalf("users %d", mem.UserCount())
	}
	if _, err := svc.FinishGoogle(ctx, "ok", started.State, redirectA); !errors.Is(err, store.ErrState) {
		t.Fatalf("second finish: %v", err)
	}

	sess, got, err := svc.Authenticate(ctx, "Bearer "+issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	if sess.ID != issued.Session.ID || got.Email != "ada@example.com" || !sess.LastSeenAt.Equal(issued.Session.LastSeenAt) {
		t.Fatalf("authenticate %+v %+v", sess, got)
	}
	if _, _, err := svc.Authenticate(ctx, issued.Token); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Authenticate(ctx, ""); !errors.Is(err, store.ErrUnauthorized) {
		t.Fatalf("empty: %v", err)
	}

	started, err = svc.StartGoogle(ctx, redirectA)
	if err != nil {
		t.Fatal(err)
	}
	again, err := svc.FinishGoogle(ctx, "rename", started.State, redirectA)
	if err != nil {
		t.Fatal(err)
	}
	if again.User.ID != issued.User.ID {
		t.Fatalf("user id changed %s -> %s", issued.User.ID, again.User.ID)
	}
	if again.User.Name != "Ada Lovelace II" || again.User.Email != "ada@example.com" {
		t.Fatalf("second login user %+v", again.User)
	}
	stored, err := mem.GetUser(ctx, issued.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Name != "Ada Lovelace II" || stored.Email != "ada@example.com" {
		t.Fatalf("stored user %+v", stored)
	}
	if mem.UserCount() != 1 {
		t.Fatalf("users after second login %d", mem.UserCount())
	}
	if _, _, err := svc.Authenticate(ctx, issued.Token); err != nil {
		t.Fatalf("first session after second login: %v", err)
	}
	if err := svc.SignOut(ctx, issued.Session.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Authenticate(ctx, issued.Token); !errors.Is(err, store.ErrUnauthorized) {
		t.Fatalf("signed out: %v", err)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encode json: %v", err)
	}
}

func jwksJSON(pub *rsa.PublicKey, kid string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": kid,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

func signRS256(key *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString
	signing := enc(header) + "." + enc(payload)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc(sig), nil
}
