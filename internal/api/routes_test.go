package api

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/more-than-code/bot-api-server/internal/auth"
	"github.com/more-than-code/bot-api-server/internal/config"
	"github.com/more-than-code/bot-api-server/internal/memstore"
)

func TestRouteTable(t *testing.T) {
	want := []string{
		"GET /health",
		"GET /.well-known/oauth-authorization-server",
		"POST /oauth/register",
		"GET /oauth/authorize",
		"POST /oauth/token",
		"POST /oauth/revoke",
		"GET /v1/auth/google/start",
		"POST /v1/auth/google/callback",
		"POST /v1/auth/signout",
		"GET /v1/me",
		"GET /v1/oauth/requests/{id}",
		"POST /v1/oauth/requests/{id}/approve",
		"POST /v1/oauth/requests/{id}/deny",
		"GET /v1/me/grants",
		"DELETE /v1/me/grants/{id}",
		"POST /v1/auth/device/code",
		"POST /v1/auth/device/token",
		"GET /v1/auth/device/{user_code}",
		"POST /v1/auth/device/{user_code}/approve",
		"POST /v1/auth/device/{user_code}/deny",
		"POST /v1/projects",
		"GET /v1/projects",
		"GET /v1/projects/{id}",
		"PATCH /v1/projects/{id}",
		"DELETE /v1/projects/{id}",
		"GET /v1/projects/{id}/members",
		"POST /v1/projects/{id}/members",
		"PATCH /v1/projects/{id}/members/{user_id}",
		"DELETE /v1/projects/{id}/members/{user_id}",
		"POST /v1/projects/{id}/transfer-ownership",
		"POST /v1/projects/{id}/join-tokens",
		"GET /v1/projects/{id}/join-tokens",
		"DELETE /v1/projects/{id}/join-tokens/{token_id}",
		"POST /v1/projects/{id}/invites",
		"GET /v1/projects/{id}/invites",
		"DELETE /v1/projects/{id}/invites/{invite_id}",
		"POST /v1/invites/lookup",
		"POST /v1/invites/accept",
		"POST /v1/projects/{id}/catalog/parse",
		"GET /v1/projects/{id}/catalog",
		"POST /v1/projects/{id}/catalog",
		"GET /v1/projects/{id}/catalog/{name}",
		"PUT /v1/projects/{id}/catalog/{name}",
		"DELETE /v1/projects/{id}/catalog/{name}",
		"GET /v1/projects/{id}/catalog/{name}/permissions",
		"PUT /v1/projects/{id}/catalog/{name}/permissions",
		"POST /v1/projects/{id}/catalog/{name}/run",
		"POST /v1/projects/{id}/catalog/{name}/stop",
		"POST /v1/projects/{id}/catalog/{name}/restart",
		"POST /v1/projects/{id}/catalog/{name}/logs",
		"POST /v1/projects/{id}/catalog/{name}/status",
		"POST /v1/projects/{id}/catalog/{name}/deploy",
		"POST /v1/projects/{id}/catalog/{name}/rollback",
		"POST /v1/projects/{id}/catalog/{name}/remove",
		"GET /v1/projects/{id}/catalog/{name}/deploys",
		"GET /v1/projects/{id}/env-sets",
		"GET /v1/projects/{id}/env-sets/{set}",
		"PUT /v1/projects/{id}/env-sets/{set}",
		"DELETE /v1/projects/{id}/env-sets/{set}",
		"PUT /v1/projects/{id}/env-sets/{set}/keys/{key}",
		"DELETE /v1/projects/{id}/env-sets/{set}/keys/{key}",
		"POST /v1/projects/{id}/env-sets/{set}/secret",
		"GET /v1/projects/{id}/registries",
		"PUT /v1/projects/{id}/registries/{host}",
		"DELETE /v1/projects/{id}/registries/{host}",
		"GET /v1/projects/{id}/image-tags",
		"GET /v1/projects/{id}/image-digest",
		"GET /v1/projects/{id}/files",
		"GET /v1/projects/{id}/files/{name}",
		"PUT /v1/projects/{id}/files/{name}",
		"DELETE /v1/projects/{id}/files/{name}",
		"GET /v1/projects/{id}/hosts",
		"GET /v1/projects/{id}/services",
		"GET /v1/hosts/{id}",
		"DELETE /v1/hosts/{id}/credential",
		"GET /v1/hosts/{id}/shares",
		"PUT /v1/hosts/{id}/shares/{project_id}",
		"DELETE /v1/hosts/{id}/shares/{project_id}",
		"GET /v1/hosts/{id}/catalog-approvals",
		"POST /v1/hosts/{id}/catalog-approvals",
		"DELETE /v1/hosts/{id}/catalog-approvals/{entry_id}",
		"GET /v1/hosts/{id}/services",
		"GET /v1/services/{id}",
		"PATCH /v1/services/{id}",
		"PUT /v1/services/{id}/health-checks",
		"GET /v1/hosts/{id}/metrics",
		"GET /v1/hosts/{id}/processes",
		"GET /v1/services/{id}/health",
		"POST /v1/hosts/{id}/snapshot",
		"POST /v1/services/{id}/probe",
		"POST /v1/confirmations/{confirmation_id}",
		"GET /v1/projects/{id}/audit",
	}
	got := Patterns()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("patterns:\n%s", strings.Join(got, "\n"))
	}
	h := testHandler(t)
	id := "11111111-1111-1111-1111-111111111111"
	for _, pattern := range want {
		method, path, _ := strings.Cut(pattern, " ")
		path = strings.ReplaceAll(path, "{project_id}", id)
		path = strings.ReplaceAll(path, "{id}", id)
		path = strings.ReplaceAll(path, "{user_id}", id)
		path = strings.ReplaceAll(path, "{token_id}", id)
		path = strings.ReplaceAll(path, "{invite_id}", id)
		path = strings.ReplaceAll(path, "{user_code}", "ABCD-EFGH")
		var body []byte
		switch pattern {
		case "POST /v1/auth/google/callback", "POST /v1/auth/device/code", "POST /v1/auth/device/token":
			body = []byte(`{}`)
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Fatalf("%s -> 404", pattern)
		}
		switch pattern {
		case "GET /health":
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"ok"`) {
				t.Fatalf("health: %d %s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), `"code"`) {
				t.Fatalf("health has an envelope: %s", rec.Body.String())
			}
		case "GET /v1/auth/google/start", "POST /v1/auth/google/callback", "POST /v1/auth/device/code", "POST /v1/auth/device/token",
			"GET /.well-known/oauth-authorization-server", "POST /oauth/register", "GET /oauth/authorize", "POST /oauth/token", "POST /oauth/revoke":
			if rec.Code == http.StatusUnauthorized {
				t.Fatalf("%s should be public, got 401", pattern)
			}
		default:
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s: got %d %s, want 401", pattern, rec.Code, rec.Body.String())
			}
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/missing", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing: %d", rec.Code)
	}
}

func TestHandlersCallAuthorize(t *testing.T) {
	public := map[string]bool{
		"handleHealth":         true,
		"handleGoogleStart":    true,
		"handleGoogleCallback": true,
		"handleDeviceCode":     true,
		"handleDeviceToken":    true,
		"handleNotFound":       true,
		"handleOAuthMetadata":  true,
		"handleOAuthRegister":  true,
		"handleOAuthAuthorize": true,
		"handleOAuthToken":     true,
		"handleOAuthRevoke":    true,
	}
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	fset := token.NewFileSet()
	for _, name := range matches {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			fd, ok := n.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Body == nil || !strings.HasPrefix(fd.Name.Name, "handle") {
				return true
			}
			seen[fd.Name.Name] = true
			has := callsAuthorize(fd.Body)
			if public[fd.Name.Name] {
				if has {
					t.Errorf("%s is public but calls Authorize", fd.Name.Name)
				}
				return true
			}
			if !has {
				t.Errorf("%s does not call authz.Authorize", fd.Name.Name)
			}
			return true
		})
	}
	if len(seen) < 20 {
		t.Fatalf("parsed %d handlers", len(seen))
	}
}

func callsAuthorize(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if ok && (sel.Sel.Name == "Authorize" || sel.Sel.Name == "AuthorizeHost" || sel.Sel.Name == "AuthorizeUnshare" || sel.Sel.Name == "gateHost" || sel.Sel.Name == "fileProject") {
			found = true
		}
		return true
	})
	return found
}

func TestEnvelopeStatus(t *testing.T) {
	cases := []struct {
		code string
		want int
	}{
		{"ok", 200},
		{"bad_request", 400},
		{"unauthorized", 401},
		{"forbidden", 403},
		{"not_found", 404},
		{"conflict", 409},
		{"unavailable", 503},
		{"timeout", 504},
		{"error", 500},
		{"authorization_pending", 400},
		{"slow_down", 400},
		{"expired_token", 400},
		{"access_denied", 400},
		{"invalid_token", 401},
		{"rate_limited", 429},
		{"not_implemented", 501},
		{"registry_unavailable", 502},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		writeCode(rec, tc.code, "")
		if rec.Code != tc.want {
			t.Fatalf("%s: http %d", tc.code, rec.Code)
		}
		var env envelope
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		if env.Code != tc.code || env.Payload != nil {
			t.Fatalf("%s: %#v", tc.code, env)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("missing nosniff")
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("missing no-store")
		}
	}
	rec := httptest.NewRecorder()
	writeOK(rec, http.StatusCreated, map[string]string{"id": "x"})
	if rec.Code != http.StatusCreated {
		t.Fatal(rec.Code)
	}
}

func testHandler(t *testing.T) http.Handler {
	t.Helper()
	cfg := config.Config{
		GoogleClientID:        "dummy-google-client-id",
		GoogleClientSecret:    "dummy-google-client-secret",
		GoogleIssuer:          "https://accounts.google.com",
		OAuthRedirectURIs:     []string{"http://127.0.0.1/callback"},
		DeviceVerificationURI: "http://127.0.0.1/device",
		AgentWSURL:            "ws://127.0.0.1/agent/v1/ws",
	}
	st := memstore.New()
	srv := &Server{
		Store:      st,
		Auth:       auth.New(st, cfg, nil),
		AgentWSURL: cfg.AgentWSURL,
	}
	return srv.Handler()
}
