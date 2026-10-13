package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/auth"
	"github.com/more-than-code/bot-api-server/internal/config"
	"github.com/more-than-code/bot-api-server/internal/memstore"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestLogsOmitSecrets(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	slog.SetDefault(log)
	st := memstore.New()
	now := time.Now().UTC()
	user, err := st.UpsertGoogleUser(t.Context(), store.GoogleSignIn{Subject: "sub", Email: "a@example.com", Name: "A", At: now})
	if err != nil {
		t.Fatal(err)
	}
	project, err := st.CreateProject(t.Context(), user.ID, "Lab", "lab", now)
	if err != nil {
		t.Fatal(err)
	}
	sessionPlain, sessionHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSession(t.Context(), user.ID, sessionHash, "console", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		GoogleClientID:        "dummy-google-client-id",
		GoogleClientSecret:    "dummy-google-client-secret",
		GoogleIssuer:          "https://accounts.google.com",
		OAuthRedirectURIs:     []string{"http://127.0.0.1/callback"},
		DeviceVerificationURI: "http://127.0.0.1/device",
		AgentWSURL:            "ws://127.0.0.1/agent/v1/ws",
	}
	srv := &Server{
		Store:      st,
		Auth:       auth.New(st, cfg, func() time.Time { return now }),
		Audit:      audit.Writer{Store: st, Log: log, Now: func() time.Time { return now }},
		AgentWSURL: cfg.AgentWSURL,
		Log:        log,
		Now:        func() time.Time { return now },
	}
	h := srv.Handler()

	joinRec := httptest.NewRecorder()
	joinReq := httptest.NewRequest(http.MethodPost, "/v1/projects/"+project.ID.String()+"/join-tokens", strings.NewReader(`{}`))
	joinReq.Header.Set("Authorization", "Bearer "+sessionPlain)
	h.ServeHTTP(joinRec, joinReq)
	if joinRec.Code != http.StatusCreated {
		t.Fatalf("join: %d %s", joinRec.Code, joinRec.Body.String())
	}
	var joinEnv struct {
		Payload struct {
			Token string `json:"token"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(joinRec.Body.Bytes(), &joinEnv); err != nil || len(joinEnv.Payload.Token) < 40 {
		t.Fatalf("join payload: %v %s", err, joinRec.Body.String())
	}

	devRec := httptest.NewRecorder()
	devReq := httptest.NewRequest(http.MethodPost, "/v1/auth/device/code", strings.NewReader(`{"client_name":"cli"}`))
	h.ServeHTTP(devRec, devReq)
	if devRec.Code != http.StatusOK {
		t.Fatalf("device: %d %s", devRec.Code, devRec.Body.String())
	}
	var devEnv struct {
		Payload struct {
			DeviceCode string `json:"device_code"`
			UserCode   string `json:"user_code"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(devRec.Body.Bytes(), &devEnv); err != nil || len(devEnv.Payload.DeviceCode) < 40 {
		t.Fatalf("device payload: %v %s", err, devRec.Body.String())
	}

	logs := buf.String()
	for _, secretText := range []string{sessionPlain, joinEnv.Payload.Token, devEnv.Payload.DeviceCode, devEnv.Payload.UserCode} {
		if strings.Contains(logs, secretText) {
			t.Fatalf("log contains secret %q\n%s", secretText, logs)
		}
	}
}
