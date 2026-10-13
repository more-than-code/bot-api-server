package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/auth"
	"github.com/more-than-code/bot-api-server/internal/config"
	"github.com/more-than-code/bot-api-server/internal/memstore"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestSlowDownKeepsRaisedInterval(t *testing.T) {
	ctx := context.Background()
	mem := memstore.New()
	clk := &manualClock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	svc := auth.New(mem, config.Config{DeviceVerificationURI: "https://console.example/device"}, clk.Now)
	dc, err := svc.StartDevice(ctx, "cli")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PollDevice(ctx, dc.DeviceCode); !errors.Is(err, auth.ErrPending) {
		t.Fatalf("first poll: %v", err)
	}
	if _, err := svc.PollDevice(ctx, dc.DeviceCode); !errors.Is(err, auth.ErrSlowDown) {
		t.Fatalf("slow_down: %v", err)
	}
	clk.Advance(6 * time.Second)
	if _, err := svc.PollDevice(ctx, dc.DeviceCode); !errors.Is(err, auth.ErrSlowDown) {
		t.Fatalf("poll inside the raised interval: %v", err)
	}
	// That poll is itself early, so it adds another 5s (interval is now 15s).
	clk.Advance(9 * time.Second)
	if _, err := svc.PollDevice(ctx, dc.DeviceCode); !errors.Is(err, auth.ErrPending) {
		t.Fatalf("poll after the raised interval: %v", err)
	}
}

func TestUnknownDeviceCodeDoesNotSlowDown(t *testing.T) {
	ctx := context.Background()
	svc := auth.New(memstore.New(), config.Config{DeviceVerificationURI: "https://console.example/device"}, nil)
	const missing = "not-a-device-code"
	if _, err := svc.PollDevice(ctx, missing); !errors.Is(err, auth.ErrExpiredToken) {
		t.Fatalf("unknown code: %v", err)
	}
	if _, err := svc.PollDevice(ctx, missing); !errors.Is(err, auth.ErrExpiredToken) {
		t.Fatalf("second poll of an unknown code: %v", err)
	}
}

func TestPurgeExpiredDevices(t *testing.T) {
	ctx := context.Background()
	mem := memstore.New()
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	clk := &manualClock{t: now}
	svc := auth.New(mem, config.Config{DeviceVerificationURI: "https://console.example/device"}, clk.Now)
	plain := "device-plain-token"
	if err := mem.CreateDevice(ctx, store.Device{
		ID:        uuid.New(),
		Hash:      secret.Hash(plain),
		UserCode:  "BCDF-GHJK",
		CreatedAt: now.Add(-26 * time.Hour),
		ExpiresAt: now.Add(-25 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PollDevice(ctx, plain); !errors.Is(err, auth.ErrExpiredToken) {
		t.Fatalf("expired poll: %v", err)
	}
	if err := svc.PurgeDevices(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PollDevice(ctx, plain); !errors.Is(err, auth.ErrExpiredToken) {
		t.Fatalf("poll after purge: %v", err)
	}
	if _, err := mem.DeviceByUserCode(ctx, "BCDF-GHJK"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("row after purge: %v", err)
	}
}

func TestOAuthStateCapAndSweep(t *testing.T) {
	ctx := context.Background()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/auth",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/keys",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	defer srv.Close()
	clk := &manualClock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	svc := auth.New(memstore.New(), config.Config{
		GoogleClientID:     "dummy-google-client-id",
		GoogleClientSecret: "dummy-google-client-secret",
		GoogleIssuer:       srv.URL,
		OAuthRedirectURIs:  []string{"https://console.example/cb"},
	}, clk.Now)
	svc.SetHTTPClient(srv.Client())
	for i := 0; i < 10000; i++ {
		if _, err := svc.StartGoogle(ctx, "https://console.example/cb"); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
	}
	if _, err := svc.StartGoogle(ctx, "https://console.example/cb"); !errors.Is(err, auth.ErrUnavailable) {
		t.Fatalf("over cap: %v", err)
	}
	clk.Advance(10 * time.Minute)
	if _, err := svc.StartGoogle(ctx, "https://console.example/cb"); err != nil {
		t.Fatalf("start after sweep: %v", err)
	}
}
