package auth_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/more-than-code/bot-api-server/internal/auth"
	"github.com/more-than-code/bot-api-server/internal/config"
	"github.com/more-than-code/bot-api-server/internal/memstore"
	"github.com/more-than-code/bot-api-server/internal/store"
)

type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestDeviceFlow(t *testing.T) {
	ctx := context.Background()
	mem := memstore.New()
	clk := &manualClock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	svc := auth.New(mem, config.Config{
		DeviceVerificationURI: "https://console.example/device",
	}, clk.Now)

	user, err := mem.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "device-user",
		Email:   "dev@example.com",
		Name:    "Dev",
		At:      clk.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}

	dc, err := svc.StartDevice(ctx, "cli")
	if err != nil {
		t.Fatal(err)
	}
	if dc.DeviceCode == "" || dc.ExpiresIn != 600 || dc.Interval != 5 {
		t.Fatalf("device code response: %+v", dc)
	}
	if dc.VerificationURI != "https://console.example/device" {
		t.Fatalf("verification uri %q", dc.VerificationURI)
	}
	wantComplete := "https://console.example/device?code=" + url.QueryEscape(dc.UserCode)
	if dc.VerificationURIComplete != wantComplete {
		t.Fatalf("complete uri %q, want %q", dc.VerificationURIComplete, wantComplete)
	}
	norm, ok := auth.NormalizeUserCode(dc.UserCode)
	if !ok || norm != dc.UserCode || !strings.Contains(dc.UserCode, "-") {
		t.Fatalf("user code %q normalized to %q ok=%v", dc.UserCode, norm, ok)
	}
	bare := strings.ToLower(strings.ReplaceAll(dc.UserCode, "-", ""))
	if strings.Contains(bare, "-") {
		t.Fatal("bare user code still has a hyphen")
	}

	if _, err := svc.PollDevice(ctx, dc.DeviceCode); !errors.Is(err, auth.ErrPending) {
		t.Fatalf("first poll: %v", err)
	}
	if _, err := svc.PollDevice(ctx, dc.DeviceCode); !errors.Is(err, auth.ErrSlowDown) {
		t.Fatalf("immediate second poll: %v", err)
	}

	st, err := svc.DeviceStatus(ctx, bare)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "pending" || st.UserCode != dc.UserCode || st.ClientName != "cli" {
		t.Fatalf("status %+v", st)
	}
	if !st.ExpiresAt.Equal(clk.Now().Add(600 * time.Second)) {
		t.Fatalf("expires %s", st.ExpiresAt)
	}

	if err := svc.ApproveDevice(ctx, bare, user.ID); err != nil {
		t.Fatalf("approve without hyphen: %v", err)
	}
	st, err = svc.DeviceStatus(ctx, dc.UserCode)
	if err != nil || st.Status != "approved" {
		t.Fatalf("approved status %+v %v", st, err)
	}

	// slow_down raised the interval from 5s to 10s and did not move last.
	clk.Advance(10 * time.Second)
	tok, err := svc.PollDevice(ctx, dc.DeviceCode)
	if err != nil {
		t.Fatalf("poll after approve: %v", err)
	}
	if tok.Token == "" || tok.Token == dc.DeviceCode {
		t.Fatal("expected a new session token")
	}
	wantExp := clk.Now().Add(30 * 24 * time.Hour)
	if !tok.ExpiresAt.Equal(wantExp) {
		t.Fatalf("mcp expiry %s, want %s", tok.ExpiresAt, wantExp)
	}
	st, err = svc.DeviceStatus(ctx, dc.UserCode)
	if err != nil || st.Status != "approved" {
		t.Fatalf("consumed status %+v %v", st, err)
	}

	clk.Advance(10 * time.Second)
	if _, err := svc.PollDevice(ctx, dc.DeviceCode); !errors.Is(err, auth.ErrExpiredToken) {
		t.Fatalf("poll after consume: %v", err)
	}
	st, err = svc.DeviceStatus(ctx, dc.UserCode)
	if err != nil || st.Status != "approved" {
		t.Fatalf("consumed stays approved until expiry: %+v %v", st, err)
	}

	sess, gotUser, err := svc.Authenticate(ctx, "Bearer "+tok.Token)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Kind != "mcp" || gotUser.ID != user.ID || !sess.ExpiresAt.Equal(wantExp) {
		t.Fatalf("session %+v user %s", sess, gotUser.ID)
	}
	seen := sess.LastSeenAt
	sess2, _, err := svc.Authenticate(ctx, tok.Token)
	if err != nil {
		t.Fatal(err)
	}
	if !sess2.LastSeenAt.Equal(seen) {
		t.Fatalf("last_seen changed from %s to %s", seen, sess2.LastSeenAt)
	}
	if err := svc.SignOut(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Authenticate(ctx, tok.Token); !errors.Is(err, store.ErrUnauthorized) {
		t.Fatalf("after signout: %v", err)
	}

	denied, err := svc.StartDevice(ctx, "denied-cli")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DenyDevice(ctx, denied.UserCode, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PollDevice(ctx, denied.DeviceCode); !errors.Is(err, auth.ErrAccessDenied) {
		t.Fatalf("deny poll: %v", err)
	}
	st, err = svc.DeviceStatus(ctx, denied.UserCode)
	if err != nil || st.Status != "denied" {
		t.Fatalf("denied status %+v %v", st, err)
	}
	if err := svc.DenyDevice(ctx, denied.UserCode, user.ID); !errors.Is(err, store.ErrState) {
		t.Fatalf("second deny: %v", err)
	}

	expiring, err := svc.StartDevice(ctx, "late")
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(600 * time.Second)
	if _, err := svc.PollDevice(ctx, expiring.DeviceCode); !errors.Is(err, auth.ErrExpiredToken) {
		t.Fatalf("expired before poll: %v", err)
	}
	st, err = svc.DeviceStatus(ctx, expiring.UserCode)
	if err != nil || st.Status != "expired" {
		t.Fatalf("expired status %+v %v", st, err)
	}
	st, err = svc.DeviceStatus(ctx, denied.UserCode)
	if err != nil || st.Status != "expired" {
		t.Fatalf("denied past expiry: %+v %v", st, err)
	}

	if _, err := svc.PollDevice(ctx, "not-a-device-code"); !errors.Is(err, auth.ErrExpiredToken) {
		t.Fatalf("unknown device code: %v", err)
	}
	if err := svc.ApproveDevice(ctx, "AAAA-AAAA", user.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("invalid approve: %v", err)
	}
	if _, err := svc.DeviceStatus(ctx, "short"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("invalid status: %v", err)
	}
}

func TestVerificationURIQuery(t *testing.T) {
	svc := auth.New(memstore.New(), config.Config{
		DeviceVerificationURI: "https://console.example/device?from=cli",
	}, time.Now)
	dc, err := svc.StartDevice(context.Background(), "cli")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://console.example/device?from=cli&code=" + url.QueryEscape(dc.UserCode)
	if dc.VerificationURIComplete != want {
		t.Fatalf("complete uri %q, want %q", dc.VerificationURIComplete, want)
	}
}

func TestNilClock(t *testing.T) {
	svc := auth.New(memstore.New(), config.Config{
		DeviceVerificationURI: "https://console.example/device",
	}, nil)
	dc, err := svc.StartDevice(context.Background(), "cli")
	if err != nil {
		t.Fatal(err)
	}
	if dc.ExpiresIn != 600 || dc.Interval != 5 || dc.DeviceCode == "" {
		t.Fatalf("%+v", dc)
	}
	if _, _, err := svc.Authenticate(context.Background(), ""); !errors.Is(err, store.ErrUnauthorized) {
		t.Fatalf("empty token: %v", err)
	}
	if _, _, err := svc.Authenticate(context.Background(), "Bearer "); !errors.Is(err, store.ErrUnauthorized) {
		t.Fatalf("empty bearer: %v", err)
	}
}

func TestNormalizeUserCode(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{in: "bcdf-ghjk", want: "BCDF-GHJK", ok: true},
		{in: "BCDFghjk", want: "BCDF-GHJK", ok: true},
		{in: "bcdf--ghjk", want: "BCDF-GHJK", ok: true},
		{in: "BCD-GHJK", ok: false},
		{in: "BCDF-GHJ1", ok: false},
		{in: "AEIOUYAA", ok: false},
		{in: "", ok: false},
		{in: "BCDF-GHJK-ZZ", ok: false},
	}
	for _, tc := range cases {
		got, ok := auth.NormalizeUserCode(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("NormalizeUserCode(%q) = %q %v, want %q %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
