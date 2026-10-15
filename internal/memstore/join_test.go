package memstore

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestConsumeJoinTokenOnce(t *testing.T) {
	ctx := context.Background()
	m := New()
	now := time.Now().UTC()
	user, err := m.UpsertGoogleUser(ctx, store.GoogleSignIn{Subject: "sub", Email: "a@example.com", At: now})
	if err != nil {
		t.Fatal(err)
	}
	project, err := m.CreateProject(ctx, user.ID, "Lab", "lab", now)
	if err != nil {
		t.Fatal(err)
	}
	plain, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateJoinToken(ctx, project.ID, hash, nil, user.ID, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			credPlain, credHash, err := secret.NewToken()
			if err != nil {
				return
			}
			_, err = m.ConsumeJoinToken(ctx, secret.Hash(plain), store.EnrollInput{
				Name: "pi4", NodeType: "pi", OS: "linux", Arch: "arm64", AlwaysOn: true, AgentVersion: "0.1.0",
			}, uuid.New(), credHash, now)
			if err == nil {
				ok.Add(1)
				if credPlain == "" {
					t.Error("empty credential")
				}
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("successes = %d, want 1", ok.Load())
	}
}

func TestDiscoveredDoesNotDowngradeDeclared(t *testing.T) {
	ctx := context.Background()
	m := New()
	now := time.Now().UTC()
	user, err := m.UpsertGoogleUser(ctx, store.GoogleSignIn{Subject: "sub", Email: "a@example.com", At: now})
	if err != nil {
		t.Fatal(err)
	}
	project, err := m.CreateProject(ctx, user.ID, "Lab", "lab", now)
	if err != nil {
		t.Fatal(err)
	}
	_, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateJoinToken(ctx, project.ID, hash, nil, user.ID, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	_, credHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	host, err := m.ConsumeJoinToken(ctx, hash, store.EnrollInput{
		Name: "pi4", NodeType: "pi", OS: "linux", Arch: "arm64", AlwaysOn: true, AgentVersion: "0.1.0",
	}, uuid.New(), credHash, now)
	if err != nil {
		t.Fatal(err)
	}
	declared := m.PutDeclared(host.ID, "api", "process", []int{8080}, now)
	later := now.Add(time.Minute)
	unit := "api.service"
	if err := m.UpsertDiscovered(ctx, host.ID, []store.Discovered{{
		Name: "api", Kind: "systemd", Ports: []int{9}, SystemdUnit: &unit,
	}}, later, true, true); err != nil {
		t.Fatal(err)
	}
	got, err := m.GetService(ctx, declared.ID, later)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != "declared" || len(got.Ports) != 1 || got.Ports[0] != 8080 {
		t.Fatalf("downgraded: %#v", got)
	}
	if !got.LastSeenAt.Equal(later) {
		t.Fatalf("last_seen = %s", got.LastSeenAt)
	}
}
