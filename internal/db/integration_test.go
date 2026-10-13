package db

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestIntegration(t *testing.T) {
	url := os.Getenv("DEPLOYBOT_TEST_DATABASE_URL")
	if url == "" {
		t.Skip()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	d, err := Open(ctx, url)
	if err != nil {
		t.Fatal("connect failed")
	}
	defer d.Close()

	var dbName string
	if err := d.pool.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatal("database name lookup failed")
	}
	if dbName != "deploybot_test" {
		t.Fatalf("refusing database %s", dbName)
	}

	if err := Migrate(ctx, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := d.pool.Exec(ctx, `
TRUNCATE TABLE
    metrics.ingest_batches,
    metrics.host_cpu,
    metrics.host_mem,
    metrics.host_disk,
    metrics.host_diskio,
    metrics.host_net,
    metrics.host_system,
    metrics.host_temp,
    metrics.process_samples,
    metrics.health_results,
    app.audit_log,
    app.health_checks,
    app.services,
    app.agent_credentials,
    app.join_tokens,
    app.device_codes,
    app.hosts,
    app.project_members,
    app.sessions,
    app.user_identities,
    app.projects,
    app.users
`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	names := map[string]bool{}
	rows, err := d.pool.Query(ctx, `SELECT name FROM app.schema_migrations`)
	if err != nil {
		t.Fatalf("migrations: %v", err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			t.Fatalf("migrations: %v", err)
		}
		names[name] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatalf("migrations: %v", err)
	}
	rows.Close()
	if !names["0001_app.sql"] || !names["0002_metrics.sql"] {
		t.Fatalf("schema_migrations = %v", names)
	}

	at := time.Now().UTC().Truncate(time.Microsecond)
	user, err := d.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "google-subject",
		Email:   "Owner@Example.com",
		Name:    "Owner",
		At:      at,
	})
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	project, err := d.CreateProject(ctx, user.ID, "Lab", "lab", at)
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	_, tokenHash, err := secret.NewToken()
	if err != nil {
		t.Fatal("token")
	}
	if _, err := d.CreateJoinToken(ctx, project.ID, tokenHash, nil, user.ID, at.Add(time.Hour), at); err != nil {
		t.Fatalf("join token: %v", err)
	}

	type cred struct {
		id   uuid.UUID
		hash []byte
	}
	creds := make([]cred, 32)
	for i := range creds {
		creds[i].id = uuid.New()
		_, hash, err := secret.NewToken()
		if err != nil {
			t.Fatal("credential token")
		}
		creds[i].hash = hash
	}
	in := store.EnrollInput{
		Name:         "pi-node",
		NodeType:     "pi",
		OS:           "linux",
		Arch:         "arm64",
		AlwaysOn:     true,
		AgentVersion: "1.0.0",
	}
	var mu sync.Mutex
	var success int
	var bad []string
	var enrolled store.Host
	var wg sync.WaitGroup
	for i := range creds {
		wg.Add(1)
		go func(c cred) {
			defer wg.Done()
			host, err := d.ConsumeJoinToken(ctx, tokenHash, in, c.id, c.hash, at)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				success++
				enrolled = host
				return
			}
			if !errors.Is(err, store.ErrUnauthorized) {
				bad = append(bad, err.Error())
			}
		}(creds[i])
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("consume successes = %d, want 1", success)
	}
	if len(bad) > 0 {
		t.Fatalf("consume errors: %v", bad)
	}
	if enrolled.ID == uuid.Nil {
		t.Fatal("enrolled host missing")
	}

	sessPlain, sessHash, err := secret.NewToken()
	if err != nil {
		t.Fatal("session token")
	}
	sess, err := d.CreateSession(ctx, user.ID, sessHash, "console", at.Add(time.Hour), at)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	var stored []byte
	if err := d.pool.QueryRow(ctx, `SELECT token_hash FROM app.sessions WHERE id = $1::uuid`, sess.ID.String()).Scan(&stored); err != nil {
		t.Fatalf("session hash: %v", err)
	}
	if !bytes.Equal(stored, secret.Hash(sessPlain)) {
		t.Fatal("session token_hash is not secret.Hash(plain)")
	}
	if bytes.Equal(stored, []byte(sessPlain)) {
		t.Fatal("session token_hash is plaintext")
	}

	first := at.Add(-time.Hour)
	later := first.Add(time.Minute)
	serviceID := uuid.New()
	if _, err := d.pool.Exec(ctx, `
INSERT INTO app.services (id, host_id, name, source, kind, ports, first_seen_at, last_seen_at)
VALUES ($1::uuid, $2::uuid, 'web', 'declared', 'process', $3::integer[], $4, $4)
`, serviceID.String(), enrolled.ID.String(), []int32{80, 443}, first); err != nil {
		t.Fatalf("seed service: %v", err)
	}
	if err := d.UpsertDiscovered(ctx, enrolled.ID, []store.Discovered{{
		Name:  "web",
		Kind:  "container",
		Ports: []int{9},
	}}, later); err != nil {
		t.Fatalf("upsert discovered: %v", err)
	}
	var source string
	var ports []int32
	var seen time.Time
	if err := d.pool.QueryRow(ctx, `
SELECT source, ports, last_seen_at
FROM app.services
WHERE id = $1::uuid
`, serviceID.String()).Scan(&source, &ports, &seen); err != nil {
		t.Fatalf("read service: %v", err)
	}
	if source != "declared" {
		t.Fatalf("source = %s, want declared", source)
	}
	if len(ports) != 2 || ports[0] != 80 || ports[1] != 443 {
		t.Fatalf("ports = %v, want [80 443]", ports)
	}
	if !seen.Equal(later) {
		t.Fatalf("last_seen_at = %s, want %s", seen.Format(time.RFC3339Nano), later.Format(time.RFC3339Nano))
	}
}
