package db

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/more-than-code/bot-api-server/internal/authz"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

func TestIntegration(t *testing.T) {
	url := os.Getenv("DEPLOYBOT_TEST_DATABASE_URL")
	if url == "" {
		t.Skip()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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
    app.host_shares,
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
	if !names["0001_app.sql"] || !names["0002_metrics.sql"] || !names["0003_shared_hosts.sql"] || names["0003_shared_hosts.down.sql"] {
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
INSERT INTO app.services (id, host_id, name, source, kind, ports, first_seen_at, last_seen_at, project_id)
VALUES ($1::uuid, $2::uuid, 'web', 'declared', 'process', $3::integer[], $4, $4, $5::uuid)
`, serviceID.String(), enrolled.ID.String(), []int32{80, 443}, first, project.ID.String()); err != nil {
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
	var projectText string
	if err := d.pool.QueryRow(ctx, `
SELECT source, ports, last_seen_at, project_id::text
FROM app.services
WHERE id = $1::uuid
`, serviceID.String()).Scan(&source, &ports, &seen, &projectText); err != nil {
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
	if projectText != project.ID.String() {
		t.Fatalf("project_id = %s, want %s", projectText, project.ID)
	}
	sharedHostsIntegration(t, d, ctx, user, project, enrolled, serviceID, at)
}

// sharedHostsIntegration is the Postgres half of spec §6: backfill shape,
// share create/remove, service filtering, the unfiltered process sample, and both cascades.
func sharedHostsIntegration(t *testing.T, d *DB, ctx context.Context, owner store.User, project store.Project, host store.Host, webID uuid.UUID, at time.Time) {
	t.Helper()
	assertSharedHostsMigration(t)

	var nullable string
	if err := d.pool.QueryRow(ctx, `
SELECT is_nullable FROM information_schema.columns
WHERE table_schema = 'app' AND table_name = 'services' AND column_name = 'project_id'
`).Scan(&nullable); err != nil {
		t.Fatalf("project_id column: %v", err)
	}
	if nullable != "NO" {
		t.Fatalf("services.project_id nullable = %s", nullable)
	}
	grants := map[string]bool{}
	rows, err := d.pool.Query(ctx, `
SELECT privilege_type FROM information_schema.role_table_grants
WHERE grantee = 'deploybot_api' AND table_schema = 'app' AND table_name = 'host_shares'
`)
	if err != nil {
		t.Fatalf("grants: %v", err)
	}
	for rows.Next() {
		var priv string
		if err := rows.Scan(&priv); err != nil {
			rows.Close()
			t.Fatalf("grants: %v", err)
		}
		grants[priv] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatalf("grants: %v", err)
	}
	rows.Close()
	for _, priv := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
		if !grants[priv] {
			t.Fatalf("deploybot_api grants on host_shares = %v", grants)
		}
	}
	var apiExec, publicExec bool
	if err := d.pool.QueryRow(ctx, `
SELECT has_function_privilege('deploybot_api', 'app.host_shares_not_owner()', 'EXECUTE'),
       has_function_privilege('public', 'app.host_shares_not_owner()', 'EXECUTE')
`).Scan(&apiExec, &publicExec); err != nil {
		t.Fatalf("function privilege: %v", err)
	}
	if !apiExec || publicExec {
		t.Fatalf("host_shares_not_owner execute deploybot_api=%v public=%v", apiExec, publicExec)
	}

	shareUser, err := d.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "share-subject", Email: "share@example.com", Name: "Share", At: at,
	})
	if err != nil {
		t.Fatalf("share user: %v", err)
	}
	thirdUser, err := d.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "third-subject", Email: "third@example.com", Name: "Third", At: at,
	})
	if err != nil {
		t.Fatalf("third user: %v", err)
	}
	projectB, err := d.CreateProject(ctx, shareUser.ID, "Share", "share", at)
	if err != nil {
		t.Fatalf("project B: %v", err)
	}
	projectC, err := d.CreateProject(ctx, thirdUser.ID, "Third", "third", at)
	if err != nil {
		t.Fatalf("project C: %v", err)
	}

	if err := d.UpsertDiscovered(ctx, host.ID, []store.Discovered{{Name: "finder", Kind: "process"}}, at); err != nil {
		t.Fatalf("discover: %v", err)
	}
	var finderProject string
	if err := d.pool.QueryRow(ctx, `
SELECT project_id::text FROM app.services WHERE host_id = $1::uuid AND name = 'finder'
`, host.ID.String()).Scan(&finderProject); err != nil {
		t.Fatalf("finder project: %v", err)
	}
	if finderProject != project.ID.String() {
		t.Fatalf("discovered project_id = %s", finderProject)
	}
	if _, err := d.pool.Exec(ctx, `
UPDATE app.services SET project_id = $2::uuid WHERE host_id = $1::uuid AND name = 'finder'
`, host.ID.String(), projectB.ID.String()); err != nil {
		t.Fatalf("move finder: %v", err)
	}
	if err := d.UpsertDiscovered(ctx, host.ID, []store.Discovered{{Name: "finder", Kind: "process", Ports: []int{9}}}, at); err != nil {
		t.Fatalf("rediscover: %v", err)
	}
	if err := d.pool.QueryRow(ctx, `
SELECT project_id::text FROM app.services WHERE host_id = $1::uuid AND name = 'finder'
`, host.ID.String()).Scan(&finderProject); err != nil {
		t.Fatalf("finder after rediscovery: %v", err)
	}
	if finderProject != projectB.ID.String() {
		t.Fatalf("rediscovery moved project_id to %s", finderProject)
	}
	if _, err := d.pool.Exec(ctx, `
UPDATE app.services SET project_id = $2::uuid WHERE host_id = $1::uuid AND name = 'finder'
`, host.ID.String(), project.ID.String()); err != nil {
		t.Fatalf("restore finder: %v", err)
	}

	insertHost := func(projectID uuid.UUID, name string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		_, err := d.pool.Exec(ctx, `
INSERT INTO app.hosts (id, project_id, name, node_type, os, arch, always_on, agent_version, enrolled_at)
VALUES ($1::uuid, $2::uuid, $3, 'pi', 'linux', 'arm64', true, '1.0.0', $4)
`, id.String(), projectID.String(), name, at)
		if err != nil {
			t.Fatalf("host %s: %v", name, err)
		}
		return id
	}
	aaa := insertHost(projectB.ID, "aaa-owned")
	zoo := insertHost(projectB.ID, "zoo-owned")
	mmm := insertHost(projectC.ID, "mmm-shared")

	_, err = d.pool.Exec(ctx, `
INSERT INTO app.host_shares (host_id, project_id, level, created_by)
VALUES ($1::uuid, $2::uuid, 'metrics', $3::uuid)
`, host.ID.String(), project.ID.String(), owner.ID.String())
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.ConstraintName != "host_shares_not_owner" {
		t.Fatalf("owner share insert: %v", err)
	}
	if _, _, err := d.PutHostShare(ctx, host.ID, project.ID, "metrics", owner.ID, at); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("PutHostShare owner: %v", err)
	}

	share, created, err := d.PutHostShare(ctx, host.ID, projectB.ID, "deploy", owner.ID, at)
	if err != nil || !created || share.Level != "deploy" || share.ProjectName != "Share" {
		t.Fatalf("create share: created %v %+v err %v", created, share, err)
	}
	updated, created, err := d.PutHostShare(ctx, host.ID, projectB.ID, "metrics", owner.ID, at.Add(time.Minute))
	if err != nil || created || updated.Level != "metrics" || !updated.CreatedAt.Equal(share.CreatedAt) || updated.CreatedBy != share.CreatedBy {
		t.Fatalf("update share: created %v %+v err %v", created, updated, err)
	}
	if _, _, err := d.PutHostShare(ctx, mmm, projectB.ID, "deploy", thirdUser.ID, at); err != nil {
		t.Fatalf("share mmm: %v", err)
	}
	listed, _, err := d.ListHosts(ctx, projectB.ID, 50, nil)
	if err != nil {
		t.Fatalf("list B: %v", err)
	}
	wantListed := []struct {
		id, relation, level string
	}{
		{aaa.String(), "owner", ""},
		{zoo.String(), "owner", ""},
		{mmm.String(), "shared", "deploy"},
		{host.ID.String(), "shared", "metrics"},
	}
	if len(listed) != len(wantListed) {
		t.Fatalf("list B len %d", len(listed))
	}
	for i, exp := range wantListed {
		level := ""
		if listed[i].ShareLevel != nil {
			level = *listed[i].ShareLevel
		}
		if listed[i].ID != uuid.MustParse(exp.id) || listed[i].Relation != exp.relation || level != exp.level {
			t.Fatalf("list B[%d] %s %s %s", i, listed[i].ID, listed[i].Relation, level)
		}
	}
	owned, _, err := d.ListHosts(ctx, project.ID, 50, nil)
	if err != nil || len(owned) != 1 || owned[0].ID != host.ID || owned[0].Relation != "owner" || owned[0].ShareLevel != nil {
		t.Fatalf("list owner: %v %+v", err, owned)
	}

	sharedID := uuid.New()
	if _, err := d.pool.Exec(ctx, `
INSERT INTO app.services (id, host_id, name, source, kind, first_seen_at, last_seen_at, project_id)
VALUES ($1::uuid, $2::uuid, 'shared-svc', 'declared', 'process', $3, $3, $4::uuid)
`, sharedID.String(), host.ID.String(), at, projectB.ID.String()); err != nil {
		t.Fatalf("shared service: %v", err)
	}
	if _, err := d.pool.Exec(ctx, `
INSERT INTO metrics.process_samples
    (time, host_id, service_id, pid, process_name, "user", cmdline, cpu_usage, memory_rss, memory_usage, num_threads)
VALUES
    ($1, $2::uuid, $3::uuid, 11, 'own', 'root', 'own', 1, 1, 1, 1),
    ($1, $2::uuid, $4::uuid, 22, 'share', 'root', 'share', 1, 1, 1, 1),
    ($1, $2::uuid, NULL, 33, 'none', 'root', 'none', 1, 1, 1, 1)
`, at, host.ID.String(), webID.String(), sharedID.String()); err != nil {
		t.Fatalf("processes: %v", err)
	}
	allSvcs, err := d.ListServices(ctx, host.ID, nil, at)
	if err != nil {
		t.Fatalf("services: %v", err)
	}
	names := map[string]uuid.UUID{}
	for _, svc := range allSvcs {
		names[svc.Name] = svc.ProjectID
	}
	if names["web"] != project.ID || names["shared-svc"] != projectB.ID || names["finder"] != project.ID {
		t.Fatalf("services %#v", names)
	}
	only, err := d.ListServices(ctx, host.ID, []uuid.UUID{projectB.ID}, at)
	if err != nil || len(only) != 1 || only[0].Name != "shared-svc" {
		t.Fatalf("filtered services: %v %+v", err, only)
	}
	empty, err := d.ListServices(ctx, host.ID, []uuid.UUID{}, at)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty service filter: %v len %d", err, len(empty))
	}
	// Unfiltered sample. service_id stays with each row: owner service,
	// deploy-share service, and none.
	_, allProcs, err := d.LatestProcesses(ctx, host.ID, at.Add(-time.Minute), "cpu", 50)
	if err != nil {
		t.Fatalf("processes: %v", err)
	}
	byPID := map[int]*uuid.UUID{}
	for _, item := range allProcs {
		byPID[item.PID] = item.ServiceID
	}
	if len(byPID) != 3 || !sameID(byPID[11], &webID) || !sameID(byPID[22], &sharedID) || byPID[33] != nil {
		t.Fatalf("processes %+v", allProcs)
	}

	if _, err := d.DeleteHostShare(ctx, host.ID, projectB.ID, false); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("unshare conflict: %v", err)
	}
	var still string
	if err := d.pool.QueryRow(ctx, `SELECT project_id::text FROM app.services WHERE id = $1::uuid`, sharedID.String()).Scan(&still); err != nil {
		t.Fatal(err)
	}
	if still != projectB.ID.String() {
		t.Fatalf("conflict moved service to %s", still)
	}
	if _, err := d.DeleteHostShare(ctx, host.ID, projectB.ID, true); err != nil {
		t.Fatalf("reassign: %v", err)
	}
	if err := d.pool.QueryRow(ctx, `SELECT project_id::text FROM app.services WHERE id = $1::uuid`, sharedID.String()).Scan(&still); err != nil {
		t.Fatal(err)
	}
	if still != project.ID.String() {
		t.Fatalf("reassign project_id = %s", still)
	}

	if _, _, err := d.PutHostShare(ctx, host.ID, projectB.ID, "deploy", owner.ID, at); err != nil {
		t.Fatalf("reshare: %v", err)
	}
	guestID := uuid.New()
	if _, err := d.pool.Exec(ctx, `
INSERT INTO app.services (id, host_id, name, source, kind, first_seen_at, last_seen_at, project_id)
VALUES ($1::uuid, $2::uuid, 'guest-svc', 'declared', 'process', $3, $3, $4::uuid)
`, guestID.String(), host.ID.String(), at, projectB.ID.String()); err != nil {
		t.Fatalf("guest service: %v", err)
	}
	if _, err := d.DeleteProject(ctx, projectB.ID, at); err != nil {
		t.Fatalf("delete B: %v", err)
	}
	var shareCount, liveHosts int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM app.host_shares WHERE project_id = $1::uuid`, projectB.ID.String()).Scan(&shareCount); err != nil {
		t.Fatal(err)
	}
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM app.hosts WHERE project_id = $1::uuid AND revoked_at IS NULL`, projectB.ID.String()).Scan(&liveHosts); err != nil {
		t.Fatal(err)
	}
	if shareCount != 0 || liveHosts != 0 {
		t.Fatalf("after delete B shares %d live hosts %d", shareCount, liveHosts)
	}
	if err := d.pool.QueryRow(ctx, `SELECT project_id::text FROM app.services WHERE id = $1::uuid`, guestID.String()).Scan(&still); err != nil {
		t.Fatal(err)
	}
	if still != project.ID.String() {
		t.Fatalf("deleted sharing project left service on %s", still)
	}

	cascadeID := insertHost(project.ID, "cascade-host")
	if _, _, err := d.PutHostShare(ctx, cascadeID, projectC.ID, "metrics", owner.ID, at); err != nil {
		t.Fatalf("cascade share: %v", err)
	}
	if _, err := d.pool.Exec(ctx, `DELETE FROM app.hosts WHERE id = $1::uuid`, cascadeID.String()); err != nil {
		t.Fatalf("delete host: %v", err)
	}
	var left int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM app.host_shares WHERE host_id = $1::uuid`, cascadeID.String()).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("host delete left %d shares", left)
	}

	assertServiceBackfill(t, d, ctx, host, webID)
	assertOutgoingOwnerDelete(t, d, ctx, at)
	assertShareAfterOwnerDelete(t, d, ctx, at)
	assertMultiShareFacts(t, d, ctx, at)
	assertHostCursorResume(t, d, ctx, at)
}

func assertServiceBackfill(t *testing.T, d *DB, ctx context.Context, host store.Host, serviceID uuid.UUID) {
	t.Helper()
	stmt := sharedHostsBackfillSQL(t)
	if !strings.Contains(stmt, "SET project_id = h.project_id") || !strings.Contains(stmt, "h.id = s.host_id") {
		t.Fatalf("backfill statement %q", stmt)
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET ROLE deploybot_owner`); err != nil {
		t.Fatalf("set role: %v", err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE app.services ALTER COLUMN project_id DROP NOT NULL`); err != nil {
		t.Fatalf("drop not null: %v", err)
	}
	tag, err := tx.Exec(ctx, `UPDATE app.services SET project_id = NULL WHERE id = $1::uuid`, serviceID.String())
	if err != nil {
		t.Fatal(err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("nulled %d services", tag.RowsAffected())
	}
	if _, err := tx.Exec(ctx, stmt); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	var got string
	if err := tx.QueryRow(ctx, `SELECT project_id::text FROM app.services WHERE id = $1::uuid`, serviceID.String()).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != host.ProjectID.String() {
		t.Fatalf("backfill project_id = %s, want %s", got, host.ProjectID)
	}
}

func assertOutgoingOwnerDelete(t *testing.T, d *DB, ctx context.Context, at time.Time) {
	t.Helper()
	owner, err := d.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "outgoing-owner", Email: "outgoing-owner@example.com", Name: "Outgoing", At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherUser, err := d.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "outgoing-other", Email: "outgoing-other@example.com", Name: "Other", At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	owned, err := d.CreateProject(ctx, owner.ID, "Outgoing", "outgoing", at)
	if err != nil {
		t.Fatal(err)
	}
	other, err := d.CreateProject(ctx, otherUser.ID, "Untouched", "untouched", at)
	if err != nil {
		t.Fatal(err)
	}
	host := enrollHostDB(t, d, ctx, owned.ID, owner.ID, "outgoing-host", at)
	kept := enrollHostDB(t, d, ctx, other.ID, otherUser.ID, "untouched-host", at)
	if _, _, err := d.PutHostShare(ctx, host.ID, other.ID, "metrics", owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := d.DeleteProject(ctx, owned.ID, at); err != nil {
		t.Fatal(err)
	}
	var shares, liveCreds int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM app.host_shares WHERE host_id = $1::uuid`, host.ID.String()).Scan(&shares); err != nil {
		t.Fatal(err)
	}
	if err := d.pool.QueryRow(ctx, `
SELECT count(*) FROM app.agent_credentials WHERE host_id = $1::uuid AND revoked_at IS NULL
`, host.ID.String()).Scan(&liveCreds); err != nil {
		t.Fatal(err)
	}
	if shares != 0 || liveCreds != 0 {
		t.Fatalf("after owner delete shares %d live credentials %d", shares, liveCreds)
	}
	var keptRevoked *time.Time
	if err := d.pool.QueryRow(ctx, `SELECT revoked_at FROM app.hosts WHERE id = $1::uuid`, kept.ID.String()).Scan(&keptRevoked); err != nil {
		t.Fatal(err)
	}
	if keptRevoked != nil {
		t.Fatal("deleting the owning project revoked another project's host")
	}
}

func assertShareAfterOwnerDelete(t *testing.T, d *DB, ctx context.Context, at time.Time) {
	t.Helper()
	owner, err := d.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "dead-owner", Email: "dead-owner@example.com", Name: "Dead", At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherUser, err := d.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "dead-other", Email: "dead-other@example.com", Name: "Other", At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	owned, err := d.CreateProject(ctx, owner.ID, "DeadOwner", "dead-owner", at)
	if err != nil {
		t.Fatal(err)
	}
	other, err := d.CreateProject(ctx, otherUser.ID, "DeadTarget", "dead-target", at)
	if err != nil {
		t.Fatal(err)
	}
	host := enrollHostDB(t, d, ctx, owned.ID, owner.ID, "dead-owner-host", at)
	if _, err := d.DeleteProject(ctx, owned.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.PutHostShare(ctx, host.ID, other.ID, "metrics", owner.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("share after owner delete: %v", err)
	}
	var n int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM app.host_shares WHERE host_id = $1::uuid`, host.ID.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("share rows after owner delete: %d", n)
	}
}

func assertMultiShareFacts(t *testing.T, d *DB, ctx context.Context, at time.Time) {
	t.Helper()
	owner, err := d.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "multi-owner", Email: "multi-owner@example.com", Name: "Multi", At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := d.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "multi-viewer", Email: "multi-viewer@example.com", Name: "Viewer", At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	mixed, err := d.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "multi-mixed", Email: "multi-mixed@example.com", Name: "Mixed", At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	both, err := d.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "multi-both", Email: "multi-both@example.com", Name: "Both", At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	home, err := d.CreateProject(ctx, owner.ID, "MultiHome", "multi-home", at)
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := d.CreateProject(ctx, mixed.ID, "MultiMetrics", "multi-metrics", at)
	if err != nil {
		t.Fatal(err)
	}
	deploy, err := d.CreateProject(ctx, owner.ID, "MultiDeploy", "multi-deploy", at)
	if err != nil {
		t.Fatal(err)
	}
	deploy2, err := d.CreateProject(ctx, both.ID, "MultiDeploy2", "multi-deploy-2", at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddMember(ctx, home.ID, viewer.ID, "viewer", owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddMember(ctx, deploy.ID, viewer.ID, "admin", owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddMember(ctx, deploy.ID, mixed.ID, "viewer", owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddMember(ctx, deploy.ID, both.ID, "admin", owner.ID, at); err != nil {
		t.Fatal(err)
	}
	host := enrollHostDB(t, d, ctx, home.ID, owner.ID, "multi-host", at)
	if _, _, err := d.PutHostShare(ctx, host.ID, metrics.ID, "metrics", owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.PutHostShare(ctx, host.ID, deploy.ID, "deploy", owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.PutHostShare(ctx, host.ID, deploy2.ID, "deploy", owner.ID, at); err != nil {
		t.Fatal(err)
	}
	insertSvc := func(name string, projectID uuid.UUID) {
		t.Helper()
		if _, err := d.pool.Exec(ctx, `
INSERT INTO app.services (id, host_id, name, source, kind, first_seen_at, last_seen_at, project_id)
VALUES ($1::uuid, $2::uuid, $3, 'declared', 'process', $4, $4, $5::uuid)
`, uuid.New().String(), host.ID.String(), name, at, projectID.String()); err != nil {
			t.Fatal(err)
		}
	}
	insertSvc("own-svc", home.ID)
	insertSvc("metrics-svc", metrics.ID)
	insertSvc("deploy-svc", deploy.ID)
	insertSvc("deploy2-svc", deploy2.ID)

	viewerFacts, err := d.HostFacts(ctx, viewer.ID, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	viewerRel := authz.Relate(viewerFacts.OwnerRole, shareAccess(viewerFacts.Shares))
	if viewerFacts.OwnerRole != "viewer" || viewerRel.Kind != authz.RelOwner || len(viewerRel.Shares) != 0 {
		t.Fatalf("owner viewer facts %+v rel %+v", viewerFacts, viewerRel)
	}
	all, err := d.ListServices(ctx, host.ID, authz.ServiceProjectFilter(viewerRel), at)
	if err != nil {
		t.Fatal(err)
	}
	if !svcSet(all)["own-svc"] || !svcSet(all)["metrics-svc"] || !svcSet(all)["deploy-svc"] || !svcSet(all)["deploy2-svc"] {
		t.Fatalf("owner viewer services %+v", namesOfSvc(all))
	}

	mixedFacts, err := d.HostFacts(ctx, mixed.ID, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	mixedRel := authz.Relate(mixedFacts.OwnerRole, shareAccess(mixedFacts.Shares))
	if mixedRel.Kind != authz.RelShare || !hasShare(mixedRel, metrics.ID, "metrics") || !hasShare(mixedRel, deploy.ID, "deploy") {
		t.Fatalf("mixed rel %+v", mixedRel)
	}
	if err := authz.AuthorizeHost(mixedRel, authz.CapHostView, uuid.Nil); err != nil {
		t.Fatalf("mixed metrics access: %v", err)
	}
	if authz.HighestShareLevel(mixedRel.Shares) != authz.ShareDeploy {
		t.Fatalf("mixed share level %s", authz.HighestShareLevel(mixedRel.Shares))
	}
	mixedSvcs, err := d.ListServices(ctx, host.ID, authz.ServiceProjectFilter(mixedRel), at)
	if err != nil || len(mixedSvcs) != 1 || mixedSvcs[0].Name != "deploy-svc" {
		t.Fatalf("mixed services %+v %v", namesOfSvc(mixedSvcs), err)
	}
	if err := authz.AuthorizeHost(mixedRel, authz.CapServiceRead, deploy.ID); err != nil {
		t.Fatalf("mixed read deploy: %v", err)
	}
	if code := deniedCode(authz.AuthorizeHost(mixedRel, authz.CapServiceRead, metrics.ID)); code != "forbidden" {
		t.Fatalf("mixed read metrics %s", code)
	}
	if code := deniedCode(authz.AuthorizeHost(mixedRel, authz.CapServiceRead, home.ID)); code != "forbidden" {
		t.Fatalf("mixed read owner service %s", code)
	}

	bothFacts, err := d.HostFacts(ctx, both.ID, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	bothRel := authz.Relate(bothFacts.OwnerRole, shareAccess(bothFacts.Shares))
	if bothRel.Kind != authz.RelShare || !hasShare(bothRel, deploy.ID, "deploy") || !hasShare(bothRel, deploy2.ID, "deploy") {
		t.Fatalf("two deploy rel %+v", bothRel)
	}
	bothSvcs, err := d.ListServices(ctx, host.ID, authz.ServiceProjectFilter(bothRel), at)
	if err != nil {
		t.Fatal(err)
	}
	if len(bothSvcs) != 2 || !svcSet(bothSvcs)["deploy-svc"] || !svcSet(bothSvcs)["deploy2-svc"] {
		t.Fatalf("two deploy services %+v", namesOfSvc(bothSvcs))
	}
	if err := authz.AuthorizeHost(bothRel, authz.CapServiceRead, deploy.ID); err != nil {
		t.Fatal(err)
	}
	if err := authz.AuthorizeHost(bothRel, authz.CapServiceRead, deploy2.ID); err != nil {
		t.Fatal(err)
	}
	if code := deniedCode(authz.AuthorizeHost(bothRel, authz.CapServiceRead, home.ID)); code != "forbidden" {
		t.Fatalf("two deploy read owner %s", code)
	}
}

func assertHostCursorResume(t *testing.T, d *DB, ctx context.Context, at time.Time) {
	t.Helper()
	owner, err := d.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "cursor-owner", Email: "cursor-owner@example.com", Name: "Cursor", At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherUser, err := d.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: "cursor-other", Email: "cursor-other@example.com", Name: "CursorOther", At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	home, err := d.CreateProject(ctx, owner.ID, "CursorHome", "cursor-home", at)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := d.CreateProject(ctx, otherUser.ID, "CursorForeign", "cursor-foreign", at)
	if err != nil {
		t.Fatal(err)
	}
	insert := func(projectID uuid.UUID, name string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := d.pool.Exec(ctx, `
INSERT INTO app.hosts (id, project_id, name, node_type, os, arch, always_on, agent_version, enrolled_at)
VALUES ($1::uuid, $2::uuid, $3, 'pi', 'linux', 'arm64', true, '1.0.0', $4)
`, id.String(), projectID.String(), name, at); err != nil {
			t.Fatal(err)
		}
		return id
	}
	a := insert(home.ID, "a-owned")
	b := insert(home.ID, "b-owned")
	c := insert(foreign.ID, "c-shared")
	z := insert(foreign.ID, "z-shared")
	if _, _, err := d.PutHostShare(ctx, c, home.ID, "deploy", owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.PutHostShare(ctx, z, home.ID, "metrics", owner.ID, at); err != nil {
		t.Fatal(err)
	}
	owned, _, err := d.ListHosts(ctx, foreign.ID, 50, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(owned) != 2 {
		t.Fatalf("owning project list %d", len(owned))
	}
	for i, h := range owned {
		if h.Relation != "owner" || h.ShareLevel != nil {
			t.Fatalf("owning row %d %s %v", i, h.Relation, h.ShareLevel)
		}
	}
	want := []uuid.UUID{a, b, c, z}
	var cur *store.Cursor
	var got []uuid.UUID
	for page := 0; page < len(want)+1; page++ {
		items, next, err := d.ListHosts(ctx, home.ID, 1, cur)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) == 0 {
			if next != nil {
				t.Fatal("empty page has a cursor")
			}
			break
		}
		if len(items) != 1 {
			t.Fatalf("page %d len %d", page, len(items))
		}
		got = append(got, items[0].ID)
		if next == nil {
			break
		}
		if next.Rank == nil || next.Name != items[0].Name || next.ID != items[0].ID.String() {
			t.Fatalf("cursor %+v", next)
		}
		if items[0].ID == c {
			if _, err := d.DeleteHostShare(ctx, c, home.ID, false); err != nil {
				t.Fatal(err)
			}
		}
		cur = next
	}
	if len(got) != len(want) {
		t.Fatalf("resumed %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order %v want %v", got, want)
		}
	}
}

func enrollHostDB(t *testing.T, d *DB, ctx context.Context, projectID, ownerID uuid.UUID, name string, at time.Time) store.Host {
	t.Helper()
	_, tokenHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateJoinToken(ctx, projectID, tokenHash, nil, ownerID, at.Add(time.Hour), at); err != nil {
		t.Fatal(err)
	}
	_, credHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	host, err := d.ConsumeJoinToken(ctx, tokenHash, store.EnrollInput{
		Name: name, NodeType: "pi", OS: "linux", Arch: "arm64", AlwaysOn: true, AgentVersion: "1.0.0",
	}, uuid.New(), credHash, at)
	if err != nil {
		t.Fatal(err)
	}
	return host
}

func shareAccess(in []store.HostShareAccess) []authz.Share {
	out := make([]authz.Share, len(in))
	for i, sh := range in {
		out[i] = authz.Share{ProjectID: sh.ProjectID, Level: sh.Level, Role: sh.Role}
	}
	return out
}

func hasShare(rel authz.Relation, projectID uuid.UUID, level string) bool {
	for _, sh := range rel.Shares {
		if sh.ProjectID == projectID && sh.Level == level {
			return true
		}
	}
	return false
}

func deniedCode(err error) string {
	var denied *authz.Denied
	if errors.As(err, &denied) {
		return denied.Code
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

func svcSet(items []store.Service) map[string]bool {
	out := map[string]bool{}
	for _, item := range items {
		out[item.Name] = true
	}
	return out
}

func namesOfSvc(items []store.Service) []string {
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = item.Name
	}
	return out
}

func sameID(got, want *uuid.UUID) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	return *got == *want
}
