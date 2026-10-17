package db

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
	"github.com/more-than-code/bot-api-server/migrations"
)

func TestServiceConfirmationsMigrationText(t *testing.T) {
	body, err := migrations.FS.ReadFile("0011_service_confirmations.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"CREATE TABLE app.service_confirmations",
		"token_hash bytea PRIMARY KEY",
		"request_hash bytea NOT NULL",
		"current_hash bytea NOT NULL",
		"checks jsonb NOT NULL",
		"CONSTRAINT service_confirmations_action_chk CHECK (action = 'health_checks')",
		"CONSTRAINT service_confirmations_checks_chk CHECK (jsonb_typeof(checks) = 'array')",
		"CONSTRAINT service_confirmations_service_fk FOREIGN KEY (service_id) REFERENCES app.services (id) ON DELETE CASCADE",
		"REVOKE ALL ON TABLE app.service_confirmations FROM deploybot_api",
		"GRANT SELECT, INSERT, DELETE ON TABLE app.service_confirmations TO deploybot_api",
		"GRANT UPDATE (used_at) ON TABLE app.service_confirmations TO deploybot_api",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("0011 missing %s", want)
		}
	}
	if strings.Contains(text, "checks_hash") {
		t.Fatal("0011 uses the spec column name")
	}
	stmts := splitSQL(text)
	if len(stmts) != 4 {
		t.Fatalf("statements %d", len(stmts))
	}
	down, err := migrations.FS.ReadFile("0011_service_confirmations.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	downText := string(down)
	if !strings.Contains(downText, "DELETE FROM app.schema_migrations WHERE name = '0011_service_confirmations.sql'") {
		t.Fatal("down script does not document the schema_migrations delete")
	}
	downStmts := splitSQL(downText)
	if len(downStmts) != 1 || !strings.HasPrefix(strings.TrimSpace(downStmts[0]), "DROP TABLE IF EXISTS app.service_confirmations") {
		t.Fatalf("down statements %#v", downStmts)
	}
}

func TestServiceConfirmationsMigration(t *testing.T) {
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
	var table string
	if err := d.pool.QueryRow(ctx, `SELECT to_regclass('app.service_confirmations')::text`).Scan(&table); err != nil || table != "app.service_confirmations" {
		t.Fatalf("table %s %v", table, err)
	}
	assertTablePrivs(t, d, ctx, "service_confirmations", true, true, false, true, []string{"used_at"})

	at := time.Now().UTC().Truncate(time.Microsecond)
	owner := catalogUser(t, d, ctx, "hc0011-owner", at)
	other := catalogUser(t, d, ctx, "hc0011-other", at)
	project := catalogProject(t, d, ctx, owner.ID, "Health", "hc0011", at)
	host := enrollHostDB(t, d, ctx, project.ID, owner.ID, "pi4", at)
	if err := d.UpsertDiscovered(ctx, host.ID, []store.Discovered{{
		Name: "swag", Kind: "process", Ports: []int{443, 8080},
	}}, at, true, true); err != nil {
		t.Fatal(err)
	}
	svc := catalogService(t, d, ctx, host.ID, "swag", at)
	path := "/health"
	checks := []store.HealthCheckInput{{
		Protocol: "tcp", Port: 443, IntervalSec: 60, ExpectStatusMin: 200, ExpectStatusMax: 399, Enabled: true,
	}, {
		Protocol: "http", Port: 8080, Path: &path, IntervalSec: 60, ExpectStatusMin: 200, ExpectStatusMax: 399, Enabled: false,
	}}
	plain, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	row := store.ServiceConfirmation{
		UserID: owner.ID, ProjectID: project.ID, ServiceID: svc.ID, Action: "health_checks",
		RequestHash: bytes.Repeat([]byte{1}, 32), CurrentHash: bytes.Repeat([]byte{2}, 32),
		Checks: checks, IdempotencyKey: "hc-0011", CreatedAt: at, ExpiresAt: at.Add(5 * time.Minute),
	}
	if err := d.PutServiceConfirmation(ctx, hash, row); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	var blob string
	if err := d.pool.QueryRow(ctx, `
SELECT token_hash, checks::text FROM app.service_confirmations WHERE service_id = $1::uuid
`, svc.ID.String()).Scan(&stored, &blob); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(stored, []byte(plain)) || !bytes.Equal(stored, hash) || strings.Contains(blob, plain) {
		t.Fatal("plaintext confirmation id was stored")
	}
	got, err := d.GetServiceConfirmation(ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != owner.ID || got.ServiceID != svc.ID || got.Action != "health_checks" || got.IdempotencyKey != "hc-0011" || got.UsedAt != nil {
		t.Fatalf("row %+v", got)
	}
	if len(got.Checks) != 2 || got.Checks[0].Protocol != "tcp" || got.Checks[1].Path == nil || *got.Checks[1].Path != "/health" || got.Checks[1].Enabled {
		t.Fatalf("checks %+v", got.Checks)
	}
	if !bytes.Equal(got.RequestHash, row.RequestHash) || !bytes.Equal(got.CurrentHash, row.CurrentHash) {
		t.Fatal("hashes changed")
	}

	if _, err := d.CommitHealthReplacement(ctx, hash, other.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other user commit %v", err)
	}
	if _, err := d.CommitHealthReplacement(ctx, hash, owner.ID, at); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale commit %v", err)
	}
	if stale, err := d.GetServiceConfirmation(ctx, hash); err != nil || stale.UsedAt != nil {
		t.Fatal("conflict marked the plan")
	}
	_, commitHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	commitRow := row
	commitRow.CurrentHash = store.HealthSetHash(nil)
	commitRow.IdempotencyKey = "hc-commit"
	if err := d.PutServiceConfirmation(ctx, commitHash, commitRow); err != nil {
		t.Fatal(err)
	}
	applied, err := d.CommitHealthReplacement(ctx, commitHash, owner.ID, at)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 2 || applied[0].Protocol != "tcp" || applied[0].Port != 443 || !applied[0].Enabled {
		t.Fatalf("applied tcp %+v", applied)
	}
	if applied[1].Protocol != "http" || applied[1].Enabled || applied[1].Path == nil || *applied[1].Path != "/health" || applied[1].IntervalSec != 60 {
		t.Fatalf("applied http %+v", applied)
	}
	usedRow, err := d.GetServiceConfirmation(ctx, commitHash)
	if err != nil || usedRow.UsedAt == nil {
		t.Fatal("commit did not mark the plan")
	}
	listed, err := d.ListHealthChecks(ctx, svc.ID)
	if err != nil {
		t.Fatal(err)
	}
	var tcp, http bool
	for _, c := range listed {
		switch c.Protocol {
		case "tcp":
			tcp = c.Port == 443 && c.Enabled && c.IntervalSec == 60
		case "http":
			http = !c.Enabled && c.Path != nil && *c.Path == "/health" && c.ExpectStatusMin == 200 && c.ExpectStatusMax == 399
		}
	}
	if !tcp || !http || len(listed) != 2 {
		t.Fatalf("listed %+v", listed)
	}
	if _, err := d.CommitHealthReplacement(ctx, commitHash, owner.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second commit %v", err)
	}
	if again, err := d.ListHealthChecks(ctx, svc.ID); err != nil || len(again) != 2 {
		t.Fatal("second commit changed the set")
	}

	if err := d.MarkServiceConfirmationUsed(ctx, hash, other.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other user %v", err)
	}
	if again, err := d.GetServiceConfirmation(ctx, hash); err != nil || again.UsedAt != nil {
		t.Fatal("other user consumed the row")
	}
	if err := d.MarkServiceConfirmationUsed(ctx, hash, owner.ID, at); err != nil {
		t.Fatal(err)
	}
	if err := d.MarkServiceConfirmationUsed(ctx, hash, owner.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second use %v", err)
	}

	_, expiredHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	expired := row
	expired.ExpiresAt = at.Add(-time.Second)
	expired.IdempotencyKey = "hc-expired"
	if err := d.PutServiceConfirmation(ctx, expiredHash, expired); err != nil {
		t.Fatal(err)
	}
	if err := d.MarkServiceConfirmationUsed(ctx, expiredHash, owner.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired %v", err)
	}

	bad := row
	bad.Action = "nope"
	bad.IdempotencyKey = "hc-bad-action"
	if _, badHash, err := secret.NewToken(); err != nil {
		t.Fatal(err)
	} else if err := d.PutServiceConfirmation(ctx, badHash, bad); !checkViolation(err) {
		t.Fatalf("bad action %v", err)
	}
	short := row
	short.RequestHash = []byte{1, 2, 3}
	short.IdempotencyKey = "hc-short"
	if _, shortHash, err := secret.NewToken(); err != nil {
		t.Fatal(err)
	} else if err := d.PutServiceConfirmation(ctx, shortHash, short); !checkViolation(err) {
		t.Fatalf("short hash %v", err)
	}

	if _, err := d.pool.Exec(ctx, `DELETE FROM app.services WHERE id = $1::uuid`, svc.ID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetServiceConfirmation(ctx, hash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cascade %v", err)
	}
}

func checkViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23514"
}
