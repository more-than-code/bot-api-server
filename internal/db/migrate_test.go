package db

import (
	"strings"
	"testing"

	"github.com/more-than-code/bot-api-server/migrations"
)

func TestMigrationSkipsDownScript(t *testing.T) {
	if numberedSQL("0003_shared_hosts.down.sql") {
		t.Fatal("down script is numbered SQL")
	}
	if !numberedSQL("0003_shared_hosts.sql") {
		t.Fatal("0003 is not numbered SQL")
	}
	names, err := migrationFiles()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(names, ",")
	for _, want := range []string{"0001_app.sql", "0002_metrics.sql", "0003_shared_hosts.sql"} {
		if !strings.Contains(got, want) {
			t.Fatalf("migrations = %s", got)
		}
	}
	if strings.Contains(got, ".down.sql") {
		t.Fatalf("down script would be applied: %s", got)
	}
}

func TestSplitSQLKeepsFunctionBody(t *testing.T) {
	body, err := migrations.FS.ReadFile("0003_shared_hosts.sql")
	if err != nil {
		t.Fatal(err)
	}
	stmts := splitSQL(string(body))
	var fn string
	for _, stmt := range stmts {
		trimmed := strings.TrimSpace(stmt)
		if trimmed == "RETURN NEW" || strings.HasPrefix(trimmed, "END") {
			t.Fatalf("function body was split: %q", trimmed)
		}
		if strings.Contains(stmt, "CREATE FUNCTION") {
			fn = stmt
		}
	}
	if !strings.Contains(fn, "RETURN NEW") || !strings.Contains(fn, "CONSTRAINT = 'host_shares_not_owner'") {
		t.Fatalf("function statement: %s", fn)
	}
	parts := splitSQL("SELECT $1;\nSELECT 2;")
	if len(parts) != 2 || !strings.Contains(parts[0], "$1") {
		t.Fatalf("dollar param split: %#v", parts)
	}
}

func TestSharedHostsMigrationText(t *testing.T) {
	assertSharedHostsMigration(t)
}

// assertSharedHostsMigration checks the embedded 0003 script. The column is
// already NOT NULL after migrate, so a live NULL backfill cannot be re-run.
func assertSharedHostsMigration(t *testing.T) {
	t.Helper()
	body, err := migrations.FS.ReadFile("0003_shared_hosts.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	updateAt := strings.Index(text, "UPDATE app.services AS s")
	notNullAt := strings.Index(text, "ALTER COLUMN project_id SET NOT NULL")
	if updateAt < 0 || notNullAt < 0 || updateAt > notNullAt {
		t.Fatal("backfill UPDATE must run before project_id is NOT NULL")
	}
	stmt := sharedHostsBackfillSQL(t)
	if !strings.Contains(stmt, "SET project_id = h.project_id") || !strings.Contains(stmt, "h.id = s.host_id") {
		t.Fatalf("backfill statement %q", stmt)
	}
	if !strings.Contains(text, "REFERENCES app.hosts (id) ON DELETE CASCADE") {
		t.Fatal("host_shares.host_id is missing ON DELETE CASCADE")
	}
	if !strings.Contains(text, "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE app.host_shares TO deploybot_api") {
		t.Fatal("missing deploybot_api grants on app.host_shares")
	}
	down, err := migrations.FS.ReadFile("0003_shared_hosts.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	downText := string(down)
	if !strings.Contains(downText, "DELETE FROM app.schema_migrations WHERE name = '0003_shared_hosts.sql'") {
		t.Fatal("down script does not document the schema_migrations delete")
	}
	if !strings.Contains(downText, "--migrate does not apply") {
		t.Fatal("down script does not say --migrate skips it")
	}
}

// sharedHostsBackfillSQL is the UPDATE in 0003 that copies hosts.project_id
// onto services. Callers run this text; they do not keep a second copy.
func sharedHostsBackfillSQL(t *testing.T) string {
	t.Helper()
	body, err := migrations.FS.ReadFile("0003_shared_hosts.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range splitSQL(string(body)) {
		if strings.Contains(stmt, "SET project_id = h.project_id") && strings.Contains(stmt, "h.id = s.host_id") {
			return stmt
		}
	}
	t.Fatal("backfill statement not found in 0003_shared_hosts.sql")
	return ""
}
