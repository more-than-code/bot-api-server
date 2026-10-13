package main

import (
	"os"
	"strings"
	"testing"

	"github.com/more-than-code/bot-api-server/migrations"
)

func TestMigrationFiles(t *testing.T) {
	metrics, err := os.ReadFile("../../migrations/0002_metrics.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(metrics)
	if !strings.Contains(text, "create_hypertable") || !strings.Contains(text, "7 days") {
		t.Fatal("retention or hypertable missing")
	}
	if strings.Contains(text, "add_continuous_aggregate_policy") {
		t.Fatal("continuous aggregates are not in wave 1")
	}
	if strings.Contains(text, "CREATE EXTENSION") || strings.Contains(text, "CREATE SCHEMA") {
		t.Fatal("0002 must not create the extension or schema")
	}
	if !strings.Contains(text, "GRANT DELETE ON TABLE metrics.ingest_batches TO deploybot_api") {
		t.Fatal("ingest_batches DELETE grant missing")
	}
	app, err := os.ReadFile("../../migrations/0001_app.sql")
	if err != nil {
		t.Fatal(err)
	}
	appText := string(app)
	for _, line := range []string{
		"REVOKE ALL ON TABLE app.audit_log FROM deploybot_api",
		"GRANT SELECT, INSERT ON TABLE app.audit_log TO deploybot_api",
		"REVOKE ALL ON TABLE app.schema_migrations FROM deploybot_api",
		"left(path, 2) <> '//'",
	} {
		if !strings.Contains(appText, line) {
			t.Fatalf("0001 missing %s", line)
		}
	}
	if strings.Contains(appText, "CREATE SCHEMA") || strings.Contains(appText, "CREATE EXTENSION") {
		t.Fatal("0001 must not create the schema or extension")
	}
	roles, err := os.ReadFile("../../migrations/roles.sql.example")
	if err != nil {
		t.Fatal(err)
	}
	body := string(roles)
	for _, s := range []string{"deploybot_owner", "deploybot_api", "deploybot_migrator", "CHANGE_ME", "NOLOGIN", "CREATE EXTENSION", "deploybot_test"} {
		if !strings.Contains(body, s) {
			t.Fatalf("roles.sql.example missing %s", s)
		}
	}
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "roles") {
			t.Fatalf("roles script is embedded: %s", entry.Name())
		}
	}
}
