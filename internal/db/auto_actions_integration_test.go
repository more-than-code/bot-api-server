package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/store"
	"github.com/more-than-code/bot-api-server/migrations"
)

func TestAutoActionsMigrationText(t *testing.T) {
	body, err := migrations.FS.ReadFile("0014_auto_actions.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"ALTER COLUMN by_user DROP NOT NULL",
		"auto_action_id uuid NULL",
		"UNIQUE (auto_action_id)",
		"via IN ('console', 'mcp', 'agent')",
		"by_user IS NOT NULL OR via = 'agent'",
		"'auto_restarted', 'auto_rolled_back', 'auto_gave_up', 'auto_failed'",
		"(via = 'agent') = (auto_action_id IS NOT NULL)",
		"OR via = 'agent'",
		"via <> 'agent' OR NOT in_flight",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("0014 missing %s", want)
		}
	}
	for _, line := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "--") && strings.Contains(trim, ";") {
			t.Fatalf("comment with a semicolon would split: %s", trim)
		}
	}
	down, err := migrations.FS.ReadFile("0014_auto_actions.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	downText := string(down)
	if !strings.Contains(downText, "DELETE FROM app.schema_migrations WHERE name = '0014_auto_actions.sql'") {
		t.Fatal("down script does not name its schema_migrations row")
	}
	if !strings.Contains(downText, "\nBEGIN;") || !strings.HasSuffix(strings.TrimSpace(downText), "COMMIT;") {
		t.Fatal("down script must run in one transaction")
	}
	deleteAt := strings.Index(downText, "DELETE FROM app.image_deploys WHERE via = 'agent'")
	notNullAt := strings.Index(downText, "SET NOT NULL")
	if deleteAt < 0 || notNullAt < deleteAt {
		t.Fatal("down script must delete agent rows before restoring NOT NULL")
	}
}

func TestAutoActionsMigration(t *testing.T) {
	url := os.Getenv("DEPLOYBOT_TEST_DATABASE_URL")
	if url == "" {
		t.Skip()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	t.Cleanup(func() {
		restoreAutoActions(t, url)
	})
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
	assertAutoSchema(t, d, ctx, true)

	at := time.Now().UTC().Truncate(time.Second)
	tag := strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	owner := catalogUser(t, d, ctx, "auto-owner-"+tag, at)
	home := catalogProject(t, d, ctx, owner.ID, "Auto", "auto"+tag, at)
	viewer := catalogProject(t, d, ctx, owner.ID, "AutoView", "autoview"+tag, at)
	host := enrollHostDB(t, d, ctx, home.ID, owner.ID, "auto-host-"+tag, at)
	if _, _, err := d.PutHostShare(ctx, host.ID, viewer.ID, "metrics", owner.ID, at); err != nil {
		t.Fatal(err)
	}
	img, err := catalog.BuildImage("web", []byte(`{"kind":"service","image":"redis","healthcheck":{"test":["redis-cli","ping"]},"health_policy":{"on_unhealthy":"restart"}}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	write := store.CatalogWrite{
		Name: "web", Kind: "image", ImageRaw: []byte(catalog.SpecJSON(img)),
		SpecHash: catalog.ImageHash(img, nil), CommandDisplay: img.Image, Actor: owner.ID, At: at,
	}
	entry, err := d.CreateCatalogEntry(ctx, home.ID, write)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateCatalogEntry(ctx, viewer.ID, write); err != nil {
		t.Fatal(err)
	}
	stored, err := d.GetCatalogEntry(ctx, home.ID, "web")
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := catalog.ParseStored(stored.ImageRaw); err != nil || parsed.HealthPolicy == nil || parsed.HealthPolicy.Effective().OnUnhealthy != "restart" {
		t.Fatalf("stored health_policy %v", err)
	}

	target, err := d.AutoActionTarget(ctx, host.ID, home.Slug, "web")
	if err != nil || target.EntryID != entry.ID || target.ProjectID != home.ID || target.Deployed || len(target.ImageRaw) == 0 {
		t.Fatalf("target before deploy %+v %v", target, err)
	}
	for _, bad := range []struct{ slug, name string }{{home.Slug, "nope"}, {viewer.Slug, "web"}, {"no-such-" + tag, "web"}} {
		if _, err := d.AutoActionTarget(ctx, host.ID, bad.slug, bad.name); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("target %v: %v", bad, err)
		}
	}
	// No rows yet: the entry's hash, and a null digest stays null.
	first, inserted, err := d.RecordAutoAction(ctx, store.AutoAction{
		ID: uuid.New(), EntryID: entry.ID, HostID: host.ID, Outcome: "auto_gave_up", At: at.Add(-2 * time.Hour),
	})
	if err != nil || !inserted || first.SpecHash != entry.SpecHash || first.Digest != nil {
		t.Fatalf("first %+v %v %v", first, inserted, err)
	}
	userHash := strings.Repeat("b", 64)
	userDigest := "sha256:" + strings.Repeat("1", 64)
	finishDeploy(t, d, ctx, entry.ID, host.ID, userHash, owner.ID, "succeeded", userDigest, at.Add(-90*time.Minute))
	if target, err := d.AutoActionTarget(ctx, host.ID, home.Slug, "web"); err != nil || !target.Deployed {
		t.Fatalf("target after deploy %+v %v", target, err)
	}

	id := uuid.New()
	newDigest := "sha256:" + strings.Repeat("2", 64)
	row, inserted, err := d.RecordAutoAction(ctx, store.AutoAction{
		ID: id, EntryID: entry.ID, HostID: host.ID, Outcome: "auto_restarted", Digest: &newDigest, At: at,
	})
	if err != nil || !inserted {
		t.Fatalf("record %v %v", inserted, err)
	}
	if row.Outcome != "auto_restarted" || row.Via != "agent" || row.By != nil || row.Digest == nil || *row.Digest != newDigest ||
		row.SpecHash != userHash || row.InFlight || !row.StartedAt.Equal(at) || row.FinishedAt == nil || !row.FinishedAt.Equal(at) {
		t.Fatalf("row %+v", row)
	}
	if _, again, err := d.RecordAutoAction(ctx, store.AutoAction{
		ID: id, EntryID: entry.ID, HostID: host.ID, Outcome: "auto_restarted", Digest: &newDigest, At: at,
	}); err != nil || again {
		t.Fatalf("replay %v %v", again, err)
	}
	rolled, inserted, err := d.RecordAutoAction(ctx, store.AutoAction{
		ID: uuid.New(), EntryID: entry.ID, HostID: host.ID, Outcome: "auto_rolled_back", At: at.Add(time.Second),
	})
	// A null digest inherits the last succeeded user digest, not the agent row's.
	if err != nil || !inserted || rolled.Digest == nil || *rolled.Digest != userDigest || rolled.SpecHash != userHash {
		t.Fatalf("rolled %+v %v", rolled, err)
	}
	failed, inserted, err := d.RecordAutoAction(ctx, store.AutoAction{
		ID: uuid.New(), EntryID: entry.ID, HostID: host.ID, Outcome: "auto_failed", Digest: &newDigest, At: at.Add(2 * time.Second),
	})
	if err != nil || !inserted || failed.Digest != nil {
		t.Fatalf("failed %+v %v", failed, err)
	}
	// Cap: 20 agent rows in the hour before At. Three are already in that hour.
	for i := 0; i < 17; i++ {
		if _, ok, err := d.RecordAutoAction(ctx, store.AutoAction{
			ID: uuid.New(), EntryID: entry.ID, HostID: host.ID, Outcome: "auto_restarted", At: at.Add(time.Duration(3+i) * time.Second),
		}); err != nil || !ok {
			t.Fatalf("fill %d %v %v", i, ok, err)
		}
	}
	if _, _, err := d.RecordAutoAction(ctx, store.AutoAction{
		ID: uuid.New(), EntryID: entry.ID, HostID: host.ID, Outcome: "auto_restarted", At: at.Add(30 * time.Second),
	}); !errors.Is(err, store.ErrAutoActionLimit) {
		t.Fatalf("21st in the hour: %v", err)
	}
	items, err := d.ListImageDeploys(ctx, entry.ID, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	var manual, auto int
	for i, it := range items {
		if i > 0 && it.FinishedAt.After(*items[i-1].FinishedAt) {
			t.Fatal("history not newest first")
		}
		if it.Via == "agent" {
			auto++
			if it.By != nil {
				t.Fatal("agent row has a user")
			}
		} else {
			manual++
			if it.By == nil || *it.By != owner.ID {
				t.Fatal("user row lost its user")
			}
		}
	}
	// The first gave_up row (2h ago) is older than the only user row.
	if manual != 1 || auto != 20 || items[0].Via != "agent" {
		t.Fatalf("history manual %d auto %d", manual, auto)
	}
	if digests, err := d.RollbackDigests(ctx, entry.ID, host.ID); err != nil || len(digests) != 1 || digests[0] != userDigest {
		t.Fatalf("rollback digests %v %v", digests, err)
	}

	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal("connect failed")
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `SET ROLE deploybot_owner`); err != nil {
		t.Fatal(err)
	}
	bad := []struct {
		name, by, via, outcome, autoID string
		inFlight                       bool
	}{
		{"console row without a user", "", "console", "succeeded", "", false},
		{"agent row without auto_action_id", "", "agent", "auto_restarted", "", false},
		{"console row with auto_action_id", owner.ID.String(), "console", "succeeded", uuid.NewString(), false},
		{"auto outcome on a console row", owner.ID.String(), "console", "auto_failed", "", false},
		{"agent row in flight", "", "agent", "in_flight", uuid.NewString(), true},
		{"unknown outcome", "", "agent", "auto_exploded", uuid.NewString(), false},
	}
	for _, b := range bad {
		var by, autoID any
		if b.by != "" {
			by = b.by
		}
		if b.autoID != "" {
			autoID = b.autoID
		}
		var finished any = time.Now().UTC()
		if b.inFlight {
			finished = nil
		}
		if _, err := conn.Exec(ctx, `
INSERT INTO app.image_deploys (id, entry_id, host_id, spec_hash, outcome, started_at, finished_at, by_user, via, in_flight, in_flight_until, auto_action_id)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, now(), $6, $7::uuid, $8, $9, CASE WHEN $9 THEN now() END, $10::uuid)
`, uuid.NewString(), entry.ID.String(), host.ID.String(), userHash, b.outcome, finished, by, b.via, b.inFlight, autoID); err == nil {
			t.Fatalf("%s was accepted", b.name)
		}
	}

	down, err := migrations.FS.ReadFile("0014_auto_actions.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	assertDownAtomic(t, d, ctx, conn, string(down), entry.ID)
	for _, stmt := range splitSQL(string(down)) {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("down: %v", err)
		}
	}
	assertAutoSchema(t, d, ctx, false)
	var left, agentLeft int
	if err := conn.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE via = 'agent') FROM app.image_deploys WHERE entry_id = $1::uuid`, entry.ID.String()).Scan(&left, &agentLeft); err != nil {
		t.Fatal(err)
	}
	if left != 1 || agentLeft != 0 { // the one user deploy stays
		t.Fatalf("after down %d rows, %d agent", left, agentLeft)
	}
	if _, err := conn.Exec(ctx, `DELETE FROM app.schema_migrations WHERE name = '0014_auto_actions.sql'`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, url); err != nil {
		t.Fatalf("restore migrate: %v", err)
	}
	assertAutoSchema(t, d, ctx, true)
}

// assertDownAtomic runs the down script the way `psql -f` does, one
// statement at a time on one connection and continuing past errors, while a
// temporary view depends on auto_action_id so the late DROP COLUMN fails.
// It fails the test unless the script's BEGIN/COMMIT kept everything.
func assertDownAtomic(t *testing.T, d *DB, ctx context.Context, conn *pgx.Conn, down string, entryID uuid.UUID) {
	t.Helper()
	if err := downAtomicProblem(t, d, ctx, conn, down, entryID); err != nil {
		t.Fatal(err)
	}
}

// runLikePsql executes each statement of script in order and returns one
// error per failing statement, with the statement text.
func runLikePsql(ctx context.Context, conn *pgx.Conn, script string) []stmtErr {
	var errs []stmtErr
	for _, stmt := range splitSQL(script) {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			errs = append(errs, stmtErr{stmt: stmt, err: err})
		}
	}
	return errs
}

type stmtErr struct {
	stmt string
	err  error
}

func sqlState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// downAtomicProblem returns nil when the failed run left 0014 fully applied.
// The first error must be 2BP01 on the DROP COLUMN. Later statements in the
// aborted transaction may only fail with 25P02.
func downAtomicProblem(t *testing.T, d *DB, ctx context.Context, conn *pgx.Conn, down string, entryID uuid.UUID) error {
	t.Helper()
	agentRows := func() (int, error) {
		var n int
		err := d.pool.QueryRow(ctx, `SELECT count(*) FROM app.image_deploys WHERE entry_id = $1::uuid AND via = 'agent'`, entryID.String()).Scan(&n)
		return n, err
	}
	before, err := agentRows()
	if err != nil {
		return err
	}
	if before == 0 {
		return errors.New("no agent rows to protect")
	}
	if _, err := conn.Exec(ctx, `DROP VIEW IF EXISTS app.tmp_auto_action_dep`); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, `CREATE VIEW app.tmp_auto_action_dep AS SELECT auto_action_id FROM app.image_deploys`); err != nil {
		return err
	}
	defer func() {
		if _, err := conn.Exec(ctx, `ROLLBACK`); err != nil {
			t.Logf("rollback: %v", err)
		}
		if _, err := conn.Exec(ctx, `DROP VIEW IF EXISTS app.tmp_auto_action_dep`); err != nil {
			t.Errorf("drop view: %v", err)
		}
	}()
	errs := runLikePsql(ctx, conn, down)
	if len(errs) == 0 {
		return errors.New("down script succeeded although a view depends on auto_action_id")
	}
	if sqlState(errs[0].err) != "2BP01" || !strings.Contains(errs[0].stmt, "DROP COLUMN") {
		return fmt.Errorf("first failure is %q on %q, want 2BP01 on DROP COLUMN", sqlState(errs[0].err), errs[0].stmt)
	}
	for _, e := range errs[1:] {
		if sqlState(e.err) != "25P02" {
			return fmt.Errorf("later failure %q on %q, want 25P02", sqlState(e.err), e.stmt)
		}
	}
	var nullable string
	var cols, checks int
	if err := d.pool.QueryRow(ctx, `
SELECT
  (SELECT is_nullable FROM information_schema.columns
   WHERE table_schema = 'app' AND table_name = 'image_deploys' AND column_name = 'by_user'),
  (SELECT count(*) FROM information_schema.columns
   WHERE table_schema = 'app' AND table_name = 'image_deploys' AND column_name = 'auto_action_id'),
  (SELECT count(*) FROM pg_constraint WHERE conname IN (
     'image_deploys_by_chk', 'image_deploys_auto_id_chk', 'image_deploys_auto_outcome_chk',
     'image_deploys_agent_flight_chk', 'image_deploys_auto_action_unique'))
`).Scan(&nullable, &cols, &checks); err != nil {
		return err
	}
	var outcome string
	if err := d.pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'image_deploys_outcome_chk'`).Scan(&outcome); err != nil {
		return err
	}
	if nullable != "YES" || cols != 1 || checks != 5 || !strings.Contains(outcome, "auto_failed") {
		return fmt.Errorf("schema changed by a failed down: by_user nullable=%s auto_action_id=%d 0014 constraints=%d outcome=%s", nullable, cols, checks, outcome)
	}
	after, err := agentRows()
	if err != nil {
		return err
	}
	if after != before {
		return fmt.Errorf("failed down deleted agent rows: %d → %d", before, after)
	}
	return nil
}

func assertAutoSchema(t *testing.T, d *DB, ctx context.Context, up bool) {
	t.Helper()
	var nullable string
	if err := d.pool.QueryRow(ctx, `
SELECT is_nullable FROM information_schema.columns
WHERE table_schema = 'app' AND table_name = 'image_deploys' AND column_name = 'by_user'
`).Scan(&nullable); err != nil {
		t.Fatal(err)
	}
	var cols int
	if err := d.pool.QueryRow(ctx, `
SELECT count(*) FROM information_schema.columns
WHERE table_schema = 'app' AND table_name = 'image_deploys' AND column_name = 'auto_action_id'
`).Scan(&cols); err != nil {
		t.Fatal(err)
	}
	var via, outcome string
	if err := d.pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'image_deploys_via_chk'`).Scan(&via); err != nil {
		t.Fatal(err)
	}
	if err := d.pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'image_deploys_outcome_chk'`).Scan(&outcome); err != nil {
		t.Fatal(err)
	}
	var byChk int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conname = 'image_deploys_by_chk'`).Scan(&byChk); err != nil {
		t.Fatal(err)
	}
	if up {
		if nullable != "YES" || cols != 1 || byChk != 1 || !strings.Contains(via, "agent") || !strings.Contains(outcome, "auto_gave_up") {
			t.Fatalf("up schema nullable=%s cols=%d by=%d via=%s outcome=%s", nullable, cols, byChk, via, outcome)
		}
		return
	}
	if nullable != "NO" || cols != 0 || byChk != 0 || strings.Contains(via, "agent") || strings.Contains(outcome, "auto_") {
		t.Fatalf("down schema nullable=%s cols=%d by=%d via=%s outcome=%s", nullable, cols, byChk, via, outcome)
	}
}

// restoreAutoActions re-applies 0014 when a failed run left it rolled back.
func restoreAutoActions(t *testing.T, url string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	d, err := Open(ctx, url)
	if err != nil {
		t.Errorf("restore 0014: %v", err)
		return
	}
	defer d.Close()
	if _, err := d.pool.Exec(ctx, `DROP VIEW IF EXISTS app.tmp_auto_action_dep`); err != nil {
		t.Errorf("restore 0014: drop view: %v", err)
	}
	var cols int
	if err := d.pool.QueryRow(ctx, `
SELECT count(*) FROM information_schema.columns
WHERE table_schema = 'app' AND table_name = 'image_deploys' AND column_name = 'auto_action_id'
`).Scan(&cols); err != nil {
		t.Errorf("restore 0014: %v", err)
		return
	}
	if cols == 1 {
		return
	}
	t.Logf("restore 0014: auto_action_id is missing, re-applying")
	if _, err := d.pool.Exec(ctx, `DELETE FROM app.schema_migrations WHERE name = '0014_auto_actions.sql'`); err != nil {
		t.Errorf("restore 0014: %v", err)
		return
	}
	if err := Migrate(ctx, url); err != nil {
		t.Errorf("restore 0014: migrate: %v", err)
	}
}

// autoStoreFixture opens the test database at 0014 and makes a project, a
// host, and n image entries with a restart policy, with unique names.
func autoStoreFixture(t *testing.T, ctx context.Context, n int) (*DB, store.User, store.Host, []store.CatalogEntry) {
	t.Helper()
	return autoStoreFixtureConns(t, ctx, n, 0)
}

// autoStoreFixtureConns is autoStoreFixture with pool_max_conns set when
// maxConns is above zero.
func autoStoreFixtureConns(t *testing.T, ctx context.Context, n, maxConns int) (*DB, store.User, store.Host, []store.CatalogEntry) {
	t.Helper()
	url := os.Getenv("DEPLOYBOT_TEST_DATABASE_URL")
	if url == "" {
		t.Skip()
	}
	open := url
	if maxConns > 0 {
		sep := "?"
		if strings.Contains(open, "?") {
			sep = "&"
		}
		open += sep + "pool_max_conns=" + strconv.Itoa(maxConns)
	}
	d, err := Open(ctx, open)
	if err != nil {
		t.Fatal("connect failed")
	}
	t.Cleanup(d.Close)
	var dbName string
	if err := d.pool.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil || dbName != "deploybot_test" {
		t.Fatalf("refusing database %s", dbName)
	}
	if err := Migrate(ctx, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	at := time.Now().UTC().Truncate(time.Second)
	tag := strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	owner := catalogUser(t, d, ctx, "auto-store-"+tag, at)
	project := catalogProject(t, d, ctx, owner.ID, "AutoStore", "autostore"+tag, at)
	host := enrollHostDB(t, d, ctx, project.ID, owner.ID, "auto-store-host-"+tag, at)
	img, err := catalog.BuildImage("web", []byte(`{"kind":"service","image":"redis","healthcheck":{"test":["redis-cli","ping"]},"health_policy":{"on_unhealthy":"restart"}}`), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]store.CatalogEntry, n)
	for i := range entries {
		entries[i], err = d.CreateCatalogEntry(ctx, project.ID, store.CatalogWrite{
			Name: "web" + strings.Repeat("x", i), Kind: "image", ImageRaw: []byte(catalog.SpecJSON(img)),
			SpecHash: catalog.ImageHash(img, nil), CommandDisplay: img.Image, Actor: owner.ID, At: at,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return d, owner, host, entries
}

func autoAt(t *testing.T, d *DB, ctx context.Context, entryID, hostID uuid.UUID, outcome string, digest *string, at time.Time) store.ImageDeploy {
	t.Helper()
	row, ok, err := d.RecordAutoAction(ctx, store.AutoAction{ID: uuid.New(), EntryID: entryID, HostID: hostID, Outcome: outcome, Digest: digest, At: at})
	if err != nil || !ok {
		t.Fatalf("record at %s: %v %v", at, ok, err)
	}
	return row
}

func TestAutoActionsHistoryMerge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	d, owner, host, entries := autoStoreFixture(t, ctx, 3)
	mixed, agentOnly, tie := entries[0], entries[1], entries[2]
	base := time.Now().UTC().Truncate(time.Second).Add(-400 * time.Hour)
	digest := "sha256:" + strings.Repeat("1", 64)
	for i := 0; i < 55; i++ {
		finishDeploy(t, d, ctx, mixed.ID, host.ID, strings.Repeat("a", 64), owner.ID, "succeeded", digest, base.Add(time.Duration(i)*time.Minute))
	}
	oldestListed := base.Add(5 * time.Minute) // rows 5..54 are the newest 50
	excluded := map[uuid.UUID]bool{}
	for _, at := range []time.Time{base.Add(time.Minute), base.Add(2 * time.Minute), oldestListed} {
		excluded[autoAt(t, d, ctx, mixed.ID, host.ID, "auto_restarted", nil, at).ID] = true
	}
	var qualifying []uuid.UUID // oldest first
	for k := 0; k < 15; k++ {
		qualifying = append(qualifying, autoAt(t, d, ctx, mixed.ID, host.ID, "auto_restarted", nil, base.Add(6*time.Minute+time.Duration(k)*61*time.Minute)).ID)
	}
	items, err := d.ListImageDeploys(ctx, mixed.ID, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := map[uuid.UUID]bool{}
	for _, id := range qualifying {
		want[id] = true
	}
	manual, auto := 0, 0
	for i, it := range items {
		if i > 0 && it.FinishedAt.After(*items[i-1].FinishedAt) {
			t.Fatal("history not newest first")
		}
		if it.Via == "agent" {
			auto++
			if excluded[it.ID] || !want[it.ID] {
				t.Fatalf("unexpected agent row at %s", it.FinishedAt)
			}
		} else {
			manual++
			if it.FinishedAt.Before(oldestListed) {
				t.Fatal("a manual row older than the newest 50 was listed")
			}
		}
	}
	// 15 qualify and 3 do not: without the window filter 18 would be listed.
	if manual != 50 || auto != 15 || items[0].ID != qualifying[14] {
		t.Fatalf("manual %d auto %d", manual, auto)
	}

	for k := 0; k < 25; k++ {
		autoAt(t, d, ctx, agentOnly.ID, host.ID, "auto_gave_up", nil, base.Add(time.Duration(k)*61*time.Minute))
	}
	if items, err := d.ListImageDeploys(ctx, agentOnly.ID, host.ID); err != nil || len(items) != 20 {
		t.Fatalf("agent-only history %d %v", len(items), err)
	}

	// The query uses >: an agent row at exactly the oldest listed manual row is excluded.
	finishDeploy(t, d, ctx, tie.ID, host.ID, strings.Repeat("a", 64), owner.ID, "succeeded", digest, base)
	same := autoAt(t, d, ctx, tie.ID, host.ID, "auto_restarted", nil, base)
	newer := autoAt(t, d, ctx, tie.ID, host.ID, "auto_restarted", nil, base.Add(time.Second))
	items, err = d.ListImageDeploys(ctx, tie.ID, host.ID)
	if err != nil || len(items) != 2 || items[0].ID != newer.ID || items[1].Via == "agent" {
		t.Fatalf("tie history %+v %v", items, err)
	}
	for _, it := range items {
		if it.ID == same.ID {
			t.Fatal("agent row equal to the oldest manual row was listed")
		}
	}
}

func TestAutoActionsConcurrentCap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	d, _, host, entries := autoStoreFixtureConns(t, ctx, 1, 25)
	if got := d.pool.Config().MaxConns; got < 8 {
		t.Fatalf("pool allows %d connections, need at least 8 to contend the lock", got)
	}
	at := time.Now().UTC().Truncate(time.Second)
	start := make(chan struct{})
	var mu sync.Mutex
	inserted, limited, other := 0, 0, 0
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, ok, err := d.RecordAutoAction(ctx, store.AutoAction{ID: uuid.New(), EntryID: entries[0].ID, HostID: host.ID, Outcome: "auto_restarted", At: at})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && ok:
				inserted++
			case errors.Is(err, store.ErrAutoActionLimit):
				limited++
			default:
				other++
			}
		}()
	}
	close(start)
	wg.Wait()
	if inserted != 20 || limited != 5 || other != 0 {
		t.Fatalf("inserted %d limited %d other %d", inserted, limited, other)
	}
}

func TestAutoActionsWindowAndDigest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	d, owner, host, entries := autoStoreFixture(t, ctx, 2)
	b := time.Now().UTC().Truncate(time.Second).Add(-10 * time.Hour)
	for i := 0; i < store.AutoActionsPerHour; i++ {
		autoAt(t, d, ctx, entries[0].ID, host.ID, "auto_restarted", nil, b)
	}
	// At-1h+1s: the rows at b count.
	if _, _, err := d.RecordAutoAction(ctx, store.AutoAction{ID: uuid.New(), EntryID: entries[0].ID, HostID: host.ID, Outcome: "auto_restarted", At: b.Add(time.Hour - time.Second)}); !errors.Is(err, store.ErrAutoActionLimit) {
		t.Fatalf("one second inside the window: %v", err)
	}
	// Exactly At-1h: they do not.
	autoAt(t, d, ctx, entries[0].ID, host.ID, "auto_restarted", nil, b.Add(time.Hour))

	web := entries[1]
	at := time.Now().UTC().Truncate(time.Second)
	userDigest := "sha256:" + strings.Repeat("1", 64)
	finishDeploy(t, d, ctx, web.ID, host.ID, strings.Repeat("a", 64), owner.ID, "succeeded", userDigest, at.Add(-time.Hour))
	finishDeploy(t, d, ctx, web.ID, host.ID, strings.Repeat("a", 64), owner.ID, "failed", "sha256:"+strings.Repeat("4", 64), at.Add(-30*time.Minute))
	x := "sha256:" + strings.Repeat("9", 64)
	autoAt(t, d, ctx, web.ID, host.ID, "auto_rolled_back", &x, at)
	restart := autoAt(t, d, ctx, web.ID, host.ID, "auto_restarted", nil, at.Add(time.Second))
	if restart.Digest == nil || *restart.Digest != userDigest {
		t.Fatalf("restart digest %v, want the last succeeded user digest", restart.Digest)
	}
	if failed := autoAt(t, d, ctx, web.ID, host.ID, "auto_failed", &x, at.Add(2*time.Second)); failed.Digest != nil {
		t.Fatalf("auto_failed digest %v", *failed.Digest)
	}
}
