package db

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/more-than-code/bot-api-server/internal/catalog"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// assertCatalog is the Postgres half of api-v1 v1.6 wave 1: migration shape,
// deploybot_api grants, approval voiding, idempotency, confirmations, and
// owned-service ingest. It runs inside TestIntegration.
func assertCatalog(t *testing.T, d *DB, ctx context.Context, at time.Time) {
	t.Helper()
	assertCatalogSchema(t, d, ctx)

	owner := catalogUser(t, d, ctx, "catalog-owner", at)
	other := catalogUser(t, d, ctx, "catalog-other", at)
	home := catalogProject(t, d, ctx, owner.ID, "Catalog", "catproj", at)
	box := catalogProject(t, d, ctx, other.ID, "Box", "boxproj", at)
	host := enrollHostDB(t, d, ctx, box.ID, other.ID, "cat-host", at)

	spec, hash, display := catalogSpec(t, "pnpm run dev")
	entry, err := d.CreateCatalogEntry(ctx, home.ID, store.CatalogWrite{
		Name: "webapp", Spec: spec, SpecHash: hash, CommandDisplay: display, Actor: owner.ID, At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	grants, err := d.ListCatalogGrants(ctx, entry.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !grantIs(grants, "role:admin", "run", "stop", "restart", "logs") || !grantIs(grants, "role:viewer", "logs") {
		t.Fatalf("default grants %#v", grants)
	}

	if _, err := d.ApproveCatalog(ctx, host.ID, entry.ID, hash, other.ID, at); err != nil {
		t.Fatal(err)
	}
	if err := d.UpsertPendingApproval(ctx, entry.ID, host.ID, hash, owner.ID, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	approved, err := d.ListCatalogApprovals(ctx, host.ID)
	if err != nil || len(approved) != 1 || approved[0].Status != "approved" || approved[0].RequestedBy != other.ID {
		t.Fatalf("upsert cleared approval %#v %v", approved, err)
	}
	if approved[0].Exec != "pnpm" || approved[0].Env == nil || len(approved[0].Args) != 2 {
		t.Fatalf("approval spec %#v", approved[0])
	}
	if n := catalogApprovalCount(t, d, ctx, entry.ID); n != 1 {
		t.Fatalf("approvals %d", n)
	}
	same, sameHash, sameDisplay := catalogSpec(t, "pnpm run dev")
	if _, _, err := d.ReplaceCatalogEntry(ctx, home.ID, "webapp", store.CatalogWrite{
		Spec: same, SpecHash: sameHash, CommandDisplay: sameDisplay, Actor: owner.ID, At: at,
	}); err != nil {
		t.Fatal(err)
	}
	if n := catalogApprovalCount(t, d, ctx, entry.ID); n != 1 {
		t.Fatalf("same hash voided approvals: %d", n)
	}
	next, nextHash, nextDisplay := catalogSpec(t, "pnpm run start")
	if nextHash == hash {
		t.Fatal("replacement hash did not change")
	}
	if _, _, err := d.ReplaceCatalogEntry(ctx, home.ID, "webapp", store.CatalogWrite{
		Spec: next, SpecHash: nextHash, CommandDisplay: nextDisplay, Actor: owner.ID, At: at,
	}); err != nil {
		t.Fatal(err)
	}
	if n := catalogApprovalCount(t, d, ctx, entry.ID); n != 0 {
		t.Fatalf("changed hash left %d approvals", n)
	}

	body := []byte(`{"code":"ok","msg":"ok","payload":null}`)
	sum := bytes32(1)
	rec := store.IdempotencyRecord{RequestHash: sum[:], Status: 200, Body: body, CreatedAt: at}
	if err := d.PutIdempotency(ctx, owner.ID, "cat-key", rec); err != nil {
		t.Fatal(err)
	}
	if err := d.PutIdempotency(ctx, owner.ID, "cat-key", rec); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate idempotency %v", err)
	}
	got, err := d.GetIdempotency(ctx, owner.ID, "cat-key", at.Add(23*time.Hour))
	if err != nil || got.Status != 200 || !sameJSON(got.Body, body) {
		t.Fatalf("idempotency %+v %v", got, err)
	}
	replaced := []byte(`{"code":"ok","msg":"ok","payload":{"unit":"u"}}`)
	if err := d.ReplaceIdempotencyResponse(ctx, owner.ID, "cat-key", 201, replaced); err != nil {
		t.Fatal(err)
	}
	got, err = d.GetIdempotency(ctx, owner.ID, "cat-key", at.Add(23*time.Hour))
	if err != nil || got.Status != 201 || !sameJSON(got.Body, replaced) {
		t.Fatalf("replaced %+v %v", got, err)
	}
	if _, err := d.GetIdempotency(ctx, owner.ID, "cat-key", at.Add(store.IdempotencyTTL)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired idempotency %v", err)
	}
	sumA := bytes32(9)
	claimedRec, claimed, err := d.ClaimIdempotency(ctx, other.ID, "claim-key", sumA[:], at)
	if err != nil || !claimed || !claimedRec.Pending {
		t.Fatalf("claim %+v %v %v", claimedRec, claimed, err)
	}
	if _, _, err := d.ClaimIdempotency(ctx, other.ID, "claim-key", sumA[:], at); !errors.Is(err, store.ErrPending) {
		t.Fatalf("in progress %v", err)
	}
	sumB := bytes32(8)
	if _, _, err := d.ClaimIdempotency(ctx, other.ID, "claim-key", sumB[:], at); !errors.Is(err, store.ErrPending) {
		t.Fatalf("in progress other hash %v", err)
	}
	failed := []byte(`{"code":"error","msg":"start_failed","payload":null}`)
	if err := d.ReplaceIdempotencyResponse(ctx, other.ID, "claim-key", 500, failed); err != nil {
		t.Fatal(err)
	}
	got, claimed, err = d.ClaimIdempotency(ctx, other.ID, "claim-key", sumA[:], at.Add(6*time.Minute))
	if err != nil || claimed || got.Pending || got.Status != 500 || !sameJSON(got.Body, failed) {
		t.Fatalf("stored error %+v %v %v", got, claimed, err)
	}
	if _, _, err := d.ClaimIdempotency(ctx, other.ID, "claim-key", sumB[:], at); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("different request %v", err)
	}
	if _, claimed, err := d.ClaimIdempotency(ctx, owner.ID, "claim-key", sumA[:], at); err != nil || !claimed {
		t.Fatalf("other user %v %v", claimed, err)
	}

	plain, tokenHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	req := bytes32(2)
	conf := store.CatalogConfirmation{
		UserID: owner.ID, ProjectID: home.ID, EntryID: entry.ID, EntryName: "webapp", HostID: host.ID,
		Action: "run", SpecHash: nextHash, IdempotencyKey: "cat-key", RequestHash: req[:],
		CreatedAt: at, ExpiresAt: at.Add(store.ConfirmationTTL),
	}
	if err := d.PutConfirmation(ctx, tokenHash, conf); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := d.pool.QueryRow(ctx, `SELECT token_hash FROM app.catalog_confirmations WHERE entry_id = $1::uuid`, entry.ID.String()).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if string(stored) == plain || !secret.Equal(stored, tokenHash) {
		t.Fatal("confirmation token is not stored as its hash")
	}
	if err := d.MarkConfirmationUsed(ctx, tokenHash, owner.ID, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	row, err := d.GetConfirmation(ctx, tokenHash)
	if err != nil || row.UsedAt == nil {
		t.Fatalf("used confirmation %+v %v", row, err)
	}
	if err := d.MarkConfirmationUsed(ctx, tokenHash, owner.ID, at.Add(2*time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second use %v", err)
	}
	expiredHash := bytes32(3)
	conf.ExpiresAt = at
	conf.IdempotencyKey = "cat-expired"
	if err := d.PutConfirmation(ctx, expiredHash[:], conf); err != nil {
		t.Fatal(err)
	}
	if err := d.MarkConfirmationUsed(ctx, expiredHash[:], owner.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired confirmation %v", err)
	}

	programs := &store.HostPrograms{Enabled: true, RunAs: []string{"joe"}, AllowShell: false, PolicyHash: "abc"}
	if err := d.SetHostPrograms(ctx, host.ID, programs); err != nil {
		t.Fatal(err)
	}
	loaded, err := d.GetHost(ctx, host.ID)
	if err != nil || loaded.Programs == nil || !loaded.Programs.Enabled || len(loaded.Programs.RunAs) != 1 || loaded.Programs.RunAs[0] != "joe" {
		t.Fatalf("programs %+v %v", loaded.Programs, err)
	}
	if err := d.SetHostPrograms(ctx, host.ID, nil); err != nil {
		t.Fatal(err)
	}
	loaded, err = d.GetHost(ctx, host.ID)
	if err != nil || loaded.Programs != nil {
		t.Fatalf("cleared programs %+v %v", loaded.Programs, err)
	}

	unit := "deploybot-missing-nope.service"
	scope := "system"
	if err := d.UpsertDiscovered(ctx, host.ID, []store.Discovered{{
		Name: "not-the-entry", Kind: "systemd", Ports: []int{3031},
		SystemdUnit: &unit, SystemdScope: &scope,
		Owner: &store.DiscoveredOwner{Kind: "program", Project: "catproj", Entry: "webapp"},
	}}, at); err != nil {
		t.Fatal(err)
	}
	owned := catalogService(t, d, ctx, host.ID, "webapp", at)
	if owned.Source != "owned" || owned.ProjectID != home.ID || owned.CatalogEntry == nil || *owned.CatalogEntry != "webapp" {
		t.Fatalf("owned %+v", owned)
	}
	if err := d.UpsertDiscovered(ctx, host.ID, []store.Discovered{{
		Name: "other", Kind: "systemd", Ports: []int{9},
		SystemdUnit: &unit, SystemdScope: &scope,
		Owner: &store.DiscoveredOwner{Kind: "program", Project: "missing", Entry: "nope"},
	}}, at); err != nil {
		t.Fatal(err)
	}
	miss := catalogService(t, d, ctx, host.ID, unit, at)
	if miss.Source != "discovered" || miss.ProjectID != box.ID || miss.CatalogEntry != nil {
		t.Fatalf("fallback %+v", miss)
	}
	absent := "deploybot-catproj-absent.service"
	if err := d.UpsertDiscovered(ctx, host.ID, []store.Discovered{{
		Name: "reported", Kind: "systemd", Ports: []int{4},
		SystemdUnit: &absent, SystemdScope: &scope,
		Owner: &store.DiscoveredOwner{Kind: "program", Project: "catproj", Entry: "no-such"},
	}}, at); err != nil {
		t.Fatal(err)
	}
	wrong := catalogService(t, d, ctx, host.ID, absent, at)
	if wrong.Source != "discovered" || wrong.ProjectID != box.ID || wrong.CatalogEntry != nil {
		t.Fatalf("wrong entry %+v", wrong)
	}
}

func assertCatalogSchema(t *testing.T, d *DB, ctx context.Context) {
	t.Helper()
	var programs, entry string
	if err := d.pool.QueryRow(ctx, `
SELECT data_type FROM information_schema.columns
WHERE table_schema = 'app' AND table_name = 'hosts' AND column_name = 'programs'
`).Scan(&programs); err != nil || programs != "jsonb" {
		t.Fatalf("hosts.programs %s %v", programs, err)
	}
	if err := d.pool.QueryRow(ctx, `
SELECT data_type FROM information_schema.columns
WHERE table_schema = 'app' AND table_name = 'services' AND column_name = 'catalog_entry'
`).Scan(&entry); err != nil || entry != "text" {
		t.Fatalf("services.catalog_entry %s %v", entry, err)
	}
	var kindCheck string
	if err := d.pool.QueryRow(ctx, `
SELECT pg_get_constraintdef(oid) FROM pg_constraint
WHERE conname = 'catalog_entries_kind_chk'
`).Scan(&kindCheck); err != nil || !strings.Contains(kindCheck, "program") {
		t.Fatalf("kind check %s %v", kindCheck, err)
	}
	assertTablePrivs(t, d, ctx, "catalog_entries", true, true, false, true, []string{"spec", "spec_hash", "command_display", "updated_at"})
	assertTablePrivs(t, d, ctx, "catalog_grants", true, true, false, true, nil)
	assertTablePrivs(t, d, ctx, "catalog_host_approvals", true, true, false, true, []string{"spec_hash", "status", "requested_by", "requested_at", "approved_by", "approved_at"})
	assertTablePrivs(t, d, ctx, "catalog_confirmations", true, true, false, true, []string{"used_at"})
	assertTablePrivs(t, d, ctx, "idempotency_keys", true, true, false, true, []string{"status_code", "response"})
	var statusNull, responseNull string
	if err := d.pool.QueryRow(ctx, `
SELECT is_nullable FROM information_schema.columns
WHERE table_schema = 'app' AND table_name = 'idempotency_keys' AND column_name = 'status_code'
`).Scan(&statusNull); err != nil || statusNull != "YES" {
		t.Fatalf("status_code nullable %s %v", statusNull, err)
	}
	if err := d.pool.QueryRow(ctx, `
SELECT is_nullable FROM information_schema.columns
WHERE table_schema = 'app' AND table_name = 'idempotency_keys' AND column_name = 'response'
`).Scan(&responseNull); err != nil || responseNull != "YES" {
		t.Fatalf("response nullable %s %v", responseNull, err)
	}
}

func assertTablePrivs(t *testing.T, d *DB, ctx context.Context, table string, sel, ins, upd, del bool, updateCols []string) {
	t.Helper()
	var gotSel, gotIns, gotUpd, gotDel bool
	q := `
SELECT has_table_privilege('deploybot_api', 'app.` + table + `', 'SELECT'),
       has_table_privilege('deploybot_api', 'app.` + table + `', 'INSERT'),
       has_table_privilege('deploybot_api', 'app.` + table + `', 'UPDATE'),
       has_table_privilege('deploybot_api', 'app.` + table + `', 'DELETE')`
	if err := d.pool.QueryRow(ctx, q).Scan(&gotSel, &gotIns, &gotUpd, &gotDel); err != nil {
		t.Fatal(err)
	}
	if gotSel != sel || gotIns != ins || gotUpd != upd || gotDel != del {
		t.Fatalf("%s privileges sel=%v ins=%v upd=%v del=%v", table, gotSel, gotIns, gotUpd, gotDel)
	}
	rows, err := d.pool.Query(ctx, `
SELECT column_name FROM information_schema.column_privileges
WHERE grantee = 'deploybot_api' AND table_schema = 'app' AND table_name = $1 AND privilege_type = 'UPDATE'
`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		got[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(updateCols) {
		t.Fatalf("%s update columns %v", table, got)
	}
	for _, name := range updateCols {
		if !got[name] {
			t.Fatalf("%s missing update on %s (%v)", table, name, got)
		}
	}
}

func catalogUser(t *testing.T, d *DB, ctx context.Context, subject string, at time.Time) store.User {
	t.Helper()
	user, err := d.UpsertGoogleUser(ctx, store.GoogleSignIn{Subject: subject, Email: subject + "@example.com", Name: subject, At: at})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func catalogProject(t *testing.T, d *DB, ctx context.Context, owner uuid.UUID, name, slug string, at time.Time) store.Project {
	t.Helper()
	project, err := d.CreateProject(ctx, owner, name, slug, at)
	if err != nil {
		t.Fatal(err)
	}
	return project
}

func catalogSpec(t *testing.T, command string) (store.ProgramSpec, string, string) {
	t.Helper()
	p, err := catalog.BuildProgram(catalog.ProgramInput{Command: command, Dir: "/home/joe/app", RunAs: "joe"})
	if err != nil {
		t.Fatal(err)
	}
	return store.ProgramSpec{
		Dir: p.Dir, Exec: p.Exec, Args: append([]string{}, p.Args...), Shell: p.Shell,
		RunAs: p.RunAs, Env: p.Env, Port: p.Port, Restart: p.Restart,
	}, catalog.SpecHash(p), p.Display
}

func catalogApprovalCount(t *testing.T, d *DB, ctx context.Context, entryID uuid.UUID) int {
	t.Helper()
	var n int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM app.catalog_host_approvals WHERE entry_id = $1::uuid`, entryID.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func catalogService(t *testing.T, d *DB, ctx context.Context, hostID uuid.UUID, name string, at time.Time) store.Service {
	t.Helper()
	items, err := d.ListServices(ctx, hostID, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.Name == name {
			return item
		}
	}
	t.Fatalf("service %s missing", name)
	return store.Service{}
}

func grantIs(grants []store.CatalogGrant, subject string, actions ...string) bool {
	for _, g := range grants {
		if g.Subject != subject || len(g.Actions) != len(actions) {
			continue
		}
		ok := true
		for i := range actions {
			if g.Actions[i] != actions[i] {
				ok = false
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func bytes32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

// sameJSON compares JSON by value: jsonb normalises key order and spacing.
func sameJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}
