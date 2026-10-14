package db

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/more-than-code/bot-api-server/internal/secret"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// assertInvites checks migration 0006: table shape, grants, both delete
// paths, the concurrent accept cap, and accept when the user is already
// a member. TestIntegration calls it.
func assertInvites(t *testing.T, d *DB, ctx context.Context) {
	t.Helper()
	assertInviteSchema(t, d, ctx)

	at := time.Now().UTC().Truncate(time.Microsecond)
	owner := inviteUser(t, d, ctx, "invite-owner", at)
	project, err := d.CreateProject(ctx, owner.ID, "Invites", "invites", at)
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	plain, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	inv, err := d.CreateInvite(ctx, project.ID, hash, "viewer", owner.ID, at.Add(time.Hour), at, 1)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var stored []byte
	if err := d.pool.QueryRow(ctx, `SELECT token_hash FROM app.invites WHERE id = $1::uuid`, inv.ID.String()).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, secret.Hash(plain)) || bytes.Equal(stored, []byte(plain)) || len(stored) != 32 {
		t.Fatal("token_hash is not the SHA-256 of the plaintext")
	}
	assertInviteChecks(t, d, ctx, project.ID, owner.ID, at)

	otherOwner := inviteUser(t, d, ctx, "invite-other", at)
	other, err := d.CreateProject(ctx, otherOwner.ID, "Other", "invite-other", at)
	if err != nil {
		t.Fatalf("other project: %v", err)
	}
	_, otherHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateInvite(ctx, other.ID, otherHash, "admin", otherOwner.ID, at.Add(time.Hour), at, 1); err != nil {
		t.Fatalf("other invite: %v", err)
	}
	if _, err := d.DeleteProject(ctx, project.ID, at); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if n := inviteCount(t, d, ctx, project.ID); n != 0 {
		t.Fatalf("soft delete left %d invites", n)
	}
	if n := inviteCount(t, d, ctx, other.ID); n != 1 {
		t.Fatalf("other project invites = %d", n)
	}

	hard := inviteUser(t, d, ctx, "invite-hard", at)
	hardProject, err := d.CreateProject(ctx, hard.ID, "Hard", "invite-hard", at)
	if err != nil {
		t.Fatalf("hard project: %v", err)
	}
	_, hardHash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateInvite(ctx, hardProject.ID, hardHash, "viewer", hard.ID, at.Add(time.Hour), at, 1); err != nil {
		t.Fatalf("hard invite: %v", err)
	}
	if _, err := d.pool.Exec(ctx, `DELETE FROM app.project_members WHERE project_id = $1::uuid`, hardProject.ID.String()); err != nil {
		t.Fatalf("delete members: %v", err)
	}
	if _, err := d.pool.Exec(ctx, `DELETE FROM app.projects WHERE id = $1::uuid`, hardProject.ID.String()); err != nil {
		t.Fatalf("hard delete did not cascade: %v", err)
	}
	if n := inviteCount(t, d, ctx, hardProject.ID); n != 0 {
		t.Fatalf("hard delete left %d invites", n)
	}

	assertInviteAcceptCap(t, d, ctx, at)
	assertInviteAcceptExistingMember(t, d, ctx, at)
	assertInviteAcceptConflictingMember(t, d, ctx, at)
}

func assertInviteSchema(t *testing.T, d *DB, ctx context.Context) {
	t.Helper()
	type col struct{ null, def string }
	cols := map[string]col{}
	rows, err := d.pool.Query(ctx, `
SELECT column_name, is_nullable, COALESCE(column_default, '')
FROM information_schema.columns
WHERE table_schema = 'app' AND table_name = 'invites'
`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name, nulls, def string
		if err := rows.Scan(&name, &nulls, &def); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		cols[name] = col{null: nulls, def: def}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	want := []string{"id", "project_id", "token_hash", "role", "created_by", "created_at", "expires_at", "max_uses", "uses", "revoked_at"}
	if len(cols) != len(want) {
		t.Fatalf("columns = %v", cols)
	}
	for _, name := range want {
		c, ok := cols[name]
		if !ok {
			t.Fatalf("missing %s", name)
		}
		nullable := "NO"
		if name == "revoked_at" {
			nullable = "YES"
		}
		if c.null != nullable {
			t.Fatalf("%s nullable %s", name, c.null)
		}
	}
	if !strings.Contains(cols["id"].def, "gen_random_uuid()") {
		t.Fatalf("id default %q", cols["id"].def)
	}
	if strings.TrimSpace(cols["uses"].def) != "0" {
		t.Fatalf("uses default %q", cols["uses"].def)
	}

	defs := map[string]string{}
	rows, err = d.pool.Query(ctx, `
SELECT conname, pg_get_constraintdef(oid)
FROM pg_constraint
WHERE conrelid = 'app.invites'::regclass
`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name, def string
		if err := rows.Scan(&name, &def); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		defs[name] = def
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	for _, name := range []string{"invites_role_chk", "invites_max_uses_chk", "invites_uses_chk", "invites_hash_len", "invites_hash_unique", "invites_project_fk", "invites_created_by_fk"} {
		if defs[name] == "" {
			t.Fatalf("missing constraint %s in %v", name, defs)
		}
	}
	if !strings.Contains(defs["invites_role_chk"], "admin") || !strings.Contains(defs["invites_role_chk"], "viewer") {
		t.Fatalf("role check %s", defs["invites_role_chk"])
	}
	if !strings.Contains(defs["invites_max_uses_chk"], "1") || !strings.Contains(defs["invites_max_uses_chk"], "50") {
		t.Fatalf("max_uses check %s", defs["invites_max_uses_chk"])
	}
	if !strings.Contains(defs["invites_uses_chk"], "0") || !strings.Contains(defs["invites_uses_chk"], "max_uses") {
		t.Fatalf("uses check %s", defs["invites_uses_chk"])
	}
	if !strings.Contains(defs["invites_hash_len"], "32") {
		t.Fatalf("hash len %s", defs["invites_hash_len"])
	}
	if !strings.Contains(defs["invites_project_fk"], "ON DELETE CASCADE") {
		t.Fatalf("project fk %s", defs["invites_project_fk"])
	}
	var deltype string
	if err := d.pool.QueryRow(ctx, `SELECT confdeltype::text FROM pg_constraint WHERE conname = 'invites_project_fk'`).Scan(&deltype); err != nil {
		t.Fatal(err)
	}
	if deltype != "c" {
		t.Fatalf("confdeltype %s", deltype)
	}
	var indexdef string
	if err := d.pool.QueryRow(ctx, `
SELECT indexdef FROM pg_indexes
WHERE schemaname = 'app' AND indexname = 'invites_project_idx'
`).Scan(&indexdef); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(indexdef, "(project_id)") {
		t.Fatalf("index %s", indexdef)
	}

	privs := map[string]bool{}
	rows, err = d.pool.Query(ctx, `
SELECT privilege_type FROM information_schema.role_table_grants
WHERE grantee = 'deploybot_api' AND table_schema = 'app' AND table_name = 'invites'
`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var priv string
		if err := rows.Scan(&priv); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		privs[priv] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	if len(privs) != 2 || !privs["SELECT"] || !privs["INSERT"] {
		t.Fatalf("table grants %v", privs)
	}
	var acl string
	if err := d.pool.QueryRow(ctx, `
SELECT COALESCE(c.relacl::text, '')
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'app' AND c.relname = 'invites'
`).Scan(&acl); err != nil {
		t.Fatal(err)
	}
	var tableSelect, tableInsert, tableUpdate, tableDelete bool
	var usesUpdate, revokedUpdate, roleUpdate, hashUpdate, maxUpdate bool
	if err := d.pool.QueryRow(ctx, `
SELECT has_table_privilege('deploybot_api', 'app.invites', 'SELECT'),
       has_table_privilege('deploybot_api', 'app.invites', 'INSERT'),
       has_table_privilege('deploybot_api', 'app.invites', 'UPDATE'),
       has_table_privilege('deploybot_api', 'app.invites', 'DELETE'),
       has_column_privilege('deploybot_api', 'app.invites', 'uses', 'UPDATE'),
       has_column_privilege('deploybot_api', 'app.invites', 'revoked_at', 'UPDATE'),
       has_column_privilege('deploybot_api', 'app.invites', 'role', 'UPDATE'),
       has_column_privilege('deploybot_api', 'app.invites', 'token_hash', 'UPDATE'),
       has_column_privilege('deploybot_api', 'app.invites', 'max_uses', 'UPDATE')
`).Scan(&tableSelect, &tableInsert, &tableUpdate, &tableDelete, &usesUpdate, &revokedUpdate, &roleUpdate, &hashUpdate, &maxUpdate); err != nil {
		t.Fatal(err)
	}
	if !tableSelect || !tableInsert || tableUpdate || tableDelete || !usesUpdate || !revokedUpdate || roleUpdate || hashUpdate || maxUpdate {
		t.Fatalf("privileges select=%v insert=%v update=%v delete=%v uses=%v revoked=%v role=%v hash=%v max=%v acl=%s",
			tableSelect, tableInsert, tableUpdate, tableDelete, usesUpdate, revokedUpdate, roleUpdate, hashUpdate, maxUpdate, acl)
	}
	updated := map[string]bool{}
	rows, err = d.pool.Query(ctx, `
SELECT column_name FROM information_schema.column_privileges
WHERE grantee = 'deploybot_api' AND table_schema = 'app' AND table_name = 'invites' AND privilege_type = 'UPDATE'
`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		updated[name] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	if len(updated) != 2 || !updated["uses"] || !updated["revoked_at"] {
		t.Fatalf("column UPDATE %v", updated)
	}

	var definer bool
	var config []string
	if err := d.pool.QueryRow(ctx, `
SELECT p.prosecdef, p.proconfig
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'app' AND p.proname = 'invites_delete_for_project'
`).Scan(&definer, &config); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(config, ",")
	if !definer || (!strings.Contains(joined, "search_path=pg_catalog, app") && !strings.Contains(joined, "search_path=pg_catalog,app")) {
		t.Fatalf("function definer=%v config=%v", definer, config)
	}
	var apiExec, publicExec bool
	rows, err = d.pool.Query(ctx, `
SELECT grantee FROM information_schema.routine_privileges
WHERE routine_schema = 'app' AND routine_name = 'invites_delete_for_project' AND privilege_type = 'EXECUTE'
`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var grantee string
		if err := rows.Scan(&grantee); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		switch grantee {
		case "deploybot_api":
			apiExec = true
		case "PUBLIC":
			publicExec = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	if !apiExec || publicExec {
		t.Fatalf("function execute api=%v public=%v", apiExec, publicExec)
	}
	var hasExec bool
	if err := d.pool.QueryRow(ctx, `
SELECT has_function_privilege('deploybot_api', 'app.invites_delete_for_project(uuid)', 'EXECUTE')
`).Scan(&hasExec); err != nil {
		t.Fatal(err)
	}
	if !hasExec {
		t.Fatal("deploybot_api cannot execute invites_delete_for_project")
	}
}

func assertInviteChecks(t *testing.T, d *DB, ctx context.Context, projectID, userID uuid.UUID, at time.Time) {
	t.Helper()
	hash := bytes.Repeat([]byte{1}, 32)
	cases := []struct {
		role string
		max  int
		uses int
	}{
		{role: "owner", max: 1, uses: 0},
		{role: "viewer", max: 51, uses: 0},
		{role: "viewer", max: 1, uses: 2},
	}
	for _, tc := range cases {
		tx, err := d.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `
INSERT INTO app.invites (
    id, project_id, token_hash, role, created_by, created_at, expires_at, max_uses, uses
) VALUES ($1::uuid, $2::uuid, $3, $4, $5::uuid, $6, $7, $8, $9)
`, uuid.New().String(), projectID.String(), hash, tc.role, userID.String(), at, at.Add(time.Hour), tc.max, tc.uses)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "23514" {
			tx.Rollback(ctx)
			t.Fatalf("check role=%s max=%d uses=%d: %v", tc.role, tc.max, tc.uses, err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func assertInviteAcceptCap(t *testing.T, d *DB, ctx context.Context, at time.Time) {
	t.Helper()
	const n = 5
	const extra = 5
	owner := inviteUser(t, d, ctx, "invite-cap-owner", at)
	project, err := d.CreateProject(ctx, owner.ID, "Cap", "invite-cap", at)
	if err != nil {
		t.Fatal(err)
	}
	_, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	inv, err := d.CreateInvite(ctx, project.ID, hash, "viewer", owner.ID, at.Add(time.Hour), at, n)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]uuid.UUID, n+extra)
	for i := range ids {
		ids[i] = inviteUser(t, d, ctx, "invite-cap-"+strconv.Itoa(i), at).ID
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	okN, miss := 0, 0
	var bad []string
	wg.Add(len(ids))
	for _, id := range ids {
		go func(userID uuid.UUID) {
			defer wg.Done()
			<-start
			res, err := d.AcceptInvite(ctx, hash, userID, at)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				okN++
				if res.Role != "viewer" || res.InviteID != inv.ID {
					bad = append(bad, "wrong result")
				}
			case errors.Is(err, store.ErrNotFound):
				miss++
			default:
				bad = append(bad, err.Error())
			}
		}(id)
	}
	close(start)
	wg.Wait()
	if len(bad) > 0 || okN != n || miss != extra {
		t.Fatalf("cap ok=%d miss=%d bad=%v", okN, miss, bad)
	}
	var uses int
	if err := d.pool.QueryRow(ctx, `SELECT uses FROM app.invites WHERE id = $1::uuid`, inv.ID.String()).Scan(&uses); err != nil {
		t.Fatal(err)
	}
	if uses != n {
		t.Fatalf("uses %d", uses)
	}
	var viewers int
	if err := d.pool.QueryRow(ctx, `
SELECT count(*) FROM app.project_members
WHERE project_id = $1::uuid AND role = 'viewer'
`, project.ID.String()).Scan(&viewers); err != nil {
		t.Fatal(err)
	}
	if viewers != n {
		t.Fatalf("viewers %d", viewers)
	}
}

// assertInviteAcceptExistingMember covers the accept that finds a member
// before inserting one. The invite grants viewer; the member is already
// an admin. The result carries that role, and the database keeps uses at
// 0 and the membership role at admin.
func assertInviteAcceptExistingMember(t *testing.T, d *DB, ctx context.Context, at time.Time) {
	t.Helper()
	owner, project, member, inv, hash := inviteMemberFixture(t, d, ctx, "invite-kept", at)
	if _, err := d.AddMember(ctx, project.ID, member.ID, "admin", owner.ID, at); err != nil {
		t.Fatal(err)
	}
	got, err := d.AcceptInvite(ctx, hash, member.ID, at)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	assertInviteKeptAdmin(t, d, ctx, inv, project.ID, member.ID, got)
}

// assertInviteAcceptConflictingMember covers the accept whose membership
// insert conflicts. AcceptInvite looks up the member, then checks that the
// user exists, then inserts. This holds AccessExclusive on app.users so the
// existence check waits, and it does not insert the admin row until pg_locks
// shows that wait. The lookup has already finished by then, so its snapshot
// has no membership. Committing the admin row makes the insert conflict.
// The result is the current admin role, uses stays 0, and the membership
// stays admin. Without ON CONFLICT DO NOTHING the insert is a unique violation.
func assertInviteAcceptConflictingMember(t *testing.T, d *DB, ctx context.Context, at time.Time) {
	t.Helper()
	owner, project, member, inv, hash := inviteMemberFixture(t, d, ctx, "invite-race", at)

	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE deploybot_owner`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE app.users IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '0'`); err != nil {
		t.Fatal(err)
	}

	done := make(chan acceptResult, 1)
	go func() {
		got, err := d.AcceptInvite(ctx, hash, member.ID, at)
		done <- acceptResult{got: got, err: err}
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case res := <-done:
			t.Fatalf("accept returned before the user lookup blocked: %+v err=%v", res.got, res.err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for AcceptInvite to block on app.users")
		}
		waiting, err := userLookupWaiting(ctx, tx)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if _, err := tx.Exec(ctx, `
INSERT INTO app.project_members (project_id, user_id, role, added_by, created_at)
VALUES ($1::uuid, $2::uuid, 'admin', $3::uuid, $4)
`, project.ID.String(), member.ID.String(), owner.ID.String(), at); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("accept: %v", res.err)
		}
		assertInviteKeptAdmin(t, d, ctx, inv, project.ID, member.ID, res.got)
	case <-time.After(5 * time.Second):
		t.Fatal("accept did not finish after the member row was committed")
	}
}

type acceptResult struct {
	got store.InviteAccept
	err error
}

func inviteMemberFixture(t *testing.T, d *DB, ctx context.Context, slug string, at time.Time) (store.User, store.Project, store.User, store.Invite, []byte) {
	t.Helper()
	owner := inviteUser(t, d, ctx, slug+"-owner", at)
	project, err := d.CreateProject(ctx, owner.ID, slug, slug, at)
	if err != nil {
		t.Fatal(err)
	}
	member := inviteUser(t, d, ctx, slug+"-member", at)
	_, hash, err := secret.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	inv, err := d.CreateInvite(ctx, project.ID, hash, "viewer", owner.ID, at.Add(time.Hour), at, 1)
	if err != nil {
		t.Fatal(err)
	}
	return owner, project, member, inv, hash
}

func assertInviteKeptAdmin(t *testing.T, d *DB, ctx context.Context, inv store.Invite, projectID, userID uuid.UUID, got store.InviteAccept) {
	t.Helper()
	if got.InviteID != inv.ID || got.ProjectID != projectID || got.Role != "admin" {
		t.Fatalf("accept %+v", got)
	}
	var uses int
	var role string
	if err := d.pool.QueryRow(ctx, `SELECT uses, role FROM app.invites WHERE id = $1::uuid`, inv.ID.String()).Scan(&uses, &role); err != nil {
		t.Fatal(err)
	}
	if uses != 0 || role != "viewer" {
		t.Fatalf("invite uses=%d role=%s", uses, role)
	}
	if err := d.pool.QueryRow(ctx, `
SELECT role FROM app.project_members WHERE project_id = $1::uuid AND user_id = $2::uuid
`, projectID.String(), userID.String()).Scan(&role); err != nil {
		t.Fatal(err)
	}
	if role != "admin" {
		t.Fatalf("member role %s", role)
	}
}

func userLookupWaiting(ctx context.Context, tx pgx.Tx) (bool, error) {
	var waiting bool
	err := tx.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1 FROM pg_locks
    WHERE locktype = 'relation'
      AND relation = 'app.users'::regclass
      AND mode = 'AccessShareLock'
      AND NOT granted
      AND pid IS DISTINCT FROM pg_backend_pid()
)
`).Scan(&waiting)
	return waiting, err
}

func inviteCount(t *testing.T, d *DB, ctx context.Context, projectID uuid.UUID) int {
	t.Helper()
	var n int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM app.invites WHERE project_id = $1::uuid`, projectID.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func inviteUser(t *testing.T, d *DB, ctx context.Context, subject string, at time.Time) store.User {
	t.Helper()
	u, err := d.UpsertGoogleUser(ctx, store.GoogleSignIn{
		Subject: subject,
		Email:   subject + "@example.com",
		Name:    subject,
		At:      at,
	})
	if err != nil {
		t.Fatal(err)
	}
	return u
}
