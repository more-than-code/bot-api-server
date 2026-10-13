package db

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/more-than-code/bot-api-server/migrations"
)

// Migrate applies embedded SQL files in lexical order using databaseURL.
// It is the only path that runs DDL. A normal server start does not call it.
// The caller is deploybot_migrator. SET ROLE deploybot_owner runs first, so
// new objects are owned by that role. roles.sql.example must already have
// created the role, the schemas, and the timescaledb extension.
func Migrate(ctx context.Context, databaseURL string) error {
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("migrate: connect failed")
	}
	defer conn.Close(ctx)

	if _, err := conn.Exec(ctx, `SET ROLE deploybot_owner`); err != nil {
		return fmt.Errorf("migrate: SET ROLE deploybot_owner failed; run migrations/roles.sql.example as superuser first")
	}
	var ext int
	if err := conn.QueryRow(ctx, `SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'`).Scan(&ext); err != nil {
		return fmt.Errorf("migrate: timescaledb extension is not installed; run migrations/roles.sql.example as superuser first")
	}

	applied, err := appliedNames(ctx, conn)
	if err != nil {
		return err
	}
	names, err := migrationFiles()
	if err != nil {
		return err
	}
	for _, name := range names {
		if applied[name] {
			continue
		}
		body, err := migrations.FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("migrate: read %s", name)
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("migrate: begin %s", name)
		}
		for _, stmt := range splitSQL(string(body)) {
			if err := applyStmt(ctx, tx, stmt); err != nil {
				_ = tx.Rollback(ctx)
				return fmt.Errorf("migrate: %s: %v", name, scrub(err))
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO app.schema_migrations (name) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migrate: record %s", name)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("migrate: commit %s", name)
		}
	}
	return nil
}

// applyStmt runs one migration statement. SELECT statements (Timescale helpers
// that return a row) are queried and drained. Everything else is Exec.
func applyStmt(ctx context.Context, tx pgx.Tx, stmt string) error {
	if leadingSelect(stmt) {
		rows, err := tx.Query(ctx, stmt)
		if err != nil {
			return err
		}
		rows.Close()
		return rows.Err()
	}
	_, err := tx.Exec(ctx, stmt)
	return err
}

func leadingSelect(stmt string) bool {
	s := strings.TrimSpace(stmt)
	for strings.HasPrefix(s, "--") {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			return false
		}
		s = strings.TrimSpace(s[i+1:])
	}
	return len(s) >= 6 && strings.EqualFold(s[:6], "select")
}

func appliedNames(ctx context.Context, conn *pgx.Conn) (map[string]bool, error) {
	out := map[string]bool{}
	var reg *string
	if err := conn.QueryRow(ctx, `SELECT to_regclass('app.schema_migrations')::text`).Scan(&reg); err != nil {
		return nil, fmt.Errorf("migrate: schema lookup failed")
	}
	if reg == nil || *reg == "" {
		return out, nil
	}
	rows, err := conn.Query(ctx, `SELECT name FROM app.schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("migrate: list applied failed")
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("migrate: scan applied failed")
		}
		out[name] = true
	}
	return out, rows.Err()
}

func migrationFiles() ([]string, error) {
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("migrate: read dir")
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if !numberedSQL(name) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func numberedSQL(name string) bool {
	if !strings.HasSuffix(name, ".sql") || len(name) < 5 {
		return false
	}
	i := 0
	for i < len(name) && unicode.IsDigit(rune(name[i])) {
		i++
	}
	return i > 0 && name[i] == '_'
}

// splitSQL splits a migration file on semicolons that are not inside quotes.
func splitSQL(sql string) []string {
	var stmts []string
	var b strings.Builder
	inSingle := false
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		if c == '\'' {
			if inSingle && i+1 < len(sql) && sql[i+1] == '\'' {
				b.WriteString("''")
				i++
				continue
			}
			inSingle = !inSingle
			b.WriteByte(c)
			continue
		}
		if c == ';' && !inSingle {
			if s := strings.TrimSpace(b.String()); meaningfulSQL(s) {
				stmts = append(stmts, s)
			}
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	if s := strings.TrimSpace(b.String()); meaningfulSQL(s) {
		stmts = append(stmts, s)
	}
	return stmts
}

func meaningfulSQL(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t != "" && !strings.HasPrefix(t, "--") {
			return true
		}
	}
	return false
}
