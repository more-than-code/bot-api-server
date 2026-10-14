// Package migrations holds the numbered SQL files embedded for --migrate.
// roles.sql.example is not embedded and is never applied automatically.
// Files named *.down.sql are embedded so the rollback stays next to the
// migration, and db.Migrate skips them.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
