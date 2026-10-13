// Package migrations holds the numbered SQL files embedded for --migrate.
// roles.sql.example is not embedded and is never applied automatically.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
