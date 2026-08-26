// Package migrations embeds the SQL schema so that a deployment carries its own
// migrations inside the binary. RF-10 asks for installation in a single
// command: applying the schema has to be something the engine does at startup,
// not a step an operator remembers to run.
package migrations

import (
	"embed"
	"io/fs"
)

//go:embed postgres/*.sql
var files embed.FS

// Postgres returns the PostgreSQL migrations, rooted so that entries are named
// "001_audit_log.sql" rather than "postgres/001_audit_log.sql".
func Postgres() fs.FS {
	sub, err := fs.Sub(files, "postgres")
	if err != nil {
		// Unreachable: the directory is embedded at compile time.
		panic("migrations: " + err.Error())
	}
	return sub
}
