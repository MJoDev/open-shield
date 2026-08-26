// Package migrate applies embedded SQL migrations at startup.
//
// It is deliberately small — a versions table, a lock and a loop — rather than
// a migration framework. The schema of this system is a handful of files, and a
// dependency that has to be installed separately would work against the
// single-command installation of RF-10.
package migrate

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// advisoryLockKey serialises migrations across processes. Two engine containers
// starting at once would otherwise both try to create the same objects.
const advisoryLockKey int64 = 7_301_562_004

// Apply runs every migration in src that has not been applied yet, in filename
// order, each one inside its own transaction.
func Apply(ctx context.Context, pool *pgxpool.Pool, src fs.FS, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("migrate: acquire connection: %w", err)
	}
	defer conn.Release()

	// A session-level lock held for the duration of the run. Other instances
	// block here and then find every migration already applied.
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, advisoryLockKey); err != nil {
		return fmt.Errorf("migrate: acquire advisory lock: %w", err)
	}
	defer func() {
		if _, err := conn.Exec(context.WithoutCancel(ctx),
			`SELECT pg_advisory_unlock($1)`, advisoryLockKey); err != nil {
			log.Warn("migrate: releasing advisory lock failed", "error", err)
		}
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version     TEXT        PRIMARY KEY,
			applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("migrate: create schema_migrations: %w", err)
	}

	applied, err := appliedVersions(ctx, conn)
	if err != nil {
		return err
	}

	names, err := sortedMigrations(src)
	if err != nil {
		return err
	}

	for _, name := range names {
		if applied[name] {
			continue
		}

		body, err := fs.ReadFile(src, name)
		if err != nil {
			return fmt.Errorf("migrate: read %s: %w", name, err)
		}

		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("migrate: begin %s: %w", name, err)
		}

		// Exec without arguments uses the simple query protocol, which is what
		// lets a migration file hold several statements and a plpgsql body.
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migrate: apply %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migrate: record %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("migrate: commit %s: %w", name, err)
		}

		log.Info("migration applied", "version", name)
	}

	return nil
}

func appliedVersions(ctx context.Context, conn *pgxpool.Conn) (map[string]bool, error) {
	rows, err := conn.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("migrate: read applied versions: %w", err)
	}
	defer rows.Close()

	applied := map[string]bool{}
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("migrate: scan applied version: %w", err)
		}
		applied[version] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("migrate: read applied versions: %w", err)
	}
	return applied, nil
}

func sortedMigrations(src fs.FS) ([]string, error) {
	entries, err := fs.ReadDir(src, ".")
	if err != nil {
		return nil, fmt.Errorf("migrate: list migrations: %w", err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		names = append(names, e.Name())
	}
	// Filenames are zero-padded (001_, 002_), so lexical order is version order.
	sort.Strings(names)
	return names, nil
}
