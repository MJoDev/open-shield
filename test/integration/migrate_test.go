//go:build integration

package integration

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-shield/open-shield/internal/migrate"
	"github.com/open-shield/open-shield/test/harness"
)

// migrate.Apply runs at engine startup, every time, before anything else. What
// it does when a migration is wrong therefore decides whether a bad schema
// change stops the container or half-applies and leaves the database in a state
// nobody wrote down.

// A migration that fails must leave nothing behind. Each one runs in its own
// transaction, so a failure rolls the whole file back — including the row that
// would have marked it applied, which is what stops a retry from skipping it.
func TestAFailedMigrationLeavesNothingBehind(t *testing.T) {
	pool := harness.Pool(t)
	ctx := harness.Context(t)

	broken := fstest.MapFS{
		"900_broken.sql": {Data: []byte(`
			CREATE TABLE migrate_probe (id INT);
			THIS IS NOT SQL;
		`)},
	}

	err := migrate.Apply(ctx, pool, broken, harness.QuietLog())
	if err == nil {
		t.Fatal("Apply accepted a migration that is not valid SQL")
	}
	if !strings.Contains(err.Error(), "900_broken.sql") {
		t.Errorf("error = %q, want it to name the file that failed", err)
	}

	var tables int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.tables WHERE table_name = 'migrate_probe'`).
		Scan(&tables); err != nil {
		t.Fatalf("look for migrate_probe: %v", err)
	}
	if tables != 0 {
		t.Error("the first statement of a failed migration was committed")
	}

	var recorded int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version = '900_broken.sql'`).
		Scan(&recorded); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if recorded != 0 {
		t.Error("a migration that failed was recorded as applied; a retry would skip it")
	}
}

// Migrations run in filename order, which is the only thing making 002 able to
// depend on 001. Sorting by anything else — directory order, map iteration —
// would work until the day it did not.
func TestMigrationsRunInFilenameOrder(t *testing.T) {
	pool := harness.Pool(t)
	ctx := harness.Context(t)

	ordered := fstest.MapFS{
		"902_second.sql": {Data: []byte(`INSERT INTO migrate_order (n) VALUES (2);`)},
		"901_first.sql":  {Data: []byte(`CREATE TABLE migrate_order (n INT); INSERT INTO migrate_order (n) VALUES (1);`)},
		"903_third.sql":  {Data: []byte(`INSERT INTO migrate_order (n) VALUES (3);`)},
		// Not SQL, and therefore not a migration. A README next to the schema
		// must not be executed.
		"README.md": {Data: []byte("no soy una migración")},
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DROP TABLE IF EXISTS migrate_order`)
		_, _ = pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version LIKE '90%'`)
	})

	if err := migrate.Apply(ctx, pool, ordered, harness.QuietLog()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	rows, err := pool.Query(ctx, `SELECT n FROM migrate_order ORDER BY n`)
	if err != nil {
		t.Fatalf("read migrate_order: %v", err)
	}
	defer rows.Close()

	var got []int
	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, n)
	}
	if len(got) != 3 {
		t.Fatalf("migrate_order holds %v, want three rows", got)
	}

	var readme int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version = 'README.md'`).Scan(&readme); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if readme != 0 {
		t.Error("a non-SQL file was treated as a migration")
	}
}

// Two engine containers starting at once both call Apply against the same
// database. The advisory lock serialises them; without it they race to create
// the same objects and one of them fails to boot.
func TestConcurrentMigrationsSerialise(t *testing.T) {
	cleanup := harness.Pool(t)
	ctx := harness.Context(t)

	const starters = 4

	// The pools are opened here, on the test goroutine: harness.PoolNoReset
	// calls t.Fatalf, and that is only valid from the goroutine running the
	// test.
	pools := make([]*pgxpool.Pool, starters)
	for i := range pools {
		pools[i] = harness.PoolNoReset(t)
	}

	t.Cleanup(func() {
		_, _ = cleanup.Exec(ctx, `DROP TABLE IF EXISTS migrate_concurrent`)
		_, _ = cleanup.Exec(ctx, `DELETE FROM schema_migrations WHERE version = '904_concurrent.sql'`)
	})

	src := fstest.MapFS{
		"904_concurrent.sql": {Data: []byte(`CREATE TABLE migrate_concurrent (n INT);`)},
	}

	errs := make(chan error, starters)
	for i := 0; i < starters; i++ {
		go func(pool *pgxpool.Pool) {
			errs <- migrate.Apply(ctx, pool, src, harness.QuietLog())
		}(pools[i])
	}

	for i := 0; i < starters; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("starter %d failed: %v — concurrent startups must serialise, not collide", i, err)
		}
	}

	// Exactly one of them applied it.
	var recorded int
	if err := cleanup.QueryRow(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version = '904_concurrent.sql'`).
		Scan(&recorded); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if recorded != 1 {
		t.Fatalf("schema_migrations holds %d rows for one migration, want 1", recorded)
	}
}
