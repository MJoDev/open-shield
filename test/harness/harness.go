// Package harness holds the fixtures the integration suite shares: a migrated
// PostgreSQL, a flushed Redis, and the helpers for seeding and tampering with
// an audit log.
//
// It exists as its own package because Go's internal rule splits the suite
// across three directories. Only code under engine/ may import
// engine/internal/…, and only code under dashboard/api/ may import
// dashboard/api/internal/… — so an integration test for the rate limiter or the
// dashboard router cannot live in test/integration/ at all. It has to sit
// beside the package it exercises, behind the same build tag. This package is
// the part they can all share; test/integration/ then covers everything
// reachable from the root internal/ tree.
//
// Every fixture skips the calling test when OS_TEST_POSTGRES_DSN and
// OS_TEST_REDIS_ADDR are unset, so the suite is never a failure on a machine
// that simply does not have the dependencies running.
package harness

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/open-shield/open-shield/internal/audit"
	"github.com/open-shield/open-shield/internal/migrate"
	"github.com/open-shield/open-shield/internal/model"
	"github.com/open-shield/open-shield/migrations"
)

const skipMessage = `integration suite needs OS_TEST_POSTGRES_DSN and OS_TEST_REDIS_ADDR.
Bring the dependencies up with:

    docker compose -f deploy/docker-compose.test.yml up -d

or run the whole suite with: make test-integration`

// PostgresDSN returns the configured DSN, skipping the test if there is none.
func PostgresDSN(t *testing.T) string {
	t.Helper()

	dsn := os.Getenv("OS_TEST_POSTGRES_DSN")
	if dsn == "" || os.Getenv("OS_TEST_REDIS_ADDR") == "" {
		t.Skip(skipMessage)
	}
	return dsn
}

// RedisAddr returns the configured Redis address, skipping the test if there is
// none.
func RedisAddr(t *testing.T) string {
	t.Helper()

	addr := os.Getenv("OS_TEST_REDIS_ADDR")
	if addr == "" || os.Getenv("OS_TEST_POSTGRES_DSN") == "" {
		t.Skip(skipMessage)
	}
	return addr
}

// Context returns a context bounded by a generous per-test timeout, so a test
// that hangs on a dependency fails with a message instead of stalling the run.
func Context(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// QuietLog discards log output. The components under test log a great deal on
// purpose; none of it belongs in a test run's output unless something fails.
func QuietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// PoolNoReset opens a migrated connection pool, leaving the existing rows
// alone. Use it to reach past the store — to disable a trigger, or to check
// that one fires.
func PoolNoReset(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn := PostgresDSN(t)
	ctx := Context(t)

	pool, err := waitForPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to postgres at %s: %v", dsn, err)
	}
	t.Cleanup(pool.Close)

	if err := migrate.Apply(ctx, pool, migrations.Postgres(), QuietLog()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return pool
}

// Pool opens a migrated connection pool with every table emptied, so each test
// starts from a known state.
func Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	pool := PoolNoReset(t)
	Reset(t, pool)
	return pool
}

// Store opens an audit.Postgres over a clean schema.
func Store(t *testing.T) *audit.Postgres {
	t.Helper()

	Pool(t) // migrate and clean first

	store, err := audit.NewPostgres(Context(t), PostgresDSN(t))
	if err != nil {
		t.Fatalf("audit.NewPostgres: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// StoreOverPool opens an audit.Postgres without emptying anything, for a test
// that has already called Pool.
func StoreOverPool(t *testing.T) *audit.Postgres {
	t.Helper()

	store, err := audit.NewPostgres(Context(t), PostgresDSN(t))
	if err != nil {
		t.Fatalf("audit.NewPostgres: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// Redis returns a client against a flushed database.
func Redis(t *testing.T) *redis.Client {
	t.Helper()

	addr := RedisAddr(t)
	client := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = client.Close() })

	ctx := Context(t)
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("connect to redis at %s: %v", addr, err)
	}
	if err := client.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flush redis: %v", err)
	}
	return client
}

// Reset empties the schema between tests.
//
// The audit log refuses DELETE and TRUNCATE by trigger, which is the point of
// it, so the trigger has to be disabled first. That this is awkward is the
// feature working: emptying the forensic log is not something ordinary code
// should be able to do by accident.
func Reset(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	ctx := Context(t)
	for _, stmt := range []string{
		`ALTER TABLE audit_log DISABLE TRIGGER USER`,
		`TRUNCATE audit_log RESTART IDENTITY`,
		`ALTER TABLE audit_log ENABLE TRIGGER USER`,
		`DELETE FROM ip_rules`,
		`UPDATE rules SET enabled = TRUE, updated_by = ''`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("reset (%s): %v", stmt, err)
		}
	}
}

// DisableTriggers runs fn with the append-only trigger switched off, which is
// what an attacker who already owns the database would do. The chain does not
// try to stop them; it makes sure they cannot do it quietly.
func DisableTriggers(t *testing.T, fn func(exec func(string, ...any))) {
	t.Helper()

	pool := PoolNoReset(t)
	ctx := Context(t)

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("exec (%s): %v", sql, err)
		}
	}

	exec(`ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_modify`)
	defer exec(`ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_modify`)
	fn(exec)
}

// SeedTraffic appends n traffic entries through a Writer — the only supported
// way to extend the chain — and returns them in append order, which is the
// order the chain runs in.
func SeedTraffic(t *testing.T, repo audit.Repository, n int) []model.AuditEntry {
	t.Helper()

	ctx := Context(t)
	writer, err := audit.NewWriter(ctx, repo, audit.WriterOptions{Buffer: n + 16})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	for i := 0; i < n; i++ {
		verdict, rule := string(model.Allow), ""
		if i%3 == 0 {
			verdict, rule = string(model.Block), "sqli"
		}
		writer.Record(model.KindTraffic, fmt.Sprintf("req-%03d", i), map[string]any{
			"ip":          fmt.Sprintf("203.0.113.%d", i%5),
			"verdict":     verdict,
			"rule":        rule,
			"path":        "/productos",
			"method":      "GET",
			"decision_ms": 1.50, // a float that must survive jsonb unchanged
			"headers":     map[string]any{"user-agent": "curl/8.5.0"},
		})
	}

	if err := writer.Close(ctx); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	entries, err := repo.List(ctx, audit.Filter{Limit: n})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// List is newest-first; the chain runs the other way.
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	return entries
}

// WaitForSubscriber blocks until Redis reports a subscriber on the channel.
// Pub/Sub retains nothing, so publishing before the subscription is registered
// delivers to nobody, and the test would hang rather than fail usefully.
func WaitForSubscriber(t *testing.T, client *redis.Client, channel string, want int64) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		counts, err := client.PubSubNumSub(context.Background(), channel).Result()
		if err == nil && counts[channel] >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no subscriber appeared on %s", channel)
}

// waitForPostgres tolerates a container that has started but is not yet
// accepting connections, which is the normal state for the first seconds of a
// CI job.
func waitForPostgres(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	deadline := time.Now().Add(60 * time.Second)
	var lastErr error

	for {
		pool, err := pgxpool.New(ctx, dsn)
		if err == nil {
			pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			err = pool.Ping(pingCtx)
			cancel()
			if err == nil {
				return pool, nil
			}
			pool.Close()
		}
		lastErr = err

		if time.Now().After(deadline) {
			return nil, lastErr
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}
