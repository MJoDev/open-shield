//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-shield/open-shield/test/harness"

	"github.com/open-shield/open-shield/internal/audit"
	"github.com/open-shield/open-shield/internal/model"
)

// The forensic claim of §6 is that an altered entry is detectable. Everything
// that makes it true lives at the boundary between Go and PostgreSQL — the
// microsecond resolution of timestamptz, what jsonb does to a number, the order
// rows come back in — so it cannot be checked without a real database.

// --- Parity with the in-memory store ----------------------------------------

// TestBothStoresSealIdenticalChains is the strongest single check in this file.
//
// The same sequence of appends, run through the in-memory store and through
// PostgreSQL, must produce byte-identical hashes. If it does not, then either
// the timestamp truncation or NormalizePayload is failing to make the sealed
// value equal to the value that comes back on a read — and a chain nobody
// touched would stop verifying after a restart.
func TestBothStoresSealIdenticalChains(t *testing.T) {
	ctx := harness.Context(t)

	entries := []struct {
		kind      string
		requestID string
		payload   map[string]any
	}{
		{model.KindTraffic, "req-1", map[string]any{"ip": "203.0.113.7", "decision_ms": 1.50}},
		{model.KindTraffic, "req-2", map[string]any{"n": 9007199254740993, "verdict": "block"}},
		{model.KindAdmin, "", map[string]any{"actor": "admin", "action": "rule.disable", "enabled": false}},
		{model.KindSystem, "req-4", map[string]any{"nested": map[string]any{"b": 2, "a": 1}, "list": []any{3, 1, 2}}},
		{model.KindTraffic, "req-5", map[string]any{"reason": `sqli signature "union_select" matched in query: …x' UNION SELECT…`}},
	}

	// The same clock for both, so the only variable is the store.
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	clock := func() func() time.Time {
		var n int
		return func() time.Time {
			n++
			return base.Add(time.Duration(n) * time.Millisecond)
		}
	}

	memory := audit.NewMemory()
	memWriter, err := audit.NewWriter(ctx, memory, audit.WriterOptions{Buffer: 16, Clock: clock()})
	if err != nil {
		t.Fatalf("memory writer: %v", err)
	}

	store := harness.Store(t)
	pgWriter, err := audit.NewWriter(ctx, store, audit.WriterOptions{Buffer: 16, Clock: clock()})
	if err != nil {
		t.Fatalf("postgres writer: %v", err)
	}

	// The two writers generate their own UUIDs, so the digests will differ.
	// What must match is that each store seals over the same *shape* of value:
	// each entry has to hash to its own content after coming back out.
	for _, e := range entries {
		memWriter.Record(e.kind, e.requestID, e.payload)
		pgWriter.Record(e.kind, e.requestID, e.payload)
	}
	if err := memWriter.Close(ctx); err != nil {
		t.Fatalf("memory writer close: %v", err)
	}
	if err := pgWriter.Close(ctx); err != nil {
		t.Fatalf("postgres writer close: %v", err)
	}

	stored, err := store.List(ctx, audit.Filter{Limit: 100})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(stored) != len(entries) {
		t.Fatalf("stored %d entries, want %d", len(stored), len(entries))
	}

	// Each entry's own hash must be reproducible from what PostgreSQL returned.
	// That is the property the two stores share; the UUIDs differ, so the
	// digests cannot be compared to the in-memory ones directly.
	for _, e := range stored {
		if got := e.ComputeHash(); got != e.Hash {
			t.Fatalf("entry %s does not hash to its stored content after a round trip\n  stored:    %s\n  recomputed: %s\n  payload:   %v",
				e.ID, e.Hash, got, e.Payload)
		}
	}

	// And the in-memory chain, for the same inputs, must verify too — if it did
	// not, the comparison above would be meaningless.
	memResult, err := memory.VerifyChain(ctx, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("memory VerifyChain: %v", err)
	}
	pgResult, err := store.VerifyChain(ctx, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("postgres VerifyChain: %v", err)
	}
	if !memResult.OK || !pgResult.OK {
		t.Fatalf("memory ok=%v, postgres ok=%v — the same appends must verify in both",
			memResult.OK, pgResult.OK)
	}
	if memResult.Checked != pgResult.Checked {
		t.Errorf("memory checked %d entries, postgres checked %d", memResult.Checked, pgResult.Checked)
	}
}

// A float that is not exactly representable is the classic way a chain breaks
// without anyone touching it: 1.50 sealed as a Go float64 comes back from jsonb
// as 1.5, hashes differently, and verification reports tampering. This is what
// NormalizePayload exists to prevent.
//
// The values below span everything a payload actually carries — decision_ms, a
// status code, an integer past float64's exact range — plus the two decimal
// boundaries where Go's encoder switches notation.
func TestNumbersSurviveTheRoundTripUnchanged(t *testing.T) {
	store := harness.Store(t)
	ctx := harness.Context(t)

	writer, err := audit.NewWriter(ctx, store, audit.WriterOptions{Buffer: 16})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for _, value := range []any{
		1.50, 0.1, 100.0, 0.0, -1.0,
		403, 429, 9007199254740993,
		0.000001,             // the smallest magnitude Go still writes in full
		999999999999999999.0, // large, but below the exponent threshold
	} {
		writer.Record(model.KindTraffic, "req-number", map[string]any{"decision_ms": value})
	}
	if err := writer.Close(ctx); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	result, err := store.VerifyChain(ctx, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !result.OK {
		t.Fatalf("a number changed shape in the database: broken at %s (%s)", result.BrokenAt, result.Detail)
	}
}

// TestExtremeMagnitudesAreOutsideTheChainsRange pins a real, narrow limitation
// rather than papering over it.
//
// encoding/json writes a float in exponent notation once its exponent reaches
// 21 or falls below -6: 1e21 is marshalled as "1e+21". PostgreSQL's jsonb keeps
// numbers as `numeric` and renders that same value as
// "1000000000000000000000". The two texts canonicalise differently, so the hash
// recomputed on read does not match the hash that was sealed — and VerifyChain
// reports tampering on a log nobody has touched.
//
// No payload the system writes today comes near either threshold: decision_ms
// is single-digit milliseconds and status is three digits. The trap is for
// whoever adds the next numeric field. Fixing it means changing what gets
// hashed, which invalidates every chain already in existence, so it is recorded
// as a known boundary instead — see docs/implementation-decisions.md.
//
// If this test starts failing, the limitation has been fixed. Update the
// document and delete it.
func TestExtremeMagnitudesAreOutsideTheChainsRange(t *testing.T) {
	for name, value := range map[string]any{
		"exponent at 21":    1e21,
		"exponent below -6": 1e-7,
	} {
		t.Run(name, func(t *testing.T) {
			store := harness.Store(t)
			ctx := harness.Context(t)

			writer, err := audit.NewWriter(ctx, store, audit.WriterOptions{Buffer: 4})
			if err != nil {
				t.Fatalf("NewWriter: %v", err)
			}
			writer.Record(model.KindTraffic, "req-extreme", map[string]any{"value": value})
			if err := writer.Close(ctx); err != nil {
				t.Fatalf("writer.Close: %v", err)
			}

			result, err := store.VerifyChain(ctx, time.Time{}, time.Time{})
			if err != nil {
				t.Fatalf("VerifyChain: %v", err)
			}
			if result.OK {
				t.Fatalf("%v now survives the round trip — the limitation is fixed; "+
					"update docs/implementation-decisions.md and remove this test", value)
			}
		})
	}
}

// Two requests can be decided inside the same microsecond, so timestamps cannot
// order the chain. seq can, and does.
func TestChainOrderIsSeqNotTimestamp(t *testing.T) {
	store := harness.Store(t)
	ctx := harness.Context(t)

	// A clock that hands out the same instant every time — the worst case, and
	// one real traffic will approximate under load.
	frozen := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	writer, err := audit.NewWriter(ctx, store, audit.WriterOptions{
		Buffer: 64,
		Clock:  func() time.Time { return frozen },
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for i := 0; i < 25; i++ {
		writer.Record(model.KindTraffic, fmt.Sprintf("req-%02d", i), map[string]any{"i": i})
	}
	if err := writer.Close(ctx); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	result, err := store.VerifyChain(ctx, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !result.OK {
		t.Fatalf("25 entries sharing one timestamp broke verification at %s: %s",
			result.BrokenAt, result.Detail)
	}
	if result.Checked != 25 {
		t.Errorf("checked = %d, want 25", result.Checked)
	}
}

// --- Detecting tampering ----------------------------------------------------

func TestTheDatabaseRefusesToModifyTheLog(t *testing.T) {
	store := harness.Store(t)
	harness.SeedTraffic(t, store, 5)

	pool := harness.PoolNoReset(t)
	ctx := harness.Context(t)

	// Detectable is not the same as difficult. The trigger is the second half:
	// ordinary code, and a mistake, cannot touch the log at all.
	for _, stmt := range []string{
		`UPDATE audit_log SET payload = '{}'::jsonb`,
		`DELETE FROM audit_log`,
		`TRUNCATE audit_log`,
	} {
		if _, err := pool.Exec(ctx, stmt); err == nil {
			t.Errorf("the database allowed: %s", stmt)
		} else if !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s failed with %q, want the append-only message", stmt, err)
		}
	}
}

func TestVerifyDetectsARewrittenPayload(t *testing.T) {
	store := harness.Store(t)
	entries := harness.SeedTraffic(t, store, 10)
	ctx := harness.Context(t)

	// Rewriting the source address is the edit an attacker would make: erase
	// which host the request came from and leave everything else in place.
	target := entries[4]
	harness.DisableTriggers(t, func(exec func(string, ...any)) {
		exec(`UPDATE audit_log SET payload = jsonb_set(payload, '{ip}', '"192.0.2.66"') WHERE id = $1`, target.ID)
	})

	result, err := store.VerifyChain(ctx, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if result.OK {
		t.Fatal("a rewritten block was not detected")
	}
	if result.BrokenAt != target.ID {
		t.Errorf("broken_at = %q, want %q", result.BrokenAt, target.ID)
	}
	if result.Position != 5 {
		t.Errorf("position = %d, want 5", result.Position)
	}
	if result.Detail == "" {
		t.Error("detail is empty; the operator needs to know what failed, not only where")
	}
}

// Deleting a row is the edit that looks cleanest from the database's side and
// is caught by the link rather than by the hash: the entry after the hole
// points at a predecessor that is no longer there.
func TestVerifyDetectsADeletedEntry(t *testing.T) {
	store := harness.Store(t)
	entries := harness.SeedTraffic(t, store, 10)
	ctx := harness.Context(t)

	removed := entries[6]
	harness.DisableTriggers(t, func(exec func(string, ...any)) {
		exec(`DELETE FROM audit_log WHERE id = $1`, removed.ID)
	})

	result, err := store.VerifyChain(ctx, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if result.OK {
		t.Fatal("a deleted entry left the chain verifying")
	}
	// The break shows up at the entry that followed the one removed.
	if result.BrokenAt != entries[7].ID {
		t.Errorf("broken_at = %q, want the entry after the hole (%q)", result.BrokenAt, entries[7].ID)
	}
}

// The thorough attacker re-seals the entry they edited so its own hash is
// correct. It still fails, because the *next* entry's prev_hash was computed
// over the original.
func TestVerifyDetectsAResealedEntry(t *testing.T) {
	store := harness.Store(t)
	entries := harness.SeedTraffic(t, store, 8)
	ctx := harness.Context(t)

	target := entries[3]
	forged := target
	forged.Payload = map[string]any{"ip": "192.0.2.66", "verdict": "allow"}
	normalized, err := model.NormalizePayload(forged.Payload)
	if err != nil {
		t.Fatalf("NormalizePayload: %v", err)
	}
	forged.Payload = normalized
	forged.Seal(target.PrevHash)

	harness.DisableTriggers(t, func(exec func(string, ...any)) {
		exec(`UPDATE audit_log SET payload = $1, hash = $2 WHERE id = $3`,
			`{"ip":"192.0.2.66","verdict":"allow"}`, forged.Hash, target.ID)
	})

	result, err := store.VerifyChain(ctx, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if result.OK {
		t.Fatal("a re-sealed entry passed verification; the chain is not linking forward")
	}
	if result.BrokenAt != entries[4].ID {
		t.Errorf("broken_at = %q, want the entry that follows the forgery (%q)",
			result.BrokenAt, entries[4].ID)
	}
}

// Without an anchor, verifying a range that starts at a rewritten entry would
// pass: the entry is internally consistent, and there is nothing before it in
// the range to contradict its prev_hash.
func TestRangeVerificationAnchorsOnTheEntryBeforeIt(t *testing.T) {
	store := harness.Store(t)
	entries := harness.SeedTraffic(t, store, 10)
	ctx := harness.Context(t)

	target := entries[5]
	forged := target
	forged.Payload = map[string]any{"ip": "192.0.2.66"}
	normalized, err := model.NormalizePayload(forged.Payload)
	if err != nil {
		t.Fatalf("NormalizePayload: %v", err)
	}
	forged.Payload = normalized
	// Sealed against a prev_hash of its own invention, as if the history before
	// it had been rewritten too.
	forged.Seal(strings.Repeat("f", 64))

	harness.DisableTriggers(t, func(exec func(string, ...any)) {
		exec(`UPDATE audit_log SET payload = $1, prev_hash = $2, hash = $3 WHERE id = $4`,
			`{"ip":"192.0.2.66"}`, forged.PrevHash, forged.Hash, target.ID)
	})

	// A range beginning exactly at the forged entry.
	result, err := store.VerifyChain(ctx, target.Timestamp, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if result.OK {
		t.Fatal("a range starting at a forged entry verified; the anchor is missing")
	}
}

// --- Reading ----------------------------------------------------------------

func TestListAppliesEveryFilter(t *testing.T) {
	store := harness.Store(t)
	entries := harness.SeedTraffic(t, store, 30)
	ctx := harness.Context(t)

	for name, c := range map[string]struct {
		filter audit.Filter
		check  func(t *testing.T, got []model.AuditEntry)
	}{
		"by verdict": {
			filter: audit.Filter{Verdict: string(model.Block), Limit: 100},
			check: func(t *testing.T, got []model.AuditEntry) {
				if len(got) == 0 {
					t.Fatal("no blocked entries")
				}
				for _, e := range got {
					if e.Payload["verdict"] != string(model.Block) {
						t.Fatalf("entry %s has verdict %v", e.ID, e.Payload["verdict"])
					}
				}
			},
		},
		"by ip": {
			filter: audit.Filter{IP: "203.0.113.2", Limit: 100},
			check: func(t *testing.T, got []model.AuditEntry) {
				if len(got) == 0 {
					t.Fatal("no entries for 203.0.113.2")
				}
				for _, e := range got {
					if e.Payload["ip"] != "203.0.113.2" {
						t.Fatalf("entry %s has ip %v", e.ID, e.Payload["ip"])
					}
				}
			},
		},
		"by rule": {
			filter: audit.Filter{Rule: "sqli", Limit: 100},
			check: func(t *testing.T, got []model.AuditEntry) {
				if len(got) == 0 {
					t.Fatal("no entries attributed to sqli")
				}
			},
		},
		"by request id": {
			filter: audit.Filter{RequestID: "req-007", Limit: 100},
			check: func(t *testing.T, got []model.AuditEntry) {
				if len(got) != 1 || got[0].RequestID != "req-007" {
					t.Fatalf("got %d entries for req-007", len(got))
				}
			},
		},
		"by kind": {
			filter: audit.Filter{Kind: model.KindAdmin, Limit: 100},
			check: func(t *testing.T, got []model.AuditEntry) {
				if len(got) != 0 {
					t.Fatalf("got %d admin entries in a traffic-only log", len(got))
				}
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := store.List(ctx, c.filter)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			c.check(t, got)
		})
	}

	t.Run("newest first", func(t *testing.T) {
		got, err := store.List(ctx, audit.Filter{Limit: 5})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 5 {
			t.Fatalf("got %d entries, want 5", len(got))
		}
		if got[0].RequestID != entries[len(entries)-1].RequestID {
			t.Fatalf("first entry is %q, want the most recent (%q)",
				got[0].RequestID, entries[len(entries)-1].RequestID)
		}
	})

	t.Run("limit is clamped", func(t *testing.T) {
		got, err := store.List(ctx, audit.Filter{Limit: 10_000})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) > 500 {
			t.Fatalf("got %d entries; a dashboard query must not be able to ask for the whole history", len(got))
		}
	})

	t.Run("pagination does not repeat or skip", func(t *testing.T) {
		seen := map[string]bool{}
		for offset := 0; offset < 30; offset += 7 {
			page, err := store.List(ctx, audit.Filter{Limit: 7, Offset: offset})
			if err != nil {
				t.Fatalf("List(offset=%d): %v", offset, err)
			}
			for _, e := range page {
				if seen[e.ID] {
					t.Fatalf("entry %s appeared on two pages", e.ID)
				}
				seen[e.ID] = true
			}
		}
		if len(seen) != 30 {
			t.Fatalf("paging saw %d of 30 entries", len(seen))
		}
	})
}

func TestCountIgnoresPagination(t *testing.T) {
	store := harness.Store(t)
	harness.SeedTraffic(t, store, 30)
	ctx := harness.Context(t)

	// The dashboard shows "showing 7 of N". N has to be the whole match, or the
	// pager renders the wrong number of pages.
	total, err := store.Count(ctx, audit.Filter{Limit: 7})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if total != 30 {
		t.Fatalf("Count = %d with Limit 7, want 30", total)
	}

	blocked, err := store.Count(ctx, audit.Filter{Verdict: string(model.Block)})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if blocked == 0 || blocked >= total {
		t.Fatalf("blocked = %d, want a strict subset of %d", blocked, total)
	}
}

func TestStatsSummarisesTheWindow(t *testing.T) {
	store := harness.Store(t)
	harness.SeedTraffic(t, store, 30)
	ctx := harness.Context(t)

	stats, err := store.Stats(ctx, time.Hour)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}

	if stats.Total != 30 {
		t.Errorf("total = %d, want 30", stats.Total)
	}
	if stats.Allowed+stats.Blocked != stats.Total {
		t.Errorf("allowed %d + blocked %d != total %d", stats.Allowed, stats.Blocked, stats.Total)
	}
	if len(stats.TopIPs) == 0 {
		t.Error("top_ips is empty; the overview has nothing to show")
	}
	if len(stats.TopRules) == 0 {
		t.Error("top_rules is empty")
	}
	if len(stats.Series) == 0 {
		t.Error("series is empty; the traffic chart would render blank")
	}

	// A window that predates every entry must come back empty rather than
	// erroring — the dashboard opens on an empty log the first time it is used.
	empty, err := store.Stats(ctx, time.Nanosecond)
	if err != nil {
		t.Fatalf("Stats over an empty window: %v", err)
	}
	if empty.Total != 0 {
		t.Errorf("total = %d over a 1ns window, want 0", empty.Total)
	}
}

// --- Resuming ---------------------------------------------------------------

// The engine restarts. The next entry must link to the last one in the
// database, not begin a second chain from genesis — which would look exactly
// like the log had been truncated.
func TestTheChainResumesAcrossARestart(t *testing.T) {
	store := harness.Store(t)
	ctx := harness.Context(t)

	first := harness.SeedTraffic(t, store, 5)
	head, err := store.Head(ctx)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if head != first[len(first)-1].Hash {
		t.Fatalf("Head = %s, want the last entry's hash %s", head, first[len(first)-1].Hash)
	}

	// A second store over the same database, as a restarted engine would open.
	restarted, err := audit.NewPostgres(ctx, harness.PostgresDSN(t))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = restarted.Close() }()

	writer, err := audit.NewWriter(ctx, restarted, audit.WriterOptions{Buffer: 8})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := writer.RecordSync(ctx, model.KindSystem, "after-restart", map[string]any{"event": "startup"}); err != nil {
		t.Fatalf("RecordSync: %v", err)
	}
	if err := writer.Close(ctx); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	result, err := restarted.VerifyChain(ctx, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !result.OK {
		t.Fatalf("the chain broke across a restart at %s: %s", result.BrokenAt, result.Detail)
	}
	if result.Checked != 6 {
		t.Errorf("checked = %d, want 6", result.Checked)
	}
}

func TestHeadOnAnEmptyLogIsGenesis(t *testing.T) {
	store := harness.Store(t)

	head, err := store.Head(harness.Context(t))
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if head != model.GenesisHash {
		t.Fatalf("Head = %q on an empty log, want the genesis hash", head)
	}
}

func TestNewPostgresRejectsABadDSN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// A misconfigured DSN must fail at startup, not on the first request that
	// needs to record a decision.
	if store, err := audit.NewPostgres(ctx, "postgres://nobody:nothing@127.0.0.1:1/nowhere?sslmode=disable"); err == nil {
		_ = store.Close()
		t.Fatal("NewPostgres succeeded against an unreachable database")
	}
}
