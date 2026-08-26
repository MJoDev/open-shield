//go:build integration

package integration

import (
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/open-shield/open-shield/internal/audit"
	"github.com/open-shield/open-shield/internal/model"
	"github.com/open-shield/open-shield/test/harness"
)

// The audit log cannot be pruned. Deleting rows breaks the chain exactly as an
// attacker would, so the table only ever grows, and VerifyChain walks all of
// it — recomputing a SHA-256 per entry and checking every link.
//
// How long that takes at a realistic size is an operational fact an operator
// needs *before* an incident, not during one. "Verify the chain before treating
// the log as evidence" is advice in the manual; if verifying a year of traffic
// takes forty minutes and holds a connection the whole time, that is something
// the manual has to say.
//
// Skipped unless OS_TEST_SCALE is set, because it is minutes rather than
// seconds. The nightly workflow sets it.

func TestChainVerificationAtScale(t *testing.T) {
	raw := os.Getenv("OS_TEST_SCALE")
	if raw == "" {
		t.Skip("set OS_TEST_SCALE to the number of entries to seed, e.g. OS_TEST_SCALE=200000")
	}
	total, err := strconv.Atoi(raw)
	if err != nil || total <= 0 {
		t.Fatalf("OS_TEST_SCALE = %q, want a positive number of entries", raw)
	}

	store := harness.Store(t)
	ctx := harness.Context(t)

	writer, err := audit.NewWriter(ctx, store, audit.WriterOptions{Buffer: 8192})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	// RecordSync would serialise on a round trip per entry. Record is the path
	// real traffic takes, and the buffer is sized so nothing is dropped —
	// a dropped entry here would be a hole in the measurement, not a finding.
	seedStart := time.Now()
	for i := 0; i < total; i++ {
		verdict, rule := string(model.Allow), ""
		if i%4 == 0 {
			verdict, rule = string(model.Block), "sqli"
		}
		writer.Record(model.KindTraffic, fmt.Sprintf("req-%08d", i), map[string]any{
			"ip":          fmt.Sprintf("203.0.113.%d", i%256),
			"verdict":     verdict,
			"rule":        rule,
			"method":      "GET",
			"path":        "/productos",
			"decision_ms": 1.25,
			"headers":     map[string]any{"user-agent": "curl/8.5.0"},
		})

		// The queue drains at whatever rate PostgreSQL accepts inserts. Letting
		// the producer run unchecked would just fill it and start dropping.
		if i%2048 == 0 {
			for writer.Stats().Queued > 4096 {
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
	if err := writer.Close(ctx); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}
	seedElapsed := time.Since(seedStart)

	stats := writer.Stats()
	if stats.Dropped > 0 {
		t.Fatalf("%d entries were dropped while seeding; the measurement would have a hole in it",
			stats.Dropped)
	}
	t.Logf("sembradas %d entradas en %s (%.0f/s)",
		stats.Written, seedElapsed.Round(time.Millisecond),
		float64(stats.Written)/seedElapsed.Seconds())

	// The measurement itself.
	verifyStart := time.Now()
	result, err := store.VerifyChain(ctx, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	verifyElapsed := time.Since(verifyStart)

	if !result.OK {
		t.Fatalf("the chain broke while being written at scale: %s at position %d (%s)",
			result.BrokenAt, result.Position, result.Detail)
	}
	if result.Checked != int64(total) {
		t.Fatalf("verification checked %d of %d entries", result.Checked, total)
	}

	perEntry := verifyElapsed.Seconds() / float64(total) * 1e6
	t.Logf("verificadas %d entradas en %s (%.1f µs por entrada, %.0f entradas/s)",
		result.Checked, verifyElapsed.Round(time.Millisecond), perEntry,
		float64(result.Checked)/verifyElapsed.Seconds())

	// Not a benchmark assertion — the runner's speed is not the subject. This
	// only catches an order-of-magnitude regression, the kind an accidental
	// per-entry query would cause.
	if perEntry > 500 {
		t.Errorf("verification costs %.1f µs per entry; something is doing per-entry work "+
			"that should be part of the scan", perEntry)
	}

	// A range query over a large log has to use the index rather than walking
	// everything: the forensic view offers date bounds precisely so an operator
	// can look at one incident without paying for the whole history.
	rangeStart := time.Now()
	partial, err := store.VerifyChain(ctx, time.Now().Add(-time.Hour), time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain over a range: %v", err)
	}
	t.Logf("rango de una hora: %d entradas en %s",
		partial.Checked, time.Since(rangeStart).Round(time.Millisecond))

	if !partial.OK {
		t.Fatalf("the ranged verification failed: %s", partial.Detail)
	}
}
