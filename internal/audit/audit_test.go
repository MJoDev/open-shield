package audit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/open-shield/open-shield/internal/model"
)

// testClock hands out strictly increasing timestamps one second apart, so that
// range queries in these tests are unambiguous. Real traffic offers no such
// guarantee — several requests can share a microsecond — which is why chain
// order is the append order, not the timestamp.
func testClock(start time.Time) func() time.Time {
	var n int
	return func() time.Time {
		n++
		return start.Add(time.Duration(n) * time.Second)
	}
}

var epoch = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

// seed writes n traffic entries through a Writer, which is the only supported
// way to append, and returns the store.
func seed(t *testing.T, n int) *Memory {
	t.Helper()

	repo := NewMemory()
	writer, err := NewWriter(context.Background(), repo, WriterOptions{
		Buffer: 64,
		Clock:  testClock(epoch),
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	for i := 0; i < n; i++ {
		verdict := string(model.Allow)
		if i%3 == 0 {
			verdict = string(model.Block)
		}
		writer.Record(model.KindTraffic, fmt.Sprintf("req-%d", i), map[string]any{
			"ip":      "203.0.113.7",
			"verdict": verdict,
			"rule":    "sqli",
			"path":    "/products",
			"seq":     i,
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := writer.Close(ctx); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	if got := len(repo.Entries()); got != n {
		t.Fatalf("wrote %d entries, want %d", got, n)
	}
	return repo
}

func TestVerifyChainAcceptsAnIntactChain(t *testing.T) {
	repo := seed(t, 25)

	result, err := repo.VerifyChain(context.Background(), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !result.OK {
		t.Fatalf("intact chain reported as broken: %+v", result)
	}
	if result.Checked != 25 {
		t.Fatalf("checked %d entries, want 25", result.Checked)
	}
}

// This is the property the whole of §6 rests on: a modified record is caught,
// and the report names the exact entry.
func TestVerifyChainDetectsAModifiedPayload(t *testing.T) {
	repo := seed(t, 25)

	// seed blocks every third request, so index 12 is a block.
	target := repo.Entries()[12]
	if target.Payload["verdict"] != string(model.Block) {
		t.Fatalf("fixture drift: entry 12 is %v, want a blocked request", target.Payload["verdict"])
	}

	repo.Tamper(12, func(e *model.AuditEntry) {
		e.Payload["verdict"] = string(model.Allow) // rewrite a block as an allow
	})

	result, err := repo.VerifyChain(context.Background(), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if result.OK {
		t.Fatal("a rewritten payload went undetected")
	}
	if result.BrokenAt != target.ID {
		t.Fatalf("blamed entry %s, want %s", result.BrokenAt, target.ID)
	}
	if result.Position != 13 {
		t.Fatalf("reported position %d, want 13 (1-based)", result.Position)
	}
}

// Deleting an entry leaves every remaining hash individually valid; only the
// link between neighbours reveals the gap.
func TestVerifyChainDetectsADeletedEntry(t *testing.T) {
	repo := seed(t, 25)
	next := repo.Entries()[8] // the entry that will follow the gap

	repo.Truncate(7)

	result, err := repo.VerifyChain(context.Background(), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if result.OK {
		t.Fatal("a deleted entry went undetected")
	}
	if result.BrokenAt != next.ID {
		t.Fatalf("blamed entry %s, want %s (the entry after the gap)", result.BrokenAt, next.ID)
	}
}

func TestVerifyChainDetectsAResealedEntry(t *testing.T) {
	repo := seed(t, 10)

	// The most patient forger: rewrite the payload *and* recompute that entry's
	// own hash so it is internally consistent. The link to the next entry still
	// gives it away.
	if got := repo.Entries()[3].Payload["verdict"]; got != string(model.Block) {
		t.Fatalf("fixture drift: entry 3 is %v, want a blocked request", got)
	}
	repo.Tamper(3, func(e *model.AuditEntry) {
		e.Payload["verdict"] = string(model.Allow)
		e.Hash = e.ComputeHash()
	})

	result, err := repo.VerifyChain(context.Background(), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if result.OK {
		t.Fatal("a resealed entry went undetected")
	}
	if result.Position != 5 {
		t.Fatalf("reported position %d, want 5: the break surfaces at the next entry", result.Position)
	}
}

func TestVerifyChainOnEmptyAndSingleEntryLogs(t *testing.T) {
	empty := NewMemory()
	result, err := empty.VerifyChain(context.Background(), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain on empty log: %v", err)
	}
	if !result.OK || result.Checked != 0 {
		t.Fatalf("empty log: %+v, want ok with 0 checked", result)
	}

	single := seed(t, 1)
	result, err = single.VerifyChain(context.Background(), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain on single-entry log: %v", err)
	}
	if !result.OK || result.Checked != 1 {
		t.Fatalf("single-entry log: %+v, want ok with 1 checked", result)
	}
}

func TestHeadIsGenesisOnAnEmptyLog(t *testing.T) {
	head, err := NewMemory().Head(context.Background())
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if head != model.GenesisHash {
		t.Fatalf("Head = %q, want the genesis hash", head)
	}
}

// A writer restarted against an existing log must continue the same chain
// rather than starting a second one.
func TestWriterResumesTheChainAcrossRestarts(t *testing.T) {
	repo := seed(t, 5)
	headBefore, _ := repo.Head(context.Background())

	writer, err := NewWriter(context.Background(), repo, WriterOptions{Buffer: 8})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	writer.Record(model.KindSystem, "", map[string]any{"event": "engine_started"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := writer.Close(ctx); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	entries := repo.Entries()
	resumed := entries[len(entries)-1]
	if resumed.PrevHash != headBefore {
		t.Fatalf("restarted writer linked to %s, want the previous head %s",
			resumed.PrevHash, headBefore)
	}

	result, err := repo.VerifyChain(context.Background(), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !result.OK {
		t.Fatalf("chain broken after restart: %+v", result)
	}
}

// Verifying a slice of the history must anchor on the entry before the range.
// Without that anchor, a forger could rewrite the first entry of the range —
// payload, hash and prev_hash together, so it is self-consistent — and a
// range-scoped verification would have nothing to compare it against.
func TestVerifyChainAnchorsARangeToTheEntryBeforeIt(t *testing.T) {
	repo := seed(t, 20)
	entries := repo.Entries()
	from := entries[10].Timestamp

	repo.Tamper(10, func(e *model.AuditEntry) {
		e.Payload["verdict"] = string(model.Allow)
		e.PrevHash = model.GenesisHash // pretend the history starts here
		e.Hash = e.ComputeHash()
	})

	result, err := repo.VerifyChain(context.Background(), from, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if result.OK {
		t.Fatal("range verification accepted a self-consistent forged first entry")
	}
	if result.Position != 1 {
		t.Fatalf("reported position %d, want 1: the break is the range's first entry", result.Position)
	}
	if result.BrokenAt != entries[10].ID {
		t.Fatalf("blamed entry %s, want %s", result.BrokenAt, entries[10].ID)
	}
}

func TestWriterRecordAfterCloseDoesNotPanic(t *testing.T) {
	repo := NewMemory()
	writer, err := NewWriter(context.Background(), repo, WriterOptions{Buffer: 4})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := writer.Close(ctx); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	writer.Record(model.KindSystem, "", map[string]any{"event": "late"})

	if got := writer.Stats().Dropped; got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
	if got := len(repo.Entries()); got != 0 {
		t.Fatalf("wrote %d entries after Close, want 0", got)
	}
}

func TestListAppliesFiltersAndPagination(t *testing.T) {
	repo := seed(t, 30)
	ctx := context.Background()

	blocked, err := repo.List(ctx, Filter{Verdict: string(model.Block), Limit: 5})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(blocked) != 5 {
		t.Fatalf("got %d entries, want the 5-entry page", len(blocked))
	}
	for _, e := range blocked {
		if e.Payload["verdict"] != string(model.Block) {
			t.Fatalf("filter leaked a non-blocked entry: %v", e.Payload["verdict"])
		}
	}

	total, err := repo.Count(ctx, Filter{Verdict: string(model.Block)})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if total != 10 {
		t.Fatalf("counted %d blocked entries, want 10", total)
	}
}
