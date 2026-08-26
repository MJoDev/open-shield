package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-shield/open-shield/internal/model"
)

// The Writer is the single point where the forensic chain is extended, and two
// of its properties are the ones the whole scheme rests on: appends are
// strictly ordered, and they never block the request path. Both are invisible
// in ordinary use and both fail silently, so they are tested directly here.
//
// audit_test.go covers what the chain looks like once written; this file covers
// how it gets written.

// --- Ordering ---------------------------------------------------------------

// TestWriterKeepsTheChainLinearUnderConcurrentRecords is the reason the writer
// is one goroutine behind a channel rather than a mutex around an append.
//
// Every entry's hash covers the hash of the entry before it. Two goroutines
// sealing against the same head would each produce a valid-looking entry
// pointing at the same predecessor — a fork, not a chain, and VerifyChain would
// report the log tampered with when nothing had touched it.
//
// Run with -race, this is also the check that Record itself is safe to call
// from every request handler at once.
func TestWriterKeepsTheChainLinearUnderConcurrentRecords(t *testing.T) {
	const writers = 50
	const perWriter = 20

	repo := NewMemory()
	// The real clock on purpose: build() runs on the calling goroutine, so the
	// sequential testClock the other tests use would itself be the race. It
	// costs nothing here — chain order is the append order, never the
	// timestamp, and several of these entries will share a microsecond.
	writer, err := NewWriter(context.Background(), repo, WriterOptions{
		Buffer: writers * perWriter,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				writer.Record(model.KindTraffic, fmt.Sprintf("req-%d-%d", w, i), map[string]any{
					"ip":      "203.0.113.7",
					"verdict": string(model.Allow),
					"worker":  w,
				})
			}
		}(w)
	}
	wg.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := writer.Close(ctx); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	entries := repo.Entries()
	if len(entries) != writers*perWriter {
		t.Fatalf("wrote %d entries, want %d — the buffer was large enough for all of them",
			len(entries), writers*perWriter)
	}

	// Every link, checked by hand rather than through VerifyChain, so a failure
	// names the position rather than just saying the chain is broken.
	prev := model.GenesisHash
	for i, e := range entries {
		if e.PrevHash != prev {
			t.Fatalf("entry %d links to %s, but the entry before it hashed to %s — the chain forked",
				i, short(e.PrevHash), short(prev))
		}
		if e.Hash != e.ComputeHash() {
			t.Fatalf("entry %d does not hash to its own content", i)
		}
		prev = e.Hash
	}

	result, err := repo.VerifyChain(ctx, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !result.OK {
		t.Fatalf("VerifyChain reports the chain broken at %s: %s", result.BrokenAt, result.Detail)
	}
}

// --- Not blocking the request path ------------------------------------------

// blockingRepo holds every append until it is released. It stands in for a
// database that has stopped keeping up with traffic.
type blockingRepo struct {
	*Memory
	release chan struct{}
	waiting atomic.Int64
}

func newBlockingRepo() *blockingRepo {
	return &blockingRepo{Memory: NewMemory(), release: make(chan struct{})}
}

func (r *blockingRepo) Append(ctx context.Context, entry model.AuditEntry) error {
	r.waiting.Add(1)
	<-r.release
	return r.Memory.Append(ctx, entry)
}

// TestWriterDropsInsteadOfBlockingWhenTheQueueIsFull pins the trade-off of
// §8.2: when the audit queue fills, entries are dropped and counted, and the
// caller returns immediately.
//
// Dropping evidence is a real cost, and it is still the right one. The
// alternative is blocking the request path on a slow database, which turns an
// audit backlog into an outage of the site the proxy exists to protect. The
// drops are counted so the condition is visible on the dashboard rather than
// silent.
func TestWriterDropsInsteadOfBlockingWhenTheQueueIsFull(t *testing.T) {
	const buffer = 4
	const attempts = 200

	repo := newBlockingRepo()
	writer, err := NewWriter(context.Background(), repo, WriterOptions{
		Buffer: buffer,
		Clock:  testClock(epoch),
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	// If Record blocks, this never finishes — which is the failure this test
	// exists to catch, so it is bounded by the timeout rather than by a
	// deadlock detector.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < attempts; i++ {
			writer.Record(model.KindTraffic, fmt.Sprintf("req-%d", i), map[string]any{"i": i})
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Record blocked with a full queue; it must drop and return")
	}

	stats := writer.Stats()
	if stats.Dropped == 0 {
		t.Fatalf("nothing was dropped after %d records into a queue of %d", attempts, buffer)
	}
	if stats.Capacity != buffer {
		t.Errorf("Stats().Capacity = %d, want %d", stats.Capacity, buffer)
	}

	close(repo.release)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := writer.Close(ctx); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	// Nothing may be invented or double-counted: every attempt was either
	// written or dropped.
	final := writer.Stats()
	if final.Written+final.Dropped != attempts {
		t.Fatalf("written %d + dropped %d = %d, want %d accounted for",
			final.Written, final.Dropped, final.Written+final.Dropped, attempts)
	}
	if int64(len(repo.Entries())) != final.Written {
		t.Fatalf("store holds %d entries but the writer counted %d written",
			len(repo.Entries()), final.Written)
	}

	// What did survive is still a valid chain: dropping entries at the tail
	// leaves no hole, because a dropped entry was never sealed.
	result, err := repo.VerifyChain(ctx, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !result.OK {
		t.Fatalf("dropping entries broke the chain at %s: %s", result.BrokenAt, result.Detail)
	}
}

// --- When the store refuses -------------------------------------------------

// flakyRepo fails a configurable number of appends, then succeeds.
type flakyRepo struct {
	*Memory
	failures atomic.Int64
}

func (r *flakyRepo) Append(ctx context.Context, entry model.AuditEntry) error {
	if r.failures.Load() > 0 {
		r.failures.Add(-1)
		return errors.New("store unavailable")
	}
	return r.Memory.Append(ctx, entry)
}

// TestWriterKeepsTheHeadContinuousAcrossAFailedAppend covers the subtle half of
// append(): when the store rejects an entry, the head is left pointing at the
// last entry that really made it in.
//
// Advancing it would leave the next entry linked to a predecessor that does not
// exist, and the chain would fail to verify from that point on — a database
// hiccup would look exactly like tampering.
func TestWriterKeepsTheHeadContinuousAcrossAFailedAppend(t *testing.T) {
	repo := &flakyRepo{Memory: NewMemory()}
	writer, err := NewWriter(context.Background(), repo, WriterOptions{
		Buffer: 16,
		Clock:  testClock(epoch),
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := writer.RecordSync(ctx, model.KindSystem, "ok-1", map[string]any{"n": 1}); err != nil {
		t.Fatalf("first append: %v", err)
	}

	repo.failures.Store(1)
	if err := writer.RecordSync(ctx, model.KindSystem, "lost", map[string]any{"n": 2}); err == nil {
		t.Fatal("RecordSync returned nil for an append the store rejected")
	}

	if err := writer.RecordSync(ctx, model.KindSystem, "ok-2", map[string]any{"n": 3}); err != nil {
		t.Fatalf("third append: %v", err)
	}

	if err := writer.Close(ctx); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	entries := repo.Entries()
	if len(entries) != 2 {
		t.Fatalf("store holds %d entries, want 2", len(entries))
	}
	if entries[1].PrevHash != entries[0].Hash {
		t.Fatalf("the entry after the failure links to %s, want %s — the head advanced over an entry that was never stored",
			short(entries[1].PrevHash), short(entries[0].Hash))
	}

	result, err := repo.VerifyChain(ctx, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !result.OK {
		t.Fatalf("a rejected append broke the chain: %s", result.Detail)
	}

	if stats := writer.Stats(); stats.Failures != 1 {
		t.Errorf("Stats().Failures = %d, want 1 — a rejected append must be counted", stats.Failures)
	}
}

// RecordSync is what the dashboard uses, and its whole point is that the caller
// learns whether the entry is durable. §6.1 requires every administrative
// change to be on the record, so a change whose entry could not be committed is
// refused rather than applied.
func TestRecordSyncReportsAFailedAppend(t *testing.T) {
	repo := &flakyRepo{Memory: NewMemory()}
	repo.failures.Store(1)

	writer, err := NewWriter(context.Background(), repo, WriterOptions{Buffer: 4, Clock: testClock(epoch)})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := writer.RecordSync(ctx, model.KindAdmin, "admin-1", map[string]any{"action": "rule.disable"}); err == nil {
		t.Fatal("RecordSync reported success for an append that failed")
	}
	if err := writer.Close(ctx); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}
	if len(repo.Entries()) != 0 {
		t.Fatalf("store holds %d entries, want none", len(repo.Entries()))
	}
}

func TestRecordSyncRefusesAfterClose(t *testing.T) {
	repo := NewMemory()
	writer, err := NewWriter(context.Background(), repo, WriterOptions{Buffer: 4, Clock: testClock(epoch)})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := writer.Close(ctx); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	// A send on a closed channel panics outright, so the closed check and the
	// send have to be atomic. Calling Close twice must also be safe: shutdown
	// runs it, and so does anything that shuts down early.
	if err := writer.RecordSync(ctx, model.KindAdmin, "late", nil); err == nil {
		t.Fatal("RecordSync succeeded after Close")
	}
	if err := writer.Close(ctx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// --- Publishing -------------------------------------------------------------

// countingPublisher stands in for the Redis publisher behind the live feed.
type countingPublisher struct {
	mu        sync.Mutex
	published []model.AuditEntry
	err       error
}

func (p *countingPublisher) Publish(_ context.Context, entry model.AuditEntry) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.published = append(p.published, entry)
	return p.err
}

func (p *countingPublisher) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.published)
}

// A dashboard that misses a live event has a cosmetic problem; the entry is
// already durable. A publisher failure must therefore not fail the append, or a
// Redis outage would start costing audit entries.
func TestPublisherFailureDoesNotFailTheAppend(t *testing.T) {
	repo := NewMemory()
	pub := &countingPublisher{err: errors.New("redis unreachable")}

	writer, err := NewWriter(context.Background(), repo, WriterOptions{
		Buffer:    16,
		Publisher: pub,
		Clock:     testClock(epoch),
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := writer.RecordSync(ctx, model.KindTraffic, "req-1", map[string]any{"ip": "203.0.113.7"}); err != nil {
		t.Fatalf("RecordSync: %v", err)
	}
	if err := writer.Close(ctx); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	if len(repo.Entries()) != 1 {
		t.Fatalf("store holds %d entries, want 1 — a failed publish must not lose the entry", len(repo.Entries()))
	}
	if pub.count() != 1 {
		t.Fatalf("publisher saw %d entries, want 1", pub.count())
	}
	if stats := writer.Stats(); stats.Failures != 0 {
		t.Errorf("Stats().Failures = %d, want 0 — a publish failure is not an append failure", stats.Failures)
	}
}

// Only entries that are durable reach the live feed. The dashboard shows the
// feed as what is happening; an event for an entry the store rejected would be
// showing something that never made it onto the record.
func TestPublisherOnlySeesEntriesThatWereStored(t *testing.T) {
	repo := &flakyRepo{Memory: NewMemory()}
	repo.failures.Store(1)
	pub := &countingPublisher{}

	writer, err := NewWriter(context.Background(), repo, WriterOptions{
		Buffer:    16,
		Publisher: pub,
		Clock:     testClock(epoch),
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_ = writer.RecordSync(ctx, model.KindTraffic, "rejected", map[string]any{"n": 1})
	if err := writer.RecordSync(ctx, model.KindTraffic, "stored", map[string]any{"n": 2}); err != nil {
		t.Fatalf("second append: %v", err)
	}
	if err := writer.Close(ctx); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	if pub.count() != 1 {
		t.Fatalf("publisher saw %d entries, want only the one that was stored", pub.count())
	}
	if pub.published[0].RequestID != "stored" {
		t.Fatalf("published %q, want %q", pub.published[0].RequestID, "stored")
	}
}

// --- Construction -----------------------------------------------------------

func TestNewWriterRequiresARepository(t *testing.T) {
	if _, err := NewWriter(context.Background(), nil, WriterOptions{}); err == nil {
		t.Fatal("NewWriter accepted a nil repository")
	}
}

// A writer that cannot read the current head cannot know what to link to. It
// must refuse to start rather than begin a second chain from genesis, which
// would look like the log had been truncated.
func TestNewWriterRefusesWhenTheHeadCannotBeRead(t *testing.T) {
	repo := &unreadableRepo{Memory: NewMemory()}

	if _, err := NewWriter(context.Background(), repo, WriterOptions{}); err == nil {
		t.Fatal("NewWriter started without knowing the head of the chain")
	}
}

type unreadableRepo struct{ *Memory }

func (r *unreadableRepo) Head(context.Context) (string, error) {
	return "", errors.New("store unavailable")
}
