package audit

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/open-shield/open-shield/internal/model"
)

// Publisher receives every entry that reaches the log. The Redis publisher
// implements it; the writer does not know or care who is listening, which is
// the decoupling described in §5.4.
type Publisher interface {
	Publish(ctx context.Context, entry model.AuditEntry) error
}

// queued is one entry on its way to the store. done is non-nil only for
// synchronous callers, who wait for the append to be durable.
type queued struct {
	entry model.AuditEntry
	done  chan error
}

// Writer is the only component allowed to append to the audit log.
//
// It is a single goroutine behind a buffered channel, for two reasons:
//
//   - Correctness. Each entry's hash covers the hash of the entry before it, so
//     appends must happen in a strict order. Two goroutines sealing entries
//     against the same head would produce a forked, unverifiable chain.
//   - Latency. §8.2 budgets the proxy under 50 ms of added latency. Blocking a
//     request on a database INSERT would spend that budget on bookkeeping, so
//     the verdict returns as soon as the rules decide and the entry is written
//     behind it.
//
// The trade-off is a small window in which a decision has been served but not
// yet persisted. Close flushes the buffer to keep that window bounded by
// shutdown rather than losing it.
type Writer struct {
	repo  Repository
	pub   Publisher
	log   *slog.Logger
	now   func() time.Time
	queue chan queued
	done  chan struct{}

	// closeMu guards the queue against a send racing with the close in Close.
	// A send on a closed channel panics outright — it does not fall through to
	// the select's default — so the check and the send have to be atomic.
	closeMu sync.RWMutex
	closed  bool

	head string // only touched by the writer goroutine

	dropped  atomic.Int64
	written  atomic.Int64
	failures atomic.Int64
}

// WriterOptions configures the append pipeline.
type WriterOptions struct {
	// Buffer is the depth of the queue between the request path and the
	// database. Default 4096.
	Buffer int
	// Publisher receives entries after they are persisted. Optional.
	Publisher Publisher
	// Logger receives write failures. Defaults to slog.Default().
	Logger *slog.Logger
	// Clock supplies entry timestamps. Defaults to time.Now. Tests override it
	// to get a strictly increasing sequence, which real traffic does not
	// guarantee: several requests can land inside the same microsecond.
	Clock func() time.Time
}

// NewWriter resumes the chain from the current head of the log and starts the
// append goroutine.
func NewWriter(ctx context.Context, repo Repository, opts WriterOptions) (*Writer, error) {
	if repo == nil {
		return nil, errors.New("audit: writer requires a repository")
	}
	if opts.Buffer <= 0 {
		opts.Buffer = 4096
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}

	head, err := repo.Head(ctx)
	if err != nil {
		return nil, err
	}
	if head == "" {
		head = model.GenesisHash
	}

	w := &Writer{
		repo:  repo,
		pub:   opts.Publisher,
		log:   opts.Logger,
		now:   opts.Clock,
		queue: make(chan queued, opts.Buffer),
		done:  make(chan struct{}),
		head:  head,
	}
	go w.run()
	return w, nil
}

// Record queues an entry. It never blocks: if the queue is full the entry is
// dropped and counted.
//
// Dropping is deliberate. The alternative — blocking the request path on a
// slow database — would turn an audit backlog into an outage of the site the
// proxy is supposed to protect. Drops are counted, logged and exposed on the
// dashboard so the condition is visible rather than silent.
func (w *Writer) Record(kind, requestID string, payload map[string]any) {
	w.closeMu.RLock()
	defer w.closeMu.RUnlock()

	if w.closed {
		w.dropped.Add(1)
		return
	}

	select {
	case w.queue <- queued{entry: w.build(kind, requestID, payload)}:
	default:
		n := w.dropped.Add(1)
		if n == 1 || n%1000 == 0 {
			w.log.Warn("audit queue full, dropping entry",
				"dropped_total", n, "kind", kind, "request_id", requestID)
		}
	}
}

// RecordSync appends an entry and waits until it is durable.
//
// Administrative changes use it. §6.1 requires every configuration change to be
// on the record, so the dashboard applies a change only after its audit entry
// is committed — an unaudited change to what the proxy blocks is worse than a
// change that could not be made.
//
// Traffic decisions must never use this: it blocks the caller on a database
// write, which is exactly what the async path exists to avoid.
func (w *Writer) RecordSync(ctx context.Context, kind, requestID string, payload map[string]any) error {
	done := make(chan error, 1)

	w.closeMu.RLock()
	if w.closed {
		w.closeMu.RUnlock()
		return errors.New("audit: writer is closed")
	}

	select {
	case w.queue <- queued{entry: w.build(kind, requestID, payload), done: done}:
		w.closeMu.RUnlock()
	case <-ctx.Done():
		w.closeMu.RUnlock()
		return ctx.Err()
	}

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *Writer) build(kind, requestID string, payload map[string]any) model.AuditEntry {
	return model.AuditEntry{
		ID:        uuid.NewString(),
		RequestID: requestID,
		// PostgreSQL's timestamptz keeps microseconds. Truncating here means the
		// timestamp that gets hashed is the same one that comes back on a read;
		// hashing nanoseconds that the store cannot keep would make every entry
		// fail verification after a round trip.
		Timestamp: w.now().UTC().Truncate(time.Microsecond),
		Kind:      kind,
		Payload:   payload,
	}
}

func (w *Writer) run() {
	defer close(w.done)
	for item := range w.queue {
		err := w.append(item.entry)
		if item.done != nil {
			item.done <- err
		}
	}
}

func (w *Writer) append(entry model.AuditEntry) error {
	// Normalising before sealing means the hash is computed over exactly the
	// value shape that will come back out of the store.
	payload, err := model.NormalizePayload(entry.Payload)
	if err != nil {
		w.failures.Add(1)
		w.log.Error("audit payload cannot be canonicalised", "error", err, "id", entry.ID)
		return err
	}
	entry.Payload = payload
	entry.Seal(w.head)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := w.repo.Append(ctx, entry); err != nil {
		// The head is left untouched: the next entry links to the last one that
		// really made it into the store, so the chain stays continuous instead
		// of pointing at an entry that does not exist.
		w.failures.Add(1)
		w.log.Error("audit append failed", "error", err, "id", entry.ID, "kind", entry.Kind)
		return err
	}

	w.head = entry.Hash
	w.written.Add(1)

	if w.pub != nil {
		if err := w.pub.Publish(ctx, entry); err != nil {
			// A dashboard that misses a live event is a cosmetic problem; the
			// entry is already durable. Log and carry on.
			w.log.Warn("audit event publish failed", "error", err, "id", entry.ID)
		}
	}
	return nil
}

// Stats reports the writer's counters for the dashboard health view.
func (w *Writer) Stats() WriterStats {
	return WriterStats{
		Written:  w.written.Load(),
		Dropped:  w.dropped.Load(),
		Failures: w.failures.Load(),
		Queued:   len(w.queue),
		Capacity: cap(w.queue),
	}
}

// WriterStats is a snapshot of the append pipeline's health.
type WriterStats struct {
	Written  int64 `json:"written"`
	Dropped  int64 `json:"dropped"`
	Failures int64 `json:"failures"`
	Queued   int   `json:"queued"`
	Capacity int   `json:"capacity"`
}

// Close drains the queue and stops the writer. It is safe to call more than
// once. Entries queued before Close are written; Record after Close is a no-op
// that counts as a drop.
func (w *Writer) Close(ctx context.Context) error {
	w.closeMu.Lock()
	if !w.closed {
		w.closed = true
		close(w.queue)
	}
	w.closeMu.Unlock()

	select {
	case <-w.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
