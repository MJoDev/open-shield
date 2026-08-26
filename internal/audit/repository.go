// Package audit owns the forensic log described in section 6 of the technical
// document: an append-only chain of entries where each one carries the hash of
// its predecessor, so that altering or deleting any entry in the middle of the
// history is detectable.
//
// The rules engine never writes SQL against the store directly. It talks to the
// Repository interface (the AuditRepository of §5.3), which is what allows the
// storage engine to change — SQLite on a small installation, PostgreSQL on a
// busier one — without touching the decision logic.
package audit

import (
	"context"
	"time"

	"github.com/open-shield/open-shield/internal/model"
)

// Repository is the storage-agnostic view of the audit log.
//
// It extends the two methods sketched in §5.3 with the reads the dashboard
// needs. VerifyChain also returns a VerifyResult rather than a bare bool: when
// the chain is broken, the operator's first question is "where", and only the
// store can answer it while walking the history.
type Repository interface {
	// Append writes one sealed entry at the end of the chain. Callers must
	// serialise their calls; see Writer, which is the only supported way to
	// append in this system.
	Append(ctx context.Context, entry model.AuditEntry) error

	// VerifyChain recomputes every hash in the given time range and reports the
	// first entry, if any, that does not match. A zero From or To means
	// unbounded on that side.
	VerifyChain(ctx context.Context, from, to time.Time) (VerifyResult, error)

	// Head returns the hash of the most recent entry, or the genesis hash if
	// the log is empty. The engine calls it at startup to resume the chain.
	Head(ctx context.Context) (string, error)

	// List returns entries newest-first for the dashboard.
	List(ctx context.Context, f Filter) ([]model.AuditEntry, error)

	// Count returns how many entries match a filter, ignoring Limit/Offset.
	Count(ctx context.Context, f Filter) (int64, error)

	// Stats summarises traffic over a window for the dashboard overview.
	Stats(ctx context.Context, window time.Duration) (Stats, error)

	// Close releases the underlying connections.
	Close() error
}

// Filter selects a slice of the audit log. Zero values mean "no constraint".
type Filter struct {
	Kind      string
	Verdict   string
	IP        string
	Rule      string
	RequestID string
	From      time.Time
	To        time.Time
	Limit     int
	Offset    int
}

// Normalized clamps pagination to sane bounds so a dashboard query cannot ask
// the database for the entire history.
//
// It is exported because a caller has to be able to report the limit that was
// actually applied. A response that echoes back a limit the store silently
// reduced makes a paginating client step over the entries it never received.
// Applying it twice is the same as applying it once.
func (f Filter) Normalized() Filter {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Limit > 500 {
		f.Limit = 500
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	return f
}

// VerifyResult reports the outcome of walking the hash chain.
type VerifyResult struct {
	OK      bool   `json:"ok"`
	Checked int64  `json:"checked"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`

	// Set only when OK is false.
	BrokenAt  string `json:"broken_at,omitempty"` // entry ID
	Position  int64  `json:"position,omitempty"`  // 1-based position within the verified range
	Timestamp string `json:"timestamp,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Stats is the traffic summary shown on the dashboard overview.
type Stats struct {
	Window   string      `json:"window"`
	Total    int64       `json:"total"`
	Allowed  int64       `json:"allowed"`
	Blocked  int64       `json:"blocked"`
	TopIPs   []CountedBy `json:"top_ips"`
	TopRules []CountedBy `json:"top_rules"`
	Series   []Bucket    `json:"series"`
}

// CountedBy is a "label with a count" row, used for top IPs and top rules.
type CountedBy struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

// Bucket is one time slice of the allowed/blocked series.
type Bucket struct {
	Start   time.Time `json:"start"`
	Allowed int64     `json:"allowed"`
	Blocked int64     `json:"blocked"`
}
