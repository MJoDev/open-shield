package audit

import (
	"fmt"
	"time"

	"github.com/open-shield/open-shield/internal/model"
)

// chainWalker verifies a run of entries incrementally. Both the PostgreSQL and
// the in-memory repositories stream entries through it, so there is exactly one
// implementation of what "the chain is intact" means.
//
// Two things are checked per entry:
//
//  1. the entry's stored hash still matches a fresh ComputeHash of its content
//     — catches a modified payload, timestamp, kind or request id;
//  2. the entry's PrevHash equals the hash of the entry before it — catches a
//     deleted or reordered entry, which leaves the hashes intact individually
//     but breaks the link between them.
type chainWalker struct {
	prev     string
	position int64
}

// newChainWalker anchors verification. anchor is the hash of the entry
// immediately preceding the verified range, or the genesis hash when the range
// starts at the beginning of the log.
//
// Anchoring matters: verifying an arbitrary time range without it would accept
// a history whose first entry had been rewritten, because there would be
// nothing to compare its PrevHash against.
func newChainWalker(anchor string) *chainWalker {
	if anchor == "" {
		anchor = model.GenesisHash
	}
	return &chainWalker{prev: anchor}
}

// step verifies one entry. It returns a non-nil break report for the first
// entry that fails; the caller should stop walking at that point, since every
// later entry is unverifiable relative to a broken link.
func (w *chainWalker) step(entry model.AuditEntry) *VerifyResult {
	w.position++

	if entry.PrevHash != w.prev {
		return w.broken(entry, fmt.Sprintf(
			"prev_hash does not match the previous entry: entry records %s, chain expects %s "+
				"(an entry was deleted, reordered or inserted here)",
			short(entry.PrevHash), short(w.prev)))
	}

	if recomputed := entry.ComputeHash(); recomputed != entry.Hash {
		return w.broken(entry, fmt.Sprintf(
			"stored hash %s does not match the recomputed hash %s "+
				"(this entry's content was modified after it was written)",
			short(entry.Hash), short(recomputed)))
	}

	w.prev = entry.Hash
	return nil
}

func (w *chainWalker) broken(entry model.AuditEntry, detail string) *VerifyResult {
	return &VerifyResult{
		OK:        false,
		Checked:   w.position,
		BrokenAt:  entry.ID,
		Position:  w.position,
		Timestamp: entry.Timestamp.UTC().Format(time.RFC3339Nano),
		Detail:    detail,
	}
}

// result reports a fully verified range.
func (w *chainWalker) result() VerifyResult {
	return VerifyResult{OK: true, Checked: w.position}
}

func short(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12] + "…"
}

// stampRange records the verified window on a result for display.
func stampRange(r *VerifyResult, from, to time.Time) {
	if !from.IsZero() {
		r.From = from.UTC().Format(time.RFC3339)
	}
	if !to.IsZero() {
		r.To = to.UTC().Format(time.RFC3339)
	}
}
