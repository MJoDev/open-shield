package audit

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-shield/open-shield/internal/model"
)

// Memory is an in-memory Repository. It exists so the rule chain, the writer
// and the dashboard handlers can be tested without a database, and so a
// developer can run the engine standalone. It is not a deployment target: the
// log disappears with the process, which is the opposite of what §6 requires.
type Memory struct {
	mu      sync.RWMutex
	entries []model.AuditEntry
}

// NewMemory returns an empty in-memory audit log.
func NewMemory() *Memory { return &Memory{} }

func (m *Memory) Append(_ context.Context, entry model.AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, entry)
	return nil
}

func (m *Memory) Head(_ context.Context) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.entries) == 0 {
		return model.GenesisHash, nil
	}
	return m.entries[len(m.entries)-1].Hash, nil
}

func (m *Memory) VerifyChain(_ context.Context, from, to time.Time) (VerifyResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Anchor on the last entry before the range, exactly as the SQL store does.
	anchor := model.GenesisHash
	start := 0
	for i, e := range m.entries {
		if !from.IsZero() && e.Timestamp.Before(from) {
			anchor = e.Hash
			start = i + 1
			continue
		}
		break
	}

	walker := newChainWalker(anchor)
	for _, e := range m.entries[start:] {
		if !to.IsZero() && e.Timestamp.After(to) {
			break
		}
		if broken := walker.step(e); broken != nil {
			stampRange(broken, from, to)
			return *broken, nil
		}
	}

	result := walker.result()
	stampRange(&result, from, to)
	return result, nil
}

func (m *Memory) List(_ context.Context, f Filter) ([]model.AuditEntry, error) {
	f = f.Normalized()

	m.mu.RLock()
	defer m.mu.RUnlock()

	var matched []model.AuditEntry
	for _, e := range m.entries {
		if memoryMatches(e, f) {
			matched = append(matched, e)
		}
	}
	// Newest first, matching the SQL store's ordering.
	sort.SliceStable(matched, func(i, j int) bool {
		return matched[i].Timestamp.After(matched[j].Timestamp)
	})

	if f.Offset >= len(matched) {
		return nil, nil
	}
	matched = matched[f.Offset:]
	if len(matched) > f.Limit {
		matched = matched[:f.Limit]
	}
	return matched, nil
}

func (m *Memory) Count(_ context.Context, f Filter) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var n int64
	for _, e := range m.entries {
		if memoryMatches(e, f) {
			n++
		}
	}
	return n, nil
}

func (m *Memory) Stats(_ context.Context, window time.Duration) (Stats, error) {
	cutoff := time.Now().UTC().Add(-window)

	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := Stats{Window: window.String()}
	ips := map[string]int64{}
	rules := map[string]int64{}

	for _, e := range m.entries {
		if e.Kind != model.KindTraffic || e.Timestamp.Before(cutoff) {
			continue
		}
		stats.Total++
		if payloadString(e, "verdict") == string(model.Block) {
			stats.Blocked++
			if rule := payloadString(e, "rule"); rule != "" {
				rules[rule]++
			}
			if ip := payloadString(e, "ip"); ip != "" {
				ips[ip]++
			}
		} else {
			stats.Allowed++
		}
	}

	stats.TopIPs = topCounts(ips, 10)
	stats.TopRules = topCounts(rules, 10)
	return stats, nil
}

func (m *Memory) Close() error { return nil }

// Entries returns a copy of the whole log. Tests use it to tamper with an entry
// and confirm that verification catches it.
func (m *Memory) Entries() []model.AuditEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.AuditEntry, len(m.entries))
	copy(out, m.entries)
	return out
}

// Tamper replaces the entry at index i, simulating a write that bypassed the
// append-only path. Test-only.
func (m *Memory) Tamper(i int, mutate func(*model.AuditEntry)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mutate(&m.entries[i])
}

// Truncate deletes the entry at index i, simulating a removed record.
// Test-only.
func (m *Memory) Truncate(i int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries[:i], m.entries[i+1:]...)
}

func memoryMatches(e model.AuditEntry, f Filter) bool {
	if f.Kind != "" && e.Kind != f.Kind {
		return false
	}
	if f.RequestID != "" && e.RequestID != f.RequestID {
		return false
	}
	if f.Verdict != "" && payloadString(e, "verdict") != f.Verdict {
		return false
	}
	if f.IP != "" && payloadString(e, "ip") != f.IP {
		return false
	}
	if f.Rule != "" && payloadString(e, "rule") != f.Rule {
		return false
	}
	if !f.From.IsZero() && e.Timestamp.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && e.Timestamp.After(f.To) {
		return false
	}
	return true
}

func payloadString(e model.AuditEntry, key string) string {
	if e.Payload == nil {
		return ""
	}
	v, ok := e.Payload[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}

func topCounts(counts map[string]int64, limit int) []CountedBy {
	out := make([]CountedBy, 0, len(counts))
	for label, n := range counts {
		out = append(out, CountedBy{Label: label, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Label < out[j].Label
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
