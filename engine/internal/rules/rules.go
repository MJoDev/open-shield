// Package rules implements the decision core: a chain of interchangeable
// filters, each one a small self-contained check, evaluated in order until one
// of them blocks.
//
// This is the Strategy pattern of §5.2. The engine knows the Rule interface and
// nothing else — not what SQL injection looks like, not how a rate limit is
// counted. Adding a rule means adding a type; the engine does not change.
package rules

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/open-shield/open-shield/internal/model"
)

// Rule is one link of the chain. A rule answers with model.Block and a reason,
// or with model.Allow and an empty reason.
//
// A rule must not mutate the request, must not block on I/O it cannot bound,
// and must be safe to call from many goroutines at once: every inbound request
// runs the whole chain concurrently.
type Rule interface {
	Name() string
	Evaluate(ctx context.Context, req *model.RequestContext) (model.Verdict, string)
}

// statusRule is an optional extension: a rule that wants a specific HTTP status
// when it blocks. Rate limiting answers 429; everything else defaults to 403.
//
// Keeping this out of Rule itself means a new rule only has to implement two
// methods, which is what makes the interface cheap to satisfy.
type statusRule interface {
	BlockStatus() int
}

// Engine evaluates the chain.
type Engine struct {
	rules []Rule

	// enabled is swapped wholesale when the dashboard toggles a rule, so a
	// running evaluation always sees a consistent set.
	mu      sync.RWMutex
	enabled map[string]bool
}

// New builds an engine over an ordered chain of rules. Order matters: the first
// Block wins, so cheap checks (an IP list lookup) come before expensive ones
// (scanning a body for patterns).
func New(chain []Rule) *Engine {
	enabled := make(map[string]bool, len(chain))
	for _, r := range chain {
		enabled[r.Name()] = true
	}
	return &Engine{rules: chain, enabled: enabled}
}

// SetEnabled replaces the enabled-rule set. Names not present in the chain are
// ignored; rules missing from the map are treated as disabled.
func (e *Engine) SetEnabled(enabled map[string]bool) {
	next := make(map[string]bool, len(e.rules))
	for _, r := range e.rules {
		next[r.Name()] = enabled[r.Name()]
	}

	e.mu.Lock()
	e.enabled = next
	e.mu.Unlock()
}

// Enabled reports the current on/off state of every rule in the chain.
func (e *Engine) Enabled() map[string]bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	out := make(map[string]bool, len(e.enabled))
	for name, on := range e.enabled {
		out[name] = on
	}
	return out
}

// Names lists the chain in evaluation order.
func (e *Engine) Names() []string {
	out := make([]string, 0, len(e.rules))
	for _, r := range e.rules {
		out = append(out, r.Name())
	}
	return out
}

// Decide runs the chain and returns the first block, or an allow if every rule
// passed. DecisionMS is filled in for the audit record (§6.1).
//
// The context is a parameter rather than a field on Engine: it belongs to the
// request being decided, and it carries the deadline that keeps a slow rule
// from spending the proxy's whole latency budget.
func (e *Engine) Decide(ctx context.Context, req *model.RequestContext) model.Decision {
	start := time.Now()

	e.mu.RLock()
	enabled := e.enabled
	e.mu.RUnlock()

	for _, rule := range e.rules {
		if !enabled[rule.Name()] {
			continue
		}

		verdict, reason := rule.Evaluate(ctx, req)
		if verdict == model.Block {
			return model.Decision{
				Verdict:    model.Block,
				Rule:       rule.Name(),
				Reason:     reason,
				Status:     blockStatus(rule),
				DecisionMS: millisSince(start),
			}
		}
	}

	return model.Decision{
		Verdict:    model.Allow,
		DecisionMS: millisSince(start),
	}
}

func blockStatus(rule Rule) int {
	if sr, ok := rule.(statusRule); ok {
		if status := sr.BlockStatus(); status != 0 {
			return status
		}
	}
	return http.StatusForbidden
}

func millisSince(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000.0
}
