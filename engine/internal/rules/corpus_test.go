package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/open-shield/open-shield/internal/model"
	"github.com/open-shield/open-shield/test/corpus"
)

// This file drives the shared corpus (test/corpus) through the real signature
// set. The hand-written cases in rules_test.go check the mechanics of a
// PatternRule; these check the detection itself, and they are the same vectors
// the end-to-end suite and the k6 attack scenario replay against a live stack.
// A vector added to the corpus is therefore covered at all three levels at once.

// signatureChain builds the two content rules in the production order — sqli
// before xss — because attribution depends on it: whichever rule blocks first
// is the one named in the audit entry.
func signatureChain(t *testing.T) *Engine {
	t.Helper()

	set, err := LoadSignatures("")
	if err != nil {
		t.Fatalf("LoadSignatures: %v", err)
	}
	return New([]Rule{
		NewPatternRule("sqli", set.SQLi, 8192),
		NewPatternRule("xss", set.XSS, 8192),
	})
}

func TestCorpusAttacksAreBlockedByTheExpectedSignature(t *testing.T) {
	chain := signatureChain(t)

	for _, c := range corpus.Attacks() {
		t.Run(c.ID, func(t *testing.T) {
			req := c.RequestContext("203.0.113.7")
			decision := chain.Decide(context.Background(), &req)

			if decision.Verdict != model.Block {
				t.Fatalf("allowed %s\n  case: %s", c.Decoded(), c.Description)
			}

			// Attribution matters as much as the block itself: the audit entry
			// names the rule, and an operator reading it has to be able to tell
			// an injection attempt from a cross-site scripting attempt.
			if decision.Rule != c.Rule {
				t.Errorf("blocked by %q, want %q\n  case: %s", decision.Rule, c.Rule, c.Decoded())
			}

			// The reason carries the signature id (see PatternRule.Evaluate).
			// Pinning it means a vector that starts matching some *other*
			// signature shows up as a failure rather than as a silent change in
			// what the forensic log will say about it.
			if got := signatureFrom(decision.Reason); got != c.Signature {
				t.Errorf("signature = %q, want %q\n  reason: %s", got, c.Signature, decision.Reason)
			}
		})
	}
}

// TestCorpusBenignTrafficIsAllowed is the false-positive budget, and the budget
// is zero. A filter that blocks O'Brien from signing in, or an article about the
// European Union, gets switched off by the operator — and then it catches
// nothing at all. A false positive is not a lesser failure than a miss.
func TestCorpusBenignTrafficIsAllowed(t *testing.T) {
	chain := signatureChain(t)

	for _, c := range corpus.Benign() {
		t.Run(c.ID, func(t *testing.T) {
			req := c.RequestContext("203.0.113.7")
			decision := chain.Decide(context.Background(), &req)

			if decision.Verdict != model.Allow {
				t.Fatalf("false positive on %s\n  case:   %s\n  rule:   %s\n  reason: %s",
					c.Decoded(), c.Description, decision.Rule, decision.Reason)
			}
		})
	}
}

// TestCorpusBlockReasonsAreBounded guards the rule of §6 that the log records
// *why* a request was blocked without becoming a copy of the request. Every
// reason ends up in an append-only store with long retention, so an excerpt
// that grows without bound is a slow leak of attacker-controlled input into it.
func TestCorpusBlockReasonsAreBounded(t *testing.T) {
	chain := signatureChain(t)

	// excerpt allows a 60-character window; the rest is the rule name, the
	// signature id and the field name. 256 leaves room for those and still
	// fails loudly if the excerpt stops being an excerpt.
	const maxReason = 256

	for _, c := range corpus.Attacks() {
		req := c.RequestContext("203.0.113.7")
		decision := chain.Decide(context.Background(), &req)

		if len(decision.Reason) > maxReason {
			t.Errorf("%s: reason is %d bytes, want at most %d\n  %s",
				c.ID, len(decision.Reason), maxReason, decision.Reason)
		}
		for _, r := range decision.Reason {
			if r < 0x20 || r == 0x7f {
				t.Errorf("%s: reason carries control character %q: %q", c.ID, r, decision.Reason)
				break
			}
		}
	}
}

// signatureFrom pulls the quoted signature id out of a block reason, which is
// formatted as: <rule> signature "<id>" matched in <field>: <excerpt>
func signatureFrom(reason string) string {
	start := strings.Index(reason, `"`)
	if start < 0 {
		return ""
	}
	rest := reason[start+1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}
