package rules

import (
	"context"
	"net/http"
	"testing"

	"github.com/open-shield/open-shield/internal/model"
)

// stubRule records that it ran and answers a fixed verdict.
type stubRule struct {
	name    string
	verdict model.Verdict
	status  int
	ran     *[]string
}

func (s stubRule) Name() string { return s.name }

func (s stubRule) Evaluate(context.Context, *model.RequestContext) (model.Verdict, string) {
	*s.ran = append(*s.ran, s.name)
	return s.verdict, s.name + " said so"
}

func (s stubRule) BlockStatus() int { return s.status }

func TestDecideStopsAtTheFirstBlock(t *testing.T) {
	var ran []string
	engine := New([]Rule{
		stubRule{name: "first", verdict: model.Allow, ran: &ran},
		stubRule{name: "second", verdict: model.Block, ran: &ran},
		stubRule{name: "third", verdict: model.Block, ran: &ran},
	})

	decision := engine.Decide(context.Background(), &model.RequestContext{IP: "203.0.113.1"})

	if decision.Verdict != model.Block {
		t.Fatalf("verdict = %s, want block", decision.Verdict)
	}
	if decision.Rule != "second" {
		t.Fatalf("attributed to %q, want the first rule that blocked", decision.Rule)
	}
	if len(ran) != 2 {
		t.Fatalf("ran %v; evaluation must stop at the first block", ran)
	}
}

func TestDecideAllowsWhenEveryRulePasses(t *testing.T) {
	var ran []string
	engine := New([]Rule{
		stubRule{name: "a", verdict: model.Allow, ran: &ran},
		stubRule{name: "b", verdict: model.Allow, ran: &ran},
	})

	decision := engine.Decide(context.Background(), &model.RequestContext{IP: "203.0.113.1"})

	if decision.Verdict != model.Allow {
		t.Fatalf("verdict = %s, want allow", decision.Verdict)
	}
	if decision.Rule != "" || decision.Reason != "" {
		t.Fatalf("an allow must not attribute a rule, got %+v", decision)
	}
	if len(ran) != 2 {
		t.Fatalf("ran %v, want the whole chain", ran)
	}
}

func TestDecideSkipsDisabledRules(t *testing.T) {
	var ran []string
	engine := New([]Rule{
		stubRule{name: "off", verdict: model.Block, ran: &ran},
		stubRule{name: "on", verdict: model.Allow, ran: &ran},
	})

	engine.SetEnabled(map[string]bool{"off": false, "on": true})

	decision := engine.Decide(context.Background(), &model.RequestContext{IP: "203.0.113.1"})
	if decision.Verdict != model.Allow {
		t.Fatalf("a disabled rule still blocked: %+v", decision)
	}
	if len(ran) != 1 || ran[0] != "on" {
		t.Fatalf("ran %v, want only the enabled rule", ran)
	}
}

// A rule left out of the enabled map is off, not on. Defaulting the other way
// would silently re-enable a rule an operator had turned off.
func TestSetEnabledTreatsMissingNamesAsDisabled(t *testing.T) {
	var ran []string
	engine := New([]Rule{
		stubRule{name: "a", verdict: model.Block, ran: &ran},
		stubRule{name: "b", verdict: model.Block, ran: &ran},
	})

	engine.SetEnabled(map[string]bool{"a": true})

	enabled := engine.Enabled()
	if !enabled["a"] {
		t.Fatal("rule a should be enabled")
	}
	if enabled["b"] {
		t.Fatal("rule b was absent from the map and must default to disabled")
	}
}

func TestBlockStatusDefaultsToForbidden(t *testing.T) {
	var ran []string

	// A rule that does not implement BlockStatus.
	plain := New([]Rule{minimalRule{name: "plain", ran: &ran}})
	if got := plain.Decide(context.Background(), &model.RequestContext{}).Status; got != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", got)
	}

	throttle := New([]Rule{stubRule{name: "throttle", verdict: model.Block,
		status: http.StatusTooManyRequests, ran: &ran}})
	if got := throttle.Decide(context.Background(), &model.RequestContext{}).Status; got != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", got)
	}
}

type minimalRule struct {
	name string
	ran  *[]string
}

func (m minimalRule) Name() string { return m.name }

func (m minimalRule) Evaluate(context.Context, *model.RequestContext) (model.Verdict, string) {
	*m.ran = append(*m.ran, m.name)
	return model.Block, "blocked"
}

func TestDecideRecordsItsOwnLatency(t *testing.T) {
	var ran []string
	engine := New([]Rule{stubRule{name: "a", verdict: model.Allow, ran: &ran}})

	decision := engine.Decide(context.Background(), &model.RequestContext{})
	if decision.DecisionMS < 0 {
		t.Fatalf("decision_ms = %v, want a non-negative duration", decision.DecisionMS)
	}
}
