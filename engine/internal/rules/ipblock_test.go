package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/open-shield/open-shield/internal/model"
)

func TestIPBlockDeniesAndAllows(t *testing.T) {
	rule := NewIPBlock()
	errs := rule.Set([]IPRule{
		{CIDR: "203.0.113.0/24", Action: "deny", Note: "scanning host"},
		{CIDR: "203.0.113.7", Action: "allow", Note: "our monitoring"},
		{CIDR: "2001:db8::/32", Action: "deny"},
	})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	cases := map[string]struct {
		ip   string
		want model.Verdict
	}{
		"inside the denied range":          {"203.0.113.44", model.Block},
		"allow entry wins over deny":       {"203.0.113.7", model.Allow},
		"outside every range":              {"198.51.100.1", model.Allow},
		"denied ipv6 range":                {"2001:db8::1", model.Block},
		"ipv6 outside the range":           {"2001:db9::1", model.Allow},
		"unparseable address is not fatal": {"not-an-ip", model.Allow},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := model.RequestContext{IP: tc.ip}
			got, reason := rule.Evaluate(context.Background(), &req)
			if got != tc.want {
				t.Fatalf("%s: verdict = %s (%s), want %s", tc.ip, got, reason, tc.want)
			}
		})
	}
}

func TestIPBlockReasonCarriesTheNote(t *testing.T) {
	rule := NewIPBlock()
	rule.Set([]IPRule{{CIDR: "198.51.100.0/24", Action: "deny", Note: "brute force 2026-08-25"}})

	req := model.RequestContext{IP: "198.51.100.9"}
	verdict, reason := rule.Evaluate(context.Background(), &req)
	if verdict != model.Block {
		t.Fatal("expected a block")
	}
	if !strings.Contains(reason, "brute force 2026-08-25") {
		t.Fatalf("reason %q does not carry the operator's note", reason)
	}
}

// One malformed row entered through the dashboard must not disable the list.
func TestIPBlockSkipsInvalidEntriesWithoutLosingTheRest(t *testing.T) {
	rule := NewIPBlock()
	errs := rule.Set([]IPRule{
		{CIDR: "not a cidr", Action: "deny"},
		{CIDR: "198.51.100.0/24", Action: "sideways"},
		{CIDR: "198.51.100.0/24", Action: "deny"},
	})

	if len(errs) != 2 {
		t.Fatalf("got %d errors, want 2: %v", len(errs), errs)
	}

	req := model.RequestContext{IP: "198.51.100.9"}
	if verdict, _ := rule.Evaluate(context.Background(), &req); verdict != model.Block {
		t.Fatal("the valid entry was lost along with the invalid ones")
	}
}

// An operator blocking a single attacker should not have to remember /32.
func TestParsePrefixAcceptsBareAddresses(t *testing.T) {
	prefix, err := ParsePrefix("203.0.113.7")
	if err != nil {
		t.Fatalf("ParsePrefix: %v", err)
	}
	if prefix.String() != "203.0.113.7/32" {
		t.Fatalf("got %s, want 203.0.113.7/32", prefix)
	}
}

// 203.0.113.7/24 has host bits set. Storing it verbatim would produce a prefix
// that never matches anything.
func TestParsePrefixMasksHostBits(t *testing.T) {
	prefix, err := ParsePrefix("203.0.113.7/24")
	if err != nil {
		t.Fatalf("ParsePrefix: %v", err)
	}
	if prefix.String() != "203.0.113.0/24" {
		t.Fatalf("got %s, want 203.0.113.0/24", prefix)
	}
}

func TestEmptyIPBlockAllowsEverything(t *testing.T) {
	rule := NewIPBlock()
	req := model.RequestContext{IP: "203.0.113.1"}
	if verdict, _ := rule.Evaluate(context.Background(), &req); verdict != model.Allow {
		t.Fatal("an empty access list must not block anything")
	}
}
