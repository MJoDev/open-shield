//go:build integration

package integration

import (
	"errors"
	"testing"

	"github.com/open-shield/open-shield/test/harness"

	"github.com/open-shield/open-shield/internal/migrate"
	"github.com/open-shield/open-shield/internal/model"
	"github.com/open-shield/open-shield/internal/rulestore"
	"github.com/open-shield/open-shield/migrations"
)

// --- Migrations --------------------------------------------------------------

// The engine applies migrations at startup, every time. Applying them twice
// must be a no-op, or the second container to start — or the same one after a
// restart — would fail to come up.
func TestMigrationsAreIdempotent(t *testing.T) {
	pool := harness.Pool(t)
	ctx := harness.Context(t)

	for i := 0; i < 3; i++ {
		if err := migrate.Apply(ctx, pool, migrations.Postgres(), harness.QuietLog()); err != nil {
			t.Fatalf("apply #%d: %v", i+1, err)
		}
	}

	var versions int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&versions); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if versions != 2 {
		t.Fatalf("schema_migrations holds %d rows after three runs, want 2", versions)
	}
}

// The seeded chain has to match what the engine actually builds, in order:
// ipblock → ratelimit → sqli → xss. A rule missing from the table is a rule the
// dashboard cannot switch off.
func TestTheSeededChainMatchesTheEngine(t *testing.T) {
	pool := harness.Pool(t)
	store := rulestore.New(pool)

	rules, err := store.Rules(harness.Context(t))
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}

	got := map[string]bool{}
	for _, r := range rules {
		got[r.Name] = r.Enabled
	}
	for _, name := range []string{"ipblock", "ratelimit", "sqli", "xss"} {
		enabled, present := got[name]
		if !present {
			t.Errorf("rule %q is missing from the seeded table", name)
			continue
		}
		if !enabled {
			t.Errorf("rule %q is seeded disabled; a fresh install must filter", name)
		}
	}
	if len(rules) != 4 {
		t.Errorf("the table holds %d rules, want the 4 in the chain", len(rules))
	}
}

// --- Rules -------------------------------------------------------------------

func TestSetEnabledRecordsWhoChangedIt(t *testing.T) {
	pool := harness.Pool(t)
	store := rulestore.New(pool)
	ctx := harness.Context(t)

	rule, err := store.SetEnabled(ctx, "xss", false, "admin")
	if err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if rule.Enabled {
		t.Fatal("SetEnabled(false) returned an enabled rule")
	}
	if rule.UpdatedBy != "admin" {
		t.Errorf("updated_by = %q, want admin", rule.UpdatedBy)
	}
	if rule.UpdatedAt.IsZero() {
		t.Error("updated_at was not set")
	}

	// The engine reads this map every 30 seconds and on every control message.
	enabled, err := store.EnabledMap(ctx)
	if err != nil {
		t.Fatalf("EnabledMap: %v", err)
	}
	if enabled["xss"] {
		t.Error("EnabledMap still reports xss as enabled")
	}
	if !enabled["sqli"] {
		t.Error("switching off xss also switched off sqli")
	}
}

// A typo in the API must fail loudly rather than add configuration nothing
// reads. Silently creating a row for "sqlii" would leave an operator convinced
// they had disabled a rule that is still running.
func TestSetEnabledRefusesARuleTheEngineDoesNotHave(t *testing.T) {
	pool := harness.Pool(t)
	store := rulestore.New(pool)

	_, err := store.SetEnabled(harness.Context(t), "sqlii", false, "admin")
	if !errors.Is(err, rulestore.ErrUnknownRule) {
		t.Fatalf("error = %v, want ErrUnknownRule", err)
	}

	var rows int
	if err := pool.QueryRow(harness.Context(t), `SELECT count(*) FROM rules`).Scan(&rows); err != nil {
		t.Fatalf("count rules: %v", err)
	}
	if rows != 4 {
		t.Fatalf("the table holds %d rules after a typo, want 4", rows)
	}
}

// --- The IP access list ------------------------------------------------------

func TestIPRulesRoundTrip(t *testing.T) {
	pool := harness.Pool(t)
	store := rulestore.New(pool)
	ctx := harness.Context(t)

	added, err := store.AddIPRule(ctx, model.IPRule{
		CIDR:   "203.0.113.0/24",
		Action: model.ActionDeny,
		Note:   "scanner",
	}, "admin")
	if err != nil {
		t.Fatalf("AddIPRule: %v", err)
	}
	if added.CIDR != "203.0.113.0/24" || added.Action != model.ActionDeny {
		t.Fatalf("stored %+v", added)
	}
	if added.CreatedBy != "admin" {
		t.Errorf("created_by = %q, want admin", added.CreatedBy)
	}

	rules, err := store.IPRules(ctx)
	if err != nil {
		t.Fatalf("IPRules: %v", err)
	}
	if len(rules) != 1 || rules[0].Note != "scanner" {
		t.Fatalf("IPRules returned %+v", rules)
	}

	removed, err := store.DeleteIPRule(ctx, "203.0.113.0/24")
	if err != nil {
		t.Fatalf("DeleteIPRule: %v", err)
	}
	if !removed {
		t.Fatal("DeleteIPRule reported nothing removed")
	}

	// Reporting false rather than an error is what lets the API answer 404 for
	// a CIDR that was never listed, instead of 500.
	removed, err = store.DeleteIPRule(ctx, "203.0.113.0/24")
	if err != nil {
		t.Fatalf("second DeleteIPRule: %v", err)
	}
	if removed {
		t.Fatal("DeleteIPRule removed the same entry twice")
	}
}

// Re-adding a CIDR replaces it. Without this, blocking a range that is already
// listed as allowed would fail on the primary key and the operator would be
// told nothing useful.
func TestAddingTheSameRangeTwiceReplacesIt(t *testing.T) {
	pool := harness.Pool(t)
	store := rulestore.New(pool)
	ctx := harness.Context(t)

	if _, err := store.AddIPRule(ctx, model.IPRule{
		CIDR: "198.51.100.0/24", Action: model.ActionAllow, Note: "office",
	}, "admin"); err != nil {
		t.Fatalf("first add: %v", err)
	}

	updated, err := store.AddIPRule(ctx, model.IPRule{
		CIDR: "198.51.100.0/24", Action: model.ActionDeny, Note: "no longer ours",
	}, "operator")
	if err != nil {
		t.Fatalf("second add: %v", err)
	}
	if updated.Action != model.ActionDeny || updated.Note != "no longer ours" {
		t.Fatalf("the entry was not replaced: %+v", updated)
	}
	if updated.CreatedBy != "operator" {
		t.Errorf("created_by = %q, want operator", updated.CreatedBy)
	}

	rules, err := store.IPRules(ctx)
	if err != nil {
		t.Fatalf("IPRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("the list holds %d entries for one range", len(rules))
	}
}

func TestAddIPRuleRejectsAnInvalidAction(t *testing.T) {
	pool := harness.Pool(t)
	store := rulestore.New(pool)

	// The CHECK constraint backs this up in the database, but the store refuses
	// first so the error names the field rather than the constraint.
	for _, action := range []string{"", "block", "DENY"} {
		if _, err := store.AddIPRule(harness.Context(t), model.IPRule{
			CIDR: "203.0.113.0/24", Action: action,
		}, "admin"); err == nil {
			t.Errorf("AddIPRule accepted action %q", action)
		}
	}
}

func TestAddIPRuleRejectsAMalformedCIDR(t *testing.T) {
	pool := harness.Pool(t)
	store := rulestore.New(pool)

	for _, cidr := range []string{"no-es-una-ip", "203.0.113.0/99", ""} {
		if _, err := store.AddIPRule(harness.Context(t), model.IPRule{
			CIDR: cidr, Action: model.ActionDeny,
		}, "admin"); err == nil {
			t.Errorf("AddIPRule accepted the CIDR %q", cidr)
		}
	}
}

// IPv6 is not an afterthought: an attacker on a v6 address must be blockable
// the same way, and the CIDR column has to round-trip the text form.
func TestTheAccessListHandlesIPv6(t *testing.T) {
	pool := harness.Pool(t)
	store := rulestore.New(pool)
	ctx := harness.Context(t)

	if _, err := store.AddIPRule(ctx, model.IPRule{
		CIDR: "2001:db8::/32", Action: model.ActionDeny, Note: "v6 range",
	}, "admin"); err != nil {
		t.Fatalf("AddIPRule: %v", err)
	}

	rules, err := store.IPRules(ctx)
	if err != nil {
		t.Fatalf("IPRules: %v", err)
	}
	if len(rules) != 1 || rules[0].CIDR != "2001:db8::/32" {
		t.Fatalf("IPRules returned %+v", rules)
	}
}
