//go:build integration

package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/open-shield/open-shield/dashboard/api/internal/auth"
	"github.com/open-shield/open-shield/dashboard/api/internal/ws"
	"github.com/open-shield/open-shield/internal/audit"
	"github.com/open-shield/open-shield/internal/events"
	"github.com/open-shield/open-shield/internal/model"
	"github.com/open-shield/open-shield/internal/rulestore"
	"github.com/open-shield/open-shield/test/harness"
)

// The rule and access-list endpoints cannot be unit tested: rulestore.Store
// takes a *pgxpool.Pool. They are also where the system's most consequential
// rule lives — an administrative change is recorded *before* it is applied, and
// refused outright if it cannot be recorded.

const (
	pgAdminUser     = "admin"
	pgAdminPassword = "correct horse battery staple"
	pgSessionSecret = "0123456789abcdef0123456789abcdef"
)

type dashboard struct {
	server *httptest.Server
	client *http.Client
	store  *audit.Postgres
	rules  *rulestore.Store
}

// newDashboard wires the real dashboard server over a real database and Redis,
// with a stand-in engine for the synchronous audit endpoint.
func newDashboard(t *testing.T, engineHandler http.Handler) *dashboard {
	t.Helper()

	pool := harness.Pool(t)
	store := harness.StoreOverPool(t)
	ctx := harness.Context(t)

	hash, err := bcrypt.GenerateFromPassword([]byte(pgAdminPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	sessions, err := auth.New(auth.Options{
		User:         pgAdminUser,
		PasswordHash: string(hash),
		Secret:       pgSessionSecret,
		TTL:          time.Hour,
	})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}

	engine := httptest.NewServer(engineHandler)
	t.Cleanup(engine.Close)

	client := harness.Redis(t)
	_ = ctx

	srv := httptest.NewServer(New(Options{
		Repo:      store,
		Rules:     rulestore.New(pool),
		Sessions:  sessions,
		Hub:       ws.NewHub(harness.QuietLog()),
		Auditor:   NewAuditClient(engine.URL),
		Publisher: events.NewPublisher(client, "openshield:integration"),
		SPA:       fstest.MapFS{"index.html": {Data: []byte("<!doctype html>")}},
		Logger:    harness.QuietLog(),
		Version:   "test",
	}).Handler())
	t.Cleanup(srv.Close)

	d := &dashboard{
		server: srv,
		client: &http.Client{Jar: &cookieJar{}},
		store:  store,
		rules:  rulestore.New(pool),
	}
	d.signIn(t)
	return d
}

// recordingEngine stands in for the rules engine's /v1/audit endpoint, keeping
// what it was asked to record. When down is set it refuses everything.
func recordingEngine(recorded *[]map[string]any, down *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/audit":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if down != nil && *down {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":"the audit entry could not be committed"}`))
				return
			}
			if recorded != nil {
				*recorded = append(*recorded, body)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"recorded"}`))
		case "/v1/status":
			_, _ = w.Write([]byte(`{"version":"test"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func (d *dashboard) signIn(t *testing.T) {
	t.Helper()

	body := fmt.Sprintf(`{"user":%q,"password":%q}`, pgAdminUser, pgAdminPassword)
	resp := d.do(t, http.MethodPost, "/api/v1/login", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(resp.Body)
		t.Fatalf("sign-in failed with %d: %s", resp.StatusCode, out)
	}
}

func (d *dashboard) do(t *testing.T, method, path, body string) *http.Response {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, d.server.URL+path, reader)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, path, err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := d.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

func (d *dashboard) json(t *testing.T, method, path, body string, target any) int {
	t.Helper()

	resp := d.do(t, method, path, body)
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if target != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, target); err != nil {
			t.Fatalf("decode %s %s: %v — body was %s", method, path, err, raw)
		}
	}
	return resp.StatusCode
}

// --- Rules -------------------------------------------------------------------

func TestRulesEndpointListsTheChain(t *testing.T) {
	d := newDashboard(t, recordingEngine(nil, nil))

	var out struct {
		Rules []model.RuleConfig `json:"rules"`
	}
	if status := d.json(t, http.MethodGet, "/api/v1/rules", "", &out); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if len(out.Rules) != 4 {
		t.Fatalf("got %d rules, want the 4 in the chain", len(out.Rules))
	}
}

// The rule of §6.1, end to end: the entry is written first, and only then does
// the configuration change. There is no window in which what the proxy enforces
// and what the log says disagree.
func TestARuleChangeIsRecordedBeforeItIsApplied(t *testing.T) {
	var recorded []map[string]any
	d := newDashboard(t, recordingEngine(&recorded, nil))

	var rule model.RuleConfig
	if status := d.json(t, http.MethodPatch, "/api/v1/rules/xss", `{"enabled":false}`, &rule); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if rule.Enabled {
		t.Fatal("the rule came back enabled after being switched off")
	}

	// The change reached the database.
	enabled, err := d.rules.EnabledMap(harness.Context(t))
	if err != nil {
		t.Fatalf("EnabledMap: %v", err)
	}
	if enabled["xss"] {
		t.Error("the database still reports xss as enabled")
	}

	// And it is on the record, attributed to whoever made it.
	var change map[string]any
	for _, entry := range recorded {
		payload, _ := entry["payload"].(map[string]any)
		if payload["action"] == "rule.set_enabled" {
			change = payload
		}
	}
	if change == nil {
		t.Fatalf("the rule change was not recorded; the engine saw %v", recorded)
	}
	if change["rule"] != "xss" || change["enabled"] != false {
		t.Errorf("recorded %v, want rule=xss enabled=false", change)
	}
	if change["actor"] != pgAdminUser {
		t.Errorf("actor = %v, want %q", change["actor"], pgAdminUser)
	}
}

// An unaudited change to what the proxy blocks is worse than a change that did
// not happen. If the entry cannot be committed, the change is refused with 503
// and the stored configuration is untouched.
func TestARuleChangeIsRefusedWhenItCannotBeRecorded(t *testing.T) {
	down := true
	d := newDashboard(t, recordingEngine(nil, &down))

	status := d.json(t, http.MethodPatch, "/api/v1/rules/sqli", `{"enabled":false}`, nil)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", status)
	}

	enabled, err := d.rules.EnabledMap(harness.Context(t))
	if err != nil {
		t.Fatalf("EnabledMap: %v", err)
	}
	if !enabled["sqli"] {
		t.Fatal("sqli was switched off even though the change could not be recorded")
	}
}

func TestPatchRuleRejectsBadInput(t *testing.T) {
	d := newDashboard(t, recordingEngine(nil, nil))

	for name, c := range map[string]struct {
		path, body string
		want       int
	}{
		"unknown rule":     {"/api/v1/rules/sqlii", `{"enabled":false}`, http.StatusNotFound},
		"no enabled field": {"/api/v1/rules/sqli", `{}`, http.StatusBadRequest},
		"wrong type":       {"/api/v1/rules/sqli", `{"enabled":"no"}`, http.StatusBadRequest},
		"unknown field":    {"/api/v1/rules/sqli", `{"activo":false}`, http.StatusBadRequest},
		"not json":         {"/api/v1/rules/sqli", `nope`, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			if status := d.json(t, http.MethodPatch, c.path, c.body, nil); status != c.want {
				t.Fatalf("status = %d, want %d", status, c.want)
			}
		})
	}
}

// --- The IP access list ------------------------------------------------------

func TestIPBlockEndpointsRoundTrip(t *testing.T) {
	var recorded []map[string]any
	d := newDashboard(t, recordingEngine(&recorded, nil))

	var added model.IPRule
	status := d.json(t, http.MethodPost, "/api/v1/ipblock",
		`{"cidr":"203.0.113.7","action":"deny","note":"scanner"}`, &added)
	if status != http.StatusCreated {
		t.Fatalf("status = %d, want 201", status)
	}
	// A bare address is stored as a /32, so the engine's prefix lookup and the
	// dashboard's list agree on what was blocked.
	if added.CIDR != "203.0.113.7/32" {
		t.Errorf("stored cidr = %q, want 203.0.113.7/32", added.CIDR)
	}

	var list struct {
		Rules []model.IPRule `json:"rules"`
	}
	if status := d.json(t, http.MethodGet, "/api/v1/ipblock", "", &list); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if len(list.Rules) != 1 {
		t.Fatalf("the list holds %d entries, want 1", len(list.Rules))
	}

	if status := d.json(t, http.MethodDelete, "/api/v1/ipblock?cidr=203.0.113.7", "", nil); status != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", status)
	}
	if status := d.json(t, http.MethodDelete, "/api/v1/ipblock?cidr=203.0.113.7", "", nil); status != http.StatusNotFound {
		t.Fatalf("second delete status = %d, want 404", status)
	}

	// Both the addition and the removal are on the record.
	actions := map[string]bool{}
	for _, entry := range recorded {
		payload, _ := entry["payload"].(map[string]any)
		if action, ok := payload["action"].(string); ok {
			actions[action] = true
		}
	}
	for _, want := range []string{"ipblock.add", "ipblock.delete"} {
		if !actions[want] {
			t.Errorf("%s was not recorded; the engine saw %v", want, actions)
		}
	}
}

func TestIPBlockRejectsBadInput(t *testing.T) {
	d := newDashboard(t, recordingEngine(nil, nil))

	for name, body := range map[string]string{
		"malformed cidr": `{"cidr":"no-es-una-ip","action":"deny"}`,
		"bad prefix":     `{"cidr":"203.0.113.0/99","action":"deny"}`,
		"missing cidr":   `{"action":"deny"}`,
		"unknown action": `{"cidr":"203.0.113.0/24","action":"block"}`,
		"empty action":   `{"cidr":"203.0.113.0/24"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if status := d.json(t, http.MethodPost, "/api/v1/ipblock", body, nil); status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", status)
			}
		})
	}
}

func TestAddingAnIPRuleIsRefusedWhenItCannotBeRecorded(t *testing.T) {
	down := true
	d := newDashboard(t, recordingEngine(nil, &down))

	status := d.json(t, http.MethodPost, "/api/v1/ipblock",
		`{"cidr":"203.0.113.0/24","action":"deny"}`, nil)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", status)
	}

	stored, err := d.rules.IPRules(harness.Context(t))
	if err != nil {
		t.Fatalf("IPRules: %v", err)
	}
	if len(stored) != 0 {
		t.Fatalf("the range was blocked even though the change could not be recorded: %+v", stored)
	}
}

// --- The forensic view over a real chain -------------------------------------

// Verify walks the chain in the database, not an in-memory copy of it. This is
// the call an operator makes before treating the log as evidence.
func TestVerifyEndpointWalksTheStoredChain(t *testing.T) {
	d := newDashboard(t, recordingEngine(nil, nil))
	harness.SeedTraffic(t, d.store, 20)

	var result audit.VerifyResult
	if status := d.json(t, http.MethodGet, "/api/v1/audit/verify", "", &result); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if !result.OK {
		t.Fatalf("chain broken at %s: %s", result.BrokenAt, result.Detail)
	}
	// The sign-in was recorded through the stand-in engine, not this chain, so
	// only the seeded traffic is here.
	if result.Checked != 20 {
		t.Errorf("checked = %d, want 20", result.Checked)
	}
}

func TestVerifyEndpointReportsARewrittenEntry(t *testing.T) {
	d := newDashboard(t, recordingEngine(nil, nil))
	entries := harness.SeedTraffic(t, d.store, 12)

	target := entries[7]
	harness.DisableTriggers(t, func(exec func(string, ...any)) {
		exec(`UPDATE audit_log SET payload = jsonb_set(payload, '{ip}', '"192.0.2.66"') WHERE id = $1`, target.ID)
	})

	var result audit.VerifyResult
	if status := d.json(t, http.MethodGet, "/api/v1/audit/verify", "", &result); status != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a broken chain is a finding, not a server error", status)
	}
	if result.OK {
		t.Fatal("the endpoint reported an intact chain after a row was rewritten")
	}
	if result.BrokenAt != target.ID {
		t.Errorf("broken_at = %q, want %q", result.BrokenAt, target.ID)
	}
	if result.Position != 8 {
		t.Errorf("position = %d, want 8", result.Position)
	}
}

func TestEventsEndpointReadsTheStoredLog(t *testing.T) {
	d := newDashboard(t, recordingEngine(nil, nil))
	harness.SeedTraffic(t, d.store, 25)

	var out struct {
		Entries []model.AuditEntry `json:"entries"`
		Total   int64              `json:"total"`
		Limit   int                `json:"limit"`
	}
	if status := d.json(t, http.MethodGet, "/api/v1/events?verdict=block&limit=1000", "", &out); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if out.Total == 0 {
		t.Fatal("no blocked entries came back")
	}
	if out.Limit > 500 {
		t.Errorf("limit = %d, want the clamped value the store applied", out.Limit)
	}
	for _, e := range out.Entries {
		if e.Payload["verdict"] != string(model.Block) {
			t.Fatalf("entry %s leaked through the verdict filter", e.ID)
		}
	}
}

// The live feed carries source addresses, paths and block reasons. It is behind
// the same session as everything else, checked here over a real upgrade rather
// than against the router alone.
func TestTheLiveFeedNeedsASession(t *testing.T) {
	d := newDashboard(t, recordingEngine(nil, nil))

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		d.server.URL+"/ws/live", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	// A client with no cookie jar: anonymous.
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}
