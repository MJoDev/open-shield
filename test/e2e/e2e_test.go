//go:build e2e

// Package e2e drives a running stack through the proxy and reads the result out
// of the dashboard, which is the only place the system's central claim can
// actually be checked: that a request is filtered, that the decision is on the
// record, and that the record verifies.
//
// It is written in Go rather than as a shell script for two reasons. It replays
// the same corpus the rule tests use, so a vector added once is covered at every
// level; and it can query the dashboard API, which is what turns "the request
// was blocked" into "the block is in the log, attributed, and the chain still
// verifies".
//
// scripts/smoke.sh is kept alongside it and is not replaced: that is the quick
// check a person runs by hand after a deployment. This is the gate.
//
//	OS_PROXY_URL=http://localhost OS_DASHBOARD_URL=http://localhost:8081 \
//	OS_ADMIN_PASSWORD='...' go test -tags=e2e ./test/e2e/...
//
// With OS_PROXY_URL unset the suite skips. See make test-e2e.
package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/open-shield/open-shield/internal/audit"
	"github.com/open-shield/open-shield/internal/model"
	"github.com/open-shield/open-shield/test/corpus"
)

const skipMessage = `end-to-end suite needs a running stack:

    make up
    OS_ADMIN_PASSWORD='...' make test-e2e`

// --- Configuration -----------------------------------------------------------

func proxyURL(t *testing.T) string {
	t.Helper()

	url := os.Getenv("OS_PROXY_URL")
	if url == "" {
		t.Skip(skipMessage)
	}
	return strings.TrimSuffix(url, "/")
}

func dashboardURL(t *testing.T) string {
	t.Helper()

	url := os.Getenv("OS_DASHBOARD_URL")
	if url == "" {
		t.Skip(skipMessage)
	}
	return strings.TrimSuffix(url, "/")
}

// adminPassword returns the dashboard password, skipping the test without it.
// The checks that only need the proxy still run: an operator verifying a
// deployment should not have to hand a password to the test suite to find out
// whether filtering works.
func adminPassword(t *testing.T) string {
	t.Helper()

	password := os.Getenv("OS_ADMIN_PASSWORD")
	if password == "" {
		t.Skip("set OS_ADMIN_PASSWORD to run the checks that read the dashboard")
	}
	return password
}

func envInt(key string, fallback int) int {
	if raw := os.Getenv(key); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			return n
		}
	}
	return fallback
}

// client is a plain client that never follows redirects, so a test sees the
// status the proxy returned rather than wherever it pointed.
func client() *http.Client {
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// send replays one corpus case through the proxy and returns the response.
func send(t *testing.T, base string, c corpus.Case, extraHeaders map[string]string) *http.Response {
	t.Helper()

	var body io.Reader
	if c.Body != "" {
		body = strings.NewReader(c.Body)
	}

	req, err := http.NewRequest(c.HTTPMethod(), c.Target(base), body)
	if err != nil {
		t.Fatalf("build request for %s: %v", c.ID, err)
	}
	for name, value := range c.Headers {
		req.Header.Set(name, value)
	}
	for name, value := range extraHeaders {
		req.Header.Set(name, value)
	}

	resp, err := client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", c.HTTPMethod(), c.Target(base), err)
	}
	return resp
}

// --- The proxy is carrying traffic -------------------------------------------

func TestTheProxyAnswersItsOwnHealthCheck(t *testing.T) {
	base := proxyURL(t)

	// Answered before the access phase, so it stays up even when the engine is
	// down — which is exactly when an operator needs to know which component
	// actually failed.
	resp, err := client().Get(base + "/__openshield/health")
	if err != nil {
		t.Fatalf("GET /__openshield/health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// RF-01 and RF-02: legitimate traffic reaches the backend, and the filter does
// not get in its way.
func TestBenignTrafficReachesTheBackend(t *testing.T) {
	base := proxyURL(t)

	for _, c := range corpus.Benign() {
		t.Run(c.ID, func(t *testing.T) {
			resp := send(t, base, c, nil)
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)

			if resp.StatusCode == http.StatusForbidden {
				t.Fatalf("the proxy blocked legitimate traffic: %s\n  case: %s", c.Decoded(), c.Description)
			}
			if resp.StatusCode >= 500 {
				t.Fatalf("status = %d for %s", resp.StatusCode, c.Decoded())
			}
		})
	}
}

// RF-03, through the whole path this time: the same vectors the rule tests
// check in isolation, replayed against a live proxy.
func TestCorpusAttacksAreBlockedByTheProxy(t *testing.T) {
	base := proxyURL(t)

	for _, c := range corpus.Attacks() {
		t.Run(c.ID, func(t *testing.T) {
			resp := send(t, base, c, nil)
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)

			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 for %s\n  case: %s",
					resp.StatusCode, c.Decoded(), c.Description)
			}

			// The reference the block page shows the visitor is what lets an
			// operator find the request in the log when someone reports a false
			// positive. Without it the page is an apology with no follow-up.
			if resp.Header.Get("X-Request-ID") == "" {
				t.Error("the block carries no X-Request-ID; the visitor has nothing to quote")
			}
		})
	}
}

// The proxy is the only address the site has. What it forwards must arrive
// intact, and the request id must arrive with it — that is what makes one
// request followable across proxy, engine and backend.
func TestAnAllowedRequestReachesTheBackendWithItsRequestID(t *testing.T) {
	base := proxyURL(t)

	resp, err := client().Get(base + "/api/echo?producto=zapatos")
	if err != nil {
		t.Fatalf("GET /api/echo: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Skipf("the bundled demo backend is not behind this proxy (status %d)", resp.StatusCode)
	}

	var echoed map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&echoed); err != nil {
		t.Fatalf("decode echo: %v", err)
	}
	if id, _ := echoed["request_id"].(string); id == "" {
		t.Fatalf("the backend received no X-Request-ID: %v", echoed)
	}
}

// --- The forensic loop -------------------------------------------------------

// This is the test the project exists for. An attack is sent, the proxy blocks
// it, and the block is then found in the audit log — attributed to the right
// rule, carrying the evidence of why — with the hash chain still verifying.
// RF-03 and RF-06 together, which is the pair that makes the log usable as
// evidence rather than as a guess.
func TestABlockedRequestIsFollowableIntoTheAuditLog(t *testing.T) {
	base := proxyURL(t)
	dash := newDashboard(t)

	attack := corpus.Case{
		ID:     "e2e-evidence",
		Method: "GET",
		Path:   "/buscar",
		Query:  "q=x%27%20UNION%20SELECT%20clave%20FROM%20usuarios--",
	}

	resp := send(t, base, attack, nil)
	requestID := resp.Header.Get("X-Request-ID")
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if requestID == "" {
		t.Fatal("the block carries no X-Request-ID to follow")
	}

	entry := dash.waitForEntry(t, requestID)

	if entry.Kind != model.KindTraffic {
		t.Errorf("kind = %q, want %q", entry.Kind, model.KindTraffic)
	}
	if entry.Payload["verdict"] != string(model.Block) {
		t.Errorf("verdict = %v, want block", entry.Payload["verdict"])
	}
	if entry.Payload["rule"] != "sqli" {
		t.Errorf("rule = %v, want sqli", entry.Payload["rule"])
	}

	reason, _ := entry.Payload["reason"].(string)
	if !strings.Contains(reason, "union_select") {
		t.Errorf("reason = %q, want it to name the signature that fired", reason)
	}
	if reason == "" {
		t.Error("the log records a block with no reason; it says that something happened, not why")
	}

	// The entry is chained, and the chain still verifies with it in place.
	if entry.Hash == "" || entry.PrevHash == "" {
		t.Fatalf("the entry is not chained: hash=%q prev=%q", entry.Hash, entry.PrevHash)
	}

	result := dash.verify(t)
	if !result.OK {
		t.Fatalf("the chain does not verify: broken at %s (%s)", result.BrokenAt, result.Detail)
	}
	if result.Checked == 0 {
		t.Error("verification checked nothing")
	}
}

// The invariant that has no visible symptom when it breaks: request bodies and
// credential headers are inspected and then discarded. An append-only log with
// long retention is the worst place for the passwords a POST carries, and a log
// that keeps session cookies is a credential store.
func TestTheAuditLogNeverKeepsBodiesOrCredentials(t *testing.T) {
	base := proxyURL(t)
	dash := newDashboard(t)

	const (
		password = "SuperSecretoE2E123"
		cookie   = "session=e2e0123456789abcdef"
		bearer   = "Bearer e2e.token.value"
	)

	attack := corpus.Case{
		ID:      "e2e-secrets",
		Method:  "POST",
		Path:    "/login",
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:    fmt.Sprintf("usuario=admin'--&clave=%s", password),
	}

	resp := send(t, base, attack, map[string]string{
		"Cookie":        cookie,
		"Authorization": bearer,
		"User-Agent":    "open-shield-e2e/1.0",
	})
	requestID := resp.Header.Get("X-Request-ID")
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}

	entry := dash.waitForEntry(t, requestID)

	// Serialise the whole payload and search it, so a secret tucked into a
	// nested field is caught too.
	raw, err := json.Marshal(entry.Payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	recorded := string(raw)

	for name, secret := range map[string]string{
		"the password from the body": password,
		"the session cookie":         cookie,
		"the authorization header":   bearer,
		"the body itself":            "usuario=admin'--",
	} {
		if strings.Contains(recorded, secret) {
			t.Errorf("the audit entry contains %s\n  payload: %s", name, recorded)
		}
	}

	// What must survive: enough to identify the client and say why.
	if entry.Payload["rule"] != "sqli" {
		t.Errorf("rule = %v, want sqli — the evidence of why is the part that is kept", entry.Payload["rule"])
	}
}

// The Lua hook is the one component with no unit tests of its own. What proves
// it is doing its job is that the fields it fills in arrive: an audit entry with
// an empty method or host means the hook stopped populating the decision
// request, and every rule that reads those fields went quietly blind.
func TestTheProxyPopulatesTheFieldsTheEngineDependsOn(t *testing.T) {
	base := proxyURL(t)
	dash := newDashboard(t)

	attack := corpus.Case{
		ID:     "e2e-contract",
		Method: "POST",
		Path:   "/comentarios",
		Query:  "origen=e2e",
		Body:   `texto=<script>alert(1)</script>`,
	}

	resp := send(t, base, attack, map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"User-Agent":   "open-shield-e2e/1.0",
	})
	requestID := resp.Header.Get("X-Request-ID")
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — the payload is in the body, which is the case auth_request could never see", resp.StatusCode)
	}

	entry := dash.waitForEntry(t, requestID)

	for _, field := range []string{"ip", "method", "path", "host", "verdict"} {
		value, _ := entry.Payload[field].(string)
		if value == "" {
			t.Errorf("payload[%q] is empty; the proxy stopped filling it in\n  payload: %v", field, entry.Payload)
		}
	}
	if entry.Payload["method"] != "POST" {
		t.Errorf("method = %v, want POST", entry.Payload["method"])
	}
	if entry.Payload["path"] != "/comentarios" {
		t.Errorf("path = %v, want /comentarios", entry.Payload["path"])
	}

	// The user agent identifies the client and is deliberately kept, unlike the
	// credential headers.
	headers, _ := entry.Payload["headers"].(map[string]any)
	if agent, _ := headers["user-agent"].(string); !strings.Contains(agent, "open-shield-e2e") {
		t.Errorf("headers.user-agent = %v, want the client's own", headers["user-agent"])
	}
}

// --- The dashboard is not open to the internet -------------------------------

func TestTheDashboardRefusesAnonymousAccess(t *testing.T) {
	dash := dashboardURL(t)

	// The live view carries source addresses, paths and block reasons —
	// precisely what an attacker would use to tune the next payload past the
	// filters.
	for _, path := range []string{
		"/api/v1/events",
		"/api/v1/audit/verify",
		"/api/v1/rules",
		"/api/v1/ipblock",
		"/api/v1/status",
		"/api/v1/stats",
	} {
		resp, err := client().Get(dash + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s = %d, want 401", path, resp.StatusCode)
		}
	}
}

// --- RF-05 --------------------------------------------------------------------

// The rate limit is checked against whatever the stack is actually running,
// read from the same environment the engine was given. It comes last in this
// file on purpose: it deliberately exhausts the budget for the current window,
// and every other check shares the source address.
func TestRateLimitingThrottlesABurst(t *testing.T) {
	base := proxyURL(t)

	limit := envInt("OS_RATELIMIT_REQUESTS", 100)
	window := time.Duration(envInt("OS_RATELIMIT_WINDOW_S", 60)) * time.Second

	if limit > 500 {
		t.Skipf("OS_RATELIMIT_REQUESTS is %d; this stack is configured for load testing, "+
			"where the limit is raised on purpose (see deploy/docker-compose.load.yml)", limit)
	}

	burst := limit + limit/4 + 10
	throttled := 0
	c := client()

	for i := 0; i < burst; i++ {
		resp, err := c.Get(base + "/rate-limit-probe")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			throttled++
		}
	}

	if throttled == 0 {
		t.Fatalf("none of %d requests were throttled at a limit of %d per %s", burst, limit, window)
	}

	// Let the window drain rather than leaving the next run of this suite
	// starting from an exhausted budget.
	t.Logf("%d of %d requests were throttled; waiting %s for the window to slide", throttled, burst, window)
	time.Sleep(window + time.Second)
}

// --- Reading the dashboard ---------------------------------------------------

type dashboardClient struct {
	base   string
	client *http.Client
}

func newDashboard(t *testing.T) *dashboardClient {
	t.Helper()

	base := dashboardURL(t)
	password := adminPassword(t)
	user := os.Getenv("OS_ADMIN_USER")
	if user == "" {
		user = "admin"
	}

	c := client()
	c.Jar = &singleOriginJar{}

	body := fmt.Sprintf(`{"user":%q,"password":%q}`, user, password)
	resp, err := c.Post(base+"/api/v1/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(resp.Body)
		t.Fatalf("sign in failed with %d: %s\n\nIf the password is right, check that OS_ADMIN_PASSWORD_HASH "+
			"in deploy/.env has its '$' characters escaped as '$$' — Compose reads a lone '$' as a "+
			"variable reference and the container receives an empty value.", resp.StatusCode, out)
	}

	return &dashboardClient{base: base, client: c}
}

// waitForEntry polls until the entry for requestID appears.
//
// Audit writes are asynchronous by design: §8.2 budgets the proxy under 50 ms
// of added latency, so the verdict returns before the insert starts. A test
// that read the log immediately would be racing the writer.
func (d *dashboardClient) waitForEntry(t *testing.T, requestID string) model.AuditEntry {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := d.client.Get(d.base + "/api/v1/events?request_id=" + requestID)
		if err != nil {
			t.Fatalf("GET /api/v1/events: %v", err)
		}

		var out struct {
			Entries []model.AuditEntry `json:"entries"`
		}
		err = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("decode events: %v", err)
		}

		if len(out.Entries) > 0 {
			return out.Entries[0]
		}
		time.Sleep(250 * time.Millisecond)
	}

	t.Fatalf("no audit entry for request %s after 20s.\n"+
		"Either the decision was never recorded, or the audit queue is dropping entries — "+
		"check the dropped counter on /api/v1/status.", requestID)
	return model.AuditEntry{}
}

func (d *dashboardClient) verify(t *testing.T) audit.VerifyResult {
	t.Helper()

	resp, err := d.client.Get(d.base + "/api/v1/audit/verify")
	if err != nil {
		t.Fatalf("GET /api/v1/audit/verify: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(resp.Body)
		t.Fatalf("verify returned %d: %s", resp.StatusCode, out)
	}

	var result audit.VerifyResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode verify: %v", err)
	}
	return result
}

// singleOriginJar keeps the session cookie. net/http/cookiejar needs a public
// suffix list before it will accept a cookie for localhost.
type singleOriginJar struct{ cookies []*http.Cookie }

func (j *singleOriginJar) SetCookies(_ *url.URL, cookies []*http.Cookie) { j.cookies = cookies }
func (j *singleOriginJar) Cookies(*url.URL) []*http.Cookie               { return j.cookies }
