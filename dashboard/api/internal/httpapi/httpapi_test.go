package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/open-shield/open-shield/dashboard/api/internal/auth"
	"github.com/open-shield/open-shield/dashboard/api/internal/ws"
	"github.com/open-shield/open-shield/internal/audit"
	"github.com/open-shield/open-shield/internal/model"
)

// The dashboard is the only part of the system exposed to a human, and
// everything it shows — source addresses, blocked paths, payload excerpts — is
// exactly what an attacker would use to tune the next payload past the filters.
// The session gate is therefore not a convenience, and the tests below walk the
// whole route table rather than sampling it.
//
// The rules and IP-list endpoints are absent here on purpose: rulestore.Store
// takes a *pgxpool.Pool, so they are covered against a real database in
// test/integration.

const (
	testUser     = "admin"
	testPassword = "correct horse battery staple"
	testSecret   = "0123456789abcdef0123456789abcdef"
)

// --- Harness -----------------------------------------------------------------

type apiTest struct {
	server *httptest.Server
	repo   *audit.Memory
	client *http.Client

	// engineCalls records what the dashboard sent to the engine's synchronous
	// audit endpoint.
	engineCalls chan map[string]any
}

type harnessOptions struct {
	// engineDown makes the stand-in engine refuse to record anything, which is
	// how the "audited before applied" rule is exercised.
	engineDown bool
	// spa overrides the embedded dashboard build.
	spa fstest.MapFS
	// engineURL points the audit client somewhere other than the stand-in
	// engine, so that "the engine is not there at all" can be exercised.
	engineURL string
}

func newHarness(t *testing.T, opts harnessOptions) *apiTest {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	sessions, err := auth.New(auth.Options{
		User:         testUser,
		PasswordHash: string(hash),
		Secret:       testSecret,
		TTL:          time.Hour,
	})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}

	calls := make(chan map[string]any, 32)
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/audit":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			select {
			case calls <- body:
			default:
			}
			if opts.engineDown {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":"the audit entry could not be committed"}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"recorded"}`))
		case "/v1/status":
			_, _ = w.Write([]byte(`{"version":"test","chain":["ipblock","sqli"],"enabled":{"sqli":true}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(engine.Close)

	spa := opts.spa
	if spa == nil {
		spa = fstest.MapFS{
			"index.html":             {Data: []byte("<!doctype html><title>open-shield</title>")},
			"assets/index-abc123.js": {Data: []byte("console.log('dashboard')")},
		}
	}

	auditorURL := engine.URL
	if opts.engineURL != "" {
		auditorURL = opts.engineURL
	}

	repo := audit.NewMemory()
	srv := httptest.NewServer(New(Options{
		Repo:     repo,
		Sessions: sessions,
		Hub:      ws.NewHub(slog.New(slog.NewTextHandler(io.Discard, nil))),
		Auditor:  NewAuditClient(auditorURL),
		SPA:      spa,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version:  "test",
	}).Handler())
	t.Cleanup(srv.Close)

	// A client that keeps the session cookie but never follows a redirect, so a
	// test sees the status the handler actually returned.
	jar := &cookieJar{}
	return &apiTest{
		server:      srv,
		repo:        repo,
		client:      &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		engineCalls: calls,
	}
}

// signIn authenticates and leaves the session cookie in the client's jar.
func (h *apiTest) signIn(t *testing.T) {
	t.Helper()

	body := fmt.Sprintf(`{"user":%q,"password":%q}`, testUser, testPassword)
	resp := h.do(t, http.MethodPost, "/api/v1/login", strings.NewReader(body))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(resp.Body)
		t.Fatalf("sign-in failed with %d: %s", resp.StatusCode, out)
	}
}

func (h *apiTest) do(t *testing.T, method, path string, body io.Reader) *http.Response {
	t.Helper()

	req, err := http.NewRequest(method, h.server.URL+path, body)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// getJSON performs an authenticated GET and decodes the body.
func (h *apiTest) getJSON(t *testing.T, path string, target any) int {
	t.Helper()

	resp := h.do(t, http.MethodGet, path, nil)
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if target != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, target); err != nil {
			t.Fatalf("decode %s: %v — body was %s", path, err, raw)
		}
	}
	return resp.StatusCode
}

// cookieJar is a single-origin jar; net/http/cookiejar would need a public
// suffix list to accept cookies for 127.0.0.1.
type cookieJar struct{ cookies []*http.Cookie }

func (j *cookieJar) SetCookies(_ *url.URL, cookies []*http.Cookie) {
	for _, c := range cookies {
		replaced := false
		for i, existing := range j.cookies {
			if existing.Name == c.Name {
				j.cookies[i] = c
				replaced = true
			}
		}
		if !replaced {
			j.cookies = append(j.cookies, c)
		}
	}
}

func (j *cookieJar) Cookies(*url.URL) []*http.Cookie {
	var out []*http.Cookie
	for _, c := range j.cookies {
		if c.MaxAge < 0 {
			continue
		}
		out = append(out, c)
	}
	return out
}

// seed writes n traffic entries into the apiTest's log through a Writer, which
// is the only supported way to append.
func (h *apiTest) seed(t *testing.T, n int) {
	t.Helper()

	writer, err := audit.NewWriter(context.Background(), h.repo, audit.WriterOptions{Buffer: n + 8})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for i := 0; i < n; i++ {
		verdict, rule := string(model.Allow), ""
		if i%3 == 0 {
			verdict, rule = string(model.Block), "sqli"
		}
		writer.Record(model.KindTraffic, fmt.Sprintf("req-%03d", i), map[string]any{
			"ip":      fmt.Sprintf("203.0.113.%d", i%5),
			"verdict": verdict,
			"rule":    rule,
			"path":    "/productos",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := writer.Close(ctx); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}
}

// --- The session gate --------------------------------------------------------

// guardedRoutes is every route behind the session, in the order Handler
// registers them. It is written out rather than derived so that adding a route
// without adding it here is a visible omission.
var guardedRoutes = []struct {
	method string
	path   string
}{
	{http.MethodGet, "/api/v1/events"},
	{http.MethodGet, "/api/v1/events/req-001"},
	{http.MethodGet, "/api/v1/stats"},
	{http.MethodGet, "/api/v1/audit/verify"},
	{http.MethodGet, "/api/v1/rules"},
	{http.MethodPatch, "/api/v1/rules/sqli"},
	{http.MethodGet, "/api/v1/ipblock"},
	{http.MethodPost, "/api/v1/ipblock"},
	{http.MethodDelete, "/api/v1/ipblock?cidr=203.0.113.0/24"},
	{http.MethodGet, "/api/v1/status"},
	{http.MethodGet, "/ws/live"},
}

func TestEveryGuardedRouteRefusesAnAnonymousRequest(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	for _, route := range guardedRoutes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			resp := h.do(t, route.method, route.path, strings.NewReader("{}"))
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
		})
	}
}

func TestGuardedRoutesRefuseAForgedSession(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	for _, token := range []string{
		"nonsense",
		"admin|9999999999|deadbeef",
		"",
	} {
		req, _ := http.NewRequest(http.MethodGet, h.server.URL+"/api/v1/events", nil)
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})

		resp, err := (&http.Client{}).Do(req)
		if err != nil {
			t.Fatalf("GET /api/v1/events: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("token %q accepted with status %d, want 401", token, resp.StatusCode)
		}
	}
}

func TestHealthIsPublic(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	resp := h.do(t, http.MethodGet, "/healthz", nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200 — an orchestrator has no session", resp.StatusCode)
	}
}

// --- Signing in --------------------------------------------------------------

func TestLoginIssuesASessionAndRecordsIt(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.signIn(t)

	var session struct {
		User string `json:"user"`
	}
	if status := h.getJSON(t, "/api/v1/session", &session); status != http.StatusOK {
		t.Fatalf("/api/v1/session = %d after signing in, want 200", status)
	}
	if session.User != testUser {
		t.Errorf("session user = %q, want %q", session.User, testUser)
	}

	// §6.1 puts administrative access on the record.
	select {
	case call := <-h.engineCalls:
		payload, _ := call["payload"].(map[string]any)
		if payload["action"] != "login" {
			t.Errorf("recorded action = %v, want login", payload["action"])
		}
		if call["kind"] != model.KindAdmin {
			t.Errorf("recorded kind = %v, want %q", call["kind"], model.KindAdmin)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the sign-in was not recorded in the audit log")
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	for name, body := range map[string]string{
		"wrong password": `{"user":"admin","password":"guess"}`,
		"unknown user":   `{"user":"root","password":"correct horse battery staple"}`,
		"empty":          `{"user":"","password":""}`,
	} {
		t.Run(name, func(t *testing.T) {
			resp := h.do(t, http.MethodPost, "/api/v1/login", strings.NewReader(body))
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			// The answer must not distinguish a wrong password from an unknown
			// user, or it becomes a user-enumeration oracle.
			out, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(out), "invalid credentials") {
				t.Errorf("body = %s, want a single generic message", out)
			}
		})
	}
}

// There is one administrator account and no lockout, so without throttling the
// login endpoint is an online password oracle that answers as fast as bcrypt
// allows.
func TestLoginThrottlesRepeatedFailures(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	const limit = 10
	throttled := false
	for i := 0; i < limit+5; i++ {
		resp := h.do(t, http.MethodPost, "/api/v1/login",
			strings.NewReader(`{"user":"admin","password":"guess"}`))
		status := resp.StatusCode
		resp.Body.Close()

		if status == http.StatusTooManyRequests {
			throttled = true
			break
		}
	}
	if !throttled {
		t.Fatalf("still answering after %d failed attempts, want 429", limit+5)
	}

	// The throttle must survive a correct password too, or an attacker simply
	// keeps guessing past it.
	resp := h.do(t, http.MethodPost, "/api/v1/login",
		strings.NewReader(fmt.Sprintf(`{"user":%q,"password":%q}`, testUser, testPassword)))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d after the limiter tripped, want 429", resp.StatusCode)
	}
}

// A successful sign-in clears the counter, so an operator who mistypes a few
// times and then gets it right is not locked out of their own dashboard.
func TestASuccessfulLoginClearsTheThrottle(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	for i := 0; i < 5; i++ {
		resp := h.do(t, http.MethodPost, "/api/v1/login",
			strings.NewReader(`{"user":"admin","password":"guess"}`))
		resp.Body.Close()
	}
	h.signIn(t)

	for i := 0; i < 8; i++ {
		resp := h.do(t, http.MethodPost, "/api/v1/login",
			strings.NewReader(`{"user":"admin","password":"guess"}`))
		status := resp.StatusCode
		resp.Body.Close()
		if status == http.StatusTooManyRequests {
			t.Fatalf("throttled after %d failures following a success; the counter was not reset", i+1)
		}
	}
}

func TestLogoutClearsTheSession(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.signIn(t)

	resp := h.do(t, http.MethodPost, "/api/v1/logout", nil)
	resp.Body.Close()

	if status := h.getJSON(t, "/api/v1/session", nil); status != http.StatusUnauthorized {
		t.Fatalf("/api/v1/session = %d after signing out, want 401", status)
	}
}

// Signing in is logged best-effort. Refusing a login because the engine is
// unreachable would lock the operator out of the tool they need in order to
// find out why the engine is unreachable.
func TestLoginSucceedsEvenWhenTheEngineCannotRecordIt(t *testing.T) {
	h := newHarness(t, harnessOptions{engineDown: true})

	resp := h.do(t, http.MethodPost, "/api/v1/login",
		strings.NewReader(fmt.Sprintf(`{"user":%q,"password":%q}`, testUser, testPassword)))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d with the engine down, want 200", resp.StatusCode)
	}
}

// --- Reading the log ---------------------------------------------------------

func TestEventsAppliesFilters(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.seed(t, 30)
	h.signIn(t)

	var all struct {
		Entries []model.AuditEntry `json:"entries"`
		Total   int64              `json:"total"`
	}
	if status := h.getJSON(t, "/api/v1/events?limit=100", &all); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if all.Total != 30 {
		t.Fatalf("total = %d, want 30", all.Total)
	}

	var blocked struct {
		Entries []model.AuditEntry `json:"entries"`
		Total   int64              `json:"total"`
	}
	if status := h.getJSON(t, "/api/v1/events?verdict=block&limit=100", &blocked); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if blocked.Total == 0 || blocked.Total >= all.Total {
		t.Fatalf("blocked total = %d, want a strict subset of %d", blocked.Total, all.Total)
	}
	for _, e := range blocked.Entries {
		if e.Payload["verdict"] != string(model.Block) {
			t.Fatalf("filter leaked a %v entry", e.Payload["verdict"])
		}
	}
}

// An empty result has to serialise as [] and not null, or the SPA has to
// special-case it on every screen.
func TestEventsReturnsAnEmptyArrayNotNull(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.signIn(t)

	resp := h.do(t, http.MethodGet, "/api/v1/events", nil)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"entries":[]`) {
		t.Fatalf("body = %s, want an empty array", body)
	}
}

// The store clamps Limit to 500. The response has to report the limit that was
// actually applied, because a client paginating on the number it was given
// would step over the entries it never received.
func TestEventsReportsTheLimitItActuallyApplied(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.seed(t, 20)
	h.signIn(t)

	var out struct {
		Entries []model.AuditEntry `json:"entries"`
		Limit   int                `json:"limit"`
		Offset  int                `json:"offset"`
	}
	if status := h.getJSON(t, "/api/v1/events?limit=1000", &out); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if out.Limit > 500 {
		t.Errorf("limit = %d, want it clamped to 500 — the client paginates on this number", out.Limit)
	}
}

func TestEventsRejectsMalformedFilters(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.signIn(t)

	for name, query := range map[string]string{
		"limit is not a number":  "limit=muchos",
		"offset is not a number": "offset=x",
		"from is not RFC3339":    "from=ayer",
		"to is not RFC3339":      "to=2026-08-25",
	} {
		t.Run(name, func(t *testing.T) {
			if status := h.getJSON(t, "/api/v1/events?"+query, nil); status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", status)
			}
		})
	}
}

func TestEventByRequestIDReturnsEveryEntryForIt(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.seed(t, 5)
	h.signIn(t)

	var out struct {
		Entries []model.AuditEntry `json:"entries"`
	}
	if status := h.getJSON(t, "/api/v1/events/req-002", &out); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if len(out.Entries) != 1 || out.Entries[0].RequestID != "req-002" {
		t.Fatalf("got %d entries for req-002", len(out.Entries))
	}

	if status := h.getJSON(t, "/api/v1/events/no-such-request", nil); status != http.StatusNotFound {
		t.Fatalf("unknown request id = %d, want 404", status)
	}
}

func TestStatsRejectsAnAbsurdWindow(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.signIn(t)

	for name, window := range map[string]string{
		"not a duration": "una hora",
		"zero":           "0s",
		"negative":       "-1h",
		"beyond a month": "1000h",
	} {
		t.Run(name, func(t *testing.T) {
			if status := h.getJSON(t, "/api/v1/stats?window="+window, nil); status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", status)
			}
		})
	}
}

func TestStatsSummarisesTheWindow(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.seed(t, 30)
	h.signIn(t)

	var stats audit.Stats
	if status := h.getJSON(t, "/api/v1/stats?window=1h", &stats); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if stats.Total != 30 {
		t.Errorf("total = %d, want 30", stats.Total)
	}
	if stats.Allowed+stats.Blocked != stats.Total {
		t.Errorf("allowed %d + blocked %d != total %d", stats.Allowed, stats.Blocked, stats.Total)
	}
}

// --- Verification ------------------------------------------------------------

func TestVerifyReportsAnIntactChain(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.seed(t, 10)
	h.signIn(t)

	var result audit.VerifyResult
	if status := h.getJSON(t, "/api/v1/audit/verify", &result); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if !result.OK {
		t.Fatalf("chain reported broken at %s: %s", result.BrokenAt, result.Detail)
	}
	if result.Checked != 10 {
		t.Errorf("checked = %d, want 10", result.Checked)
	}
}

// The operator's first question about a broken chain is "where". A bare false
// would send them to read the whole log by hand.
func TestVerifyNamesTheEntryThatWasTamperedWith(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.seed(t, 10)
	h.signIn(t)

	tampered := h.repo.Entries()[4]
	h.repo.Tamper(4, func(e *model.AuditEntry) {
		// Rewriting the source address is the edit an attacker would make:
		// erase which host the request came from, leave everything else intact.
		e.Payload["ip"] = "192.0.2.66"
	})

	var result audit.VerifyResult
	if status := h.getJSON(t, "/api/v1/audit/verify", &result); status != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a broken chain is a finding, not a server error", status)
	}
	if result.OK {
		t.Fatal("verification passed on a log whose fifth entry was rewritten")
	}
	if result.BrokenAt != tampered.ID {
		t.Errorf("broken_at = %q, want %q", result.BrokenAt, tampered.ID)
	}
	if result.Position != 5 {
		t.Errorf("position = %d, want 5", result.Position)
	}
	if result.Detail == "" {
		t.Error("detail is empty; the operator needs to know what failed, not only where")
	}
}

func TestVerifyRejectsMalformedBounds(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.signIn(t)

	for _, query := range []string{"from=ayer", "to=25/08/2026"} {
		if status := h.getJSON(t, "/api/v1/audit/verify?"+query, nil); status != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", query, status)
		}
	}
}

// --- Status ------------------------------------------------------------------

func TestStatusReportsTheEngine(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.signIn(t)

	var out struct {
		Version string         `json:"version"`
		Engine  map[string]any `json:"engine"`
	}
	if status := h.getJSON(t, "/api/v1/status", &out); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if out.Version != "test" {
		t.Errorf("version = %q, want test", out.Version)
	}
	if out.Engine["reachable"] != true {
		t.Errorf("engine.reachable = %v, want true", out.Engine["reachable"])
	}
}

// A dashboard that cannot reach the engine still has to render. Saying so on
// the status view is more useful than a blank page, and it is the first thing
// an operator checks when the live feed goes quiet.
func TestStatusRendersWithTheEngineUnreachable(t *testing.T) {
	// Port 1 is not something anything listens on, so the audit client fails to
	// connect rather than getting an error response.
	h := newHarness(t, harnessOptions{engineURL: "http://127.0.0.1:1"})
	h.signIn(t)

	var out struct {
		Engine map[string]any `json:"engine"`
	}
	if status := h.getJSON(t, "/api/v1/status", &out); status != http.StatusOK {
		t.Fatalf("status = %d, want 200 even with the engine down", status)
	}
	if out.Engine["reachable"] != false {
		t.Fatalf("engine.reachable = %v, want false", out.Engine["reachable"])
	}
	if out.Engine["error"] == nil {
		t.Error("engine.error is absent; the operator needs to know why it is unreachable")
	}
}

// --- The SPA and its headers -------------------------------------------------

// A deep link the operator bookmarked is handed to the client-side router
// rather than answered with 404.
func TestUnknownPathsFallBackToTheSPA(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	for _, path := range []string{"/", "/events", "/forensics/2026", "/rules"} {
		resp := h.do(t, http.MethodGet, path, nil)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, resp.StatusCode)
		}
		if !strings.Contains(string(body), "<!doctype html>") {
			t.Errorf("GET %s did not return index.html: %s", path, body)
		}
		if cache := resp.Header.Get("Cache-Control"); cache != "no-cache" {
			t.Errorf("GET %s Cache-Control = %q, want no-cache — a cached index keeps loading an old build's asset names",
				path, cache)
		}
	}
}

func TestHashedAssetsAreCachedHard(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	resp := h.do(t, http.MethodGet, "/assets/index-abc123.js", nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if cache := resp.Header.Get("Cache-Control"); !strings.Contains(cache, "immutable") {
		t.Errorf("Cache-Control = %q, want an immutable asset cache", cache)
	}
}

// The dashboard renders attacker-controlled strings: the paths and payload
// excerpts of blocked requests. React escapes them; the policy is the second
// lock, so that a protection tool cannot be turned against its own operator
// through the payloads it caught.
func TestEveryResponseCarriesTheSecurityHeaders(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	for _, path := range []string{"/", "/healthz", "/api/v1/events", "/assets/index-abc123.js"} {
		resp := h.do(t, http.MethodGet, path, nil)
		resp.Body.Close()

		for header, want := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
			"Referrer-Policy":        "no-referrer",
		} {
			if got := resp.Header.Get(header); got != want {
				t.Errorf("GET %s: %s = %q, want %q", path, header, got, want)
			}
		}

		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("GET %s: CSP = %q, want it to forbid framing", path, csp)
		}
		if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
			t.Errorf("GET %s: CSP allows inline script, which defeats the point", path)
		}
	}
}

// A build with no SPA compiled into it must say so rather than serve an empty
// page that looks like a broken dashboard.
func TestAMissingSPABuildIsReported(t *testing.T) {
	h := newHarness(t, harnessOptions{spa: fstest.MapFS{}})

	resp := h.do(t, http.MethodGet, "/", nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "dashboard assets are missing") {
		t.Errorf("body = %s, want an explanation", body)
	}
}

// --- Helpers -----------------------------------------------------------------

func TestClientIPPrefersTheForwardedAddress(t *testing.T) {
	// The dashboard sits behind the same proxy the system installs, so
	// RemoteAddr is the proxy. Getting this wrong would throttle every operator
	// as if they shared one address, and would record the proxy as the actor of
	// every administrative change.
	for name, c := range map[string]struct {
		remote    string
		forwarded string
		want      string
	}{
		"no forwarded header": {remote: "203.0.113.7:54321", want: "203.0.113.7"},
		"single hop":          {remote: "10.0.0.1:443", forwarded: "203.0.113.7", want: "203.0.113.7"},
		"chain of proxies":    {remote: "10.0.0.1:443", forwarded: "203.0.113.7, 10.0.0.5", want: "203.0.113.7"},
		"padded":              {remote: "10.0.0.1:443", forwarded: "  203.0.113.7 , 10.0.0.5", want: "203.0.113.7"},
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = c.remote
			if c.forwarded != "" {
				req.Header.Set("X-Forwarded-For", c.forwarded)
			}
			if got := clientIP(req); got != c.want {
				t.Fatalf("clientIP = %q, want %q", got, c.want)
			}
		})
	}
}

func TestParsePrefixNormalisesEntries(t *testing.T) {
	// 203.0.113.7/24 and 203.0.113.0/24 mean the same range. Storing both as
	// separate rows would let an operator "delete" a block that stays in force.
	for input, want := range map[string]string{
		"203.0.113.0/24": "203.0.113.0/24",
		"203.0.113.7/24": "203.0.113.0/24",
		"203.0.113.7":    "203.0.113.7/32",
		"2001:db8::1":    "2001:db8::1/128",
		"2001:db8::/32":  "2001:db8::/32",
		" 203.0.113.7 ":  "203.0.113.7/32",
	} {
		got, err := parsePrefix(input)
		if err != nil {
			t.Errorf("parsePrefix(%q): %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("parsePrefix(%q) = %q, want %q", input, got, want)
		}
	}

	for _, input := range []string{"", "   ", "no-es-una-ip", "203.0.113.0/99", "203.0.113"} {
		if got, err := parsePrefix(input); err == nil {
			t.Errorf("parsePrefix(%q) = %q, want an error", input, got)
		}
	}
}
