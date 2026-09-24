// Package httpapi serves the dashboard: the REST API, the live WebSocket and
// the React application itself.
package httpapi

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/open-shield/open-shield/dashboard/api/internal/auth"
	"github.com/open-shield/open-shield/dashboard/api/internal/ws"
	"github.com/open-shield/open-shield/internal/audit"
	"github.com/open-shield/open-shield/internal/events"
	"github.com/open-shield/open-shield/internal/model"
	"github.com/open-shield/open-shield/internal/rulestore"
)

// Server holds the dashboard's dependencies.
type Server struct {
	repo      audit.Repository
	rules     *rulestore.Store
	sessions  *auth.Manager
	hub       *ws.Hub
	auditor   *AuditClient
	publisher *events.Publisher
	spa       fs.FS
	log       *slog.Logger
	version   string

	logins  *loginLimiter
	trusted trustedProxies
}

// Options configures the dashboard server.
type Options struct {
	Repo      audit.Repository
	Rules     *rulestore.Store
	Sessions  *auth.Manager
	Hub       *ws.Hub
	Auditor   *AuditClient
	Publisher *events.Publisher
	// SPA is the built React application, embedded in the binary.
	SPA     fs.FS
	Logger  *slog.Logger
	Version string
	// TrustedProxies are the networks whose X-Forwarded-For is believed.
	// Empty — the default — means the peer address is used and the header is
	// ignored, which is what keeps the sign-in throttle countable.
	TrustedProxies []netip.Prefix
}

// New returns a dashboard server.
func New(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Server{
		repo:      opts.Repo,
		rules:     opts.Rules,
		sessions:  opts.Sessions,
		hub:       opts.Hub,
		auditor:   opts.Auditor,
		publisher: opts.Publisher,
		spa:       opts.SPA,
		log:       opts.Logger,
		version:   opts.Version,
		logins:    newLoginLimiter(10, 15*time.Minute),
		trusted:   trustedProxies(opts.TrustedProxies),
	}
}

// Handler builds the router.
//
// Everything but /healthz and the login endpoint is behind a session. The live
// feed in particular: it carries source addresses, request paths and block
// reasons, which is precisely what an attacker would use to tune a payload past
// the filters.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public.
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /api/v1/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/logout", s.handleLogout)
	mux.HandleFunc("GET /api/v1/session", s.handleSession)

	// Authenticated.
	guarded := http.NewServeMux()
	guarded.HandleFunc("GET /api/v1/events", s.handleEvents)
	guarded.HandleFunc("GET /api/v1/events/{id}", s.handleEvent)
	guarded.HandleFunc("GET /api/v1/stats", s.handleStats)
	guarded.HandleFunc("GET /api/v1/audit/verify", s.handleVerify)
	guarded.HandleFunc("GET /api/v1/rules", s.handleListRules)
	guarded.HandleFunc("PATCH /api/v1/rules/{name}", s.handlePatchRule)
	guarded.HandleFunc("GET /api/v1/ipblock", s.handleListIPRules)
	guarded.HandleFunc("POST /api/v1/ipblock", s.handleAddIPRule)
	guarded.HandleFunc("DELETE /api/v1/ipblock", s.handleDeleteIPRule)
	guarded.HandleFunc("GET /api/v1/status", s.handleStatus)
	guarded.Handle("GET /ws/live", s.hub.Handler())

	mux.Handle("/api/", s.sessions.Require(guarded))
	mux.Handle("/ws/", s.sessions.Require(guarded))

	// The React application, and any client-side route within it.
	mux.Handle("/", s.spaHandler())

	return securityHeaders(mux)
}

// --- Session -----------------------------------------------------------------

type loginRequest struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Without this, a single administrator account with no lockout is an open
	// invitation to an offline-speed online guessing attack.
	if !s.logins.allow(s.trusted.clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, apiError{
			Error: "too many failed sign-in attempts; try again later"})
		return
	}

	var req loginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "malformed request"})
		return
	}

	token, err := s.sessions.Login(req.User, req.Password)
	if err != nil {
		s.logins.fail(s.trusted.clientIP(r))
		s.log.Warn("failed sign-in", "user", req.User, "ip", s.trusted.clientIP(r))
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "invalid credentials"})
		return
	}

	s.logins.reset(s.trusted.clientIP(r))
	s.sessions.SetCookie(w, token)

	// A sign-in is administrative access, which §6.1 puts on the record. It is
	// logged best-effort: refusing a login because the engine is unreachable
	// would lock an operator out of the tool they need in order to find out
	// why the engine is unreachable.
	if err := s.auditor.RecordAdmin(r.Context(), req.User, "login", map[string]any{
		"ip": s.trusted.clientIP(r),
	}); err != nil {
		s.log.Warn("could not record the sign-in", "error", err)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user":       req.User,
		"expires_in": int(s.sessions.TTL().Seconds()),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(auth.CookieName); err == nil {
		if user, err := s.sessions.Verify(cookie.Value); err == nil {
			if err := s.auditor.RecordAdmin(r.Context(), user, "logout", nil); err != nil {
				s.log.Warn("could not record the sign-out", "error", err)
			}
		}
	}

	s.sessions.ClearCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed out"})
}

// handleSession lets the SPA find out, on load, whether it already has a valid
// session instead of showing a login form to someone who is signed in.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(auth.CookieName)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "no session"})
		return
	}
	user, err := s.sessions.Verify(cookie.Value)
	if err != nil {
		s.sessions.ClearCookie(w)
		writeJSON(w, http.StatusUnauthorized, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"user": user})
}

// --- Audit log ---------------------------------------------------------------

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	filter, err := parseFilter(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}

	// Clamped here as well as inside the store, so that the limit reported back
	// is the limit that was applied. A client paginating on a number the store
	// quietly reduced would skip every entry between the two.
	filter = filter.Normalized()

	entries, err := s.repo.List(r.Context(), filter)
	if err != nil {
		s.fail(w, "listing audit entries", err)
		return
	}
	total, err := s.repo.Count(r.Context(), filter)
	if err != nil {
		s.fail(w, "counting audit entries", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"entries": nonNil(entries),
		"total":   total,
		"limit":   filter.Limit,
		"offset":  filter.Offset,
	})
}

// handleEvent returns every entry sharing one request id, which is how an
// operator follows a single request through the log.
func (s *Server) handleEvent(w http.ResponseWriter, r *http.Request) {
	entries, err := s.repo.List(r.Context(), audit.Filter{
		RequestID: r.PathValue("id"),
		Limit:     100,
	})
	if err != nil {
		s.fail(w, "reading audit entry", err)
		return
	}
	if len(entries) == 0 {
		writeJSON(w, http.StatusNotFound, apiError{Error: "no entry with that request id"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	window := time.Hour
	if raw := r.URL.Query().Get("window"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 || parsed > 30*24*time.Hour {
			writeJSON(w, http.StatusBadRequest, apiError{
				Error: "window must be a duration between 1s and 720h, e.g. 1h or 24h"})
			return
		}
		window = parsed
	}

	stats, err := s.repo.Stats(r.Context(), window)
	if err != nil {
		s.fail(w, "computing traffic statistics", err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// handleVerify walks the hash chain. This is the forensic guarantee of §6 made
// available as a single call.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	from, err := parseTime(r.URL.Query().Get("from"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "from: " + err.Error()})
		return
	}
	to, err := parseTime(r.URL.Query().Get("to"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "to: " + err.Error()})
		return
	}

	result, err := s.repo.VerifyChain(r.Context(), from, to)
	if err != nil {
		s.fail(w, "verifying the audit chain", err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// --- Rules -------------------------------------------------------------------

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.rules.Rules(r.Context())
	if err != nil {
		s.fail(w, "listing rules", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

type patchRuleRequest struct {
	Enabled *bool `json:"enabled"`
}

func (s *Server) handlePatchRule(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	actor := auth.UserFrom(r.Context())

	var req patchRuleRequest
	if err := decodeJSON(w, r, &req); err != nil || req.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: `body must be {"enabled": true|false}`})
		return
	}

	// Recorded before it is applied. If the entry cannot be committed the
	// change does not happen, so there is no window in which the enforced
	// configuration and the record of it disagree.
	if err := s.auditor.RecordAdmin(r.Context(), actor, "rule.set_enabled", map[string]any{
		"rule":    name,
		"enabled": *req.Enabled,
		"ip":      s.trusted.clientIP(r),
	}); err != nil {
		s.refuseUnaudited(w, err)
		return
	}

	rule, err := s.rules.SetEnabled(r.Context(), name, *req.Enabled, actor)
	if errors.Is(err, rulestore.ErrUnknownRule) {
		writeJSON(w, http.StatusNotFound, apiError{Error: "no such rule: " + name})
		return
	}
	if err != nil {
		s.fail(w, "updating rule", err)
		return
	}

	s.notifyEngine(r, "rules")
	writeJSON(w, http.StatusOK, rule)
}

// --- IP access list ----------------------------------------------------------

func (s *Server) handleListIPRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.rules.IPRules(r.Context())
	if err != nil {
		s.fail(w, "listing ip rules", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": nonNilIP(rules)})
}

func (s *Server) handleAddIPRule(w http.ResponseWriter, r *http.Request) {
	actor := auth.UserFrom(r.Context())

	var req model.IPRule
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "malformed request"})
		return
	}

	// Normalised here so that 203.0.113.7/24 and 203.0.113.0/24 cannot both
	// exist as rows meaning the same range, and so a bare address becomes /32.
	prefix, err := parsePrefix(req.CIDR)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	req.CIDR = prefix

	if req.Action != model.ActionAllow && req.Action != model.ActionDeny {
		writeJSON(w, http.StatusBadRequest, apiError{
			Error: `action must be "allow" or "deny"`})
		return
	}

	if err := s.auditor.RecordAdmin(r.Context(), actor, "ipblock.add", map[string]any{
		"cidr":   req.CIDR,
		"target": req.Action,
		"note":   req.Note,
		"ip":     s.trusted.clientIP(r),
	}); err != nil {
		s.refuseUnaudited(w, err)
		return
	}

	rule, err := s.rules.AddIPRule(r.Context(), req, actor)
	if err != nil {
		s.fail(w, "adding ip rule", err)
		return
	}

	s.notifyEngine(r, "ipblock")
	writeJSON(w, http.StatusCreated, rule)
}

// handleDeleteIPRule takes the CIDR as a query parameter rather than a path
// segment, because a CIDR contains a slash.
func (s *Server) handleDeleteIPRule(w http.ResponseWriter, r *http.Request) {
	actor := auth.UserFrom(r.Context())

	prefix, err := parsePrefix(r.URL.Query().Get("cidr"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}

	if err := s.auditor.RecordAdmin(r.Context(), actor, "ipblock.delete", map[string]any{
		"cidr": prefix,
		"ip":   s.trusted.clientIP(r),
	}); err != nil {
		s.refuseUnaudited(w, err)
		return
	}

	removed, err := s.rules.DeleteIPRule(r.Context(), prefix)
	if err != nil {
		s.fail(w, "deleting ip rule", err)
		return
	}
	if !removed {
		writeJSON(w, http.StatusNotFound, apiError{Error: "no such entry: " + prefix})
		return
	}

	s.notifyEngine(r, "ipblock")
	w.WriteHeader(http.StatusNoContent)
}

// --- Status ------------------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.version})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]any{
		"version":    s.version,
		"ws_clients": s.hub.Clients(),
	}

	engine, err := s.auditor.EngineStatus(r.Context())
	if err != nil {
		// A dashboard that cannot reach the engine still has to render, and
		// saying so is more useful than a blank page.
		status["engine"] = map[string]any{"reachable": false, "error": err.Error()}
	} else {
		engine["reachable"] = true
		status["engine"] = engine
	}

	writeJSON(w, http.StatusOK, status)
}

// --- Helpers -----------------------------------------------------------------

// notifyEngine tells a running engine to reload its configuration. A failure is
// not fatal: the engine also re-reads on a timer, so the change lands late
// rather than never.
func (s *Server) notifyEngine(r *http.Request, kind string) {
	if err := s.publisher.Notify(r.Context(), kind); err != nil {
		s.log.Warn("could not notify the engine of a configuration change",
			"error", err, "kind", kind)
	}
}

func (s *Server) refuseUnaudited(w http.ResponseWriter, err error) {
	s.log.Error("refusing a change that could not be audited", "error", err)
	writeJSON(w, http.StatusServiceUnavailable, apiError{
		Error: "the change was not applied because it could not be recorded in the audit log: " + err.Error(),
	})
}

// fail logs the real error and returns a generic one. Database errors carry
// schema and connection details that do not belong in an HTTP response.
func (s *Server) fail(w http.ResponseWriter, action string, err error) {
	s.log.Error(action+" failed", "error", err)
	writeJSON(w, http.StatusInternalServerError, apiError{Error: action + " failed"})
}

type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Default().Warn("writing response failed", "error", err)
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(target)
}

func parseFilter(r *http.Request) (audit.Filter, error) {
	q := r.URL.Query()

	from, err := parseTime(q.Get("from"))
	if err != nil {
		return audit.Filter{}, errors.New("from: " + err.Error())
	}
	to, err := parseTime(q.Get("to"))
	if err != nil {
		return audit.Filter{}, errors.New("to: " + err.Error())
	}

	filter := audit.Filter{
		Kind:      q.Get("kind"),
		Verdict:   q.Get("verdict"),
		IP:        q.Get("ip"),
		Rule:      q.Get("rule"),
		RequestID: q.Get("request_id"),
		From:      from,
		To:        to,
	}

	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return audit.Filter{}, errors.New("limit must be a number")
		}
		filter.Limit = n
	}
	if raw := q.Get("offset"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return audit.Filter{}, errors.New("offset must be a number")
		}
		filter.Offset = n
	}

	return filter, nil
}

func parseTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, errors.New("must be an RFC3339 timestamp, e.g. 2026-08-25T12:00:00Z")
	}
	return t.UTC(), nil
}

// nonNil turns a nil slice into an empty one so the JSON is [] rather than
// null, which the SPA would have to special-case.
func nonNil(entries []model.AuditEntry) []model.AuditEntry {
	if entries == nil {
		return []model.AuditEntry{}
	}
	return entries
}

func nonNilIP(rules []model.IPRule) []model.IPRule {
	if rules == nil {
		return []model.IPRule{}
	}
	return rules
}
