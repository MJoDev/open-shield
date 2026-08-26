// Package httpapi exposes the rules engine over HTTP. It is the "control
// plane" half of §3.1: the proxy carries the request, this decides what
// happens to it.
//
// Only the proxy talks to this server, and it is never published outside the
// compose network.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/open-shield/open-shield/engine/internal/rules"
	"github.com/open-shield/open-shield/internal/audit"
	"github.com/open-shield/open-shield/internal/model"
)

// maxDecideBody caps the decision request itself. The proxy already truncates
// the inspected body; this is the engine's own guard against a malformed or
// hostile caller.
const maxDecideBody = 1 << 20 // 1 MiB

// Server wires the rule chain, the audit writer and the health checks.
type Server struct {
	engine  *rules.Engine
	writer  *audit.Writer
	log     *slog.Logger
	ready   func() error
	version string
}

// Options configures the engine server.
type Options struct {
	Engine *rules.Engine
	Writer *audit.Writer
	Logger *slog.Logger
	// Ready reports whether the engine's dependencies are usable. It backs
	// /readyz, which is what Compose waits on before starting the proxy.
	Ready   func() error
	Version string
}

// New returns a Server.
func New(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Ready == nil {
		opts.Ready = func() error { return nil }
	}
	return &Server{
		engine:  opts.Engine,
		writer:  opts.Writer,
		log:     opts.Logger,
		ready:   opts.Ready,
		version: opts.Version,
	}
}

// Handler builds the router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/decide", s.handleDecide)
	mux.HandleFunc("POST /v1/audit", s.handleAudit)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /v1/status", s.handleStatus)
	return mux
}

// decideRequest is what the proxy's Lua hook posts for every inbound request.
type decideRequest struct {
	RequestID     string            `json:"request_id"`
	IP            string            `json:"ip"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Query         string            `json:"query"`
	Host          string            `json:"host"`
	Scheme        string            `json:"scheme"`
	Headers       map[string]string `json:"headers"`
	Body          string            `json:"body"`
	BodyTruncated bool              `json:"body_truncated"`
}

// decideResponse is what the proxy acts on.
type decideResponse struct {
	Verdict    model.Verdict `json:"verdict"`
	Rule       string        `json:"rule,omitempty"`
	Reason     string        `json:"reason,omitempty"`
	Status     int           `json:"status,omitempty"`
	RequestID  string        `json:"request_id"`
	DecisionMS float64       `json:"decision_ms"`
}

func (s *Server) handleDecide(w http.ResponseWriter, r *http.Request) {
	var req decideRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDecideBody))
	if err := dec.Decode(&req); err != nil {
		// The proxy is the only caller; a malformed body means the two are out
		// of step. Answering 400 makes the proxy fall back to its configured
		// fail mode rather than guessing.
		s.log.Error("malformed decision request", "error", err, "remote", r.RemoteAddr)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed decision request"})
		return
	}

	reqCtx := model.RequestContext{
		RequestID:     req.RequestID,
		IP:            req.IP,
		Method:        req.Method,
		Path:          req.Path,
		Query:         req.Query,
		Headers:       lowercaseKeys(req.Headers),
		Body:          req.Body,
		BodyTruncated: req.BodyTruncated,
		ReceivedAt:    time.Now().UTC(),
	}

	decision := s.engine.Decide(r.Context(), &reqCtx)

	writeJSON(w, http.StatusOK, decideResponse{
		Verdict:    decision.Verdict,
		Rule:       decision.Rule,
		Reason:     decision.Reason,
		Status:     decision.Status,
		RequestID:  req.RequestID,
		DecisionMS: decision.DecisionMS,
	})

	// Recorded after the response is written: the verdict is on its way back to
	// the proxy before any of the audit work begins (§8.2, latency budget).
	s.writer.Record(model.KindTraffic, req.RequestID, trafficPayload(req, reqCtx, decision))
}

// trafficPayload is the audit record for one request.
//
// Two things are deliberately left out:
//
//   - The request body. It is scanned, never stored. Bodies carry passwords,
//     tokens and personal data, and an append-only log that is kept for a long
//     time is the worst possible place for them. What survives is the bounded
//     excerpt inside the block reason, which is the evidence of *why* the
//     request was blocked.
//   - Cookie and Authorization headers, for the same reason: an audit log that
//     stores session tokens turns into a credential store.
func trafficPayload(req decideRequest, ctx model.RequestContext, decision model.Decision) map[string]any {
	payload := map[string]any{
		"ip":          req.IP,
		"method":      req.Method,
		"path":        truncate(req.Path, 2048),
		"query":       truncate(req.Query, 2048),
		"host":        req.Host,
		"verdict":     string(decision.Verdict),
		"decision_ms": decision.DecisionMS,
		"headers":     auditHeaders(ctx.Headers),
	}

	if req.BodyTruncated {
		payload["body_truncated"] = true
	}
	if decision.Verdict == model.Block {
		payload["rule"] = decision.Rule
		payload["reason"] = truncate(decision.Reason, 512)
		payload["status"] = decision.Status
	}
	return payload
}

// auditHeaders keeps the headers that identify a client and drops the ones that
// authenticate it.
func auditHeaders(headers map[string]string) map[string]any {
	const keep = "user-agent,referer,origin,accept-language,x-forwarded-for"

	out := map[string]any{}
	for _, name := range strings.Split(keep, ",") {
		if value := headers[name]; value != "" {
			out[name] = truncate(value, 512)
		}
	}
	return out
}

// auditRequest is how the dashboard records an administrative action.
type auditRequest struct {
	Kind      string         `json:"kind"`
	RequestID string         `json:"request_id"`
	Payload   map[string]any `json:"payload"`
}

// handleAudit appends an entry on behalf of the dashboard.
//
// The dashboard cannot write to the chain itself. Each entry's hash covers the
// one before it, so a second process appending in parallel would fork the chain
// into two branches that no longer verify. Everything that goes on the record
// goes through this one writer.
//
// The append is synchronous: the dashboard applies a configuration change only
// once its audit entry is durable.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	var req auditRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDecideBody))
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed audit request"})
		return
	}

	// 'traffic' is reserved for the decision path: an entry claiming to be a
	// blocked request must actually have come from one.
	if req.Kind != model.KindAdmin && req.Kind != model.KindSystem {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("kind must be %q or %q", model.KindAdmin, model.KindSystem),
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := s.writer.RecordSync(ctx, req.Kind, req.RequestID, req.Payload); err != nil {
		s.log.Error("could not record administrative entry", "error", err, "kind", req.Kind)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "the audit entry could not be committed: " + err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"status": "recorded"})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.version})
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	if err := s.ready(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "unavailable",
			"error":  err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// handleStatus reports what the engine is currently enforcing. The dashboard
// shows it so that "the rate limit is silently not running" is visible rather
// than something an operator discovers after an incident.
func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version": s.version,
		"chain":   s.engine.Names(),
		"enabled": s.engine.Enabled(),
		"audit":   s.writer.Stats(),
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil && !errors.Is(err, http.ErrHandlerTimeout) {
		slog.Default().Warn("writing response failed", "error", err)
	}
}

func lowercaseKeys(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	out := make(map[string]string, len(headers))
	for name, value := range headers {
		out[strings.ToLower(name)] = value
	}
	return out
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
