// Package model holds the types shared by the rules engine and the dashboard API:
// the context of an inbound request, the verdict produced for it, and the audit
// entry that records the decision.
package model

import "time"

// Verdict is the outcome of evaluating a request against the rule chain.
type Verdict string

const (
	Allow Verdict = "allow"
	Block Verdict = "block"
)

// Kind classifies an audit entry. Section 6.1 of the technical document requires
// external traffic, internal system events and administrative access to be
// recorded on the same chain but distinguishable from each other.
const (
	KindTraffic = "traffic"
	KindSystem  = "system"
	KindAdmin   = "admin"
)

// RequestContext is everything the rule chain is allowed to know about an
// inbound request. The proxy builds it in Lua and posts it to /v1/decide.
//
// Body carries at most OS_MAX_BODY_INSPECT_BYTES bytes; BodyTruncated reports
// whether the proxy had to cut it. Rules must treat a truncated body as
// partially unknown rather than as safe.
type RequestContext struct {
	RequestID     string            `json:"request_id"`
	IP            string            `json:"ip"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Query         string            `json:"query"`
	Headers       map[string]string `json:"headers,omitempty"`
	Body          string            `json:"body,omitempty"`
	BodyTruncated bool              `json:"body_truncated,omitempty"`
	ReceivedAt    time.Time         `json:"received_at"`
}

// Header returns the value of a header by canonical lowercase name. The proxy
// lowercases header names before sending them, so lookups here are exact.
func (r *RequestContext) Header(name string) string {
	if r.Headers == nil {
		return ""
	}
	return r.Headers[name]
}

// Decision is what the engine answers to the proxy. Rule and Reason are empty
// on Allow: nothing blocked the request, so there is nothing to attribute.
type Decision struct {
	Verdict Verdict `json:"verdict"`
	Rule    string  `json:"rule,omitempty"`
	Reason  string  `json:"reason,omitempty"`
	// Status is the HTTP status the proxy should return when Verdict is Block.
	Status int `json:"status,omitempty"`
	// DecisionMS is how long the rule chain took, in milliseconds. Section 6.1
	// asks for per-stage latency in the audit record.
	DecisionMS float64 `json:"decision_ms"`
}
