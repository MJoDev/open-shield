package model

import "time"

// IPRule is one row of the IP access list (§4.1, RF-03).
//
// It lives here rather than next to the rule that uses it because the write
// side (the dashboard API) and the read side (the engine's rule chain) sit in
// packages that cannot import each other.
type IPRule struct {
	CIDR      string    `json:"cidr"`
	Action    string    `json:"action"` // "allow" or "deny"
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
}

// Valid IPRule actions.
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
)

// RuleConfig is the stored on/off state of one rule in the chain.
type RuleConfig struct {
	Name      string         `json:"name"`
	Enabled   bool           `json:"enabled"`
	Config    map[string]any `json:"config,omitempty"`
	UpdatedAt time.Time      `json:"updated_at"`
	UpdatedBy string         `json:"updated_by,omitempty"`
}
