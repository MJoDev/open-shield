// Package rulestore reads and writes the mutable configuration of the rule
// chain: which rules are enabled, and the IP access list.
//
// The engine only reads from it. The dashboard API writes to it and then
// publishes a control notification, which is how a change made in the browser
// reaches a running engine without restarting anything.
package rulestore

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-shield/open-shield/internal/model"
)

// ErrUnknownRule is returned when a caller refers to a rule that is not in the
// chain.
var ErrUnknownRule = errors.New("rulestore: unknown rule")

// Store is the PostgreSQL-backed configuration store.
type Store struct {
	pool *pgxpool.Pool
}

// New returns a Store over an existing pool. The pool is shared with the audit
// repository rather than opened again: one service, one set of connections.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Rules returns every rule's stored state, in chain order.
func (s *Store) Rules(ctx context.Context) ([]model.RuleConfig, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT name, enabled, config, updated_at, updated_by
		FROM rules
		ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("rulestore: list rules: %w", err)
	}
	defer rows.Close()

	var out []model.RuleConfig
	for rows.Next() {
		var (
			rule model.RuleConfig
			raw  []byte
		)
		if err := rows.Scan(&rule.Name, &rule.Enabled, &raw, &rule.UpdatedAt, &rule.UpdatedBy); err != nil {
			return nil, fmt.Errorf("rulestore: scan rule: %w", err)
		}
		if rule.Config, err = model.DecodeJSONPayload(raw); err != nil {
			return nil, err
		}
		rule.UpdatedAt = rule.UpdatedAt.UTC()
		out = append(out, rule)
	}
	return out, rows.Err()
}

// EnabledMap returns the on/off state keyed by rule name, which is the shape
// the engine's chain wants.
func (s *Store) EnabledMap(ctx context.Context) (map[string]bool, error) {
	rules, err := s.Rules(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(rules))
	for _, r := range rules {
		out[r.Name] = r.Enabled
	}
	return out, nil
}

// SetEnabled turns a rule on or off. It returns ErrUnknownRule rather than
// silently creating a row for a rule the engine does not have: a typo in the
// API should fail loudly, not add configuration nothing reads.
func (s *Store) SetEnabled(ctx context.Context, name string, enabled bool, actor string) (model.RuleConfig, error) {
	var (
		rule model.RuleConfig
		raw  []byte
	)
	err := s.pool.QueryRow(ctx, `
		UPDATE rules
		SET enabled = $2, updated_at = now(), updated_by = $3
		WHERE name = $1
		RETURNING name, enabled, config, updated_at, updated_by`,
		name, enabled, actor).
		Scan(&rule.Name, &rule.Enabled, &raw, &rule.UpdatedAt, &rule.UpdatedBy)

	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return model.RuleConfig{}, fmt.Errorf("%w: %s", ErrUnknownRule, name)
	case err != nil:
		return model.RuleConfig{}, fmt.Errorf("rulestore: update rule %s: %w", name, err)
	}

	if rule.Config, err = model.DecodeJSONPayload(raw); err != nil {
		return model.RuleConfig{}, err
	}
	rule.UpdatedAt = rule.UpdatedAt.UTC()
	return rule, nil
}

// IPRules returns the whole access list.
func (s *Store) IPRules(ctx context.Context) ([]model.IPRule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT cidr::text, action, note, created_at, created_by
		FROM ip_rules
		ORDER BY action, cidr`)
	if err != nil {
		return nil, fmt.Errorf("rulestore: list ip rules: %w", err)
	}
	defer rows.Close()

	var out []model.IPRule
	for rows.Next() {
		var rule model.IPRule
		if err := rows.Scan(&rule.CIDR, &rule.Action, &rule.Note,
			&rule.CreatedAt, &rule.CreatedBy); err != nil {
			return nil, fmt.Errorf("rulestore: scan ip rule: %w", err)
		}
		rule.CreatedAt = rule.CreatedAt.UTC()
		out = append(out, rule)
	}
	return out, rows.Err()
}

// AddIPRule inserts or replaces one access-list entry. The CIDR must already be
// normalised by the caller (see rules.ParsePrefix), so that 203.0.113.7/24 and
// 203.0.113.0/24 cannot both exist as separate rows meaning the same thing.
func (s *Store) AddIPRule(ctx context.Context, rule model.IPRule, actor string) (model.IPRule, error) {
	if rule.Action != model.ActionAllow && rule.Action != model.ActionDeny {
		return model.IPRule{}, fmt.Errorf("rulestore: action must be %q or %q, got %q",
			model.ActionAllow, model.ActionDeny, rule.Action)
	}

	var out model.IPRule
	err := s.pool.QueryRow(ctx, `
		INSERT INTO ip_rules (cidr, action, note, created_by)
		VALUES ($1::cidr, $2, $3, $4)
		ON CONFLICT (cidr) DO UPDATE
			SET action = EXCLUDED.action,
			    note = EXCLUDED.note,
			    created_at = now(),
			    created_by = EXCLUDED.created_by
		RETURNING cidr::text, action, note, created_at, created_by`,
		rule.CIDR, rule.Action, rule.Note, actor).
		Scan(&out.CIDR, &out.Action, &out.Note, &out.CreatedAt, &out.CreatedBy)
	if err != nil {
		return model.IPRule{}, fmt.Errorf("rulestore: add ip rule %s: %w", rule.CIDR, err)
	}

	out.CreatedAt = out.CreatedAt.UTC()
	return out, nil
}

// DeleteIPRule removes one access-list entry. It reports whether a row was
// actually removed, so the API can answer 404 for a CIDR that was not listed.
func (s *Store) DeleteIPRule(ctx context.Context, cidr string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM ip_rules WHERE cidr = $1::cidr`, cidr)
	if err != nil {
		return false, fmt.Errorf("rulestore: delete ip rule %s: %w", cidr, err)
	}
	return tag.RowsAffected() > 0, nil
}
