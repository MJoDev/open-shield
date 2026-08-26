-- Rule configuration and the IP access list.
--
-- Unlike audit_log these tables are mutable: they hold the current state of the
-- system, not its history. Every change made through the dashboard is recorded
-- in audit_log as a kind='admin' entry (§6.1), so the mutable state always has
-- an immutable trail behind it.

CREATE TABLE IF NOT EXISTS rules (
    name       TEXT        PRIMARY KEY,
    enabled    BOOLEAN     NOT NULL DEFAULT TRUE,
    config     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT        NOT NULL DEFAULT ''
);

-- The rule chain runs in this order; the first Block wins, so the cheap checks
-- come before the expensive pattern matching.
INSERT INTO rules (name, enabled, config) VALUES
    ('ipblock',   TRUE, '{}'::jsonb),
    ('ratelimit', TRUE, '{}'::jsonb),
    ('sqli',      TRUE, '{}'::jsonb),
    ('xss',       TRUE, '{}'::jsonb)
ON CONFLICT (name) DO NOTHING;

-- CIDR rather than INET so a single row can cover a network. An 'allow' entry
-- wins over a 'deny' entry, which is what makes it possible to block a range
-- and still let a known office address through.
CREATE TABLE IF NOT EXISTS ip_rules (
    cidr       CIDR        PRIMARY KEY,
    action     TEXT        NOT NULL CHECK (action IN ('allow', 'deny')),
    note       TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS ip_rules_action_idx ON ip_rules (action);
