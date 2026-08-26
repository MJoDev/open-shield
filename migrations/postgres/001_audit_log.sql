-- The forensic audit log of section 6.
--
-- seq, not ts, is the chain order: two requests can land inside the same
-- microsecond, and PostgreSQL's timestamptz would not tell them apart. The
-- single writer goroutine in internal/audit appends in seq order, and
-- verification walks the same order.

CREATE TABLE IF NOT EXISTS audit_log (
    seq        BIGSERIAL    PRIMARY KEY,
    id         UUID         NOT NULL UNIQUE,
    request_id TEXT         NOT NULL DEFAULT '',
    ts         TIMESTAMPTZ  NOT NULL,
    kind       TEXT         NOT NULL CHECK (kind IN ('traffic', 'system', 'admin')),
    payload    JSONB        NOT NULL,
    prev_hash  CHAR(64)     NOT NULL,
    hash       CHAR(64)     NOT NULL UNIQUE
);

-- Newest-first listings and time-range verification.
CREATE INDEX IF NOT EXISTS audit_log_ts_idx        ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS audit_log_kind_ts_idx   ON audit_log (kind, ts DESC);
CREATE INDEX IF NOT EXISTS audit_log_request_idx   ON audit_log (request_id) WHERE request_id <> '';

-- The dashboard filters on fields that live inside the payload, so they get
-- expression indexes rather than a full GIN index over documents that are
-- mostly free-form.
CREATE INDEX IF NOT EXISTS audit_log_verdict_idx ON audit_log ((payload ->> 'verdict'), ts DESC);
CREATE INDEX IF NOT EXISTS audit_log_ip_idx      ON audit_log ((payload ->> 'ip'), ts DESC);
CREATE INDEX IF NOT EXISTS audit_log_rule_idx     ON audit_log ((payload ->> 'rule'), ts DESC);

-- Append-only enforcement.
--
-- The hash chain makes tampering *detectable*; this makes it hard. An UPDATE or
-- DELETE against the audit log is always a bug or an attack, so the database
-- refuses it outright. Someone with enough privilege can still disable the
-- trigger — and that is the point of the chain: they will get their edit, and
-- verification will name the entry they touched.
CREATE OR REPLACE FUNCTION audit_log_append_only() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % is not permitted', TG_OP
        USING HINT = 'The forensic log may only be extended. Verify the chain via the dashboard.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_no_modify ON audit_log;
CREATE TRIGGER audit_log_no_modify
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log;
CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only();
