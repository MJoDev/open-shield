package audit

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-shield/open-shield/internal/model"
)

// Postgres is the production Repository. It is the "PostgreSQL + own schema"
// row of §3.1: the database is third-party infrastructure, the append-only
// chain on top of it is ours.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres opens a connection pool and verifies the database is reachable.
func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("audit: parse postgres dsn: %w", err)
	}
	cfg.MaxConns = 10
	cfg.MaxConnLifetime = time.Hour
	cfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("audit: connect to postgres: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("audit: ping postgres: %w", err)
	}

	return &Postgres{pool: pool}, nil
}

// Pool exposes the underlying pool so that the rule store and the migration
// runner can share one set of connections rather than opening their own.
func (p *Postgres) Pool() *pgxpool.Pool { return p.pool }

func (p *Postgres) Close() error {
	p.pool.Close()
	return nil
}

const auditColumns = `id, request_id, ts, kind, payload, prev_hash, hash`

func (p *Postgres) Append(ctx context.Context, entry model.AuditEntry) error {
	// The payload is serialised here rather than left to the driver's type
	// inference, so the bytes that reach the column are exactly the ones the
	// hash was computed over.
	payload, err := model.CanonicalJSON(entry.Payload)
	if err != nil {
		return fmt.Errorf("audit: encode payload for entry %s: %w", entry.ID, err)
	}

	_, err = p.pool.Exec(ctx, `
		INSERT INTO audit_log (id, request_id, ts, kind, payload, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		entry.ID, entry.RequestID, entry.Timestamp, entry.Kind,
		payload, entry.PrevHash, entry.Hash)
	if err != nil {
		return fmt.Errorf("audit: append entry %s: %w", entry.ID, err)
	}
	return nil
}

func (p *Postgres) Head(ctx context.Context) (string, error) {
	var hash string
	err := p.pool.QueryRow(ctx,
		`SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&hash)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return model.GenesisHash, nil
	case err != nil:
		return "", fmt.Errorf("audit: read chain head: %w", err)
	}
	return hash, nil
}

func (p *Postgres) VerifyChain(ctx context.Context, from, to time.Time) (VerifyResult, error) {
	anchor, err := p.anchorBefore(ctx, from)
	if err != nil {
		return VerifyResult{}, err
	}

	where, args := timeRange(from, to)
	// Ordered by seq, not ts: seq is the append order the chain was built in.
	// Rows stream from the server, so verifying a long history does not need to
	// hold it in memory.
	rows, err := p.pool.Query(ctx,
		`SELECT `+auditColumns+` FROM audit_log `+where+` ORDER BY seq ASC`, args...)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("audit: read chain: %w", err)
	}
	defer rows.Close()

	walker := newChainWalker(anchor)
	for rows.Next() {
		entry, err := scanEntry(rows)
		if err != nil {
			return VerifyResult{}, err
		}
		if broken := walker.step(entry); broken != nil {
			rows.Close()
			stampRange(broken, from, to)
			return *broken, nil
		}
	}
	if err := rows.Err(); err != nil {
		return VerifyResult{}, fmt.Errorf("audit: read chain: %w", err)
	}

	result := walker.result()
	stampRange(&result, from, to)
	return result, nil
}

// anchorBefore returns the hash of the last entry before the verified range, so
// that a range-scoped verification cannot be fooled by a rewritten first entry.
func (p *Postgres) anchorBefore(ctx context.Context, from time.Time) (string, error) {
	if from.IsZero() {
		return model.GenesisHash, nil
	}

	var hash string
	err := p.pool.QueryRow(ctx,
		`SELECT hash FROM audit_log WHERE ts < $1 ORDER BY seq DESC LIMIT 1`, from).Scan(&hash)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return model.GenesisHash, nil
	case err != nil:
		return "", fmt.Errorf("audit: read chain anchor: %w", err)
	}
	return hash, nil
}

func (p *Postgres) List(ctx context.Context, f Filter) ([]model.AuditEntry, error) {
	f = f.normalized()
	where, args := filterClause(f)

	args = append(args, f.Limit, f.Offset)
	query := fmt.Sprintf(
		`SELECT %s FROM audit_log %s ORDER BY seq DESC LIMIT $%d OFFSET $%d`,
		auditColumns, where, len(args)-1, len(args))

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: list entries: %w", err)
	}
	defer rows.Close()

	var out []model.AuditEntry
	for rows.Next() {
		entry, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: list entries: %w", err)
	}
	return out, nil
}

func (p *Postgres) Count(ctx context.Context, f Filter) (int64, error) {
	where, args := filterClause(f)

	var n int64
	if err := p.pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_log `+where, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("audit: count entries: %w", err)
	}
	return n, nil
}

func (p *Postgres) Stats(ctx context.Context, window time.Duration) (Stats, error) {
	if window <= 0 {
		window = time.Hour
	}
	since := time.Now().UTC().Add(-window)
	stats := Stats{Window: window.String()}

	err := p.pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE payload ->> 'verdict' = 'allow'),
		       count(*) FILTER (WHERE payload ->> 'verdict' = 'block')
		FROM audit_log
		WHERE kind = 'traffic' AND ts >= $1`, since).
		Scan(&stats.Total, &stats.Allowed, &stats.Blocked)
	if err != nil {
		return Stats{}, fmt.Errorf("audit: traffic totals: %w", err)
	}

	if stats.TopIPs, err = p.topBlocked(ctx, since, "ip"); err != nil {
		return Stats{}, err
	}
	if stats.TopRules, err = p.topBlocked(ctx, since, "rule"); err != nil {
		return Stats{}, err
	}
	if stats.Series, err = p.series(ctx, since, window); err != nil {
		return Stats{}, err
	}
	return stats, nil
}

// topBlocked ranks the values of one payload field among blocked requests.
// field is not user input — callers pass a literal — but it is still whitelisted
// rather than interpolated, so this can never become an injection point.
func (p *Postgres) topBlocked(ctx context.Context, since time.Time, field string) ([]CountedBy, error) {
	switch field {
	case "ip", "rule":
	default:
		return nil, fmt.Errorf("audit: unsupported ranking field %q", field)
	}

	rows, err := p.pool.Query(ctx, `
		SELECT payload ->> $2 AS label, count(*) AS n
		FROM audit_log
		WHERE kind = 'traffic'
		  AND ts >= $1
		  AND payload ->> 'verdict' = 'block'
		  AND payload ->> $2 IS NOT NULL
		GROUP BY label
		ORDER BY n DESC, label ASC
		LIMIT 10`, since, field)
	if err != nil {
		return nil, fmt.Errorf("audit: top %s: %w", field, err)
	}
	defer rows.Close()

	var out []CountedBy
	for rows.Next() {
		var row CountedBy
		if err := rows.Scan(&row.Label, &row.Count); err != nil {
			return nil, fmt.Errorf("audit: top %s: %w", field, err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// series buckets traffic into roughly 60 slices across the window, which is
// what the dashboard chart draws.
func (p *Postgres) series(ctx context.Context, since time.Time, window time.Duration) ([]Bucket, error) {
	bucketSeconds := int(window.Seconds()) / 60
	if bucketSeconds < 1 {
		bucketSeconds = 1
	}

	rows, err := p.pool.Query(ctx, `
		SELECT to_timestamp(floor(extract(epoch FROM ts) / $2) * $2) AS bucket,
		       count(*) FILTER (WHERE payload ->> 'verdict' = 'allow') AS allowed,
		       count(*) FILTER (WHERE payload ->> 'verdict' = 'block') AS blocked
		FROM audit_log
		WHERE kind = 'traffic' AND ts >= $1
		GROUP BY bucket
		ORDER BY bucket ASC`, since, bucketSeconds)
	if err != nil {
		return nil, fmt.Errorf("audit: traffic series: %w", err)
	}
	defer rows.Close()

	var out []Bucket
	for rows.Next() {
		var b Bucket
		if err := rows.Scan(&b.Start, &b.Allowed, &b.Blocked); err != nil {
			return nil, fmt.Errorf("audit: traffic series: %w", err)
		}
		b.Start = b.Start.UTC()
		out = append(out, b)
	}
	return out, rows.Err()
}

// scanEntry reads one row into an AuditEntry, decoding the payload into the
// same normalised shape it had when the hash was computed.
func scanEntry(rows pgx.Rows) (model.AuditEntry, error) {
	var (
		entry model.AuditEntry
		raw   []byte
	)
	if err := rows.Scan(&entry.ID, &entry.RequestID, &entry.Timestamp,
		&entry.Kind, &raw, &entry.PrevHash, &entry.Hash); err != nil {
		return model.AuditEntry{}, fmt.Errorf("audit: scan entry: %w", err)
	}

	payload, err := model.DecodeJSONPayload(raw)
	if err != nil {
		return model.AuditEntry{}, err
	}
	entry.Payload = payload
	entry.Timestamp = entry.Timestamp.UTC()
	return entry, nil
}

// timeRange builds the WHERE clause for a bare time window.
func timeRange(from, to time.Time) (string, []any) {
	var (
		clauses []string
		args    []any
	)
	if !from.IsZero() {
		args = append(args, from)
		clauses = append(clauses, "ts >= $"+strconv.Itoa(len(args)))
	}
	if !to.IsZero() {
		args = append(args, to)
		clauses = append(clauses, "ts <= $"+strconv.Itoa(len(args)))
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

// filterClause builds the WHERE clause for a dashboard query. Every value is a
// bound parameter; nothing from the request reaches the SQL text.
func filterClause(f Filter) (string, []any) {
	var (
		clauses []string
		args    []any
	)
	add := func(sql string, value any) {
		args = append(args, value)
		clauses = append(clauses, strings.Replace(sql, "?", "$"+strconv.Itoa(len(args)), 1))
	}

	if f.Kind != "" {
		add("kind = ?", f.Kind)
	}
	if f.RequestID != "" {
		add("request_id = ?", f.RequestID)
	}
	if f.Verdict != "" {
		add("payload ->> 'verdict' = ?", f.Verdict)
	}
	if f.IP != "" {
		add("payload ->> 'ip' = ?", f.IP)
	}
	if f.Rule != "" {
		add("payload ->> 'rule' = ?", f.Rule)
	}
	if !f.From.IsZero() {
		add("ts >= ?", f.From)
	}
	if !f.To.IsZero() {
		add("ts <= ?", f.To)
	}

	if len(clauses) == 0 {
		return "", nil
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}
