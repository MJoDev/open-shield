// Package ratelimit implements RF-05: a cap on how many requests one client
// may make within a time window.
//
// The counter lives in Redis rather than in the engine's memory. That is what
// makes the limit hold when the engine restarts, and what would let a second
// engine instance share the same view of a client — the memory of an attack has
// to outlive the process being attacked.
package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// slidingWindow keeps one sorted set per client, scored by timestamp.
//
// A fixed window is cheaper but lets a client send 2×limit requests across a
// window boundary — the exact burst a rate limit exists to stop. A sorted set
// costs one key per active client and expires on its own.
//
// The whole check is one script so it is atomic: between counting and
// recording, no other request can slip in. Doing it as separate commands would
// let concurrent requests all read the same count and all decide they are
// under the limit.
var slidingWindow = redis.NewScript(`
	local key       = KEYS[1]
	local now_ms    = tonumber(ARGV[1])
	local window_ms = tonumber(ARGV[2])
	local limit     = tonumber(ARGV[3])
	local member    = ARGV[4]

	-- Drop everything that fell out of the window.
	redis.call('ZREMRANGEBYSCORE', key, 0, now_ms - window_ms)

	local count = redis.call('ZCARD', key)
	if count >= limit then
		-- Refresh the TTL so a client that keeps hammering keeps its record.
		redis.call('PEXPIRE', key, window_ms)
		return {1, count}
	end

	redis.call('ZADD', key, now_ms, member)
	redis.call('PEXPIRE', key, window_ms)
	return {0, count + 1}
`)

// Limiter enforces a request budget per key.
type Limiter struct {
	client *redis.Client
	prefix string
	limit  int
	window time.Duration
	now    func() time.Time
}

// New returns a Limiter allowing limit requests per window.
func New(client *redis.Client, limit int, window time.Duration) *Limiter {
	return &Limiter{
		client: client,
		prefix: "openshield:rl:",
		limit:  limit,
		window: window,
		now:    time.Now,
	}
}

// WithClock replaces the limiter's source of time. Tests use it to advance the
// window; production always uses time.Now.
//
// The timestamp is computed here and passed into the script rather than read
// from the Redis server, so the script stays deterministic and one slow round
// trip cannot shift a request into a different window than the one it arrived
// in.
func (l *Limiter) WithClock(now func() time.Time) *Limiter {
	l.now = now
	return l
}

// Result describes one rate-limit check.
type Result struct {
	Limited bool
	// Count is how many requests are on record for this key inside the window,
	// including the current one when it was allowed.
	Count int64
	Limit int
	// RetryAfter is how long the caller should wait before trying again. It is
	// the window length: the worst case for the oldest entry to expire.
	RetryAfter time.Duration
}

// Allow records a request against key and reports whether it exceeds the
// budget. member must be unique per request — the request id is ideal, since
// two requests in the same millisecond would otherwise collapse into one entry
// in the sorted set and undercount the burst.
func (l *Limiter) Allow(ctx context.Context, key, member string) (Result, error) {
	nowMS := l.now().UnixMilli()
	windowMS := l.window.Milliseconds()

	raw, err := slidingWindow.Run(ctx, l.client,
		[]string{l.prefix + key},
		nowMS, windowMS, l.limit, member,
	).Slice()
	if err != nil {
		return Result{}, fmt.Errorf("ratelimit: evaluate %s: %w", key, err)
	}
	if len(raw) != 2 {
		return Result{}, fmt.Errorf("ratelimit: unexpected script result %v", raw)
	}

	limited, _ := raw[0].(int64)
	count, _ := raw[1].(int64)

	return Result{
		Limited:    limited == 1,
		Count:      count,
		Limit:      l.limit,
		RetryAfter: l.window,
	}, nil
}

// Limit reports the configured budget, for the block reason and the dashboard.
func (l *Limiter) Limit() int { return l.limit }

// Window reports the configured window.
func (l *Limiter) Window() time.Duration { return l.window }
