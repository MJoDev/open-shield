package rules

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/open-shield/open-shield/engine/internal/ratelimit"
	"github.com/open-shield/open-shield/internal/model"
)

// RateLimit is the chain's adapter over the Redis limiter (RF-05).
type RateLimit struct {
	limiter *ratelimit.Limiter
	log     *slog.Logger

	// storeErrors counts checks that could not be evaluated because Redis was
	// unreachable. The dashboard surfaces it: a rate limit that is silently not
	// running is worse than one that is off on purpose.
	storeErrors atomic.Int64
}

// NewRateLimit wraps a limiter as a Rule.
func NewRateLimit(limiter *ratelimit.Limiter, log *slog.Logger) *RateLimit {
	if log == nil {
		log = slog.Default()
	}
	return &RateLimit{limiter: limiter, log: log}
}

func (r *RateLimit) Name() string { return "ratelimit" }

// BlockStatus makes the proxy answer 429 rather than 403. The distinction is
// not cosmetic: a well-behaved client reads 429 as "slow down and retry", while
// 403 tells it to give up.
func (r *RateLimit) BlockStatus() int { return http.StatusTooManyRequests }

// Evaluate counts the request against its source address.
//
// When Redis cannot be reached the request is allowed. Refusing all traffic
// because the counter store is down would convert a Redis outage into an
// outage of the site being protected — the opposite of what a protection layer
// is for. The failure is counted and logged so it cannot pass unnoticed.
func (r *RateLimit) Evaluate(ctx context.Context, req *model.RequestContext) (model.Verdict, string) {
	member := req.RequestID
	if member == "" {
		// Without a unique member, two requests in the same millisecond would
		// collapse into one entry in the sorted set and the burst would be
		// undercounted.
		member = fmt.Sprintf("%s-%d", req.IP, req.ReceivedAt.UnixNano())
	}

	result, err := r.limiter.Allow(ctx, req.IP, member)
	if err != nil {
		n := r.storeErrors.Add(1)
		if n == 1 || n%100 == 0 {
			r.log.Error("rate limit check failed, allowing request",
				"error", err, "ip", req.IP, "failures_total", n)
		}
		return model.Allow, ""
	}

	if result.Limited {
		return model.Block, fmt.Sprintf(
			"rate limit exceeded: more than %d requests from %s within %s",
			result.Limit, req.IP, r.limiter.Window())
	}
	return model.Allow, ""
}

// StoreErrors reports how many rate-limit checks failed open.
func (r *RateLimit) StoreErrors() int64 { return r.storeErrors.Load() }
