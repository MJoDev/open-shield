//go:build integration

package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/open-shield/open-shield/test/harness"
)

// ratelimit_test.go runs against miniredis, which reimplements the protocol in
// Go. That is enough for the logic and nothing like enough for the thing that
// actually matters here: whether a real Redis evaluates the sliding-window
// script atomically under concurrency.
//
// This file has to live beside the package rather than in test/integration,
// because Go only lets engine/… import engine/internal/….

func TestRateLimitHoldsTheLineOnRealRedis(t *testing.T) {
	client := harness.Redis(t)
	limiter := New(client, 20, time.Minute)
	ctx := harness.Context(t)

	allowed := 0
	for i := 0; i < 40; i++ {
		result, err := limiter.Allow(ctx, "203.0.113.7", fmt.Sprintf("req-%d", i))
		if err != nil {
			t.Fatalf("Allow %d: %v", i, err)
		}
		if !result.Limited {
			allowed++
		}
	}

	if allowed != 20 {
		t.Fatalf("allowed %d of 40 requests, want exactly the limit of 20", allowed)
	}
}

// The counter is per source address. A limit that leaked across clients would
// let one noisy visitor throttle everybody else — a denial of service delivered
// by the protection layer itself.
func TestRateLimitIsPerClientOnRealRedis(t *testing.T) {
	client := harness.Redis(t)
	limiter := New(client, 5, time.Minute)
	ctx := harness.Context(t)

	for i := 0; i < 10; i++ {
		if _, err := limiter.Allow(ctx, "203.0.113.7", fmt.Sprintf("noisy-%d", i)); err != nil {
			t.Fatalf("Allow: %v", err)
		}
	}

	result, err := limiter.Allow(ctx, "198.51.100.4", "quiet-1")
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if result.Limited {
		t.Fatal("a second address was throttled by the first one's burst")
	}
}

// Every request handler runs this concurrently. Redis evaluates the script
// atomically, so the limit must hold exactly even when the whole burst arrives
// at once — an off-by-a-few here is a rate limit that can be overrun by
// parallelism.
func TestConcurrentRequestsCannotOvershootOnRealRedis(t *testing.T) {
	client := harness.Redis(t)

	const limit = 50
	const attempts = 200
	limiter := New(client, limit, time.Minute)
	ctx := harness.Context(t)

	var (
		mu      sync.Mutex
		allowed int
		wg      sync.WaitGroup
	)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			result, err := limiter.Allow(ctx, "203.0.113.7", fmt.Sprintf("req-%d", i))
			if err != nil {
				return
			}
			if !result.Limited {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if allowed != limit {
		t.Fatalf("allowed %d of %d concurrent requests, want exactly %d", allowed, attempts, limit)
	}
}

// An idle client must cost nothing. Without an expiry, every address that ever
// touched the proxy would stay in Redis for good, and the memory footprint
// would grow with the size of the internet rather than with the traffic.
func TestRateLimitKeysExpireOnRealRedis(t *testing.T) {
	client := harness.Redis(t)
	limiter := New(client, 5, 2*time.Second)
	ctx := harness.Context(t)

	if _, err := limiter.Allow(ctx, "203.0.113.7", "req-1"); err != nil {
		t.Fatalf("Allow: %v", err)
	}

	keys, err := client.Keys(ctx, "*").Result()
	if err != nil {
		t.Fatalf("KEYS: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("the limiter stored nothing")
	}

	ttl, err := client.TTL(ctx, keys[0]).Result()
	if err != nil {
		t.Fatalf("TTL: %v", err)
	}
	if ttl <= 0 {
		t.Fatalf("TTL on %s is %v; the key would live forever", keys[0], ttl)
	}
	if ttl > 5*time.Second {
		t.Errorf("TTL on %s is %v, far beyond the 2s window", keys[0], ttl)
	}
}
