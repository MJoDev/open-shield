package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newLimiter(t *testing.T, limit int, window time.Duration) (*Limiter, *miniredis.Miniredis) {
	t.Helper()

	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	return New(client, limit, window), server
}

func TestAllowPermitsUpToTheLimit(t *testing.T) {
	limiter, _ := newLimiter(t, 5, time.Minute)
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		result, err := limiter.Allow(ctx, "203.0.113.9", fmt.Sprintf("req-%d", i))
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if result.Limited {
			t.Fatalf("request %d of 5 was limited; the budget is 5", i)
		}
		if result.Count != int64(i) {
			t.Fatalf("request %d: count = %d, want %d", i, result.Count, i)
		}
	}

	result, err := limiter.Allow(ctx, "203.0.113.9", "req-6")
	if err != nil {
		t.Fatalf("request 6: %v", err)
	}
	if !result.Limited {
		t.Fatal("the 6th request should exceed a budget of 5")
	}
}

func TestLimitIsPerClient(t *testing.T) {
	limiter, _ := newLimiter(t, 2, time.Minute)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := limiter.Allow(ctx, "203.0.113.9", fmt.Sprintf("a-%d", i)); err != nil {
			t.Fatalf("noisy client: %v", err)
		}
	}

	// A different address must be unaffected by the first one's budget.
	result, err := limiter.Allow(ctx, "198.51.100.4", "b-1")
	if err != nil {
		t.Fatalf("quiet client: %v", err)
	}
	if result.Limited {
		t.Fatal("one client's burst consumed another client's budget")
	}
}

// The reason to pay for a sorted set instead of a counter: a fixed window lets
// a client send 2×limit requests across the boundary between two windows.
//
// Both clocks have to move together — miniredis's, which drives key expiry, and
// the limiter's, which scores the entries.
func TestWindowSlidesInsteadOfResetting(t *testing.T) {
	const window = 10 * time.Second

	limiter, server := newLimiter(t, 3, window)
	clock := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	limiter.WithClock(func() time.Time { return clock })

	advance := func(d time.Duration) {
		clock = clock.Add(d)
		server.FastForward(d)
	}

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := limiter.Allow(ctx, "203.0.113.9", fmt.Sprintf("early-%d", i)); err != nil {
			t.Fatalf("early request: %v", err)
		}
	}

	// Most of the window has passed, but the early requests are still inside it.
	advance(8 * time.Second)
	result, err := limiter.Allow(ctx, "203.0.113.9", "mid")
	if err != nil {
		t.Fatalf("mid request: %v", err)
	}
	if !result.Limited {
		t.Fatal("requests still inside the window stopped counting: this is fixed-window behaviour")
	}

	// Now they have aged out.
	advance(3 * time.Second)
	result, err = limiter.Allow(ctx, "203.0.113.9", "late")
	if err != nil {
		t.Fatalf("late request: %v", err)
	}
	if result.Limited {
		t.Fatal("requests older than the window are still being counted")
	}
}

// Counting and recording happen in one script precisely so that concurrent
// requests cannot all read the same count and all decide they fit.
func TestConcurrentRequestsCannotOvershootTheLimit(t *testing.T) {
	const (
		limit    = 20
		attempts = 200
	)
	limiter, _ := newLimiter(t, limit, time.Minute)
	ctx := context.Background()

	var (
		mu      sync.Mutex
		allowed int
		wg      sync.WaitGroup
	)

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			result, err := limiter.Allow(ctx, "203.0.113.9", fmt.Sprintf("req-%d", i))
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
		t.Fatalf("%d requests got through a budget of %d", allowed, limit)
	}
}

// Two requests inside the same millisecond must both count. They would collapse
// into one sorted-set entry if the member were the timestamp alone.
func TestDistinctMembersAreCountedSeparately(t *testing.T) {
	limiter, _ := newLimiter(t, 10, time.Minute)
	ctx := context.Background()

	first, err := limiter.Allow(ctx, "203.0.113.9", "req-a")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := limiter.Allow(ctx, "203.0.113.9", "req-b")
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	if first.Count != 1 || second.Count != 2 {
		t.Fatalf("counts were %d and %d, want 1 and 2", first.Count, second.Count)
	}
}

func TestLimitedRequestsAreNotRecorded(t *testing.T) {
	limiter, _ := newLimiter(t, 1, time.Minute)
	ctx := context.Background()

	if _, err := limiter.Allow(ctx, "203.0.113.9", "first"); err != nil {
		t.Fatalf("first: %v", err)
	}

	// A client that keeps hammering must not push its own count up forever:
	// rejected requests are not added to the window, so the count stays at the
	// limit instead of growing without bound.
	for i := 0; i < 5; i++ {
		result, err := limiter.Allow(ctx, "203.0.113.9", fmt.Sprintf("blocked-%d", i))
		if err != nil {
			t.Fatalf("blocked request %d: %v", i, err)
		}
		if !result.Limited {
			t.Fatalf("blocked request %d got through", i)
		}
		if result.Count != 1 {
			t.Fatalf("count grew to %d while rejecting; rejected requests must not be recorded", result.Count)
		}
	}
}

func TestKeysExpireSoIdleClientsCostNothing(t *testing.T) {
	limiter, server := newLimiter(t, 5, 30*time.Second)
	ctx := context.Background()

	if _, err := limiter.Allow(ctx, "203.0.113.9", "req-1"); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if len(server.Keys()) == 0 {
		t.Fatal("no key was created")
	}

	server.FastForward(31 * time.Second)
	if keys := server.Keys(); len(keys) != 0 {
		t.Fatalf("keys %v outlived the window; idle clients would accumulate forever", keys)
	}
}
