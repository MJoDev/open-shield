// Command engine is the rules and decision engine: the core of the system and,
// with the audit chain, the part that is original development rather than
// third-party configuration (§11).
//
// It answers one question over HTTP — should this request be allowed — and
// records the answer on a tamper-evident chain.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/open-shield/open-shield/engine/internal/httpapi"
	"github.com/open-shield/open-shield/engine/internal/ratelimit"
	"github.com/open-shield/open-shield/engine/internal/rules"
	"github.com/open-shield/open-shield/internal/audit"
	"github.com/open-shield/open-shield/internal/config"
	"github.com/open-shield/open-shield/internal/events"
	"github.com/open-shield/open-shield/internal/migrate"
	"github.com/open-shield/open-shield/internal/model"
	"github.com/open-shield/open-shield/internal/rulestore"
	"github.com/open-shield/open-shield/migrations"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

// configRefreshInterval is a safety net behind the control channel. Redis
// Pub/Sub does not retain messages, so an engine that was reconnecting when a
// rule changed would never hear about it. Re-reading periodically bounds how
// long a stale chain can run.
const configRefreshInterval = 30 * time.Second

func main() {
	if err := run(); err != nil {
		slog.Error("engine failed to start", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadEngine()
	if err != nil {
		return err
	}

	log := newLogger(cfg.LogLevel)
	slog.SetDefault(log)
	log.Info("starting open-shield engine", "version", version, "addr", cfg.Addr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- Storage -----------------------------------------------------------
	store, err := audit.NewPostgres(ctx, cfg.PostgresDSN)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	// The schema travels with the binary, so a fresh VPS needs no migration
	// step of its own (RF-10).
	if err := migrate.Apply(ctx, store.Pool(), migrations.Postgres(), log); err != nil {
		return err
	}

	redisClient, err := events.NewClient(ctx, cfg.RedisAddr, cfg.RedisPass, cfg.RedisDB)
	if err != nil {
		return err
	}
	defer func() { _ = redisClient.Close() }()

	publisher := events.NewPublisher(redisClient, cfg.EventsChannel)

	writer, err := audit.NewWriter(ctx, store, audit.WriterOptions{
		Buffer:    cfg.AuditBuffer,
		Publisher: publisher,
		Logger:    log,
	})
	if err != nil {
		return err
	}

	// --- Rule chain --------------------------------------------------------
	signatures, err := rules.LoadSignatures(os.Getenv("OS_PATTERNS_FILE"))
	if err != nil {
		return err
	}

	ipBlock := rules.NewIPBlock()
	limiter := ratelimit.New(redisClient, cfg.RateLimitRequests, cfg.RateLimitWindow)

	// Order is the design: an IP lookup costs a prefix comparison, a rate-limit
	// check costs one Redis round trip, and pattern matching costs a scan of
	// the whole request. Cheapest first, so a known-bad client never reaches
	// the expensive checks.
	chain := rules.New([]rules.Rule{
		ipBlock,
		rules.NewRateLimit(limiter, log),
		rules.NewPatternRule("sqli", signatures.SQLi, cfg.MaxBodyInspect),
		rules.NewPatternRule("xss", signatures.XSS, cfg.MaxBodyInspect),
	})

	configStore := rulestore.New(store.Pool())
	reload := func(reason string) {
		reloadCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		applyConfig(reloadCtx, configStore, chain, ipBlock, log, reason)
	}
	reload("startup")

	go watchConfig(ctx, redisClient, cfg.EventsChannel, reload, log)

	// --- HTTP --------------------------------------------------------------
	api := httpapi.New(httpapi.Options{
		Engine:  chain,
		Writer:  writer,
		Logger:  log,
		Version: version,
		Ready: func() error {
			checkCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := store.Pool().Ping(checkCtx); err != nil {
				return fmt.Errorf("postgres: %w", err)
			}
			if err := redisClient.Ping(checkCtx).Err(); err != nil {
				return fmt.Errorf("redis: %w", err)
			}
			return nil
		},
	})

	server := &http.Server{
		Addr:    cfg.Addr,
		Handler: api.Handler(),
		// The proxy holds keepalive connections to this server, so read and
		// write timeouts have to be short: a decision that takes seconds has
		// already blown the latency budget of every request behind it.
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	writer.Record(model.KindSystem, "", map[string]any{
		"event":            "engine_started",
		"version":          version,
		"chain":            chain.Names(),
		"ratelimit_limit":  cfg.RateLimitRequests,
		"ratelimit_window": cfg.RateLimitWindow.String(),
	})

	errCh := make(chan error, 1)
	go func() {
		log.Info("engine listening", "addr", cfg.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutdown signal received")
	}

	return shutdown(server, writer, log)
}

// shutdown stops accepting requests, then drains the audit queue. The order
// matters: entries already queued are decisions that were served, and losing
// them would leave the chain with a gap that verification cannot distinguish
// from tampering.
func shutdown(server *http.Server, writer *audit.Writer, log *slog.Logger) error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Warn("http shutdown did not complete cleanly", "error", err)
	}

	writer.Record(model.KindSystem, "", map[string]any{"event": "engine_stopping"})

	if err := writer.Close(shutdownCtx); err != nil {
		return fmt.Errorf("draining the audit queue: %w", err)
	}

	stats := writer.Stats()
	log.Info("engine stopped",
		"audit_written", stats.Written,
		"audit_dropped", stats.Dropped,
		"audit_failures", stats.Failures)
	return nil
}

// applyConfig reloads rule state and the IP access list from the database.
//
// A failure here leaves the chain running with whatever it had. That is the
// safe direction: a database blip should not silently disarm the filters.
func applyConfig(ctx context.Context, store *rulestore.Store, chain *rules.Engine,
	ipBlock *rules.IPBlock, log *slog.Logger, reason string) {

	enabled, err := store.EnabledMap(ctx)
	if err != nil {
		log.Error("could not reload rule state, keeping the current chain",
			"error", err, "reason", reason)
	} else {
		chain.SetEnabled(enabled)
	}

	ipRules, err := store.IPRules(ctx)
	if err != nil {
		log.Error("could not reload the ip access list, keeping the current one",
			"error", err, "reason", reason)
		return
	}

	for _, ruleErr := range ipBlock.Set(ipRules) {
		log.Warn("skipping malformed ip rule", "error", ruleErr)
	}

	allow, deny := ipBlock.Size()
	log.Info("configuration applied",
		"reason", reason, "enabled", enabled, "ip_allow", allow, "ip_deny", deny)
}

// watchConfig reloads on a control notification from the dashboard, and on a
// timer as a fallback.
//
// The notification is what makes a change in the browser take effect in under a
// second. The timer is what makes it take effect at all if the notification was
// published while this engine's subscription was reconnecting — Pub/Sub retains
// nothing, so a missed message is missed for good.
func watchConfig(ctx context.Context, client *redis.Client, channel string,
	reload func(string), log *slog.Logger) {

	notifications := events.SubscribeControl(ctx, client, channel)
	ticker := time.NewTicker(configRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case kind, ok := <-notifications:
			if !ok {
				log.Warn("control channel closed, falling back to periodic refresh")
				notifications = nil
				continue
			}
			reload("notification:" + kind)
		case <-ticker.C:
			reload("periodic")
		}
	}
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
