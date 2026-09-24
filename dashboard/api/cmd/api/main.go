// Command dashboard-api serves the monitoring dashboard: the REST API over the
// audit log, the live WebSocket feed, and the React application itself.
//
// It reads the audit log and writes rule configuration. It never appends to the
// hash chain directly — that goes through the engine, which is the chain's only
// writer.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/open-shield/open-shield/dashboard/api/internal/auth"
	"github.com/open-shield/open-shield/dashboard/api/internal/httpapi"
	"github.com/open-shield/open-shield/dashboard/api/internal/ws"
	"github.com/open-shield/open-shield/dashboard/api/web"
	"github.com/open-shield/open-shield/internal/audit"
	"github.com/open-shield/open-shield/internal/config"
	"github.com/open-shield/open-shield/internal/events"
	"github.com/open-shield/open-shield/internal/rulestore"
)

var version = "dev"

func main() {
	// Generating the administrator's bcrypt hash has to be possible before the
	// stack can start, since the hash is what the stack needs in order to
	// start. Shipping it in this binary avoids telling operators to install a
	// separate tool during setup.
	hashPassword := flag.String("hash-password", "",
		"print the bcrypt hash of a password for OS_ADMIN_PASSWORD_HASH and exit")
	flag.Parse()

	if *hashPassword != "" {
		if err := printPasswordHash(*hashPassword); err != nil {
			fmt.Fprintln(os.Stderr, "could not hash the password:", err)
			os.Exit(1)
		}
		return
	}

	if err := run(); err != nil {
		slog.Error("dashboard api failed to start", "error", err)
		os.Exit(1)
	}
}

// printPasswordHash emits the .env line to paste, with every '$' doubled.
//
// A bcrypt hash starts with "$2a$10$", and Docker Compose expands '$' in a .env
// file as a variable reference — so pasting the raw hash silently delivers an
// empty value to the container and the dashboard refuses every password. The
// escape is easy to miss and impossible to debug from the symptom, so the tool
// that produces the hash also produces the escaped form.
func printPasswordHash(password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	escaped := strings.ReplaceAll(string(hash), "$", "$$")

	fmt.Println()
	fmt.Println("Copia esta línea en deploy/.env tal cual:")
	fmt.Println()
	fmt.Printf("OS_ADMIN_PASSWORD_HASH=%s\n", escaped)
	fmt.Println()
	fmt.Println("Los '$$' son intencionales: Docker Compose los convierte en un solo '$'.")
	fmt.Printf("El hash real es: %s\n", hash)
	return nil
}

func run() error {
	cfg, err := config.LoadDashboard()
	if err != nil {
		return err
	}

	log := newLogger(cfg.LogLevel)
	slog.SetDefault(log)
	log.Info("starting open-shield dashboard api", "version", version, "addr", cfg.Addr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sessions, err := auth.New(auth.Options{
		User:         cfg.AdminUser,
		PasswordHash: cfg.AdminPasswordHash,
		Secret:       cfg.SessionSecret,
		TTL:          cfg.SessionTTL,
		Secure:       cfg.SecureCookies,
	})
	if err != nil {
		return err
	}

	store, err := audit.NewPostgres(ctx, cfg.PostgresDSN)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	redisClient, err := events.NewClient(ctx, cfg.RedisAddr, cfg.RedisPass, cfg.RedisDB)
	if err != nil {
		return err
	}
	defer func() { _ = redisClient.Close() }()

	hub := ws.NewHub(log)
	go hub.Run(ctx, events.Subscribe(ctx, redisClient, cfg.EventsChannel, 512, log))

	engineURL := os.Getenv("OS_ENGINE_URL")
	if engineURL == "" {
		engineURL = "http://engine:8080"
	}

	api := httpapi.New(httpapi.Options{
		Repo:      store,
		Rules:     rulestore.New(store.Pool()),
		Sessions:  sessions,
		Hub:       hub,
		Auditor:   httpapi.NewAuditClient(engineURL),
		Publisher: events.NewPublisher(redisClient, cfg.EventsChannel),
		SPA:       web.FS(),
		Logger:    log,
		Version:   version,

		TrustedProxies: cfg.TrustedProxies,
	})

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		// No WriteTimeout: it would cut the live WebSocket feed at a fixed
		// interval. The hub bounds its own writes instead.
		IdleTimeout: 120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("dashboard listening", "addr", cfg.Addr)
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

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("http shutdown: %w", err)
	}

	log.Info("dashboard api stopped")
	return nil
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
