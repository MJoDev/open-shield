// Package config loads every setting from the environment, as required by §5.5
// of the technical document: nothing is hardcoded and nothing is edited by hand
// inside a running container. A missing or malformed value fails at startup
// rather than at the first request that needs it.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Engine is the rules engine's configuration.
type Engine struct {
	Addr        string
	PostgresDSN string
	RedisAddr   string
	RedisPass   string
	RedisDB     int

	AuditBuffer   int
	EventsChannel string

	RateLimitRequests int
	RateLimitWindow   time.Duration

	// MaxBodyInspect caps how much of a request body the rules read. It must
	// match the proxy's OS_MAX_BODY_INSPECT_BYTES; the proxy truncates, this is
	// the engine's own guard against an oversized decision request.
	MaxBodyInspect int

	LogLevel string
}

// Dashboard is the dashboard API's configuration.
type Dashboard struct {
	Addr        string
	PostgresDSN string
	RedisAddr   string
	RedisPass   string
	RedisDB     int

	EventsChannel string

	AdminUser         string
	AdminPasswordHash string
	SessionSecret     string
	SessionTTL        time.Duration
	SecureCookies     bool

	// TrustedProxies are the networks whose X-Forwarded-For the dashboard
	// believes when deciding which address a request came from. Empty means
	// none: the peer address is used and the header ignored.
	TrustedProxies []netip.Prefix

	LogLevel string
}

// LoadEngine reads the engine configuration from the environment.
func LoadEngine() (Engine, error) {
	var errs []error
	cfg := Engine{
		Addr:              str("OS_ENGINE_ADDR", ":8080"),
		PostgresDSN:       required("OS_POSTGRES_DSN", &errs),
		RedisAddr:         str("OS_REDIS_ADDR", "redis:6379"),
		RedisPass:         str("OS_REDIS_PASSWORD", ""),
		RedisDB:           integer("OS_REDIS_DB", 0, &errs),
		AuditBuffer:       integer("OS_AUDIT_BUFFER", 4096, &errs),
		EventsChannel:     str("OS_EVENTS_CHANNEL", "openshield:events"),
		RateLimitRequests: integer("OS_RATELIMIT_REQUESTS", 100, &errs),
		RateLimitWindow:   seconds("OS_RATELIMIT_WINDOW_S", 60, &errs),
		MaxBodyInspect:    integer("OS_MAX_BODY_INSPECT_BYTES", 8192, &errs),
		LogLevel:          str("OS_LOG_LEVEL", "info"),
	}

	if cfg.RateLimitRequests <= 0 {
		errs = append(errs, errors.New("OS_RATELIMIT_REQUESTS must be greater than zero"))
	}
	if cfg.RateLimitWindow <= 0 {
		errs = append(errs, errors.New("OS_RATELIMIT_WINDOW_S must be greater than zero"))
	}
	if cfg.MaxBodyInspect < 0 {
		errs = append(errs, errors.New("OS_MAX_BODY_INSPECT_BYTES cannot be negative"))
	}

	return cfg, errors.Join(errs...)
}

// LoadDashboard reads the dashboard API configuration from the environment.
func LoadDashboard() (Dashboard, error) {
	var errs []error
	cfg := Dashboard{
		Addr:              str("OS_DASHBOARD_ADDR", ":8081"),
		PostgresDSN:       required("OS_POSTGRES_DSN", &errs),
		RedisAddr:         str("OS_REDIS_ADDR", "redis:6379"),
		RedisPass:         str("OS_REDIS_PASSWORD", ""),
		RedisDB:           integer("OS_REDIS_DB", 0, &errs),
		EventsChannel:     str("OS_EVENTS_CHANNEL", "openshield:events"),
		AdminUser:         str("OS_ADMIN_USER", "admin"),
		AdminPasswordHash: required("OS_ADMIN_PASSWORD_HASH", &errs),
		SessionSecret:     required("OS_SESSION_SECRET", &errs),
		SessionTTL:        seconds("OS_SESSION_TTL_S", 8*3600, &errs),
		SecureCookies:     boolean("OS_SECURE_COOKIES", false, &errs),
		TrustedProxies:    prefixes("OS_TRUSTED_PROXY", &errs),
		LogLevel:          str("OS_LOG_LEVEL", "info"),
	}

	// A short secret is a weak secret. Refusing at startup is better than
	// serving an admin panel that can be forged into.
	if cfg.SessionSecret != "" && len(cfg.SessionSecret) < 32 {
		errs = append(errs, errors.New(
			"OS_SESSION_SECRET must be at least 32 characters; generate one with: openssl rand -hex 32"))
	}
	if cfg.AdminPasswordHash != "" && !strings.HasPrefix(cfg.AdminPasswordHash, "$2") {
		errs = append(errs, errors.New(
			"OS_ADMIN_PASSWORD_HASH must be a bcrypt hash (starts with $2a$/$2b$/$2y$), not a plaintext password"))
	}

	return cfg, errors.Join(errs...)
}

// prefixes parses a list of CIDR blocks separated by commas or whitespace.
//
// A malformed entry fails at startup rather than being skipped. This list
// decides whose X-Forwarded-For is believed, so quietly dropping an
// unparseable network would leave a security control that reads as configured
// and enforces something else.
func prefixes(key string, errs *[]error) []netip.Prefix {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}

	fields := strings.Fields(strings.ReplaceAll(raw, ",", " "))
	out := make([]netip.Prefix, 0, len(fields))
	for _, field := range fields {
		prefix, err := netip.ParsePrefix(field)
		if err != nil {
			*errs = append(*errs, fmt.Errorf("%s: %q is not a CIDR block", key, field))
			continue
		}
		out = append(out, prefix.Masked())
	}
	return out
}

func str(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func required(key string, errs *[]error) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		*errs = append(*errs, fmt.Errorf("%s is required", key))
	}
	return v
}

func integer(key string, fallback int, errs *[]error) int {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s must be an integer, got %q", key, raw))
		return fallback
	}
	return n
}

func seconds(key string, fallback int, errs *[]error) time.Duration {
	return time.Duration(integer(key, fallback, errs)) * time.Second
}

func boolean(key string, fallback bool, errs *[]error) bool {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return fallback
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s must be true or false, got %q", key, raw))
		return fallback
	}
	return b
}
