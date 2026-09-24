package config

import (
	"strings"
	"testing"
	"time"
)

// §5.5 makes a promise these tests hold the code to: every setting comes from
// the environment, and a missing or malformed value fails at startup rather
// than at the first request that needs it.
//
// The failure mode this guards against is specific and nasty. A rate limit that
// silently falls back to a default because OS_RATELIMIT_REQUESTS was mistyped
// is not visibly broken — it is quietly wrong, and nobody finds out until the
// burst it was supposed to stop goes through.

// The two secrets and a DSN, enough for a valid dashboard configuration.
const (
	validSecret = "0123456789abcdef0123456789abcdef" // 32 chars, the minimum
	validHash   = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	validDSN    = "postgres://openshield:secret@db:5432/openshield?sslmode=disable"
)

// setEnv applies a set of variables for one test and restores the environment
// afterwards. Every variable the loaders read is cleared first, so a test never
// inherits a value from the developer's shell or from the CI runner.
func setEnv(t *testing.T, vars map[string]string) {
	t.Helper()

	known := []string{
		"OS_ENGINE_ADDR", "OS_DASHBOARD_ADDR", "OS_POSTGRES_DSN",
		"OS_REDIS_ADDR", "OS_REDIS_PASSWORD", "OS_REDIS_DB",
		"OS_AUDIT_BUFFER", "OS_EVENTS_CHANNEL",
		"OS_RATELIMIT_REQUESTS", "OS_RATELIMIT_WINDOW_S",
		"OS_MAX_BODY_INSPECT_BYTES", "OS_LOG_LEVEL",
		"OS_ADMIN_USER", "OS_ADMIN_PASSWORD_HASH", "OS_SESSION_SECRET",
		"OS_SESSION_TTL_S", "OS_SECURE_COOKIES", "OS_TRUSTED_PROXY",
	}
	for _, key := range known {
		t.Setenv(key, "")
	}
	for key, value := range vars {
		t.Setenv(key, value)
	}
}

func engineEnv(extra map[string]string) map[string]string {
	vars := map[string]string{"OS_POSTGRES_DSN": validDSN}
	for k, v := range extra {
		vars[k] = v
	}
	return vars
}

func dashboardEnv(extra map[string]string) map[string]string {
	vars := map[string]string{
		"OS_POSTGRES_DSN":        validDSN,
		"OS_ADMIN_PASSWORD_HASH": validHash,
		"OS_SESSION_SECRET":      validSecret,
	}
	for k, v := range extra {
		vars[k] = v
	}
	return vars
}

// --- Engine -----------------------------------------------------------------

func TestLoadEngineAppliesTheDocumentedDefaults(t *testing.T) {
	setEnv(t, engineEnv(nil))

	cfg, err := LoadEngine()
	if err != nil {
		t.Fatalf("LoadEngine: %v", err)
	}

	// These are the values deploy/.env.example documents. If one changes here
	// without changing there, the settings reference is lying.
	for _, c := range []struct {
		name string
		got  any
		want any
	}{
		{"Addr", cfg.Addr, ":8080"},
		{"RedisAddr", cfg.RedisAddr, "redis:6379"},
		{"AuditBuffer", cfg.AuditBuffer, 4096},
		{"EventsChannel", cfg.EventsChannel, "openshield:events"},
		{"RateLimitRequests", cfg.RateLimitRequests, 100},
		{"RateLimitWindow", cfg.RateLimitWindow, 60 * time.Second},
		{"MaxBodyInspect", cfg.MaxBodyInspect, 8192},
		{"LogLevel", cfg.LogLevel, "info"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestLoadEngineRequiresTheDatabase(t *testing.T) {
	setEnv(t, nil)

	_, err := LoadEngine()
	if err == nil {
		t.Fatal("LoadEngine succeeded with no OS_POSTGRES_DSN")
	}
	if !strings.Contains(err.Error(), "OS_POSTGRES_DSN") {
		t.Errorf("error = %q, want it to name the missing variable", err)
	}
}

// A mistyped number must not fall through to a default. The engine would then
// be enforcing something other than what the operator configured, with nothing
// anywhere saying so.
func TestLoadEngineRejectsMalformedNumbers(t *testing.T) {
	for _, key := range []string{
		"OS_REDIS_DB", "OS_AUDIT_BUFFER", "OS_RATELIMIT_REQUESTS",
		"OS_RATELIMIT_WINDOW_S", "OS_MAX_BODY_INSPECT_BYTES",
	} {
		t.Run(key, func(t *testing.T) {
			setEnv(t, engineEnv(map[string]string{key: "cien"}))

			_, err := LoadEngine()
			if err == nil {
				t.Fatalf("LoadEngine accepted %s=cien", key)
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("error = %q, want it to name %s", err, key)
			}
		})
	}
}

// Zero requests per window is not "no limit", it is "block everything". Nobody
// means that, so it is refused rather than enforced.
func TestLoadEngineRejectsANonsensicalRateLimit(t *testing.T) {
	for name, vars := range map[string]map[string]string{
		"zero requests":            {"OS_RATELIMIT_REQUESTS": "0"},
		"negative requests":        {"OS_RATELIMIT_REQUESTS": "-5"},
		"zero window":              {"OS_RATELIMIT_WINDOW_S": "0"},
		"negative body inspection": {"OS_MAX_BODY_INSPECT_BYTES": "-1"},
	} {
		t.Run(name, func(t *testing.T) {
			setEnv(t, engineEnv(vars))

			if _, err := LoadEngine(); err == nil {
				t.Fatalf("LoadEngine accepted %v", vars)
			}
		})
	}
}

// Zero is a legitimate value for body inspection: it turns it off. That is
// different from a negative value, which is a mistake.
func TestLoadEngineAcceptsBodyInspectionSwitchedOff(t *testing.T) {
	setEnv(t, engineEnv(map[string]string{"OS_MAX_BODY_INSPECT_BYTES": "0"}))

	cfg, err := LoadEngine()
	if err != nil {
		t.Fatalf("LoadEngine: %v", err)
	}
	if cfg.MaxBodyInspect != 0 {
		t.Fatalf("MaxBodyInspect = %d, want 0", cfg.MaxBodyInspect)
	}
}

// Every problem in one report. An operator filling in a fresh .env should not
// have to restart the stack once per mistake.
func TestLoadEngineReportsEveryProblemAtOnce(t *testing.T) {
	setEnv(t, map[string]string{
		"OS_AUDIT_BUFFER":       "muchos",
		"OS_RATELIMIT_WINDOW_S": "un minuto",
	})

	_, loadErr := LoadEngine()
	if loadErr == nil {
		t.Fatal("LoadEngine succeeded with three bad settings")
	}
	for _, want := range []string{"OS_POSTGRES_DSN", "OS_AUDIT_BUFFER", "OS_RATELIMIT_WINDOW_S"} {
		if !strings.Contains(loadErr.Error(), want) {
			t.Errorf("error does not mention %s:\n%v", want, loadErr)
		}
	}
}

// --- Dashboard --------------------------------------------------------------

func TestLoadDashboardAppliesTheDocumentedDefaults(t *testing.T) {
	setEnv(t, dashboardEnv(nil))

	cfg, err := LoadDashboard()
	if err != nil {
		t.Fatalf("LoadDashboard: %v", err)
	}

	for _, c := range []struct {
		name string
		got  any
		want any
	}{
		{"Addr", cfg.Addr, ":8081"},
		{"AdminUser", cfg.AdminUser, "admin"},
		{"SessionTTL", cfg.SessionTTL, 8 * time.Hour},
		// Secure cookies default off: over plain HTTP the browser drops the
		// cookie, sign-in appears to succeed and then silently fails.
		{"SecureCookies", cfg.SecureCookies, false},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestLoadDashboardRequiresItsSecrets(t *testing.T) {
	setEnv(t, map[string]string{"OS_POSTGRES_DSN": validDSN})

	_, err := LoadDashboard()
	if err == nil {
		t.Fatal("LoadDashboard succeeded with no secrets configured")
	}
	for _, want := range []string{"OS_ADMIN_PASSWORD_HASH", "OS_SESSION_SECRET"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s:\n%v", want, err)
		}
	}
}

// A short secret is a forgeable secret, and the thing it signs is the session
// cookie of the admin panel.
func TestLoadDashboardRejectsAShortSessionSecret(t *testing.T) {
	setEnv(t, dashboardEnv(map[string]string{"OS_SESSION_SECRET": "demasiado-corto"}))

	_, err := LoadDashboard()
	if err == nil {
		t.Fatal("LoadDashboard accepted a 15-character session secret")
	}
	if !strings.Contains(err.Error(), "32") {
		t.Errorf("error = %q, want it to state the minimum length", err)
	}
}

// The compose gotcha, caught at startup instead of at the login screen.
//
// A '$' in deploy/.env is read by Compose as a variable reference, so pasting a
// raw bcrypt hash delivers an empty value to the container and every sign-in
// fails with nothing useful in the logs. Refusing anything that is not a bcrypt
// hash turns that into a startup error naming the variable.
func TestLoadDashboardRejectsAPasswordThatIsNotABcryptHash(t *testing.T) {
	for name, value := range map[string]string{
		"a plaintext password": "contraseña-en-claro",
		"an unrelated hash":    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
		"a half-escaped hash":  "2a10N9qo8uLOickgx2ZMRZoMye",
	} {
		t.Run(name, func(t *testing.T) {
			setEnv(t, dashboardEnv(map[string]string{"OS_ADMIN_PASSWORD_HASH": value}))

			_, err := LoadDashboard()
			if err == nil {
				t.Fatalf("LoadDashboard accepted %q as a password hash", value)
			}
			if !strings.Contains(err.Error(), "bcrypt") {
				t.Errorf("error = %q, want it to say a bcrypt hash is expected", err)
			}
		})
	}
}

func TestLoadDashboardAcceptsEveryBcryptVariant(t *testing.T) {
	// $2a$, $2b$ and $2y$ are all bcrypt; which one appears depends on the
	// library that generated it.
	for _, prefix := range []string{"$2a$", "$2b$", "$2y$"} {
		t.Run(prefix, func(t *testing.T) {
			hash := prefix + "10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
			setEnv(t, dashboardEnv(map[string]string{"OS_ADMIN_PASSWORD_HASH": hash}))

			if _, err := LoadDashboard(); err != nil {
				t.Fatalf("LoadDashboard rejected a %s hash: %v", prefix, err)
			}
		})
	}
}

func TestLoadDashboardRejectsAMalformedBoolean(t *testing.T) {
	setEnv(t, dashboardEnv(map[string]string{"OS_SECURE_COOKIES": "sí"}))

	_, err := LoadDashboard()
	if err == nil {
		t.Fatal("LoadDashboard accepted OS_SECURE_COOKIES=sí")
	}
	if !strings.Contains(err.Error(), "OS_SECURE_COOKIES") {
		t.Errorf("error = %q, want it to name the variable", err)
	}
}

// Both services read OS_POSTGRES_DSN, OS_REDIS_ADDR and OS_EVENTS_CHANNEL from
// the same .env. If they ever diverge, the dashboard reads a different log from
// the one the engine writes, and the live feed goes quiet for no visible reason.
func TestBothServicesReadTheSameSharedSettings(t *testing.T) {
	setEnv(t, dashboardEnv(map[string]string{
		"OS_REDIS_ADDR":     "redis.interno:6380",
		"OS_REDIS_PASSWORD": "clave",
		"OS_REDIS_DB":       "3",
		"OS_EVENTS_CHANNEL": "openshield:otro",
	}))

	engine, err := LoadEngine()
	if err != nil {
		t.Fatalf("LoadEngine: %v", err)
	}
	dashboard, err := LoadDashboard()
	if err != nil {
		t.Fatalf("LoadDashboard: %v", err)
	}

	if engine.PostgresDSN != dashboard.PostgresDSN {
		t.Errorf("PostgresDSN differs: %q vs %q", engine.PostgresDSN, dashboard.PostgresDSN)
	}
	if engine.RedisAddr != dashboard.RedisAddr || engine.RedisDB != dashboard.RedisDB {
		t.Errorf("Redis differs: %s/%d vs %s/%d",
			engine.RedisAddr, engine.RedisDB, dashboard.RedisAddr, dashboard.RedisDB)
	}
	if engine.EventsChannel != dashboard.EventsChannel {
		t.Errorf("EventsChannel differs: %q vs %q", engine.EventsChannel, dashboard.EventsChannel)
	}
}

// OS_TRUSTED_PROXY decides whose X-Forwarded-For the dashboard believes. A
// typo that silently dropped an entry would leave the sign-in throttle keyed on
// an address the client chooses, so a malformed block has to stop startup.
func TestLoadDashboardRejectsAMalformedTrustedProxy(t *testing.T) {
	setEnv(t, map[string]string{
		"OS_POSTGRES_DSN":        validDSN,
		"OS_ADMIN_PASSWORD_HASH": validHash,
		"OS_SESSION_SECRET":      validSecret,
		"OS_TRUSTED_PROXY":       "100.64.0.0/10, no-es-un-cidr",
	})

	if _, err := LoadDashboard(); err == nil {
		t.Fatal("LoadDashboard accepted a malformed CIDR; it must refuse to start")
	} else if !strings.Contains(err.Error(), "OS_TRUSTED_PROXY") {
		t.Fatalf("error = %v, want it to name OS_TRUSTED_PROXY", err)
	}
}

func TestLoadDashboardParsesTrustedProxies(t *testing.T) {
	setEnv(t, map[string]string{
		"OS_POSTGRES_DSN":        validDSN,
		"OS_ADMIN_PASSWORD_HASH": validHash,
		"OS_SESSION_SECRET":      validSecret,
		// Commas and whitespace both separate; host bits are masked off so a
		// range written as 100.64.0.7/10 still matches what it means.
		"OS_TRUSTED_PROXY": "100.64.0.7/10 fd00::1/8",
	})

	cfg, err := LoadDashboard()
	if err != nil {
		t.Fatalf("LoadDashboard: %v", err)
	}
	if len(cfg.TrustedProxies) != 2 {
		t.Fatalf("TrustedProxies = %v, want 2 entries", cfg.TrustedProxies)
	}
	if got := cfg.TrustedProxies[0].String(); got != "100.64.0.0/10" {
		t.Errorf("first prefix = %s, want the masked 100.64.0.0/10", got)
	}
}

// The default has to be "believe nobody": a deployment that never sets this is
// reachable directly, where any header at all is the client's own.
func TestLoadDashboardTrustsNoProxyByDefault(t *testing.T) {
	setEnv(t, map[string]string{
		"OS_POSTGRES_DSN":        validDSN,
		"OS_ADMIN_PASSWORD_HASH": validHash,
		"OS_SESSION_SECRET":      validSecret,
	})

	cfg, err := LoadDashboard()
	if err != nil {
		t.Fatalf("LoadDashboard: %v", err)
	}
	if len(cfg.TrustedProxies) != 0 {
		t.Fatalf("TrustedProxies = %v, want none by default", cfg.TrustedProxies)
	}
}
