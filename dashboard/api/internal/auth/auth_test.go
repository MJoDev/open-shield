package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func newManager(t *testing.T, password string, ttl time.Duration) *Manager {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}

	m, err := New(Options{
		User:         "admin",
		PasswordHash: string(hash),
		Secret:       testSecret,
		TTL:          ttl,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func TestLoginAcceptsCorrectCredentials(t *testing.T) {
	m := newManager(t, "correct horse battery staple", time.Hour)

	token, err := m.Login("admin", "correct horse battery staple")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	user, err := m.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if user != "admin" {
		t.Fatalf("token names %q, want admin", user)
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	m := newManager(t, "correct horse battery staple", time.Hour)

	cases := map[string][2]string{
		"wrong password": {"admin", "hunter2"},
		"wrong user":     {"root", "correct horse battery staple"},
		"both wrong":     {"root", "hunter2"},
		"empty":          {"", ""},
	}

	for name, creds := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := m.Login(creds[0], creds[1]); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("err = %v, want ErrInvalidCredentials", err)
			}
		})
	}
}

// The whole point of signing the token: its contents must not be editable by
// whoever holds it.
func TestVerifyRejectsTamperedTokens(t *testing.T) {
	m := newManager(t, "pw", time.Hour)
	token, err := m.Login("admin", "pw")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	parts := strings.Split(token, ".")

	cases := map[string]string{
		"rewritten user":     "cm9vdA." + parts[1] + "." + parts[2],
		"extended expiry":    parts[0] + ".99999999999." + parts[2],
		"forged signature":   parts[0] + "." + parts[1] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"dropped signature":  parts[0] + "." + parts[1],
		"empty token":        "",
		"structurally wrong": "not.a.token",
	}

	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := m.Verify(token); err == nil {
				t.Fatal("a tampered token was accepted")
			}
		})
	}
}

// A token signed with a different secret must not be accepted: rotating
// OS_SESSION_SECRET has to invalidate outstanding sessions.
func TestVerifyRejectsTokensFromAnotherSecret(t *testing.T) {
	first := newManager(t, "pw", time.Hour)
	token, err := first.Login("admin", "pw")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	second, err := New(Options{
		User:         "admin",
		PasswordHash: string(first.passwordHash),
		Secret:       "ffffffffffffffffffffffffffffffff",
		TTL:          time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := second.Verify(token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("err = %v, want ErrInvalidSession", err)
	}
}

func TestVerifyRejectsExpiredSessions(t *testing.T) {
	m := newManager(t, "pw", time.Hour)
	token := m.issue("admin", time.Now().Add(-time.Minute))

	if _, err := m.Verify(token); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("err = %v, want ErrSessionExpired", err)
	}
}

func TestNewRejectsWeakConfiguration(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)

	cases := map[string]Options{
		"short secret":        {User: "admin", PasswordHash: string(hash), Secret: "tooshort"},
		"plaintext password":  {User: "admin", PasswordHash: "hunter2", Secret: testSecret},
		"no user":             {User: "", PasswordHash: string(hash), Secret: testSecret},
		"empty password hash": {User: "admin", PasswordHash: "", Secret: testSecret},
	}

	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(opts); err == nil {
				t.Fatal("weak configuration was accepted at startup")
			}
		})
	}
}

func TestRequireBlocksUnauthenticatedRequests(t *testing.T) {
	m := newManager(t, "pw", time.Hour)
	guarded := m.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(UserFrom(r.Context())))
	}))

	t.Run("no cookie", func(t *testing.T) {
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("valid session", func(t *testing.T) {
		token, err := m.Login("admin", "pw")
		if err != nil {
			t.Fatalf("Login: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
		req.AddCookie(&http.Cookie{Name: CookieName, Value: token})

		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		// The handler must be able to attribute the action to a user, which is
		// what makes admin audit entries meaningful.
		if got := rec.Body.String(); got != "admin" {
			t.Fatalf("handler saw user %q, want admin", got)
		}
	})
}

func TestCookieIsHttpOnlyAndSameSiteStrict(t *testing.T) {
	m := newManager(t, "pw", time.Hour)
	rec := httptest.NewRecorder()
	m.SetCookie(rec, "token")

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	cookie := cookies[0]

	if !cookie.HttpOnly {
		t.Error("session cookie is readable from JavaScript")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Errorf("Path = %q, want /", cookie.Path)
	}
}
