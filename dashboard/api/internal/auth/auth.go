// Package auth guards the dashboard.
//
// The dashboard can change what the proxy blocks, so getting into it is
// equivalent to getting past the proxy. v1 keeps a single administrator whose
// bcrypt hash comes from the environment (§5.5) — no user table, nothing to
// enumerate — and issues a signed session cookie.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// CookieName is the session cookie's name.
const CookieName = "openshield_session"

// Errors returned by Manager.
var (
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	ErrInvalidSession     = errors.New("auth: invalid session")
	ErrSessionExpired     = errors.New("auth: session expired")
)

// Manager issues and validates sessions.
type Manager struct {
	user         string
	passwordHash []byte
	secret       []byte
	ttl          time.Duration
	secure       bool
}

// Options configures the Manager.
type Options struct {
	User         string
	PasswordHash string
	Secret       string
	TTL          time.Duration
	// Secure marks the cookie Secure, which browsers only send over HTTPS. It
	// must be off while the stack is served over plain HTTP, or login silently
	// fails to stick.
	Secure bool
}

// New returns a Manager.
func New(opts Options) (*Manager, error) {
	if opts.User == "" {
		return nil, errors.New("auth: administrator user is required")
	}
	if len(opts.Secret) < 32 {
		return nil, errors.New("auth: session secret must be at least 32 characters")
	}
	if _, err := bcrypt.Cost([]byte(opts.PasswordHash)); err != nil {
		return nil, fmt.Errorf("auth: administrator password hash is not a valid bcrypt hash: %w", err)
	}
	if opts.TTL <= 0 {
		opts.TTL = 8 * time.Hour
	}

	return &Manager{
		user:         opts.User,
		passwordHash: []byte(opts.PasswordHash),
		secret:       []byte(opts.Secret),
		ttl:          opts.TTL,
		secure:       opts.Secure,
	}, nil
}

// Login verifies credentials and returns a session token.
//
// The bcrypt comparison runs even when the username is wrong. Skipping it would
// make a bad username measurably faster than a bad password, which is enough to
// enumerate the administrator's name.
func (m *Manager) Login(user, password string) (string, error) {
	userMatches := subtle.ConstantTimeCompare([]byte(user), []byte(m.user)) == 1
	passwordMatches := bcrypt.CompareHashAndPassword(m.passwordHash, []byte(password)) == nil

	if !userMatches || !passwordMatches {
		return "", ErrInvalidCredentials
	}
	return m.issue(m.user, time.Now().Add(m.ttl)), nil
}

// issue builds a token of the form base64(user).expiry.signature.
func (m *Manager) issue(user string, expiry time.Time) string {
	body := base64.RawURLEncoding.EncodeToString([]byte(user)) + "." +
		strconv.FormatInt(expiry.Unix(), 10)
	return body + "." + m.sign(body)
}

func (m *Manager) sign(body string) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Verify checks a token's signature and expiry and returns the user it names.
func (m *Manager) Verify(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ErrInvalidSession
	}

	body := parts[0] + "." + parts[1]
	// The signature is checked before anything inside the token is trusted or
	// even parsed, and with a constant-time comparison so the check cannot be
	// probed one byte at a time.
	if !hmac.Equal([]byte(parts[2]), []byte(m.sign(body))) {
		return "", ErrInvalidSession
	}

	rawUser, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", ErrInvalidSession
	}
	expiry, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", ErrInvalidSession
	}
	if time.Now().After(time.Unix(expiry, 0)) {
		return "", ErrSessionExpired
	}

	return string(rawUser), nil
}

// SetCookie writes the session cookie.
func (m *Manager) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:  CookieName,
		Value: token,
		Path:  "/",
		// HttpOnly keeps the token out of reach of any script that lands on the
		// page; SameSite=Strict means a link from another site cannot carry the
		// session into a state-changing request.
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   m.secure,
		MaxAge:   int(m.ttl.Seconds()),
	})
}

// ClearCookie expires the session cookie.
func (m *Manager) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   m.secure,
		MaxAge:   -1,
	})
}

// userKey is the context key carrying the authenticated user.
type userKey struct{}

// Require wraps a handler so that only an authenticated request reaches it.
func (m *Manager) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(CookieName)
		if err != nil {
			unauthorized(w, "authentication required")
			return
		}

		user, err := m.Verify(cookie.Value)
		if err != nil {
			m.ClearCookie(w)
			unauthorized(w, err.Error())
			return
		}

		next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), user)))
	})
}

// TTL reports the configured session lifetime.
func (m *Manager) TTL() time.Duration { return m.ttl }

func unauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"` + message + `"}`))
}
