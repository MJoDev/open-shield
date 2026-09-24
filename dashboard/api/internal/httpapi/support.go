package httpapi

import (
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"path"
	"strings"
	"sync"
	"time"
)

// --- Sign-in throttling ------------------------------------------------------

// loginLimiter caps failed sign-in attempts per source address.
//
// There is one administrator account and no lockout, so without this the login
// endpoint is an online password oracle that answers as fast as bcrypt allows.
// Successful sign-ins clear the counter, so an operator who mistypes a few
// times and then gets it right is not punished.
type loginLimiter struct {
	max    int
	window time.Duration

	mu       sync.Mutex
	attempts map[string]*attemptRecord
}

type attemptRecord struct {
	count int
	first time.Time
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{
		max:      max,
		window:   window,
		attempts: map[string]*attemptRecord{},
	}
}

func (l *loginLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweep()

	record, ok := l.attempts[ip]
	if !ok {
		return true
	}
	if time.Since(record.first) > l.window {
		delete(l.attempts, ip)
		return true
	}
	return record.count < l.max
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	record, ok := l.attempts[ip]
	if !ok || time.Since(record.first) > l.window {
		l.attempts[ip] = &attemptRecord{count: 1, first: time.Now()}
		return
	}
	record.count++
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	delete(l.attempts, ip)
	l.mu.Unlock()
}

// sweep drops expired records so the map cannot grow without bound under a
// distributed guessing attempt. Callers hold the lock.
func (l *loginLimiter) sweep() {
	if len(l.attempts) < 1024 {
		return
	}
	for ip, record := range l.attempts {
		if time.Since(record.first) > l.window {
			delete(l.attempts, ip)
		}
	}
}

// --- Client address resolution -----------------------------------------------

// trustedProxies decides whose X-Forwarded-For may be believed.
//
// The header is a list any client can prepend to, so taking its first entry
// trusts whoever sent the request. That address is what the sign-in throttle
// counts against and what the audit entry records as the author of an
// administrative change, which makes believing it worth two things to an
// attacker: an unlimited password oracle, and a forged provenance sealed into
// the hash chain as though it were evidence.
//
// Empty means believe nobody — correct whenever clients reach the dashboard
// directly, and the default for that reason. Behind an edge that rewrites the
// header, list the edge's networks. See OS_TRUSTED_PROXY in
// deploy/.env.example.
type trustedProxies []netip.Prefix

func (t trustedProxies) contains(addr netip.Addr) bool {
	for _, prefix := range t {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// clientIP returns the address to attribute a request to.
//
// The forwarded list is walked from the right — the end an edge appends to —
// and the first address outside the trusted set wins. Anything further left was
// supplied by a party that was already untrusted at that point, so it is never
// reached. A malformed entry ends the walk rather than being stepped over:
// past it there is nothing but attacker-controlled text.
func (t trustedProxies) clientIP(r *http.Request) string {
	peer := peerAddr(r)
	if len(t) == 0 {
		return peer
	}

	addr, err := netip.ParseAddr(peer)
	if err != nil || !t.contains(addr) {
		return peer
	}

	forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(forwarded) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(forwarded[i])
		if candidate == "" {
			continue
		}
		parsed, err := netip.ParseAddr(candidate)
		if err != nil {
			return peer
		}
		if !t.contains(parsed) {
			return parsed.String()
		}
	}
	return peer
}

// peerAddr is the address that actually opened the connection — the only one
// no client can choose.
func peerAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// --- CIDR --------------------------------------------------------------------

// parsePrefix normalises an access-list entry. It accepts a CIDR or a bare
// address, and masks off host bits so that 203.0.113.7/24 is stored as the
// range it actually means rather than as a prefix that never matches.
//
// It mirrors rules.ParsePrefix, which lives in the engine's tree and cannot be
// imported from here.
func parsePrefix(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("cidr is required")
	}

	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked().String(), nil
	}

	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", fmt.Errorf("%q is neither an IP address nor a CIDR range", value)
	}
	return netip.PrefixFrom(addr, addr.BitLen()).String(), nil
}

// --- Static assets -----------------------------------------------------------

// spaHandler serves the built React application.
//
// Anything that is not a real file falls back to index.html, so a deep link the
// operator bookmarked (/events, /forensics) is handed to the client-side router
// instead of returning 404.
func (s *Server) spaHandler() http.Handler {
	files := http.FileServer(http.FS(s.spa))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "" {
			name = "index.html"
		}

		if _, err := fs.Stat(s.spa, name); err != nil {
			s.serveIndex(w, r)
			return
		}

		// Hashed asset filenames change whenever their content changes, so they
		// can be cached hard. index.html must not be, or a browser keeps
		// loading an old build's asset names after an upgrade.
		if strings.HasPrefix(name, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	index, err := fs.ReadFile(s.spa, "index.html")
	if err != nil {
		http.Error(w, "dashboard assets are missing from this build", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, "index.html", time.Time{}, strings.NewReader(string(index)))
}

// --- Middleware --------------------------------------------------------------

// securityHeaders hardens the dashboard itself.
//
// The dashboard renders attacker-controlled strings — the paths and payload
// excerpts of blocked requests. React escapes them, but a content security
// policy is the second lock: a protection tool that can be turned against its
// operator through the very payloads it caught would be a poor one.
func securityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; " +
		"script-src 'self'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; " +
		"connect-src 'self' ws: wss:; " +
		"frame-ancestors 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
