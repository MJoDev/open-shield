package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

// The address these tests are about is not cosmetic. It is the key the sign-in
// throttle counts against, and the author recorded on every administrative
// entry sealed into the hash chain. A client that can choose it gets an
// unlimited password oracle and a forged provenance in the audit log, so the
// rule each test holds the code to is the same one: believe the header only
// from a peer that was configured as trustworthy, and never past the first
// address that was not.

func mustPrefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			t.Fatalf("bad test fixture %q: %v", value, err)
		}
		out = append(out, prefix)
	}
	return out
}

func request(remoteAddr, forwarded string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/login", nil)
	r.RemoteAddr = remoteAddr
	if forwarded != "" {
		r.Header.Set("X-Forwarded-For", forwarded)
	}
	return r
}

// With no trusted network configured the header is inert. This is the default,
// and it is what makes a direct-to-internet deployment safe out of the box.
func TestClientIPIgnoresForwardedHeaderWhenNothingIsTrusted(t *testing.T) {
	var trusted trustedProxies

	got := trusted.clientIP(request("198.51.100.7:51234", "203.0.113.99"))
	if got != "198.51.100.7" {
		t.Fatalf("clientIP = %q, want the peer address 198.51.100.7", got)
	}
}

// The regression this whole change exists for: an attacker sending a forged
// header from an untrusted address must not be able to pick their own identity,
// or every failed sign-in lands in a fresh throttle bucket.
func TestClientIPRejectsForgedHeaderFromUntrustedPeer(t *testing.T) {
	trusted := trustedProxies(mustPrefixes(t, "100.64.0.0/10"))

	got := trusted.clientIP(request("198.51.100.7:51234", "203.0.113.99"))
	if got != "198.51.100.7" {
		t.Fatalf("clientIP = %q, want 198.51.100.7: a peer outside the trusted "+
			"networks must not be able to name itself", got)
	}
}

func TestClientIPTrustsForwardedHeaderFromTrustedPeer(t *testing.T) {
	trusted := trustedProxies(mustPrefixes(t, "100.64.0.0/10"))

	got := trusted.clientIP(request("100.64.0.3:51234", "203.0.113.99"))
	if got != "203.0.113.99" {
		t.Fatalf("clientIP = %q, want 203.0.113.99", got)
	}
}

// The walk runs right to left, so entries a client prepended before the edge
// appended the real address are never reached.
func TestClientIPTakesTheRightmostUntrustedEntry(t *testing.T) {
	trusted := trustedProxies(mustPrefixes(t, "100.64.0.0/10"))

	got := trusted.clientIP(request(
		"100.64.0.3:51234",
		"203.0.113.1, 198.51.100.7, 100.64.0.9",
	))
	if got != "198.51.100.7" {
		t.Fatalf("clientIP = %q, want 198.51.100.7: the walk must stop at the "+
			"first untrusted address from the right, not run to the left end", got)
	}
}

// A header that is entirely trusted names nobody, so the peer stands.
func TestClientIPFallsBackToPeerWhenEveryEntryIsTrusted(t *testing.T) {
	trusted := trustedProxies(mustPrefixes(t, "100.64.0.0/10"))

	got := trusted.clientIP(request("100.64.0.3:51234", "100.64.0.9, 100.64.0.4"))
	if got != "100.64.0.3" {
		t.Fatalf("clientIP = %q, want the peer 100.64.0.3", got)
	}
}

// Garbage is not evidence. Walking past it would mean reading whatever an
// attacker put to its left.
func TestClientIPStopsAtAMalformedEntry(t *testing.T) {
	trusted := trustedProxies(mustPrefixes(t, "100.64.0.0/10"))

	got := trusted.clientIP(request("100.64.0.3:51234", "203.0.113.1, not-an-address"))
	if got != "100.64.0.3" {
		t.Fatalf("clientIP = %q, want the peer 100.64.0.3: a malformed entry "+
			"must end the walk rather than be stepped over", got)
	}
}

func TestClientIPHandlesIPv6Peers(t *testing.T) {
	trusted := trustedProxies(mustPrefixes(t, "fd00::/8"))

	got := trusted.clientIP(request("[fd00::1]:51234", "203.0.113.99"))
	if got != "203.0.113.99" {
		t.Fatalf("clientIP = %q, want 203.0.113.99", got)
	}
}

// An absent header is the common case for a trusted peer that did not add one.
func TestClientIPUsesPeerWhenHeaderIsAbsent(t *testing.T) {
	trusted := trustedProxies(mustPrefixes(t, "100.64.0.0/10"))

	got := trusted.clientIP(request("100.64.0.3:51234", ""))
	if got != "100.64.0.3" {
		t.Fatalf("clientIP = %q, want 100.64.0.3", got)
	}
}
