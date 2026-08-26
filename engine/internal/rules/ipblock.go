package rules

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/open-shield/open-shield/internal/model"
)

// IPRule is one row of the access list. It lives in internal/model because the
// dashboard API writes these rows and this package reads them, and neither can
// import the other.
type IPRule = model.IPRule

// IPBlock is the first and cheapest link of the chain: a prefix lookup against
// the configured access list.
//
// An allow entry beats a deny entry. That ordering is what makes it possible to
// deny a whole range and still let one known address through — the common shape
// of "block this hosting provider, except our own monitoring".
type IPBlock struct {
	mu    sync.RWMutex
	allow []netip.Prefix
	deny  []netip.Prefix
	notes map[string]string
}

// NewIPBlock returns an empty access list. Nothing is blocked until Set is
// called with entries.
func NewIPBlock() *IPBlock {
	return &IPBlock{notes: map[string]string{}}
}

func (r *IPBlock) Name() string { return "ipblock" }

// Set replaces the access list. Invalid CIDRs are reported and skipped: one bad
// row entered through the dashboard must not take the whole list out of
// service.
func (r *IPBlock) Set(entries []IPRule) []error {
	var (
		allow []netip.Prefix
		deny  []netip.Prefix
		errs  []error
	)
	notes := make(map[string]string, len(entries))

	for _, e := range entries {
		prefix, err := ParsePrefix(e.CIDR)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		notes[prefix.String()] = e.Note

		switch e.Action {
		case "allow":
			allow = append(allow, prefix)
		case "deny":
			deny = append(deny, prefix)
		default:
			errs = append(errs, fmt.Errorf("rules: ip rule %s has unknown action %q", e.CIDR, e.Action))
		}
	}

	r.mu.Lock()
	r.allow, r.deny, r.notes = allow, deny, notes
	r.mu.Unlock()

	return errs
}

// Evaluate blocks a request whose source address falls inside a deny prefix and
// no allow prefix.
func (r *IPBlock) Evaluate(_ context.Context, req *model.RequestContext) (model.Verdict, string) {
	addr, err := netip.ParseAddr(req.IP)
	if err != nil {
		// An unparseable source address means the proxy sent something
		// unexpected. Allow and let the remaining rules judge the request on
		// its content; blocking here would turn a proxy misconfiguration into
		// a total outage.
		return model.Allow, ""
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, prefix := range r.allow {
		if prefix.Contains(addr) {
			return model.Allow, ""
		}
	}
	for _, prefix := range r.deny {
		if prefix.Contains(addr) {
			note := r.notes[prefix.String()]
			if note != "" {
				return model.Block, fmt.Sprintf("source address is in denied range %s (%s)", prefix, note)
			}
			return model.Block, fmt.Sprintf("source address is in denied range %s", prefix)
		}
	}

	return model.Allow, ""
}

// Size reports how many allow and deny prefixes are loaded, for the health
// endpoint.
func (r *IPBlock) Size() (allow, deny int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.allow), len(r.deny)
}

// ParsePrefix accepts either a CIDR ("203.0.113.0/24") or a bare address
// ("203.0.113.7"), which it treats as a single-host prefix. The dashboard
// accepts both, because an operator blocking one attacker should not have to
// remember to type /32.
func ParsePrefix(value string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		// Masked() drops any host bits, so 203.0.113.7/24 is stored as
		// 203.0.113.0/24 rather than silently never matching.
		return prefix.Masked(), nil
	}

	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("rules: %q is neither an IP address nor a CIDR range", value)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}
