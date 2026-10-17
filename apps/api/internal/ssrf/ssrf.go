// Package ssrf keeps outgoing webhook and notification requests away from
// internal infrastructure (loopback, private networks, link-local and cloud
// metadata addresses).
//
// This file is duplicated verbatim in apps/api/internal/ssrf (the two live in
// separate modules and cannot import each other's internal packages); keep
// them in sync. The indexer additionally has client.go for delivery-time
// enforcement.
package ssrf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
)

// EnvAllowedHosts names the optional comma-separated host allowlist. When set,
// webhooks may only target the listed hosts ("example.com" matches exactly,
// "*.example.com" matches any subdomain). Blocked address ranges stay blocked
// even for allowlisted hosts.
const EnvAllowedHosts = "WEBHOOK_ALLOWED_HOSTS"

// ErrBlocked is wrapped by every error caused by a forbidden destination.
var ErrBlocked = errors.New("destination is not allowed")

// LookupFunc resolves a hostname to IP addresses. nil selects the system
// resolver; tests inject their own to simulate DNS rebinding.
type LookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

func defaultLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// Ranges that are not covered by the netip.Addr predicates below.
var blockedPrefixes = mustPrefixes(
	"0.0.0.0/8",       // "this network"
	"100.64.0.0/10",   // carrier-grade NAT (includes Alibaba metadata 100.100.100.200)
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"240.0.0.0/4",     // reserved, includes broadcast
	"100::/64",        // IPv6 discard-only
	"2001::/32",       // Teredo
	"2001:db8::/32",   // IPv6 documentation
)

var (
	nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour   = netip.MustParsePrefix("2002::/16")
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// IsBlockedAddr reports whether a server-side request must never be sent to a.
// IPv4-mapped IPv6 addresses and IPv4 addresses embedded in NAT64 and 6to4
// addresses are judged by the IPv4 address they carry.
func IsBlockedAddr(a netip.Addr) bool {
	if !a.IsValid() {
		return true
	}
	a = a.Unmap().WithZone("")
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	if a.Is6() {
		b := a.As16()
		switch {
		case nat64Prefix.Contains(a):
			return IsBlockedAddr(netip.AddrFrom4([4]byte(b[12:16])))
		case sixToFour.Contains(a):
			return IsBlockedAddr(netip.AddrFrom4([4]byte(b[2:6])))
		}
	}
	return false
}

// Allowlist is a set of permitted hosts; the zero value permits every host.
type Allowlist []string

// ParseAllowlist parses a comma-separated host list.
func ParseAllowlist(s string) Allowlist {
	var out Allowlist
	for _, h := range strings.Split(s, ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// AllowedHostsFromEnv reads the allowlist from WEBHOOK_ALLOWED_HOSTS.
func AllowedHostsFromEnv() Allowlist {
	return ParseAllowlist(os.Getenv(EnvAllowedHosts))
}

// Allows reports whether host may be contacted.
func (l Allowlist) Allows(host string) bool {
	if len(l) == 0 {
		return true
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, entry := range l {
		if suffix, ok := strings.CutPrefix(entry, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
		} else if host == entry {
			return true
		}
	}
	return false
}

// Resolve returns the addresses host points at. An IP literal is returned
// as-is without a DNS query.
func Resolve(ctx context.Context, host string, lookup LookupFunc) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	if lookup == nil {
		lookup = defaultLookup
	}
	addrs, err := lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %q: no addresses", host)
	}
	return addrs, nil
}

// checkAddrs fails with ErrBlocked if any of addrs is a forbidden destination.
// One bad record is enough: a host that also points inside is not trusted.
func checkAddrs(host string, addrs []netip.Addr) error {
	for _, a := range addrs {
		if IsBlockedAddr(a) {
			return fmt.Errorf("%w: %q resolves to a private, loopback, link-local or metadata address", ErrBlocked, host)
		}
	}
	return nil
}

// ValidateURL checks that raw is an http(s) URL without embedded credentials,
// whose host is allowlisted and resolves only to public addresses. It is the
// create-time check; delivery re-checks through the guarded client.
func ValidateURL(ctx context.Context, raw string, allow Allowlist, lookup LookupFunc) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("scheme must be http or https")
	}
	if u.User != nil {
		return errors.New("credentials in the URL are not allowed")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("host is required")
	}
	if !allow.Allows(host) {
		return fmt.Errorf("%w: host %q is not on the allowlist", ErrBlocked, host)
	}
	addrs, err := Resolve(ctx, host, lookup)
	if err != nil {
		return fmt.Errorf("host could not be resolved: %w", err)
	}
	return checkAddrs(host, addrs)
}
