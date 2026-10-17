package ssrf

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// maxRedirects bounds how many redirects a delivery follows.
const maxRedirects = 3

// NewClient returns an http.Client for delivering webhooks. Every connection,
// including each redirect hop, resolves the host itself, refuses forbidden
// addresses and dials the exact address it checked, so a DNS answer that
// changes between validation and delivery (rebinding) cannot reach an
// internal service. Environment proxies are ignored because a proxy would
// connect on the caller's behalf and bypass the check.
func NewClient(timeout time.Duration, allow Allowlist) *http.Client {
	return newClient(timeout, allow, nil, IsBlockedAddr)
}

// newClient is NewClient with the resolver and the address policy injectable
// for tests.
func newClient(timeout time.Duration, allow Allowlist, lookup LookupFunc, blocked func(netip.Addr) bool) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if !allow.Allows(host) {
				return nil, fmt.Errorf("%w: host %q is not on the allowlist", ErrBlocked, host)
			}
			addrs, err := Resolve(ctx, host, lookup)
			if err != nil {
				return nil, err
			}
			for _, a := range addrs {
				if blocked(a) {
					return nil, fmt.Errorf("%w: %q resolves to a private, loopback, link-local or metadata address", ErrBlocked, host)
				}
			}
			var lastErr error
			for _, a := range addrs {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("%w: redirect to scheme %q", ErrBlocked, req.URL.Scheme)
			}
			if !allow.Allows(req.URL.Hostname()) {
				return fmt.Errorf("%w: redirect to host %q is not on the allowlist", ErrBlocked, req.URL.Hostname())
			}
			// Private targets are refused by the dialer when the hop connects.
			return nil
		},
	}
}
