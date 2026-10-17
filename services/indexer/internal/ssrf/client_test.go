package ssrf

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func get(t *testing.T, c *http.Client, url string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c.Do(req)
}

func allowAll(netip.Addr) bool { return false }

// The default policy refuses a real loopback server: this is the end-to-end
// check that NewClient is wired to IsBlockedAddr.
func TestNewClientRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("request reached a loopback server")
	}))
	defer srv.Close()

	_, err := get(t, NewClient(2*time.Second, nil), srv.URL)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
}

func TestClientDialsTheCheckedAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	lookup := fixedLookup(map[string][]string{"hook.test": {"127.0.0.1"}})
	resp, err := get(t, newClient(2*time.Second, nil, lookup, allowAll), "http://hook.test:"+port+"/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// A host that validated as public at creation but now resolves inside must be
// refused when the delivery dials (DNS rebinding).
func TestClientRefusesRebinding(t *testing.T) {
	answers := [][]netip.Addr{
		{netip.MustParseAddr("93.184.216.34")},
		{netip.MustParseAddr("169.254.169.254")},
	}
	var calls atomic.Int32
	lookup := func(context.Context, string) ([]netip.Addr, error) {
		i := int(calls.Add(1)) - 1
		if i >= len(answers) {
			i = len(answers) - 1
		}
		return answers[i], nil
	}

	if err := ValidateURL(context.Background(), "http://rebind.test/hook", nil, lookup); err != nil {
		t.Fatalf("create-time validation should pass on the first (public) answer: %v", err)
	}
	_, err := get(t, newClient(2*time.Second, nil, lookup, IsBlockedAddr), "http://rebind.test/hook")
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("delivery err = %v, want ErrBlocked", err)
	}
}

func TestClientRefusesBadRecordsAndLiterals(t *testing.T) {
	lookup := fixedLookup(map[string][]string{
		"mixed.test": {"93.184.216.34", "10.0.0.1"},
		"v6.test":    {"fd00:ec2::254"},
	})
	c := newClient(2*time.Second, nil, lookup, IsBlockedAddr)
	for _, host := range []string{"mixed.test", "v6.test", "169.254.169.254", "[::1]", "[::ffff:127.0.0.1]"} {
		if _, err := get(t, c, "http://"+host+"/"); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: err = %v, want ErrBlocked", host, err)
		}
	}
}

func TestClientRefusesRedirectToPrivateAddress(t *testing.T) {
	var reached atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
			return
		}
		reached.Store(true)
	}))
	defer srv.Close()

	// 127.0.0.1 (the test server) is permitted; the redirect target is not.
	policy := func(a netip.Addr) bool { return a != netip.MustParseAddr("127.0.0.1") }
	_, err := get(t, newClient(2*time.Second, nil, nil, policy), srv.URL+"/start")
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
	if reached.Load() {
		t.Error("redirect target was contacted")
	}
}

func TestClientLimitsRedirects(t *testing.T) {
	var hops atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops.Add(1)
		http.Redirect(w, r, srv.URL+"/again", http.StatusFound)
	}))
	defer srv.Close()

	_, err := get(t, newClient(2*time.Second, nil, nil, allowAll), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Fatalf("err = %v, want redirect-limit error", err)
	}
	if got := hops.Load(); got != maxRedirects+1 {
		t.Fatalf("server saw %d requests, want %d", got, maxRedirects+1)
	}
}

func TestClientRefusesRedirectOffAllowlist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://other.example.net/", http.StatusFound)
	}))
	defer srv.Close()

	c := newClient(2*time.Second, Allowlist{"127.0.0.1"}, nil, allowAll)
	if _, err := get(t, c, srv.URL); !errors.Is(err, ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
}

func TestClientRefusesNonHTTPRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "gopher://127.0.0.1/")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	if _, err := get(t, newClient(2*time.Second, nil, nil, allowAll), srv.URL); err == nil {
		t.Fatal("expected the non-http redirect to be refused")
	}
}
