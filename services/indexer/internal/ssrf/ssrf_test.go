package ssrf

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestIsBlockedAddr(t *testing.T) {
	cases := []struct {
		addr    string
		blocked bool
	}{
		// IPv4
		{"127.0.0.1", true},
		{"127.255.255.254", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true}, // AWS/GCP/Azure metadata
		{"169.254.0.1", true},
		{"100.100.100.200", true}, // Alibaba metadata (CGNAT)
		{"100.64.0.1", true},
		{"0.0.0.0", true},
		{"0.1.2.3", true},
		{"224.0.0.1", true},
		{"255.255.255.255", true},
		{"240.0.0.1", true},
		{"192.0.2.1", true},
		{"198.18.0.1", true},
		{"8.8.8.8", false},
		{"93.184.216.34", false},
		{"172.15.0.1", false},
		{"172.32.0.1", false},
		{"100.63.255.255", false},
		// IPv6
		{"::1", true},
		{"::", true},
		{"fe80::1", true},
		{"fe80::1%eth0", true},
		{"fc00::1", true},
		{"fd00:ec2::254", true}, // AWS IPv6 metadata
		{"ff02::1", true},
		{"2001:db8::1", true},
		{"2001::1", true},
		{"2606:4700:4700::1111", false},
		{"2001:4860:4860::8888", false},
		// IPv4 carried inside IPv6
		{"::ffff:127.0.0.1", true},
		{"::ffff:169.254.169.254", true},
		{"::ffff:10.0.0.1", true},
		{"::ffff:8.8.8.8", false},
		{"64:ff9b::7f00:1", true},    // NAT64 -> 127.0.0.1
		{"64:ff9b::a9fe:a9fe", true}, // NAT64 -> 169.254.169.254
		{"64:ff9b::808:808", false},  // NAT64 -> 8.8.8.8
		{"2002:7f00:1::", true},      // 6to4 -> 127.0.0.1
		{"2002:a9fe:a9fe::", true},   // 6to4 -> 169.254.169.254
		{"2002:808:808::", false},    // 6to4 -> 8.8.8.8
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			if got := IsBlockedAddr(netip.MustParseAddr(tc.addr)); got != tc.blocked {
				t.Fatalf("IsBlockedAddr(%s) = %v, want %v", tc.addr, got, tc.blocked)
			}
		})
	}
	if !IsBlockedAddr(netip.Addr{}) {
		t.Error("the zero Addr must be blocked")
	}
}

func fixedLookup(m map[string][]string) LookupFunc {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		ips, ok := m[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		out := make([]netip.Addr, len(ips))
		for i, s := range ips {
			out[i] = netip.MustParseAddr(s)
		}
		return out, nil
	}
}

func TestValidateURL(t *testing.T) {
	lookup := fixedLookup(map[string][]string{
		"hooks.example.com":  {"93.184.216.34"},
		"v6.example.com":     {"2606:4700:4700::1111"},
		"internal.evil.com":  {"10.0.0.5"},
		"loopback.evil.com":  {"127.0.0.1"},
		"metadata.evil.com":  {"169.254.169.254"},
		"mixed.evil.com":     {"93.184.216.34", "192.168.0.1"},
		"v6metadata.evil.io": {"fd00:ec2::254"},
		"mapped.evil.com":    {"::ffff:127.0.0.1"},
	})
	cases := []struct {
		name, url string
		allow     Allowlist
		wantErr   bool
		blocked   bool // error must wrap ErrBlocked
	}{
		{"public https", "https://hooks.example.com/x", nil, false, false},
		{"public http", "http://hooks.example.com/x", nil, false, false},
		{"public ipv6 host", "https://v6.example.com/", nil, false, false},
		{"public ip literal", "https://8.8.8.8/hook", nil, false, false},
		{"public port", "https://hooks.example.com:8443/x", nil, false, false},
		{"loopback literal", "http://127.0.0.1/", nil, true, true},
		{"loopback literal port", "http://127.0.0.1:8080/admin", nil, true, true},
		{"private literal", "http://10.1.2.3/", nil, true, true},
		{"link-local literal", "http://169.254.169.254/latest/meta-data/", nil, true, true},
		{"ipv6 loopback literal", "http://[::1]/", nil, true, true},
		{"ipv6 metadata literal", "http://[fd00:ec2::254]/", nil, true, true},
		{"ipv4-mapped literal", "http://[::ffff:169.254.169.254]/", nil, true, true},
		{"unspecified literal", "http://0.0.0.0/", nil, true, true},
		{"dns to private", "https://internal.evil.com/", nil, true, true},
		{"dns to loopback", "https://loopback.evil.com/", nil, true, true},
		{"dns to metadata", "https://metadata.evil.com/", nil, true, true},
		{"dns to ipv6 metadata", "https://v6metadata.evil.io/", nil, true, true},
		{"dns to mapped loopback", "https://mapped.evil.com/", nil, true, true},
		{"dns with one private record", "https://mixed.evil.com/", nil, true, true},
		{"decimal ip is not a literal", "http://2130706433/", nil, true, false},
		{"unresolvable", "https://nope.example.com/", nil, true, false},
		{"ftp scheme", "ftp://hooks.example.com/", nil, true, false},
		{"file scheme", "file:///etc/passwd", nil, true, false},
		{"no scheme", "hooks.example.com/x", nil, true, false},
		{"empty host", "https:///x", nil, true, false},
		{"userinfo", "https://user:pw@hooks.example.com/", nil, true, false},
		{"allowlist exact hit", "https://hooks.example.com/", Allowlist{"hooks.example.com"}, false, false},
		{"allowlist wildcard hit", "https://hooks.example.com/", Allowlist{"*.example.com"}, false, false},
		{"allowlist miss", "https://hooks.example.com/", Allowlist{"other.com"}, true, true},
		{"allowlist wildcard needs subdomain", "https://example.com/", Allowlist{"*.example.com"}, true, true},
		{"allowlist does not override ip block", "http://127.0.0.1/", Allowlist{"127.0.0.1"}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateURL(context.Background(), tc.url, tc.allow, lookup)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateURL(%q) err = %v, wantErr %v", tc.url, err, tc.wantErr)
			}
			if tc.blocked && !errors.Is(err, ErrBlocked) {
				t.Fatalf("ValidateURL(%q) err = %v, want ErrBlocked", tc.url, err)
			}
		})
	}
}

func TestParseAllowlist(t *testing.T) {
	l := ParseAllowlist(" Hooks.Example.com, *.slack.com ,,")
	if len(l) != 2 || l[0] != "hooks.example.com" || l[1] != "*.slack.com" {
		t.Fatalf("ParseAllowlist = %v", l)
	}
	if !l.Allows("HOOKS.example.com.") || !l.Allows("a.slack.com") || l.Allows("slack.com") || l.Allows("evil.com") {
		t.Error("Allows disagrees with the parsed list")
	}
	if !ParseAllowlist("").Allows("anything.example") {
		t.Error("an empty allowlist must permit all hosts")
	}
}

func TestAllowedHostsFromEnv(t *testing.T) {
	t.Setenv(EnvAllowedHosts, "a.example.com")
	if l := AllowedHostsFromEnv(); !l.Allows("a.example.com") || l.Allows("b.example.com") {
		t.Fatalf("AllowedHostsFromEnv = %v", l)
	}
}
