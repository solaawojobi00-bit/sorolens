package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/sorolens/sorolens/apps/api/internal/handler"
)

// Every hostname resolves to a public address unless a test says otherwise, so
// the subscription tests do not depend on real DNS.
func init() {
	handler.SetWebhookLookup(func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	})
}

func TestCreateSubscriptionRejectsInternalDestinations(t *testing.T) {
	restore := handler.SetWebhookLookup(func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "internal.example.com":
			return []netip.Addr{netip.MustParseAddr("10.0.0.7")}, nil
		case "metadata.example.com":
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		case "mixed.example.com":
			return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("127.0.0.1")}, nil
		case "v6.example.com":
			return []netip.Addr{netip.MustParseAddr("fd00:ec2::254")}, nil
		case "gone.example.com":
			return nil, context.DeadlineExceeded
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	})
	defer restore()

	ms := seedRBACUsers(t)
	seedMonitored(t, ms)
	srv := newTestHandler(ms, true, true)

	cases := map[string]string{
		"loopback v4":            `{"contract_id":"C1","webhook_url":"http://127.0.0.1:8080/x"}`,
		"loopback v6":            `{"contract_id":"C1","webhook_url":"http://[::1]/x"}`,
		"localhost-style dns":    `{"contract_id":"C1","webhook_url":"https://internal.example.com/x"}`,
		"private 10/8":           `{"contract_id":"C1","webhook_url":"https://10.1.2.3/x"}`,
		"private 172.16/12":      `{"contract_id":"C1","webhook_url":"https://172.20.0.1/x"}`,
		"private 192.168/16":     `{"contract_id":"C1","webhook_url":"https://192.168.0.10/x"}`,
		"aws metadata literal":   `{"contract_id":"C1","webhook_url":"http://169.254.169.254/latest/meta-data/"}`,
		"aws metadata via dns":   `{"contract_id":"C1","webhook_url":"https://metadata.example.com/"}`,
		"aws ipv6 metadata":      `{"contract_id":"C1","webhook_url":"http://[fd00:ec2::254]/"}`,
		"ipv6 metadata via dns":  `{"contract_id":"C1","webhook_url":"https://v6.example.com/"}`,
		"ipv4-mapped ipv6":       `{"contract_id":"C1","webhook_url":"http://[::ffff:127.0.0.1]/"}`,
		"one private dns record": `{"contract_id":"C1","webhook_url":"https://mixed.example.com/"}`,
		"unresolvable host":      `{"contract_id":"C1","webhook_url":"https://gone.example.com/"}`,
		"credentials in url":     `{"contract_id":"C1","webhook_url":"https://user:pw@hooks.example.com/"}`,
		"slack to private":       `{"contract_id":"C1","channel_type":"slack","webhook_url":"https://internal.example.com/services/x"}`,
		"discord to loopback":    `{"contract_id":"C1","channel_type":"discord","webhook_url":"https://127.0.0.1/api/webhooks/1/x"}`,
		"pagerduty to metadata":  `{"contract_id":"C1","channel_type":"pagerduty","routing_key":"k","webhook_url":"https://169.254.169.254/v2/enqueue"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			w := doRequestAsUser(srv, http.MethodPost, subsPath, "", contributorUser, body)
			if w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("want 422, got %d (%s)", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "webhook_url") {
				t.Fatalf("error should name webhook_url: %s", w.Body.String())
			}
		})
	}

	// Nothing was stored for any rejected request.
	list := doRequestAsUser(srv, http.MethodGet, subsPath, "", contributorUser, "")
	var got struct {
		Subscriptions []json.RawMessage `json:"subscriptions"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Subscriptions) != 0 {
		t.Fatalf("rejected requests created %d subscription(s)", len(got.Subscriptions))
	}
}

func TestCreateSubscriptionAcceptsPublicDestinations(t *testing.T) {
	ms := seedRBACUsers(t)
	seedMonitored(t, ms)
	srv := newTestHandler(ms, true, true)

	for name, body := range map[string]string{
		"https hostname": `{"contract_id":"C1","webhook_url":"https://hooks.example.com/x"}`,
		"http hostname":  `{"contract_id":"C1","webhook_url":"http://hooks.example.com:8080/x"}`,
		"public literal": `{"contract_id":"C1","webhook_url":"https://8.8.8.8/x"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if w := doRequestAsUser(srv, http.MethodPost, subsPath, "", contributorUser, body); w.Code != http.StatusCreated {
				t.Fatalf("want 201, got %d (%s)", w.Code, w.Body.String())
			}
		})
	}
}

func TestCreateSubscriptionHonoursHostAllowlist(t *testing.T) {
	t.Setenv("WEBHOOK_ALLOWED_HOSTS", "hooks.example.com, *.slack.com")
	ms := seedRBACUsers(t)
	seedMonitored(t, ms)
	srv := newTestHandler(ms, true, true)

	for body, want := range map[string]int{
		`{"contract_id":"C1","webhook_url":"https://hooks.example.com/x"}`:                                   http.StatusCreated,
		`{"contract_id":"C1","channel_type":"slack","webhook_url":"https://hooks.slack.com/services/T/B/x"}`: http.StatusCreated,
		`{"contract_id":"C1","webhook_url":"https://other.example.org/x"}`:                                   http.StatusUnprocessableEntity,
		`{"contract_id":"C1","webhook_url":"https://slack.com/x"}`:                                           http.StatusUnprocessableEntity,
	} {
		if w := doRequestAsUser(srv, http.MethodPost, subsPath, "", contributorUser, body); w.Code != want {
			t.Errorf("%s: want %d, got %d (%s)", body, want, w.Code, w.Body.String())
		}
	}
}
