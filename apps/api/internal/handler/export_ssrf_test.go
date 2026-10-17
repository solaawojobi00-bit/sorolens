package handler

import "github.com/sorolens/sorolens/apps/api/internal/ssrf"

// SetWebhookLookup replaces the webhook host resolver and returns a restore func.
func SetWebhookLookup(f ssrf.LookupFunc) (restore func()) {
	prev := webhookLookup
	webhookLookup = f
	return func() { webhookLookup = prev }
}
