// Package integrations is the single boundary between Vault3 and the outside
// world. Every call that leaves this deployment for a third party goes
// through a client declared here — the same way internal/database is the
// only package that speaks SQL, and for the same reasons.
//
// Why the boundary exists at all, in a product whose whole claim is that the
// server cannot read anything:
//
//   - It makes the third-party surface countable. `ls internal/integrations`
//     is the complete list of who we talk to, and a new entry is a file a
//     reviewer cannot miss. docs/security.md treats adding one as a decision,
//     not an implementation detail; this package is where that decision
//     becomes visible.
//   - It keeps credentials in one layer. API keys are read once at startup
//     (newIntegrations in internal/runtime/runtime.go) and live on a client,
//     so no handler reaches for r.Config to talk to a vendor.
//   - It keeps what we send them auditable. Both clients below take plain,
//     already-rendered values. Neither is handed a *Runtime, a database
//     handle, a user record or a cipher, so no future edit can widen an
//     outbound request into something that carries vault data by accident.
//
// The division of labour mirrors database/: this package owns transport —
// endpoints, credentials, wire format, timeouts — and returns results and
// errors. Callers own policy: whether to send at all, what to log, and what
// a failure means. That is why turnstile.Verify returns a verdict instead of
// a bool, and why mailgun.Send takes finished HTML instead of a template
// name: the fail-closed rule and the template set are Vault3's, not
// Cloudflare's or Mailgun's.
//
// Like database/, nothing here imports internal/runtime or internal/config.
package integrations

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// Clients bundles every third-party client. One is built at startup and
// hangs off Runtime.Integrations; handlers reach a vendor only through it.
type Clients struct {
	Mailgun   *Mailgun
	Turnstile *Turnstile
}

// Config is the resolved credential set, filled from environment config by
// the caller. Taking plain strings rather than *config.Config keeps this
// package free of the config import and puts every key name at one readable
// wiring site.
type Config struct {
	MailgunAPIKey      string
	MailgunDomain      string
	MailgunFromEmail   string
	MailgunFromName    string
	TurnstileSiteKey   string
	TurnstileSecretKey string
}

// New builds every client. It never fails and never dials: missing
// credentials are reported by the client itself (Mailgun.Configured), so a
// dev stack with empty keys boots exactly like a production one.
func New(cfg Config) *Clients {
	return &Clients{
		Mailgun:   newMailgun(cfg.MailgunAPIKey, cfg.MailgunDomain, cfg.MailgunFromEmail, cfg.MailgunFromName),
		Turnstile: newTurnstile(cfg.TurnstileSiteKey, cfg.TurnstileSecretKey),
	}
}

// formRequest builds the x-www-form-urlencoded POST both vendors expect.
// user is the HTTP basic-auth username, or "" for an unauthenticated call.
func formRequest(ctx context.Context, endpoint, user, password string, form url.Values) (*http.Request, error) {
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if reqErr != nil {
		return nil, reqErr
	}
	if user != "" {
		req.SetBasicAuth(user, password)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}
