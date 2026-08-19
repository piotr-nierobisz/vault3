package integrations

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Mailgun transports one finished email. It knows the endpoint, the
// credentials and the wire format, and nothing else: the template set, the
// platform-level send toggle and every logging decision stay in
// internal/runtime/email.go, because they are product policy rather than
// vendor detail.
//
// Mailgun is the one third party that sees a user's email address, and it
// sees only what the template rendered — never vault data, which exists on
// the server as ciphertext alone.

// mailgunAPIBase is the EU region host. It is not the default one: accounts
// are region-bound, and a message posted to the US host with EU credentials
// is rejected rather than rerouted.
const mailgunAPIBase = "https://api.eu.mailgun.net/v3"

// mailgunTimeout bounds a send. Email is a side effect of a user's action
// (notify.go dispatches after the triggering write commits), so a slow vendor
// must not hold a request open indefinitely.
const mailgunTimeout = 15 * time.Second

type Mailgun struct {
	apiKey    string
	domain    string
	fromEmail string
	fromName  string
	http      *http.Client
}

func newMailgun(apiKey, domain, fromEmail, fromName string) *Mailgun {
	return &Mailgun{
		apiKey:    apiKey,
		domain:    domain,
		fromEmail: fromEmail,
		fromName:  fromName,
		http:      &http.Client{Timeout: mailgunTimeout},
	}
}

// Email is one rendered message. Subject and HTML are finished text: this
// package renders nothing.
type Email struct {
	ToEmail string
	ToName  string
	Subject string
	HTML    string
}

// Configured reports whether the credential trio is present. The three keys
// are deliberately absent from REQUIRED_ENV_VARS so a dev stack boots with
// them blank, which makes "not configured" an ordinary state the caller must
// handle rather than a startup failure.
func (m *Mailgun) Configured() bool {
	return m.apiKey != "" && m.domain != "" && m.fromEmail != ""
}

// Send posts one message. It returns an error for a real delivery failure
// only; the caller decides whether a send should have happened at all.
// Calling it while !Configured() is a programming error and says so.
func (m *Mailgun) Send(ctx context.Context, msg Email) error {
	if !m.Configured() {
		return fmt.Errorf("mailgun: send attempted without credentials")
	}
	if msg.ToEmail == "" {
		return fmt.Errorf("mailgun: recipient has no email address")
	}

	form := url.Values{}
	form.Set("from", fmt.Sprintf("%s <%s>", m.fromName, m.fromEmail))
	form.Set("to", formatRecipient(msg.ToName, msg.ToEmail))
	form.Set("subject", msg.Subject)
	form.Set("html", msg.HTML)

	endpoint := fmt.Sprintf("%s/%s/messages", mailgunAPIBase, m.domain)
	req, reqErr := formRequest(ctx, endpoint, "api", m.apiKey, form)
	if reqErr != nil {
		return fmt.Errorf("mailgun: build request: %w", reqErr)
	}

	resp, doErr := m.http.Do(req)
	if doErr != nil {
		return fmt.Errorf("mailgun: %w", doErr)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("mailgun: responded %d", resp.StatusCode)
	}
	return nil
}

// formatRecipient renders the To header, falling back to the bare address
// when we hold no display name for the recipient.
func formatRecipient(name, email string) string {
	if name == "" {
		return email
	}
	return fmt.Sprintf("%s <%s>", name, email)
}
