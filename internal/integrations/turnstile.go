package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Turnstile redeems one Cloudflare challenge token with siteverify. It holds
// the key pair and speaks the protocol; it decides nothing.
//
// In particular it does NOT decide what an unreachable Cloudflare means.
// Verify returns (verdict, error) rather than a bool precisely so the
// fail-closed rule stays where it can be read next to the reasoning for it,
// in internal/runtime/turnstile.go. A vendor client that quietly answered
// "false" on a transport error would put a security decision somewhere nobody
// looks.

const (
	// TurnstileOrigin is the host the widget's script and iframe come from.
	// Exported because the CSP directive in internal/runtime/middleware.go and
	// the script URL the browser fetches must agree, and this is the one place
	// that host is stated.
	TurnstileOrigin = "https://challenges.cloudflare.com"

	turnstileVerifyURL = TurnstileOrigin + "/turnstile/v0/siteverify"

	// TurnstileTestSiteKey / TurnstileTestSecretKey are Cloudflare's published
	// always-pass pair, used outside production. Dev therefore runs the real
	// widget, the real token round-trip and the real siteverify call — the
	// whole path, minus the production secret sitting on a laptop. The
	// counterparts, if you need to watch a refusal: 2x00000000000000000000AB
	// always blocks, 3x00000000000000000000FF forces an interactive challenge.
	TurnstileTestSiteKey   = "1x00000000000000000000AA"
	TurnstileTestSecretKey = "1x0000000000000000000000000000000AA"

	// turnstileTimeout bounds siteverify. It sits in front of sign-in, so a
	// slow Cloudflare must become a refusal a user can retry rather than a
	// request that hangs.
	turnstileTimeout = 10 * time.Second
)

type Turnstile struct {
	siteKey   string
	secretKey string
	http      *http.Client
}

func newTurnstile(siteKey, secretKey string) *Turnstile {
	return &Turnstile{
		siteKey:   siteKey,
		secretKey: secretKey,
		http:      &http.Client{Timeout: turnstileTimeout},
	}
}

// TurnstileVerdict is Cloudflare's answer. ErrorCodes are theirs verbatim,
// and are what distinguishes "invalid-input-secret" (our misconfiguration)
// from an ordinary lapsed token.
type TurnstileVerdict struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
}

// SiteKey is the public half, which the widget is rendered with. It travels
// in the page payload like any other view setting; the secret half never
// leaves this process.
func (t *Turnstile) SiteKey() string {
	return t.siteKey
}

// Verify redeems one token. Tokens are single-use and lapse after five
// minutes, so every attempt needs its own.
//
// An error means we could not get an answer (unreachable, malformed
// response); a returned verdict with Success false means Cloudflare gave one
// and it was no. The caller treats both as a refusal — see verifyTurnstile in
// internal/runtime/turnstile.go — but only by choosing to.
//
// remoteip is deliberately not sent. It is optional, Cloudflare validates it
// against the address the challenge was solved from, and the one thing worse
// than a missing signal here is a proxy chain that reports a different address
// than the browser used and locks every legitimate user out of sign-in.
func (t *Turnstile) Verify(ctx context.Context, token string) (TurnstileVerdict, error) {
	form := url.Values{}
	form.Set("secret", t.secretKey)
	form.Set("response", token)

	req, reqErr := formRequest(ctx, turnstileVerifyURL, "", "", form)
	if reqErr != nil {
		return TurnstileVerdict{}, fmt.Errorf("turnstile: build siteverify request: %w", reqErr)
	}

	resp, doErr := t.http.Do(req)
	if doErr != nil {
		return TurnstileVerdict{}, fmt.Errorf("turnstile: siteverify unreachable: %w", doErr)
	}
	defer func() { _ = resp.Body.Close() }()

	var verdict TurnstileVerdict
	if decodeErr := json.NewDecoder(resp.Body).Decode(&verdict); decodeErr != nil {
		return TurnstileVerdict{}, fmt.Errorf("turnstile: malformed siteverify response (status %d): %w", resp.StatusCode, decodeErr)
	}
	return verdict, nil
}
