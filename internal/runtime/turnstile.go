package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vault3/internal/config"

	bungo "github.com/piotr-nierobisz/BunGo"
	"go.uber.org/zap"
)

// Cloudflare Turnstile: the bot check in front of sign-in and registration.
//
// Those two endpoints are the whole of what an attacker can call with no
// account — credential stuffing against one, mass signup against the other —
// and per-IP throttling belongs to the reverse proxy, which does not help
// against a distributed attempt. The widget is rendered by
// web/components/auth/turnstile.tsx; the token it produces rides in the same
// JSON body as the request it guards, and is checked here before the handler
// ever runs.
//
// What this is NOT: a second authentication factor. A solved challenge proves
// only that a browser and (probably) a person were involved. Every credential
// check downstream is unchanged, and the generic login error still says the
// same thing to everyone.

var turnstileHTTPClient = &http.Client{Timeout: 10 * time.Second}

// turnstileKeys returns the site key the widget is rendered with and the
// secret key siteverify is called with. Production uses the deployment's own
// pair; everywhere else gets Cloudflare's always-pass test pair, so dev runs
// the same widget and the same round-trip without holding the real secret.
// Same shape as sessionCookieName() in auth.go, for the same reason.
func (r *Runtime) turnstileKeys() (siteKey string, secretKey string) {
	if r.Config.MustBool("PRODUCTION_BOOL") {
		return r.Config.MustString(config.TurnstileSiteKeyEnv), r.Config.MustString(config.TurnstileSecretKeyEnv)
	}
	return config.TurnstileTestSiteKey, config.TurnstileTestSecretKey
}

// turnstileTokenPayload is the one field every challenged request adds. It is
// decoded on its own so the layer never has to know the shape of the body it
// is guarding; the handler decodes the same bytes again for its own fields.
type turnstileTokenPayload struct {
	TurnstileToken string `json:"turnstileToken"`
}

// RequireHuman is the security layer the challengedAPI() helper attaches in
// cmd/vault3/main.go. It rejects with 403 and one message for every failure
// mode — absent token, spent token, refused challenge, verification
// unreachable — because the distinctions are useful to an attacker tuning a
// bot and useless to the person who just has to try again.
//
// It runs BEFORE the handler, so a request that cannot prove a human sent it
// never reaches an Argon2id comparison or a database write.
func (r *Runtime) RequireHuman(req *bungo.Request) (bool, *bungo.APIResponse) {
	payload, deny := decodeBody[turnstileTokenPayload](req)
	if deny != nil {
		return false, deny
	}
	if !r.verifyTurnstile(req.Context, strings.TrimSpace(payload.TurnstileToken)) {
		refusal := apiError(403, config.TurnstileFailedError)
		return false, &refusal
	}
	return true, nil
}

// verifyTurnstile redeems one token with Cloudflare's siteverify endpoint.
// Tokens are single-use and lapse after five minutes, so every attempt needs
// its own; the client mints a fresh one whenever a submission is refused.
//
// It fails CLOSED — a token Cloudflare will not confirm, and an outage that
// stops us asking, both come back false. That is the deliberate trade: a
// bot check an attacker could switch off by disrupting one outbound request
// is not a bot check, and the failure it costs is a sign-in someone retries,
// not data lost. It is also the loud failure of the two, which is what a
// disabled security control should be.
//
// remoteip is deliberately not sent. It is optional, Cloudflare validates it
// against the address the challenge was solved from, and the one thing worse
// than a missing signal here is a proxy chain that reports a different address
// than the browser used and locks every legitimate user out of sign-in.
func (r *Runtime) verifyTurnstile(ctx context.Context, token string) bool {
	if token == "" {
		return false
	}
	_, secretKey := r.turnstileKeys()

	form := url.Values{}
	form.Set("secret", secretKey)
	form.Set("response", token)

	httpReq, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, config.TurnstileVerifyURL, strings.NewReader(form.Encode()))
	if reqErr != nil {
		r.Log.Error("turnstile: build siteverify request", zap.Error(reqErr))
		return false
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, doErr := turnstileHTTPClient.Do(httpReq)
	if doErr != nil {
		r.Log.Error("turnstile: siteverify unreachable; refusing the request", zap.Error(doErr))
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	var verdict struct {
		Success    bool     `json:"success"`
		ErrorCodes []string `json:"error-codes"`
	}
	if decodeErr := json.NewDecoder(resp.Body).Decode(&verdict); decodeErr != nil {
		r.Log.Error("turnstile: malformed siteverify response",
			zap.Int("status", resp.StatusCode),
			zap.Error(decodeErr),
		)
		return false
	}
	if !verdict.Success {
		// Info, not warn: a lapsed or already-spent token is the ordinary
		// cost of a form left open, and a bot hitting the wall is the layer
		// working. The codes are Cloudflare's, and they are what distinguishes
		// "invalid-input-secret" (our misconfiguration) from the rest.
		r.Log.Info("turnstile: challenge refused", zap.Strings("error_codes", verdict.ErrorCodes))
		return false
	}
	return true
}
