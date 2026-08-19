package runtime

import (
	"context"
	"strings"

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
//
// The round-trip itself lives in internal/integrations/turnstile.go, which
// holds the key pair and the endpoint. What stays here is the policy: which
// requests are challenged, what a refusal says, and what an outage means.

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

// verifyTurnstile redeems one token and decides what the answer means.
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
// The Verify call returns an error rather than folding an outage into a
// false, so that trade is made here, in the open, instead of inside a vendor
// client.
func (r *Runtime) verifyTurnstile(ctx context.Context, token string) bool {
	if token == "" {
		return false
	}

	verdict, verifyErr := r.Integrations.Turnstile.Verify(ctx, token)
	if verifyErr != nil {
		r.Log.Error("turnstile: verification failed; refusing the request", zap.Error(verifyErr))
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
