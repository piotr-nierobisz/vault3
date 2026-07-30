package runtime

import (
	"database/sql"
	"errors"
	"strings"

	"vault3/internal/crypto"
	"vault3/internal/database"

	bungo "github.com/piotr-nierobisz/BunGo"
	"go.uber.org/zap"
)

// /verify-email: redeems the emailed single-use token (?token=…) or, without
// one, requests a fresh verification link. The verify API is authenticated
// by the token it redeems; the resend API is a public form behind the auth
// throttle.

// VerifyEmailPage renders the redeem/resend view. The token (if any) rides
// in the query string; the client posts it to the verify API.
func (r *Runtime) VerifyEmailPage(req *bungo.Request) (map[string]any, error) {
	return r.PageData(map[string]any{
		"PageTitle": "Verify your email | Vault3",
		"Token":     req.Params["token"],
		"NoIndex":   true,
	}), nil
}

// VerifyEmailAPI handles POST /api/v1/auth/verify-email {token}. Single-use:
// redemption clears the token in the same statement that flips the flag.
func (r *Runtime) VerifyEmailAPI(req *bungo.Request) (bungo.APIResponse, error) {
	payload, deny := decodeBody[tokenPayload](req)
	if deny != nil {
		return *deny, nil
	}
	token := strings.TrimSpace(payload.Token)
	if token == "" {
		return apiError(400, "Verification token is required."), nil
	}

	userID, redeemErr := database.RedeemEmailVerificationToken(req.Context, r.GetDb(), &r.Builder, crypto.HashToken(token))
	if redeemErr != nil {
		if errors.Is(redeemErr, sql.ErrNoRows) {
			return apiError(400, "This verification link is invalid or has expired. Request a new one below."), nil
		}
		return bungo.APIResponse{}, redeemErr
	}

	r.audit(req, userID, "email_verified", "user", userID, "")
	r.Log.Info("email verified", zap.String("user_id", userID))
	return bungo.APIResponse{StatusCode: 200, Body: map[string]any{"verified": true}}, nil
}

// ResendVerificationAPI handles POST /api/v1/auth/resend-verification
// {email}. Always answers 200 with the same body so it cannot be used to
// probe which addresses hold accounts; a link is actually sent only when an
// unverified account exists.
func (r *Runtime) ResendVerificationAPI(req *bungo.Request) (bungo.APIResponse, error) {
	payload, deny := decodeBody[emailPayload](req)
	if deny != nil {
		return *deny, nil
	}
	email := strings.ToLower(strings.TrimSpace(payload.Email))
	neutral := bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]any{"message": "If an unverified account exists for that address, a new link is on its way."},
	}
	if email == "" {
		return neutral, nil
	}

	user, lookupErr := database.SelectUserFullByKeyValue(req.Context, r.GetDb(), &r.Builder, r.Cipher, "email", email)
	if lookupErr != nil {
		if !errors.Is(lookupErr, sql.ErrNoRows) {
			r.Log.Error("resend verification: lookup failed", zap.Error(lookupErr))
		}
		return neutral, nil
	}
	if user.Auth == nil || user.Auth.EmailVerified {
		return neutral, nil
	}

	r.sendVerificationEmail(req.Context, req, user.ID)
	return neutral, nil
}
