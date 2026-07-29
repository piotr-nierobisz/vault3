package runtime

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"vault3/internal/config"
	"vault3/internal/crypto"
	"vault3/internal/database"
	"vault3/internal/models"

	bungo "github.com/piotr-nierobisz/BunGo"
	"go.uber.org/zap"
)

// /recover: the zero-knowledge answer to "I forgot my Master Password".
// There is no password reset that preserves data — the server holds only
// ciphertext — so recovery is an explicit, emailed, single-use ACCOUNT RESET
// that erases the vault and restarts the account's cryptography. The page
// says exactly that before anyone clicks anything.

// RecoverPage renders the request/confirm view; ?token= switches it to the
// confirm branch where the destructive re-onboarding happens.
func (r *Runtime) RecoverPage(req *bungo.Request) (map[string]any, error) {
	return r.PageData(map[string]any{
		"PageTitle":     "Recover your account | Vault3",
		"Token":         req.Params["token"],
		"KdfIterations": config.KdfDefaultIterations,
		"NoIndex":       true,
	}), nil
}

// RecoverRequestAPI handles POST /api/v1/auth/recover/request {email}.
// Neutral response regardless of account existence.
func (r *Runtime) RecoverRequestAPI(req *bungo.Request) (bungo.APIResponse, error) {
	var payload struct {
		Email string `json:"email"`
	}
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	email := strings.ToLower(strings.TrimSpace(payload.Email))
	neutral := bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]any{"message": "If an account exists for that address, a reset link is on its way."},
	}
	if email == "" {
		return neutral, nil
	}

	userID, lookupErr := database.SelectUserIDByEmail(req.Context, r.GetDb(), &r.Builder, email)
	if lookupErr != nil {
		if !errors.Is(lookupErr, sql.ErrNoRows) {
			r.Log.Error("recover request: lookup failed", zap.Error(lookupErr))
		}
		return neutral, nil
	}

	token, tokenHash, tokenErr := crypto.NewToken()
	if tokenErr != nil {
		r.Log.Error("recover request: token generation failed", zap.Error(tokenErr))
		return neutral, nil
	}
	expiry := timeNow().Add(config.AccountResetTokenTTL)
	if setErr := database.SetAccountResetToken(req.Context, r.GetDb(), &r.Builder, userID, tokenHash, expiry); setErr != nil {
		r.Log.Error("recover request: store token failed", zap.Error(setErr))
		return neutral, nil
	}

	resetURL := config.SITE_URL + "/recover?token=" + token
	if notifyErr := r.Notify(req.Context, &AccountReset{UserID: userID, ResetURL: resetURL}); notifyErr != nil {
		r.Log.Warn("recover request: notify failed", zap.Error(notifyErr))
	}
	r.audit(req, userID, "account_reset_requested", "user", userID, "")
	return neutral, nil
}

type recoverConfirmPayload struct {
	Token string `json:"token"`
	registerPayload
}

// RecoverConfirmAPI handles POST /api/v1/auth/recover/confirm: redeems the
// emailed token, then — in one transaction — deletes every vault the user
// owns, replaces the keypair, installs the freshly derived credentials and a
// new empty personal vault, and revokes every session. The browser runs the
// same crypto onboarding as registration (new Secret Phrase included) and
// sends the same bundle plus the token.
func (r *Runtime) RecoverConfirmAPI(req *bungo.Request) (bungo.APIResponse, error) {
	var payload recoverConfirmPayload
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	token := strings.TrimSpace(payload.Token)
	if token == "" {
		return apiError(400, "Reset token is required."), nil
	}
	if fieldErr := validateRegistrationCrypto(&payload.registerPayload); fieldErr != nil {
		return apiError(400, fieldErr.Error()), nil
	}

	userID, tokenErr := database.SelectUserIDByResetTokenHash(req.Context, r.GetDb(), &r.Builder, crypto.HashToken(token))
	if tokenErr != nil {
		if errors.Is(tokenErr, sql.ErrNoRows) {
			return apiError(400, "This reset link is invalid or has expired. Request a new one."), nil
		}
		return bungo.APIResponse{}, tokenErr
	}

	authKeyHash, hashErr := hashAuthKey(payload.AuthKey)
	if hashErr != nil {
		return bungo.APIResponse{}, hashErr
	}

	vaultID := newUUID()
	transactionErr := WithTransaction(r, req.Context, func(txRt *Runtime) error {
		if wipeErr := database.DeleteUserOwnedVaults(req.Context, txRt.GetDb(), &txRt.Builder, userID); wipeErr != nil {
			return wipeErr
		}
		// Memberships in other people's vaults are wrapped under the OLD
		// key-encryption key — undecryptable after the reset, so drop them.
		if membershipErr := database.DeleteUserVaultMemberships(req.Context, txRt.GetDb(), &txRt.Builder, userID); membershipErr != nil {
			return membershipErr
		}
		if authErr := database.ResetAccountAuth(req.Context, txRt.GetDb(), &txRt.Builder, userID,
			authKeyHash, payload.KdfSalt, payload.KdfIterations); authErr != nil {
			return authErr
		}
		if keysErr := database.ReplaceUserKeys(req.Context, txRt.GetDb(), &txRt.Builder, &models.UserKeys{
			UserID:        userID,
			Algo:          payload.KeysAlgo,
			PublicKey:     payload.PublicKey,
			EncPrivateKey: payload.EncPrivateKey,
		}); keysErr != nil {
			return keysErr
		}
		if vaultErr := database.InsertVault(req.Context, txRt.GetDb(), &txRt.Builder, &models.Vault{
			ID:          vaultID,
			OwnerUserID: userID,
			Kind:        "personal",
			EncName:     payload.Vault.EncName,
		}); vaultErr != nil {
			return vaultErr
		}
		if accessErr := database.InsertVaultAccess(req.Context, txRt.GetDb(), &txRt.Builder, &models.VaultAccess{
			ID:         newUUID(),
			VaultID:    vaultID,
			UserID:     userID,
			Role:       "owner",
			WrapAlgo:   "muk",
			WrappedKey: payload.Vault.WrappedKey,
		}); accessErr != nil {
			return accessErr
		}
		// Every existing session belongs to the pre-reset credentials.
		return database.DeleteOtherUserSessions(req.Context, txRt.GetDb(), &txRt.Builder, userID, "")
	})
	if transactionErr != nil {
		return bungo.APIResponse{}, transactionErr
	}

	session, cookie, sessionErr := r.createSession(req, userID)
	if sessionErr != nil {
		return bungo.APIResponse{}, sessionErr
	}
	_ = session

	r.audit(req, userID, "account_reset_completed", "user", userID, "")
	r.Log.Info("account reset completed", zap.String("user_id", userID))

	return bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]any{"redirectTo": config.DefaultPostLoginRedirect},
		Cookies:    []bungo.Cookie{cookie},
	}, nil
}
