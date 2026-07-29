package runtime

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"strings"
	"time"

	"vault3/internal/config"
	"vault3/internal/database"
	"vault3/internal/models"
	"vault3/internal/view"

	bungo "github.com/piotr-nierobisz/BunGo"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// /app/settings: profile, security (Master Password change, 2FA, sessions),
// notification preferences, and the danger zone. The Master Password change
// is the one flow where client crypto and server state must move together:
// the browser derives a fresh auth key and re-wraps every key it holds, and
// the server applies the whole set in one transaction.

// sessionRow is the client-facing shape of one active session.
type sessionRow struct {
	ID         string    `json:"id"`
	IPAddress  string    `json:"ipAddress"`
	UserAgent  string    `json:"userAgent"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	Current    bool      `json:"current"`
}

// SettingsPage renders /app/settings.
func (r *Runtime) SettingsPage(req *bungo.Request) (map[string]any, error) {
	user := CurrentUser(req)
	current := CurrentSession(req)

	sessions, sessionsErr := database.SelectUserSessions(req.Context, r.GetDb(), &r.Builder, r.Cipher, user.ID)
	if sessionsErr != nil {
		return nil, sessionsErr
	}
	rows := make([]sessionRow, 0, len(sessions))
	for _, s := range sessions {
		rows = append(rows, sessionRow{
			ID:         s.ID,
			IPAddress:  s.IPAddress,
			UserAgent:  s.UserAgent,
			CreatedAt:  s.CreatedAt,
			LastSeenAt: s.LastSeenAt,
			Current:    current != nil && current.ID == s.ID,
		})
	}

	return r.PageData(map[string]any{
		"PageTitle":        "Settings | Vault3",
		"Viewer":           r.Viewer(req),
		"ActiveNav":        "settings",
		"NoIndex":          true,
		"Sessions":         rows,
		"Prefs":            models.DecodeNotificationPrefs(user.NotificationPrefs),
		"TwoFactorEnabled": user.Auth.TwoFactorEnabled(),
		"EmailVerified":    user.Auth != nil && user.Auth.EmailVerified,
		"KdfIterations":    config.KdfDefaultIterations,
		"Keyset":           view.NewKeyset(user),
		"Revision":         user.Revision,
	}), nil
}

// UpdateProfileAPI handles POST /api/v1/account/profile {displayName}.
func (r *Runtime) UpdateProfileAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	var payload struct {
		DisplayName string `json:"displayName"`
	}
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	displayName := strings.TrimSpace(payload.DisplayName)
	if len(displayName) > 100 {
		return apiError(400, "Name is too long."), nil
	}

	var revision int64
	transactionErr := WithTransaction(r, req.Context, func(txRt *Runtime) error {
		if updateErr := database.UpdateUserDisplayName(req.Context, txRt.GetDb(), &txRt.Builder, txRt.Cipher, user.ID, displayName); updateErr != nil {
			return updateErr
		}
		var bumpErr error
		revision, bumpErr = SignalUserChanged(req.Context, txRt, user.ID)
		return bumpErr
	})
	if transactionErr != nil {
		return bungo.APIResponse{}, transactionErr
	}

	r.PublishChange(req, user.ID, revision)
	r.audit(req, user.ID, "profile_updated", "user", user.ID, "")
	return bungo.APIResponse{StatusCode: 200, Body: map[string]any{"saved": true}}, nil
}

// UpdateNotificationPrefsAPI handles POST /api/v1/account/notifications with
// the canonical models.NotificationPrefs shape.
func (r *Runtime) UpdateNotificationPrefsAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	var prefs models.NotificationPrefs
	if unmarshalErr := json.Unmarshal(req.Body, &prefs); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	encoded, marshalErr := json.Marshal(prefs)
	if marshalErr != nil {
		return bungo.APIResponse{}, fmt.Errorf("encode notification prefs: %w", marshalErr)
	}
	if updateErr := database.UpdateUserNotificationPrefs(req.Context, r.GetDb(), &r.Builder, user.ID, encoded); updateErr != nil {
		return bungo.APIResponse{}, updateErr
	}
	return bungo.APIResponse{StatusCode: 200, Body: map[string]any{"saved": true}}, nil
}

type changePasswordPayload struct {
	CurrentAuthKey string          `json:"currentAuthKey"`
	NewAuthKey     string          `json:"newAuthKey"`
	NewKdfSalt     string          `json:"newKdfSalt"`
	NewKdfIters    int             `json:"newKdfIterations"`
	EncPrivateKey  json.RawMessage `json:"encPrivateKey"`
	Vaults         []struct {
		VaultID    string          `json:"vaultId"`
		WrappedKey json.RawMessage `json:"wrappedKey"`
	} `json:"vaults"`
}

// ChangePasswordAPI handles POST /api/v1/account/password. The Secret Phrase
// stays the same; the browser derives the new MUK, re-wraps every vault key
// and the private key, and sends the whole set. Applied atomically, then
// every other session is revoked.
func (r *Runtime) ChangePasswordAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	session := CurrentSession(req)
	var payload changePasswordPayload
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}

	// Re-authenticate with the current auth key before anything changes.
	if compareErr := bcrypt.CompareHashAndPassword([]byte(user.Auth.AuthKeyHash), []byte(payload.CurrentAuthKey)); compareErr != nil {
		return apiError(401, "Your current Master Password wasn't right."), nil
	}
	if len(payload.NewAuthKey) != config.AuthKeyEncodedLength {
		return apiError(400, "Malformed new credentials."), nil
	}
	if payload.NewKdfIters < config.KdfMinIterations {
		return apiError(400, "KDF iteration count below the platform floor."), nil
	}
	if envErr := models.ValidateCipherEnvelope(payload.EncPrivateKey, 8*1024); envErr != nil {
		return apiError(400, "Malformed private key envelope."), nil
	}
	if len(payload.Vaults) != len(user.Vaults) {
		return apiError(400, "Re-wrapped key set does not cover every vault."), nil
	}
	for _, v := range payload.Vaults {
		if envErr := models.ValidateCipherEnvelope(v.WrappedKey, 1024); envErr != nil {
			return apiError(400, "Malformed vault key envelope."), nil
		}
	}

	newHash, hashErr := hashAuthKey(payload.NewAuthKey)
	if hashErr != nil {
		return bungo.APIResponse{}, hashErr
	}

	var revision int64
	transactionErr := WithTransaction(r, req.Context, func(txRt *Runtime) error {
		if credErr := database.UpdateUserAuthCredentials(req.Context, txRt.GetDb(), &txRt.Builder,
			user.ID, newHash, payload.NewKdfSalt, payload.NewKdfIters); credErr != nil {
			return credErr
		}
		if keyErr := database.UpdateEncPrivateKey(req.Context, txRt.GetDb(), &txRt.Builder, user.ID, payload.EncPrivateKey); keyErr != nil {
			return keyErr
		}
		for _, v := range payload.Vaults {
			if wrapErr := database.UpdateVaultAccessWrappedKey(req.Context, txRt.GetDb(), &txRt.Builder,
				user.ID, v.VaultID, v.WrappedKey); wrapErr != nil {
				return wrapErr
			}
		}
		if revokeErr := database.DeleteOtherUserSessions(req.Context, txRt.GetDb(), &txRt.Builder, user.ID, session.ID); revokeErr != nil {
			return revokeErr
		}
		var bumpErr error
		revision, bumpErr = SignalUserChanged(req.Context, txRt, user.ID)
		return bumpErr
	})
	if transactionErr != nil {
		return bungo.APIResponse{}, transactionErr
	}

	r.PublishChange(req, user.ID, revision)
	r.audit(req, user.ID, "password_changed", "user", user.ID, "")
	if notifyErr := r.Notify(req.Context, &PasswordChanged{UserID: user.ID}); notifyErr != nil {
		r.Log.Warn("password change: notification failed", zap.Error(notifyErr))
	}
	return bungo.APIResponse{StatusCode: 200, Body: map[string]any{"changed": true}}, nil
}

// TwoFactorSetupAPI handles POST /api/v1/account/2fa/setup: mints a TOTP
// secret, stashes it pending (encrypted at rest), and returns the otpauth URL
// plus a scannable QR of it. Verification promotes it.
//
// This secret is *account* 2FA, not vault data: the server mints it and must
// keep reading it to validate codes at sign-in, so it lives under FieldCipher
// (see docs/security.md). The QR encodes the same otpauth URL already in this
// response — it exposes nothing further. Vault items store their own TOTP
// seeds, and those the server never sees; the two must not be conflated.
func (r *Runtime) TwoFactorSetupAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	key, keyErr := totp.Generate(totp.GenerateOpts{
		Issuer:      config.SITE_NAME,
		AccountName: user.Email,
	})
	if keyErr != nil {
		return bungo.APIResponse{}, fmt.Errorf("generate totp secret: %w", keyErr)
	}
	qr, qrErr := otpauthQRDataURI(key)
	if qrErr != nil {
		return bungo.APIResponse{}, qrErr
	}
	if setErr := database.SetTempTwoFactorSecret(req.Context, r.GetDb(), &r.Builder, r.Cipher, user.ID, key.Secret()); setErr != nil {
		return bungo.APIResponse{}, setErr
	}
	return bungo.APIResponse{
		StatusCode: 200,
		Body: map[string]any{
			"secret":     key.Secret(),
			"otpauthUrl": key.URL(),
			"qrDataUri":  qr,
		},
	}, nil
}

// otpauthQRDataURI renders the key's otpauth URL as a PNG data URI the
// settings page can drop straight into an <img> (the CSP allows img-src
// data:). Inlining it keeps the QR out of any cache or URL a screenshot,
// proxy or log could outlive the enrolment.
func otpauthQRDataURI(key *otp.Key) (string, error) {
	img, imgErr := key.Image(232, 232)
	if imgErr != nil {
		return "", fmt.Errorf("render totp qr: %w", imgErr)
	}
	var buf bytes.Buffer
	if encodeErr := png.Encode(&buf, img); encodeErr != nil {
		return "", fmt.Errorf("encode totp qr: %w", encodeErr)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// TwoFactorVerifyAPI handles POST /api/v1/account/2fa/verify {code}:
// validates against the pending secret and promotes it.
func (r *Runtime) TwoFactorVerifyAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	var payload struct {
		Code string `json:"code"`
	}
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	if user.Auth.TempTwoFactorSecretEnc == "" {
		return apiError(400, "No pending two-factor setup. Start again."), nil
	}
	secret, secretErr := r.Cipher.DecryptString(user.Auth.TempTwoFactorSecretEnc)
	if secretErr != nil {
		return bungo.APIResponse{}, fmt.Errorf("decrypt pending 2fa secret: %w", secretErr)
	}
	if !totp.Validate(strings.TrimSpace(payload.Code), secret) {
		return apiError(400, "That code wasn't right. Please try again."), nil
	}
	if promoteErr := database.PromoteTwoFactorSecret(req.Context, r.GetDb(), &r.Builder, user.ID); promoteErr != nil {
		return bungo.APIResponse{}, promoteErr
	}
	r.audit(req, user.ID, "two_factor_enabled", "user", user.ID, "")
	if notifyErr := r.Notify(req.Context, &TwoFactorChanged{UserID: user.ID, Enabled: true}); notifyErr != nil {
		r.Log.Warn("2fa enable: notification failed", zap.Error(notifyErr))
	}
	return bungo.APIResponse{StatusCode: 200, Body: map[string]any{"enabled": true}}, nil
}

// TwoFactorDisableAPI handles POST /api/v1/account/2fa/disable {code}: a
// valid current code is required to switch 2FA off.
func (r *Runtime) TwoFactorDisableAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	var payload struct {
		Code string `json:"code"`
	}
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	if !user.Auth.TwoFactorEnabled() {
		return apiError(400, "Two-factor authentication is not enabled."), nil
	}
	secret, secretErr := r.Cipher.DecryptString(user.Auth.TwoFactorSecretEnc)
	if secretErr != nil {
		return bungo.APIResponse{}, fmt.Errorf("decrypt 2fa secret: %w", secretErr)
	}
	if !totp.Validate(strings.TrimSpace(payload.Code), secret) {
		return apiError(400, "That code wasn't right. Please try again."), nil
	}
	if clearErr := database.ClearTwoFactorSecrets(req.Context, r.GetDb(), &r.Builder, user.ID); clearErr != nil {
		return bungo.APIResponse{}, clearErr
	}
	r.audit(req, user.ID, "two_factor_disabled", "user", user.ID, "")
	if notifyErr := r.Notify(req.Context, &TwoFactorChanged{UserID: user.ID, Enabled: false}); notifyErr != nil {
		r.Log.Warn("2fa disable: notification failed", zap.Error(notifyErr))
	}
	return bungo.APIResponse{StatusCode: 200, Body: map[string]any{"disabled": true}}, nil
}

// RevokeSessionAPI handles POST /api/v1/account/sessions/revoke {sessionId}.
// Revoking the current session is allowed (it is just a logout the hard way).
func (r *Runtime) RevokeSessionAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	var payload struct {
		SessionID string `json:"sessionId"`
	}
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	if strings.TrimSpace(payload.SessionID) == "" {
		return apiError(400, "sessionId is required."), nil
	}
	if revokeErr := database.DeleteSessionByID(req.Context, r.GetDb(), &r.Builder, user.ID, payload.SessionID); revokeErr != nil {
		return bungo.APIResponse{}, revokeErr
	}
	r.audit(req, user.ID, "session_revoked", "session", payload.SessionID, "")
	return bungo.APIResponse{StatusCode: 200, Body: map[string]any{"revoked": true}}, nil
}

// DeleteAccountAPI handles POST /api/v1/account/delete {authKey}: full
// account deletion, re-authenticated by the current auth key. Cascades
// remove vaults, items, sessions and notifications; the audit row is written
// first (user id becomes NULL after the cascade, by design).
func (r *Runtime) DeleteAccountAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	var payload struct {
		AuthKey string `json:"authKey"`
	}
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}
	if compareErr := bcrypt.CompareHashAndPassword([]byte(user.Auth.AuthKeyHash), []byte(payload.AuthKey)); compareErr != nil {
		return apiError(401, "Your Master Password wasn't right."), nil
	}

	r.audit(req, user.ID, "account_deleted", "user", user.ID, "")
	if deleteErr := database.DeleteUser(req.Context, r.GetDb(), &r.Builder, user.ID); deleteErr != nil {
		return bungo.APIResponse{}, deleteErr
	}
	r.Log.Info("account deleted", zap.String("user_id", user.ID))
	return bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]any{"deleted": true},
		Cookies:    []bungo.Cookie{r.clearSessionCookie()},
	}, nil
}
