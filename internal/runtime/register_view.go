package runtime

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"vault3/internal/config"
	"vault3/internal/crypto"
	"vault3/internal/database"
	"vault3/internal/models"

	"github.com/google/uuid"
	bungo "github.com/piotr-nierobisz/BunGo"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// /join: the self-signup flow. The browser does all the cryptography before
// this API is ever called — generates the Secret Phrase, derives the auth
// key, creates the keypair and the personal vault key — so registration
// arrives as one bundle of public parameters and ciphertext. The server
// verifies shape, hashes the auth key, and persists everything in one
// transaction.

var emailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// timeNow indirection keeps token expiries stubbable in tests.
var timeNow = time.Now

// newUUID returns a fresh UUIDv7 string; generation cannot realistically
// fail (it panics only if the OS entropy source is broken, which no request
// should limp past).
func newUUID() string {
	return uuid.Must(uuid.NewV7()).String()
}

// hashAuthKey bcrypts the client-derived auth key for storage.
func hashAuthKey(authKey string) (string, error) {
	hash, hashErr := bcrypt.GenerateFromPassword([]byte(authKey), bcrypt.DefaultCost)
	if hashErr != nil {
		return "", fmt.Errorf("hash auth key: %w", hashErr)
	}
	return string(hash), nil
}

// JoinPage renders the registration wizard. The page itself is public; the
// register API re-checks the platform gate, and the page passes the gate
// state so the view can show a closed notice instead of a dead form.
func (r *Runtime) JoinPage(req *bungo.Request) (map[string]any, error) {
	return r.PageData(map[string]any{
		"PageTitle":        "Create your vault | Vault3",
		"PageDescription":  "Create a Vault3 account. Your Master Password and Secret Phrase never leave your device.",
		"CanonicalURL":     config.SITE_URL + "/join",
		"RegistrationOpen": r.PublicRegistrationEnabled(req.Context),
		"KdfIterations":    config.KdfDefaultIterations,
	}), nil
}

type registerPayload struct {
	Email         string          `json:"email"`
	DisplayName   string          `json:"displayName"`
	AuthKey       string          `json:"authKey"`
	KdfSalt       string          `json:"kdfSalt"`
	KdfIterations int             `json:"kdfIterations"`
	KeysAlgo      string          `json:"keysAlgo"`
	PublicKey     json.RawMessage `json:"publicKey"`
	EncPrivateKey json.RawMessage `json:"encPrivateKey"`
	Vault         struct {
		EncName    json.RawMessage `json:"encName"`
		WrappedKey json.RawMessage `json:"wrappedKey"`
	} `json:"vault"`
}

// RegisterAPI handles POST /api/v1/auth/register: validates the crypto
// bundle, creates user + auth + keypair + personal vault in one transaction,
// signs the new account in, and (best-effort, post-commit) sends the welcome
// and verification emails.
func (r *Runtime) RegisterAPI(req *bungo.Request) (bungo.APIResponse, error) {
	if !r.PublicRegistrationEnabled(req.Context) {
		return apiError(403, "Registration is currently closed."), nil
	}

	var payload registerPayload
	if unmarshalErr := json.Unmarshal(req.Body, &payload); unmarshalErr != nil {
		return apiError(400, "Invalid request body"), nil
	}

	email := strings.ToLower(strings.TrimSpace(payload.Email))
	displayName := strings.TrimSpace(payload.DisplayName)
	if !emailPattern.MatchString(email) {
		return apiFieldError(400, "Enter a valid email address.", "email"), nil
	}
	if len(displayName) > 100 {
		return apiFieldError(400, "Name is too long.", "displayName"), nil
	}
	if fieldErr := validateRegistrationCrypto(&payload); fieldErr != nil {
		return apiFieldError(400, fieldErr.Error(), "crypto"), nil
	}

	if _, takenErr := database.SelectUserIDByEmail(req.Context, r.GetDb(), &r.Builder, email); takenErr == nil {
		return apiFieldError(409, "An account with this email already exists.", "email"), nil
	} else if !errors.Is(takenErr, sql.ErrNoRows) {
		return bungo.APIResponse{}, fmt.Errorf("check email availability: %w", takenErr)
	}

	authKeyHash, hashErr := bcrypt.GenerateFromPassword([]byte(payload.AuthKey), bcrypt.DefaultCost)
	if hashErr != nil {
		return bungo.APIResponse{}, fmt.Errorf("hash auth key: %w", hashErr)
	}

	userID := uuid.Must(uuid.NewV7()).String()
	vaultID := uuid.Must(uuid.NewV7()).String()
	prefs, _ := json.Marshal(models.DefaultNotificationPrefs())

	transactionErr := WithTransaction(r, req.Context, func(txRt *Runtime) error {
		insertUserErr := database.InsertUser(req.Context, txRt.GetDb(), &txRt.Builder, txRt.Cipher, &models.User{
			ID:                userID,
			Email:             email,
			DisplayName:       displayName,
			NotificationPrefs: prefs,
			IsActive:          true,
		})
		if insertUserErr != nil {
			return insertUserErr
		}
		insertAuthErr := database.InsertUserAuth(req.Context, txRt.GetDb(), &txRt.Builder, &models.UserAuth{
			UserID:        userID,
			AuthKeyHash:   string(authKeyHash),
			KdfSalt:       payload.KdfSalt,
			KdfIterations: payload.KdfIterations,
			EmailVerified: false,
		})
		if insertAuthErr != nil {
			return insertAuthErr
		}
		insertKeysErr := database.InsertUserKeys(req.Context, txRt.GetDb(), &txRt.Builder, &models.UserKeys{
			UserID:        userID,
			Algo:          payload.KeysAlgo,
			PublicKey:     payload.PublicKey,
			EncPrivateKey: payload.EncPrivateKey,
		})
		if insertKeysErr != nil {
			return insertKeysErr
		}
		insertVaultErr := database.InsertVault(req.Context, txRt.GetDb(), &txRt.Builder, &models.Vault{
			ID:          vaultID,
			OwnerUserID: userID,
			Kind:        "personal",
			EncName:     payload.Vault.EncName,
		})
		if insertVaultErr != nil {
			return insertVaultErr
		}
		return database.InsertVaultAccess(req.Context, txRt.GetDb(), &txRt.Builder, &models.VaultAccess{
			ID:         uuid.Must(uuid.NewV7()).String(),
			VaultID:    vaultID,
			UserID:     userID,
			Role:       "owner",
			WrapAlgo:   "muk",
			WrappedKey: payload.Vault.WrappedKey,
		})
	})
	if transactionErr != nil {
		return bungo.APIResponse{}, fmt.Errorf("register account: %w", transactionErr)
	}

	session, cookie, sessionErr := r.createSession(req, userID)
	if sessionErr != nil {
		return bungo.APIResponse{}, sessionErr
	}

	r.audit(req, userID, "account_created", "user", userID, "")
	r.Log.Info("account registered", zap.String("user_id", userID))
	_ = session

	if notifyErr := r.Notify(req.Context, &Welcome{UserID: userID}); notifyErr != nil {
		r.Log.Warn("register: welcome notification failed", zap.Error(notifyErr))
	}
	r.sendVerificationEmail(req.Context, req, userID)

	return bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]any{"redirectTo": config.DefaultPostLoginRedirect},
		Cookies:    []bungo.Cookie{cookie},
	}, nil
}

// sendVerificationEmail mints a fresh single-use token and raises the
// verification event. Best-effort: a failure is logged, never surfaced —
// /verify-email can always issue another link.
func (r *Runtime) sendVerificationEmail(ctx context.Context, req *bungo.Request, userID string) {
	token, tokenHash, tokenErr := crypto.NewToken()
	if tokenErr != nil {
		r.Log.Error("verification email: token generation failed", zap.Error(tokenErr))
		return
	}
	expiry := timeNow().Add(config.EmailVerificationTokenTTL)
	if setErr := database.SetEmailVerificationToken(ctx, r.GetDb(), &r.Builder, userID, tokenHash, expiry); setErr != nil {
		r.Log.Error("verification email: store token failed", zap.Error(setErr))
		return
	}
	verifyURL := config.SITE_URL + "/verify-email?token=" + token
	if notifyErr := r.Notify(ctx, &EmailVerification{UserID: userID, VerifyURL: verifyURL}); notifyErr != nil {
		r.Log.Warn("verification email: notify failed", zap.Error(notifyErr))
	}
	_ = req
}

// validateRegistrationCrypto structurally checks the crypto bundle: KDF
// parameters within policy, auth key the exact derived length, envelopes
// well-formed, public key a plausible JWK. It cannot (by design) check any
// plaintext property.
func validateRegistrationCrypto(payload *registerPayload) error {
	if len(payload.AuthKey) != config.AuthKeyEncodedLength {
		return fmt.Errorf("malformed auth key")
	}
	salt, saltErr := base64.RawURLEncoding.DecodeString(payload.KdfSalt)
	if saltErr != nil || len(salt) != config.KdfSaltBytes {
		return fmt.Errorf("malformed KDF salt")
	}
	if payload.KdfIterations < config.KdfMinIterations {
		return fmt.Errorf("KDF iteration count below the platform floor")
	}
	if payload.KeysAlgo != "rsa-oaep-2048" {
		return fmt.Errorf("unsupported keypair algorithm")
	}
	var jwk struct {
		Kty string `json:"kty"`
	}
	if jwkErr := json.Unmarshal(payload.PublicKey, &jwk); jwkErr != nil || jwk.Kty == "" {
		return fmt.Errorf("malformed public key")
	}
	if envErr := models.ValidateCipherEnvelope(payload.EncPrivateKey, 8*1024); envErr != nil {
		return fmt.Errorf("malformed private key envelope: %w", envErr)
	}
	if envErr := models.ValidateCipherEnvelope(payload.Vault.WrappedKey, 1024); envErr != nil {
		return fmt.Errorf("malformed vault key envelope: %w", envErr)
	}
	if envErr := models.ValidateCipherEnvelope(payload.Vault.EncName, 1024); envErr != nil {
		return fmt.Errorf("malformed vault name envelope: %w", envErr)
	}
	return nil
}
