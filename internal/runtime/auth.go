package runtime

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"vault3/internal/config"
	"vault3/internal/crypto"
	"vault3/internal/database"
	"vault3/internal/models"
	"vault3/internal/view"

	bungo "github.com/piotr-nierobisz/BunGo"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
)

// RequireAuth is the security-layer handler that gates pages and APIs behind
// a valid session. It validates the cookie, loads the full user view through
// the canonical database helper, and stashes both the session and the user
// into req.Internal so downstream layers and handlers can pull them without
// re-querying.
//
// A rejection is shaped to the caller (see authChallenge): a browser
// navigating to a page is bounced to /login, while a fetch() from the app
// gets the JSON 401 its error handling already understands.
func (r *Runtime) RequireAuth(req *bungo.Request) (bool, *bungo.APIResponse) {
	session, user := r.resolveSession(req)
	if user == nil {
		return false, authChallenge(req)
	}

	req.Internal[config.SessionInternalKey] = session
	req.Internal[config.UserInternalKey] = user

	if touchErr := database.TouchSessionLastSeen(req.Context, r.GetDb(), &r.Builder, session.ID); touchErr != nil {
		r.Log.Warn("require_auth: touch last seen failed", zap.Error(touchErr))
	}
	return true, nil
}

// isDocumentRequest reports whether the request is a browser navigating to a
// page, as opposed to a script calling the API. Sec-Fetch-Dest is the precise
// signal and every engine this app supports sends it; the Accept sniff is the
// fallback for a client that does not, and errs toward the JSON answer, which
// is the safe way to be wrong — a stray redirect inside fetch() is followed
// silently and surfaces as an HTML body where JSON was expected, whereas an
// unexpected 401 on a navigation is at least legible.
func isDocumentRequest(req *bungo.Request) bool {
	if dest := req.Headers["Sec-Fetch-Dest"]; dest != "" {
		return dest == "document"
	}
	return strings.Contains(req.Headers["Accept"], "text/html")
}

// authChallenge builds the rejection an unauthenticated caller receives.
// Browsers land on /login; API callers get the standard {"message": …} 401.
//
// The redirect carries no return path. Every authenticated surface in this app
// is behind the client-side unlock ceremony anyway, so a signed-in visitor
// resumes at the vault rather than the URL they were refused — and a
// ?next= parameter is an open-redirect footgun that would have to be
// validated on the way back out for no gain here.
func authChallenge(req *bungo.Request) *bungo.APIResponse {
	if isDocumentRequest(req) {
		return &bungo.APIResponse{
			StatusCode: 302,
			Headers:    map[string]string{"Location": config.LoginPath},
		}
	}
	return &bungo.APIResponse{
		StatusCode: 401,
		Body:       map[string]string{"message": config.SessionExpiredError},
	}
}

// OptionalAuth is the security-layer handler for otherwise public pages that
// should adapt when the visitor happens to be signed in (the legal and
// security pages render the app header instead of the marketing one). It
// loads the session + user into req.Internal when a valid cookie is present
// but always returns true, so anonymous visitors are never rejected. Unlike
// require_auth it does not touch the session's last-seen: a public page view
// is not meaningful app activity. Chain load_viewer after it.
func (r *Runtime) OptionalAuth(req *bungo.Request) (bool, *bungo.APIResponse) {
	session, user := r.resolveSession(req)
	if user != nil {
		req.Internal[config.SessionInternalKey] = session
		req.Internal[config.UserInternalKey] = user
	}
	return true, nil
}

// RequireAdmin is the security-layer handler gating the management console.
// It reads the vault3_admin spoke that require_auth already loaded, so it
// costs no query and cannot disagree with view.UserSummary.IsAdmin.
//
// Chain it AFTER require_auth: on its own it would reject every request,
// because an anonymous one has no user to check.
//
// A signed-in non-admin is answered 404, not 403 — the console's existence is
// not something a curious account should be able to confirm by the status code
// it gets back. That used to be a happy accident of BunGo only being able to
// say 401; now that unmatched paths render a real 404 (bungo.NotFoundPath), 401
// would be the tell instead, because a nonexistent path answers differently.
// So the refusal is stated deliberately, and it matches what probing
// /app/no-such-thing returns.
func (r *Runtime) RequireAdmin(req *bungo.Request) (bool, *bungo.APIResponse) {
	user := CurrentUser(req)
	if user == nil || user.Admin == nil {
		return false, notFoundChallenge(req)
	}
	return true, nil
}

// notFoundChallenge is the "this path does not exist" answer, shaped to the
// caller the same way authChallenge is. Its job is to be indistinguishable
// from what an unregistered path returns.
func notFoundChallenge(req *bungo.Request) *bungo.APIResponse {
	if isDocumentRequest(req) {
		return &bungo.APIResponse{
			StatusCode: 404,
			Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
			Body:       nil,
		}
	}
	return &bungo.APIResponse{
		StatusCode: 404,
		Body:       map[string]string{"message": "Not Found"},
	}
}

// resolveSession validates the request's session cookie and loads the active
// user behind it, returning nil, nil when there is no cookie, the session or
// user cannot be found, or the account is inactive/archived. It performs no
// writes and stashes nothing in req.Internal; callers decide whether a
// missing user is fatal (require_auth) or fine (optional_auth).
func (r *Runtime) resolveSession(req *bungo.Request) (*models.Session, *models.UserFull) {
	token := r.readSessionCookie(req)
	if token == "" {
		return nil, nil
	}

	session, sessionErr := database.SelectSessionByTokenHash(req.Context, r.GetDb(), &r.Builder, r.Cipher, crypto.HashToken(token))
	if sessionErr != nil {
		if !errors.Is(sessionErr, sql.ErrNoRows) {
			r.Log.Error("resolve session: lookup session", zap.Error(sessionErr))
		}
		return nil, nil
	}
	if session.UserID == "" {
		return nil, nil
	}

	user, userErr := database.SelectUserFullByKeyValue(req.Context, r.GetDb(), &r.Builder, r.Cipher, "id", session.UserID)
	if userErr != nil {
		if !errors.Is(userErr, sql.ErrNoRows) {
			r.Log.Error("resolve session: load user", zap.Error(userErr))
		}
		return nil, nil
	}
	if !user.IsActive || user.ArchivedAt != nil {
		return nil, nil
	}

	return session, user
}

// AuthParamsAPI handles POST /api/v1/auth/params: the pre-login exchange
// that hands the browser the KDF salt and iteration count it needs to derive
// keys for this email. For an unknown email it returns deterministic decoy
// parameters (an HMAC of the address under the server key) so the response
// shape and timing never reveal whether an account exists.
func (r *Runtime) AuthParamsAPI(req *bungo.Request) (bungo.APIResponse, error) {
	payload, deny := decodeBody[emailPayload](req)
	if deny != nil {
		return *deny, nil
	}
	email := strings.ToLower(strings.TrimSpace(payload.Email))
	if email == "" {
		return apiError(400, "Email is required."), nil
	}

	salt, costs, lookupErr := database.SelectKdfParamsByEmail(req.Context, r.GetDb(), &r.Builder, email)
	if lookupErr != nil {
		if !errors.Is(lookupErr, sql.ErrNoRows) {
			r.Log.Error("auth params: lookup failed", zap.Error(lookupErr))
		}
		// Decoys must be the *current defaults*, not anything distinctive: an
		// unknown address has to look exactly like an account registered
		// today, or the response itself answers the question this endpoint
		// exists to refuse.
		salt = r.decoyKdfSalt(email)
		costs = defaultKdfCosts()
	}

	return bungo.APIResponse{
		StatusCode: 200,
		Body: map[string]any{
			"kdfSalt":         salt,
			"kdfIterations":   costs.KdfIterations,
			"argon2MemoryKiB": costs.Argon2MemoryKiB,
			"argon2Time":      costs.Argon2Time,
			"argon2Lanes":     costs.Argon2Lanes,
		},
	}, nil
}

// decoyKdfSalt derives a stable fake salt for an unknown email so repeated
// probes see consistent, plausible parameters.
func (r *Runtime) decoyKdfSalt(email string) string {
	digest := r.Cipher.Blind("kdf-salt-decoy:" + email)
	raw, decodeErr := hex.DecodeString(digest)
	if decodeErr != nil || len(raw) < config.KdfSaltBytes {
		return base64.RawURLEncoding.EncodeToString([]byte(digest)[:config.KdfSaltBytes])
	}
	return base64.RawURLEncoding.EncodeToString(raw[:config.KdfSaltBytes])
}

type loginPayload struct {
	Email   string `json:"email"`
	AuthKey string `json:"authKey"`
	Code    string `json:"code"`
}

// LoginAPI handles POST /api/v1/auth/login. The client has already run the
// two-secret derivation locally and sends only the derived auth key — never
// the Master Password or Secret Key. On any failure (missing user, missing
// hash, mismatched auth key) it returns the same generic 401 so attackers
// cannot enumerate accounts.
func (r *Runtime) LoginAPI(req *bungo.Request) (bungo.APIResponse, error) {
	payload, deny := decodeBody[loginPayload](req)
	if deny != nil {
		return *deny, nil
	}

	email := strings.ToLower(strings.TrimSpace(payload.Email))
	authKey := strings.TrimSpace(payload.AuthKey)
	if email == "" || len(authKey) != config.AuthKeyEncodedLength {
		return apiError(401, config.GenericLoginError), nil
	}

	userID, authKeyHash, lookupErr := database.SelectUserAuthKeyHash(req.Context, r.GetDb(), &r.Builder, email)
	if lookupErr != nil {
		if !errors.Is(lookupErr, sql.ErrNoRows) {
			r.Log.Error("login: lookup user", zap.Error(lookupErr))
		}
		return apiError(401, config.GenericLoginError), nil
	}
	if authKeyHash == "" {
		r.Log.Warn("login: user has no auth key hash", zap.String("user_id", userID))
		return apiError(401, config.GenericLoginError), nil
	}
	if !crypto.CompareAuthKey(authKeyHash, authKey) {
		r.audit(req, userID, "login_failed", "", "", "")
		return apiError(401, config.GenericLoginError), nil
	}

	auth, authErr := database.SelectUserAuthRow(req.Context, r.GetDb(), &r.Builder, userID)
	if authErr != nil {
		r.Log.Error("login: load auth row", zap.String("user_id", userID), zap.Error(authErr))
		return apiError(401, config.GenericLoginError), nil
	}

	// Unverified accounts are refused only when the platform requires it
	// (off in dev, where no email can be sent). Checked after the auth key
	// holds, so the block never leaks whether an email is registered; the
	// emailNotVerified flag lets the login page offer a resend.
	if r.EmailVerificationRequired(req.Context) && !auth.EmailVerified {
		r.Log.Info("login refused: email not verified", zap.String("user_id", userID))
		return bungo.APIResponse{
			StatusCode: 403,
			Body: map[string]any{
				"emailNotVerified": true,
				"message":          "Please verify your email address before signing in. Check your inbox for a verification email.",
			},
		}, nil
	}

	// Two-factor challenge. When the account has an enrolled TOTP secret the
	// auth key alone is not enough: the client is told a code is required
	// and, once it sends one, it is validated before any session is created.
	if auth.TwoFactorEnabled() {
		secret, secretErr := r.Cipher.DecryptString(auth.TwoFactorSecretEnc)
		if secretErr != nil {
			r.Log.Error("login: decrypt 2fa secret", zap.String("user_id", userID), zap.Error(secretErr))
			return apiError(401, config.GenericLoginError), nil
		}
		code := strings.TrimSpace(payload.Code)
		if code == "" {
			return bungo.APIResponse{
				StatusCode: 200,
				Body:       map[string]any{"twoFactorRequired": true},
			}, nil
		}
		if !totp.Validate(code, secret) {
			r.Log.Warn("login: invalid 2fa code", zap.String("user_id", userID))
			r.audit(req, userID, "login_2fa_failed", "", "", "")
			return bungo.APIResponse{
				StatusCode: 401,
				Body:       map[string]any{"twoFactorRequired": true, "message": "That code wasn't right. Please try again."},
			}, nil
		}
	}

	// New-device check must run before this login's own session appears.
	ip := ClientIP(req)
	seenIP, seenErr := database.UserHasSessionFromIP(req.Context, r.GetDb(), &r.Builder, r.Cipher, userID, ip)
	if seenErr != nil {
		r.Log.Warn("login: new device check failed", zap.Error(seenErr))
		seenIP = true // fail quiet: better to miss one alert than false-alarm every login
	}

	session, cookie, sessionErr := r.createSession(req, userID)
	if sessionErr != nil {
		return bungo.APIResponse{}, sessionErr
	}
	if touchErr := database.MarkUserLoggedIn(req.Context, r.GetDb(), &r.Builder, userID); touchErr != nil {
		r.Log.Warn("login: mark user logged in failed", zap.Error(touchErr))
	}

	r.audit(req, userID, "login_succeeded", "session", session.ID, "")
	r.Log.Info("login succeeded", zap.String("user_id", userID))

	if !seenIP && ip != "" {
		if notifyErr := r.Notify(req.Context, &NewDeviceLogin{
			UserID:    userID,
			IPAddress: ip,
			UserAgent: req.Headers["User-Agent"],
			At:        time.Now(),
		}); notifyErr != nil {
			r.Log.Warn("login: new device notification failed", zap.Error(notifyErr))
		}
	}

	return bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]any{"redirectTo": config.DefaultPostLoginRedirect},
		Cookies:    []bungo.Cookie{cookie},
	}, nil
}

// createSession mints an opaque token, persists its hash, and returns the
// session row plus the Set-Cookie for the response. Shared by login and
// registration.
func (r *Runtime) createSession(req *bungo.Request, userID string) (*models.Session, bungo.Cookie, error) {
	token, tokenHash, tokenErr := crypto.NewToken()
	if tokenErr != nil {
		return nil, bungo.Cookie{}, fmt.Errorf("generate session token: %w", tokenErr)
	}
	expires := time.Now().Add(config.SessionTTL)
	session := &models.Session{
		ID:        newUUID(),
		TokenHash: tokenHash,
		UserID:    userID,
		IPAddress: ClientIP(req),
		UserAgent: req.Headers["User-Agent"],
		ExpiresAt: expires,
	}
	if insertErr := database.InsertSession(req.Context, r.GetDb(), &r.Builder, r.Cipher, session); insertErr != nil {
		return nil, bungo.Cookie{}, fmt.Errorf("persist session: %w", insertErr)
	}
	return session, r.sessionCookie(token, expires), nil
}

// LogoutAPI handles POST /api/v1/auth/logout. It deletes the session row (if
// any) and emits a Set-Cookie that clears the cookie. Always returns 200 so
// callers can treat logout as idempotent. The client clears its key store
// before calling this — locking never depends on the network.
func (r *Runtime) LogoutAPI(req *bungo.Request) (bungo.APIResponse, error) {
	if token := r.readSessionCookie(req); token != "" {
		if delErr := database.DeleteSessionByTokenHash(req.Context, r.GetDb(), &r.Builder, crypto.HashToken(token)); delErr != nil {
			r.Log.Warn("logout: delete session failed", zap.Error(delErr))
		}
	}
	return bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]any{"ok": true},
		Cookies:    []bungo.Cookie{r.clearSessionCookie()},
	}, nil
}

// SyncRevisionAPI handles GET /api/v1/sync/revision: the polling/reconnect
// fallback for the change-signal socket (ChangeSignalPath). Returns the user's
// current revision.
func (r *Runtime) SyncRevisionAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	revision, revisionErr := database.SelectUserRevision(req.Context, r.GetDb(), &r.Builder, user.ID)
	if revisionErr != nil {
		return bungo.APIResponse{}, revisionErr
	}
	return bungo.APIResponse{StatusCode: 200, Body: map[string]any{"revision": revision}}, nil
}

// sessionCookieName is the cookie this deployment issues and reads. Production
// earns the browser-enforced __Host- prefix; dev, served over plain HTTP,
// cannot set Secure and so must use the bare name.
func (r *Runtime) sessionCookieName() string {
	if r.Config.MustBool("PRODUCTION_BOOL") {
		return config.SessionCookieNameSecure
	}
	return config.SessionCookieName
}

// sessionCookie builds the Set-Cookie payload for a fresh login. Secure is
// flipped on in production so the cookie never travels over plain HTTP — and
// the __Host- prefix the production name carries is only honoured by browsers
// together with Secure and Path=/, both set here.
func (r *Runtime) sessionCookie(token string, expires time.Time) bungo.Cookie {
	production := r.Config.MustBool("PRODUCTION_BOOL")
	return bungo.Cookie{
		Name:     r.sessionCookieName(),
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   production,
		SameSite: bungo.SameSiteLax,
	}
}

// clearSessionCookie returns a Set-Cookie that drops the session cookie on
// the client (MaxAge < 0 instructs the engine to delete it). The attributes
// must mirror the ones it was set with, or a __Host- cookie will not match.
func (r *Runtime) clearSessionCookie() bungo.Cookie {
	production := r.Config.MustBool("PRODUCTION_BOOL")
	return bungo.Cookie{
		Name:     r.sessionCookieName(),
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   production,
		SameSite: bungo.SameSiteLax,
	}
}

// readSessionCookie extracts this deployment's session cookie value from the
// incoming request. Returns "" when no cookie is present.
func (r *Runtime) readSessionCookie(req *bungo.Request) string {
	raw := req.Headers["Cookie"]
	if raw == "" {
		return ""
	}
	wanted := r.sessionCookieName()
	for _, pair := range strings.Split(raw, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok {
			continue
		}
		if name == wanted {
			return value
		}
	}
	return ""
}

// CurrentUser pulls the hydrated UserFull that RequireAuth stashed in
// req.Internal. Returns nil when the request has not passed through
// require_auth (i.e. the route is public).
func CurrentUser(req *bungo.Request) *models.UserFull {
	v, ok := req.Internal[config.UserInternalKey]
	if !ok {
		return nil
	}
	u, _ := v.(*models.UserFull)
	return u
}

// CurrentSession pulls the *models.Session that RequireAuth stashed in
// req.Internal. Returns nil when the route did not run require_auth.
// Handlers use it to identify "this device" in the active-sessions list and
// to keep the current session alive when revoking the others.
func CurrentSession(req *bungo.Request) *models.Session {
	v, ok := req.Internal[config.SessionInternalKey]
	if !ok {
		return nil
	}
	s, _ := v.(*models.Session)
	return s
}

// LoadViewer is the security-layer handler that builds the display-oriented
// view.UserSummary from the authenticated user and stashes it in
// req.Internal, so handlers call Viewer(req) instead of rebuilding the
// summary per request. Chain it after require_auth (or optional_auth) — it
// always returns true, because a nil summary is a valid state the handler
// renders its own branch for.
func (r *Runtime) LoadViewer(req *bungo.Request) (bool, *bungo.APIResponse) {
	req.Internal[config.ViewerInternalKey] = view.NewUserSummary(CurrentUser(req))
	return true, nil
}

// Viewer returns the view.UserSummary the load_viewer layer stashed. As a
// fallback it builds the summary on demand (nil for anonymous requests), so
// a handler on a route that omits the layer still works.
func (r *Runtime) Viewer(req *bungo.Request) *view.UserSummary {
	if v, ok := req.Internal[config.ViewerInternalKey]; ok {
		summary, _ := v.(*view.UserSummary)
		return summary
	}
	return view.NewUserSummary(CurrentUser(req))
}
