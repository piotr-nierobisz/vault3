package config

import "time"

const SELF_NAME = "Vault3"
const VERSION = "1.0.0"

// Session / authentication constants -----------------------------------
//
// Single source of truth for cookie name, lifetime, and the req.Internal
// keys that the auth security layer populates. Handlers should reference
// these rather than redeclaring string literals locally.
const (
	SessionCookieName = "vault3_session"
	// SessionCookieNameSecure is the production session cookie name. The
	// __Host- prefix is a guarantee the browser itself enforces: it refuses
	// the cookie unless it was set with Secure, Path=/ and no Domain. That
	// makes the session cookie unplantable and unoverwritable by a sibling
	// subdomain or by a network attacker on a plain-http origin — a cookie
	// this name can only have come from this exact origin over TLS. Secure
	// is impossible on the dev server's plain HTTP, hence two names.
	SessionCookieNameSecure = "__Host-vault3_session"
	SessionTTL              = 30 * 24 * time.Hour
	SessionInternalKey      = "Session"
	UserInternalKey         = "User"
	// ViewerInternalKey holds the *view.UserSummary the load_viewer security
	// layer builds from the authenticated user, so handlers read req.Internal
	// instead of rebuilding the summary per request.
	ViewerInternalKey = "Viewer"

	// GenericLoginError is returned for every failed sign-in so attackers
	// cannot distinguish "wrong password" from "wrong Secret Phrase" from "no
	// such account".
	GenericLoginError = "Those details don't match an account. Check your email, Master Password and Secret Phrase, then try again."

	// SessionExpiredError is the body of the 401 an API caller receives when
	// its session is missing or expired. The client turns this into the
	// "signed out" state rather than a generic failure banner.
	SessionExpiredError = "Your session has expired. Please sign in again."
)

// Default redirect after a successful sign-in.
const DefaultPostLoginRedirect = "/app"

// LoginPath is where the require_auth security layer sends a browser whose
// session is missing or expired. Stated once here because the redirect target
// and the route registration in cmd/vault3/main.go must not drift apart.
const LoginPath = "/login"

// JoinPath is the self-signup page. Stated here for the same reason as
// LoginPath, plus one of its own: these two paths are the only documents
// served the widened Turnstile CSP (internal/runtime/middleware.go), and a
// path that drifts from its route registration would drop the allowance on
// the floor — leaving a page that cannot load the widget it requires.
const JoinPath = "/join"

// Zero-knowledge key derivation -----------------------------------------
//
// The client derives every key in the browser (see web/lib/crypto.ts); the
// server never sees the Master Password, the Secret Phrase, or any derived
// encryption key. These constants are the server-side halves of that
// contract: the KDF parameters registration must arrive with, and the
// account-unlock values /api/v1/auth/params hands back before login.
//
// The browser runs Argon2id over PBKDF2-HMAC-SHA-512 (web/lib/crypto.ts).
// Both layers are post-quantum by construction — Grover only halves a
// preimage search, and SHA-512 leaves 256 bits after that — but they resist
// different attackers, which is why both are there rather than one:
//
//   - PBKDF2-HMAC-SHA-512 is the FIPS-approved floor, implemented natively by
//     WebCrypto. If the Argon2 wasm module were ever wrong, unavailable, or
//     substituted, the Master Password has still been through a million
//     rounds of an approved KDF.
//   - Argon2id supplies the memory-hardness PBKDF2 structurally cannot. That
//     is what prices a GPU or ASIC cracking rig out of a stolen database, and
//     it is the layer that matters against a classical attacker.
//
// Every parameter below is stored per account and echoed by
// /api/v1/auth/params, exactly as the iteration count already was, so all of
// them can be raised later without stranding an existing account.
const (
	// KdfDefaultIterations is the PBKDF2-HMAC-SHA-512 iteration count new
	// accounts register with (~330ms in a desktop browser).
	KdfDefaultIterations = 1000000
	// KdfMinIterations rejects registrations weakened below the floor. This
	// is OWASP's PBKDF2-HMAC-SHA-512 recommendation.
	KdfMinIterations = 210000
	// KdfSaltBytes is the decoded length of the per-account KDF salt.
	KdfSaltBytes = 16

	// Argon2DefaultMemoryKiB / Time / Lanes are the Argon2id costs new
	// accounts register with: 64 MiB, four passes, four lanes (~440ms in a
	// desktop browser). The memory figure deliberately matches the profile
	// browser-based password managers already ship, because it is the number
	// proven to survive a mid-range phone — a device that cannot grow wasm
	// linear memory far enough cannot unlock its own vault at all.
	Argon2DefaultMemoryKiB = 65536
	Argon2DefaultTime      = 4
	Argon2DefaultLanes     = 4
	// Argon2MinMemoryKiB / MinTime floor a weakened registration. 19 MiB at
	// two passes is OWASP's minimum Argon2id configuration.
	Argon2MinMemoryKiB = 19456
	Argon2MinTime      = 2

	// AuthKeyEncodedLength is the exact base64url length of the client-derived
	// 64-byte auth key. Anything else is rejected before hashing.
	AuthKeyEncodedLength = 86
)

// Account tokens ---------------------------------------------------------
//
// Emailed single-use tokens are stored hashed (SHA-512) and time-limited.
const (
	EmailVerificationTokenTTL = 24 * time.Hour
)

// Bot check (Cloudflare Turnstile) ---------------------------------------
//
// Sign-in and registration are the only two endpoints anyone on the internet
// can call without an account, which makes them the two worth automating:
// credential stuffing against one, mass signup against the other. Turnstile
// gates both, and nothing else — see RequireHuman in
// internal/runtime/turnstile.go and the challengedAPI() helper that attaches
// it in cmd/vault3/main.go.
//
// This is the one third party the browser talks to, and it is confined to the
// two pages that need it: the CSP allowance naming integrations.TurnstileOrigin
// is served on LoginPath and JoinPath only (internal/runtime/middleware.go),
// so /app — where a vault is actually open — still admits code from this
// origin alone.
//
// What Cloudflare owns — the siteverify endpoint, the widget origin, the
// published test key pair — lives in internal/integrations/turnstile.go with
// the client that speaks to it. What this deployment owns stays here: the
// names of the environment variables holding our key pair, and the wording a
// refused challenge shows.
const (
	// The per-deployment key pair, read only in production
	// (newIntegrations in internal/runtime/runtime.go).
	TurnstileSiteKeyEnv   = "TURNSTILE_SITE_KEY_STRING"
	TurnstileSecretKeyEnv = "TURNSTILE_SECRET_KEY_STRING"

	// TurnstileFailedError is what a rejected challenge says. It names the
	// check rather than the caller: a real person whose token lapsed while
	// the form sat open sees this too, and the fix for both is the same.
	TurnstileFailedError = "That human check didn't pass. Please try again."
)

// Email delivery (Mailgun) -----------------------------------------------
//
// The names of the credential trio, read by newIntegrations in
// internal/runtime/runtime.go. All three are deliberately absent from
// REQUIRED_ENV_VARS — see the note there — so an empty value is an ordinary
// state the delivery layer degrades through, not a startup failure.
const (
	MailgunAPIKeyEnv    = "MAILGUN_API_KEY_STRING"
	MailgunDomainEnv    = "MAILGUN_DOMAIN_STRING"
	MailgunFromEmailEnv = "MAILGUN_FROM_EMAIL_STRING"
)

// Platform settings (vault3_platform_setting keys) -----------------------
//
// Read/write only through the (*Runtime) accessors in
// internal/runtime/platform_setting.go; they fail safe on missing rows.
const (
	// PublicRegistrationSettingKey gates the /join self-signup page and the
	// register API. Seeded true in scripts/sql/005.sql.
	PublicRegistrationSettingKey = "public_registration_enabled"
	// EmailSendingSettingKey gates outbound email delivery platform-wide.
	// When off, every triggered email is skipped (logged, not sent), which
	// keeps local dev quiet while the Mailgun keys are empty.
	EmailSendingSettingKey = "email_sending_enabled"
	// EmailVerificationRequiredSettingKey decides whether sign-in refuses
	// unverified accounts. Off by default so a dev stack without Mailgun
	// credentials never locks anyone out; flip it on once email works.
	EmailVerificationRequiredSettingKey = "email_verification_required"
)

// Admin console ----------------------------------------------------------
//
// The management console lives behind the require_admin security layer,
// which is satisfied by a vault3_admin row and nothing else. The path is
// deliberately not /app/admin: obscurity is not the gate, but keeping the
// console off the one path every scanner wordlist tries costs nothing.
const (
	// AdminConsolePath is the single console page. Everything it does runs
	// through /api/v1/admin/* endpoints behind the same layer.
	AdminConsolePath = "/app/v3-mgmt"
	// AdminPageSize bounds every listing the console pages through (users,
	// audit trail, contact inbox), so no query can be asked for the whole
	// table.
	AdminPageSize = 25
	// MaxSuspensionReasonChars caps the note an operator leaves on a
	// suspended account. It is stored in the clear and shown back in the
	// console, not to the user.
	MaxSuspensionReasonChars = 200
	// AdminBootstrapEmailEnv names the optional environment variable that
	// grants the first admin. It is read once at web-process startup and is
	// deliberately absent from REQUIRED_ENV_VARS: an empty value is the
	// normal state, and the grant it performs is idempotent.
	AdminBootstrapEmailEnv = "ADMIN_BOOTSTRAP_EMAIL_STRING"
)

// Item limits ------------------------------------------------------------
//
// Item blobs arrive as ciphertext envelopes the server cannot inspect, so
// the only server-side validation is structural: envelope shape and size.
const (
	// MaxItemOverviewBytes / MaxItemDetailsBytes cap the base64 ciphertext of
	// the two item blobs. Overviews hold title/username/URLs; details hold
	// the secrets and free-text notes, so they get more room.
	MaxItemOverviewBytes = 16 * 1024
	MaxItemDetailsBytes  = 256 * 1024
	// MaxItemsPerVault bounds a single vault. Well above real use; it exists
	// so a runaway client cannot grow a vault without limit.
	MaxItemsPerVault = 5000
	// TrashRetention is how long a trashed item is kept before the scheduler
	// purges it permanently.
	TrashRetention = 30 * 24 * time.Hour
)

// Sharing ----------------------------------------------------------------
//
// Share links and vault invites redeem opaque tokens (stored hashed); the
// decryption secret rides only in the URL fragment, which browsers never
// transmit. These bounds are structural: the server cannot see what is
// shared, only how many links exist and when they lapse.
const (
	// ShareLinkMaxTTLHours caps a share link's requested lifetime (30 days);
	// ShareLinkDefaultTTLHours applies when the client sends no expiry.
	ShareLinkMaxTTLHours     = 720
	ShareLinkDefaultTTLHours = 24
	// MaxActiveShareLinksPerItem bounds live (unexpired, unrevoked) links on
	// one item.
	MaxActiveShareLinksPerItem = 10
	// VaultInviteTTL is the fixed lifetime of a vault invite link.
	VaultInviteTTL = 7 * 24 * time.Hour
	// MaxActiveInvitesPerVault bounds pending invites on one vault.
	MaxActiveInvitesPerVault = 10
	// MaxMembersPerVault bounds access rows per vault (owner included).
	MaxMembersPerVault = 10
	// MaxVaultsPerUser bounds how many vaults one account can reach.
	MaxVaultsPerUser = 20
	// MaxVaultNameBytes caps the encName envelope's decoded ciphertext.
	MaxVaultNameBytes = 1024
	// MaxWrappedKeyBytes caps any wrapped-key envelope's decoded ciphertext.
	MaxWrappedKeyBytes = 1024
	// SharingPurgeGrace is how long lapsed share links and invites stay
	// visible (as expired/revoked history) before the scheduler removes the
	// rows entirely.
	SharingPurgeGrace = 7 * 24 * time.Hour
)

// Profile ----------------------------------------------------------------
const (
	// MaxDisplayNameChars caps the account display name. Enforced identically
	// at registration and on profile update — the two must not drift.
	MaxDisplayNameChars = 100
)

// Contact form -----------------------------------------------------------
const (
	MaxContactNameChars    = 100
	MaxContactMessageChars = 2000
)

// Public-facing brand and SEO defaults. Every template, sitemap, robots.txt,
// email, and external link should reference these — do not hardcode the URL or
// brand copy elsewhere.
const (
	//SITE_URL = "http://localhost:3403"
	SITE_URL           = "https://vault3.com"
	SITE_NAME          = "Vault3"
	SITE_TAGLINE       = "Vault3. Your secrets, sealed."
	SITE_DESCRIPTION   = "Vault3 is a zero-knowledge password manager. Everything you store is encrypted on your device before it reaches us — we could not read your vault if we tried."
	SITE_OG_IMAGE_PATH = "/static/og-image.png"
	SITE_FAVICON_PATH  = "/static/favicon.svg"
	// SITE_CONTACT_EMAIL is the public "get in touch" address surfaced on the
	// contact and legal pages (via .Site.ContactEmail).
	SITE_CONTACT_EMAIL = "hello@vault3.com"

	// SITE_COMPANY_* identify the legal entity that makes and operates
	// Vault3. The legal name is the one the documents must name (contracting
	// party in the Terms, data controller in the Privacy Policy); the trading
	// name is what the footer credits.
	SITE_COMPANY_LEGAL_NAME = "Octa Systems Ltd"
	SITE_COMPANY_NAME       = "Octa Digital"
	SITE_COMPANY_URL        = "https://octa.sh"
	// SITE_REPO_URL is the public source repository, linked from the footer.
	SITE_REPO_URL = "https://github.com/piotr-nierobisz/vault3"
)

// SQLScriptsDir holds numbered scripts: 001.sql, 002.sql, …
const SQLScriptsDir = "scripts/sql"

// LATEST_SQL_SCRIPT_VERSION is the highest script number to run in development (inclusive).
// Bump when adding scripts/sql/00N.sql; runtime replays 1..N on each dev startup.
const LATEST_SQL_SCRIPT_VERSION = 9

// REQUIRED_ENV_VARS fail fast at startup if missing or empty.
//
// Two groups are deliberately NOT required, and both must stay that way:
//
//   - The Mailgun trio (MAILGUN_API_KEY_STRING, MAILGUN_DOMAIN_STRING,
//     MAILGUN_FROM_EMAIL_STRING): the delivery layer degrades to a logged skip
//     while the keys are empty, and the email_sending_enabled platform setting
//     keeps dev quiet regardless. Add them here once the production Mailgun
//     domain is verified.
//   - AdminBootstrapEmailEnv: unset is the steady state. It exists to grant
//     the first admin on a fresh deployment (and to break back in if the last
//     grant is ever removed), so requiring it would make every stack carry a
//     value it needs exactly once.
var REQUIRED_ENV_VARS = []string{
	"PRODUCTION_BOOL",
	"PORT_INT",
	"POSTGRES_DSN_STRING",

	// SERVER_ENCRYPTION_KEY_STRING is the base64 32-byte key behind
	// internal/crypto.FieldCipher: server-side encryption at rest for the
	// small set of operational fields that are not client-encrypted (display
	// name, session IP/UA, TOTP secrets). It is unrelated to vault data,
	// which only ever exists as client-side ciphertext.
	"SERVER_ENCRYPTION_KEY_STRING",

	"SUPPORT_EMAIL_STRING",
}
