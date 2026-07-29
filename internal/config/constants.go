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
	SessionCookieName  = "vault3_session"
	SessionTTL         = 30 * 24 * time.Hour
	SessionInternalKey = "Session"
	UserInternalKey    = "User"
	// ViewerInternalKey holds the *view.UserSummary the load_viewer security
	// layer builds from the authenticated user, so handlers read req.Internal
	// instead of rebuilding the summary per request.
	ViewerInternalKey = "Viewer"

	// GenericLoginError is returned for every failed sign-in so attackers
	// cannot distinguish "wrong password" from "wrong Secret Key" from "no
	// such account".
	GenericLoginError = "Those details don't match an account. Check your email, Master Password and Secret Key, then try again."
)

// Default redirect after a successful sign-in.
const DefaultPostLoginRedirect = "/app"

// Zero-knowledge key derivation -----------------------------------------
//
// The client derives every key in the browser (see web/lib/crypto.ts); the
// server never sees the Master Password, the Secret Key, or any derived
// encryption key. These constants are the server-side halves of that
// contract: the KDF parameters registration must arrive with, and the
// account-unlock values /api/v1/auth/params hands back before login.
const (
	// KdfDefaultIterations is the PBKDF2-SHA256 iteration count new accounts
	// register with. The client sends its actual count and the server stores
	// it per account, so this can be raised without breaking existing users.
	KdfDefaultIterations = 650000
	// KdfMinIterations rejects registrations weakened below the floor.
	KdfMinIterations = 100000
	// KdfSaltBytes is the decoded length of the per-account KDF salt.
	KdfSaltBytes = 16
	// AuthKeyEncodedLength is the exact base64url length of the client-derived
	// 32-byte auth key. Anything else is rejected before bcrypt.
	AuthKeyEncodedLength = 43
)

// Account tokens ---------------------------------------------------------
//
// Emailed single-use tokens are stored hashed (SHA-256) and time-limited.
const (
	EmailVerificationTokenTTL = 24 * time.Hour
	// AccountResetTokenTTL bounds the emailed account-reset link. Because
	// Vault3 is zero-knowledge, redeeming it wipes the vault: there is no
	// password reset that preserves data.
	AccountResetTokenTTL = time.Hour
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

// Contact form -----------------------------------------------------------
const (
	MaxContactNameChars    = 100
	MaxContactMessageChars = 2000
)

// Public-facing brand and SEO defaults. Every template, sitemap, robots.txt,
// email, and external link should reference these — do not hardcode the URL or
// brand copy elsewhere.
const (
	SITE_URL = "http://localhost:3403"
	//SITE_URL           = "https://vault3.com" // TODO: Change this in production
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
const LATEST_SQL_SCRIPT_VERSION = 6

// REQUIRED_ENV_VARS fail fast at startup if missing or empty.
//
// The Mailgun group (MAILGUN_API_KEY_STRING, MAILGUN_DOMAIN_STRING,
// MAILGUN_FROM_EMAIL_STRING) is deliberately NOT required: the delivery layer
// degrades to a logged skip while the keys are empty, and the
// email_sending_enabled platform setting keeps dev quiet regardless. Add them
// here once the production Mailgun domain is verified.
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
