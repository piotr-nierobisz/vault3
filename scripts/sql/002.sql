-- 002.sql — schema only.
-- Identity: user hub plus its 1:1 auth and key-material spokes.
--
-- Layout notes:
--   * vault3_user is the hub: identity, lifecycle, notification prefs, and
--     the per-user Revision counter that drives the cross-device sync signal.
--   * vault3_user_auth holds only auth-sensitive fields, kept separate so
--     ordinary user reads never load secrets. The password itself never
--     reaches the server: AuthKeyHash is bcrypt of the CLIENT-derived auth
--     key (see docs/security.md), and the KDF salt/iterations are the public
--     parameters handed back before login.
--   * vault3_user_keys is the user's asymmetric keypair: public key in the
--     clear, private key as client-side ciphertext. It exists now so vault
--     sharing and share links can wrap keys to a recipient later without a
--     migration.
--   * Columns ending in Enc hold server-side FieldCipher ciphertext
--     (internal/crypto): readable by the app, opaque in the database.

-- Users -------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS "vault3_user" (
    "Vault3UserID"                UUID        PRIMARY KEY,
    "Vault3UserEmail"             TEXT        NOT NULL UNIQUE,
    "Vault3UserDisplayNameEnc"    TEXT,
    "Vault3UserNotificationPrefs" JSONB       NOT NULL DEFAULT '{}'::jsonb,
    "Vault3UserRevision"          BIGINT      NOT NULL DEFAULT 1,
    "Vault3UserIsActive"          BOOLEAN     NOT NULL DEFAULT TRUE,
    "Vault3UserLastLoginAt"       TIMESTAMPTZ,
    "Vault3UserArchivedAt"        TIMESTAMPTZ,
    "Vault3UserArchivedReason"    TEXT,
    "Vault3UserCreatedAt"         TIMESTAMPTZ NOT NULL DEFAULT now(),
    "Vault3UserUpdatedAt"         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT "vault3_user_email_lowercase_check"
        CHECK ("Vault3UserEmail" = lower("Vault3UserEmail"))
);

CREATE INDEX IF NOT EXISTS "vault3_user_active_idx"
    ON "vault3_user" ("Vault3UserIsActive")
    WHERE "Vault3UserArchivedAt" IS NULL;

-- Auth-sensitive split. 1:1 with vault3_user.

CREATE TABLE IF NOT EXISTS "vault3_user_auth" (
    "Vault3UserAuthUserID"                       UUID        PRIMARY KEY
        REFERENCES "vault3_user" ("Vault3UserID") ON DELETE CASCADE,
    "Vault3UserAuthAuthKeyHash"                  TEXT        NOT NULL,
    "Vault3UserAuthKdfSalt"                      TEXT        NOT NULL,
    "Vault3UserAuthKdfIterations"                INTEGER     NOT NULL,
    "Vault3UserAuthLastPasswordChangeAt"         TIMESTAMPTZ,
    "Vault3UserAuthTwoFactorSecretEnc"           TEXT,
    "Vault3UserAuthTempTwoFactorSecretEnc"       TEXT,
    "Vault3UserAuthEmailVerified"                BOOLEAN     NOT NULL DEFAULT FALSE,
    "Vault3UserAuthEmailVerificationTokenHash"   TEXT,
    "Vault3UserAuthEmailVerificationTokenExpiry" TIMESTAMPTZ,
    "Vault3UserAuthAccountResetTokenHash"        TEXT,
    "Vault3UserAuthAccountResetTokenExpiry"      TIMESTAMPTZ,
    "Vault3UserAuthUpdatedAt"                    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Asymmetric keypair. 1:1 with vault3_user. The private key is client-side
-- ciphertext (encrypted in the browser under the account's key-encryption
-- key); the server can wrap TO the public key but never unwrap.

CREATE TABLE IF NOT EXISTS "vault3_user_keys" (
    "Vault3UserKeysUserID"        UUID        PRIMARY KEY
        REFERENCES "vault3_user" ("Vault3UserID") ON DELETE CASCADE,
    "Vault3UserKeysAlgo"          TEXT        NOT NULL DEFAULT 'rsa-oaep-2048',
    "Vault3UserKeysPublicKey"     JSONB       NOT NULL,
    "Vault3UserKeysEncPrivateKey" JSONB       NOT NULL,
    "Vault3UserKeysCreatedAt"     TIMESTAMPTZ NOT NULL DEFAULT now(),
    "Vault3UserKeysUpdatedAt"     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Admin flag (future management console). Empty by default; the console
-- routes will gate on this table when they ship.

CREATE TABLE IF NOT EXISTS "vault3_admin" (
    "Vault3AdminUserID"          UUID        PRIMARY KEY
        REFERENCES "vault3_user" ("Vault3UserID") ON DELETE CASCADE,
    "Vault3AdminGrantedAt"       TIMESTAMPTZ NOT NULL DEFAULT now(),
    "Vault3AdminGrantedByUserID" UUID
        REFERENCES "vault3_user" ("Vault3UserID"),
    "Vault3AdminNotes"           TEXT
);
