-- 004.sql — schema only.
-- Operational spokes: sessions, notifications, audit trail, contact
-- inquiries, platform settings.
--
-- Columns ending in Enc hold server-side FieldCipher ciphertext
-- (internal/crypto). IpHash is the keyed HMAC blind of the IP so equality
-- checks (new-device detection) work without storing the address readably.

-- Sessions ------------------------------------------------------------------
-- Server-side session store. The cookie holds the opaque token; TokenHash is
-- the lookup key here.

CREATE TABLE IF NOT EXISTS "vault3_session" (
    "Vault3SessionID"           UUID        PRIMARY KEY,
    "Vault3SessionTokenHash"    TEXT        NOT NULL UNIQUE,
    "Vault3SessionUserID"       UUID        NOT NULL
        REFERENCES "vault3_user" ("Vault3UserID") ON DELETE CASCADE,
    "Vault3SessionIpAddressEnc" TEXT,
    "Vault3SessionIpHash"       TEXT,
    "Vault3SessionUserAgentEnc" TEXT,
    "Vault3SessionExpiresAt"    TIMESTAMPTZ NOT NULL,
    "Vault3SessionCreatedAt"    TIMESTAMPTZ NOT NULL DEFAULT now(),
    "Vault3SessionLastSeenAt"   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS "vault3_session_user_idx"
    ON "vault3_session" ("Vault3SessionUserID");
CREATE INDEX IF NOT EXISTS "vault3_session_expires_idx"
    ON "vault3_session" ("Vault3SessionExpiresAt");

-- Notifications -------------------------------------------------------------
-- The in-app bell and notifications centre. Title and body are encrypted at
-- rest because security notices carry operational detail (IP, device);
-- Metadata stays plain JSONB but holds only non-sensitive routing keys
-- (e.g. an href).

CREATE TABLE IF NOT EXISTS "vault3_notification" (
    "Vault3NotificationID"        UUID        PRIMARY KEY,
    "Vault3NotificationUserID"    UUID        NOT NULL
        REFERENCES "vault3_user" ("Vault3UserID") ON DELETE CASCADE,
    "Vault3NotificationKind"      TEXT        NOT NULL,
    "Vault3NotificationTitleEnc"  TEXT        NOT NULL,
    "Vault3NotificationBodyEnc"   TEXT        NOT NULL,
    "Vault3NotificationIsRead"    BOOLEAN     NOT NULL DEFAULT FALSE,
    "Vault3NotificationReadAt"    TIMESTAMPTZ,
    "Vault3NotificationMetadata"  JSONB       NOT NULL DEFAULT '{}'::jsonb,
    "Vault3NotificationCreatedAt" TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS "vault3_notification_user_idx"
    ON "vault3_notification" ("Vault3NotificationUserID", "Vault3NotificationCreatedAt" DESC);
CREATE INDEX IF NOT EXISTS "vault3_notification_unread_idx"
    ON "vault3_notification" ("Vault3NotificationUserID")
    WHERE "Vault3NotificationIsRead" = FALSE;

-- Audit log -----------------------------------------------------------------
-- Append-only security trail: sign-ins (and failures), item lifecycle by id,
-- account changes. DetailEnc is an encrypted JSON blob; item content is never
-- logged (the server never has it).

CREATE TABLE IF NOT EXISTS "vault3_audit_log" (
    "Vault3AuditLogID"           UUID        PRIMARY KEY,
    "Vault3AuditLogUserID"       UUID
        REFERENCES "vault3_user" ("Vault3UserID") ON DELETE SET NULL,
    "Vault3AuditLogAction"       TEXT        NOT NULL,
    "Vault3AuditLogEntityType"   TEXT,
    "Vault3AuditLogEntityID"     TEXT,
    "Vault3AuditLogIpAddressEnc" TEXT,
    "Vault3AuditLogUserAgentEnc" TEXT,
    "Vault3AuditLogDetailEnc"    TEXT,
    "Vault3AuditLogCreatedAt"    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS "vault3_audit_log_user_idx"
    ON "vault3_audit_log" ("Vault3AuditLogUserID", "Vault3AuditLogCreatedAt" DESC);

-- Contact inquiries ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS "vault3_contact_inquiry" (
    "Vault3ContactInquiryID"           UUID        PRIMARY KEY,
    "Vault3ContactInquiryName"         TEXT        NOT NULL,
    "Vault3ContactInquiryEmail"        TEXT        NOT NULL,
    "Vault3ContactInquiryMessage"      TEXT        NOT NULL,
    "Vault3ContactInquiryIpAddressEnc" TEXT,
    "Vault3ContactInquiryUserAgentEnc" TEXT,
    "Vault3ContactInquiryCreatedAt"    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Platform settings ---------------------------------------------------------
-- Key/value platform config, read through the fail-safe accessors in
-- internal/runtime/platform_setting.go. Never read or write ad hoc.

CREATE TABLE IF NOT EXISTS "vault3_platform_setting" (
    "Vault3PlatformSettingKey"       TEXT        PRIMARY KEY,
    "Vault3PlatformSettingValue"     TEXT        NOT NULL,
    "Vault3PlatformSettingKind"      TEXT        NOT NULL DEFAULT 'bool',
    "Vault3PlatformSettingUpdatedAt" TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT "vault3_platform_setting_kind_check"
        CHECK ("Vault3PlatformSettingKind" IN ('bool', 'string', 'int'))
);
