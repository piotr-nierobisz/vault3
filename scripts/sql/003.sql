-- 003.sql — schema only.
-- Vaults and items: the encrypted heart of the product.
--
-- Key hierarchy (all wrapping happens in the browser, see docs/security.md):
--
--   Master Password + Secret Key ──2SKD──▶ MUK ──▶ key-encryption key
--        key-encryption key  wraps  vault key   (vault3_vault_access.WrappedKey)
--        vault key           wraps  item key    (vault3_item.WrappedItemKey)
--        item key            seals  overview + details blobs
--
-- Every JSONB envelope below has the client-side shape
--   {"v":1,"alg":"A256GCM","n":"<base64url nonce>","c":"<base64url ct+tag>"}
-- and is opaque to the server. Per-item keys exist so a future share link can
-- re-wrap ONE item's key to a recipient without touching the vault key, and
-- vault3_vault_access is a join table (not a column on vault) so a future
-- shared vault is one INSERT wrapping the vault key to another user's public
-- key — both are architectural runway, unused by v1's single personal vault.

-- Vaults --------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS "vault3_vault" (
    "Vault3VaultID"          UUID        PRIMARY KEY,
    "Vault3VaultOwnerUserID" UUID        NOT NULL
        REFERENCES "vault3_user" ("Vault3UserID") ON DELETE CASCADE,
    "Vault3VaultKind"        TEXT        NOT NULL DEFAULT 'personal',
    "Vault3VaultEncName"     JSONB       NOT NULL,
    "Vault3VaultCreatedAt"   TIMESTAMPTZ NOT NULL DEFAULT now(),
    "Vault3VaultUpdatedAt"   TIMESTAMPTZ NOT NULL DEFAULT now(),
    "Vault3VaultArchivedAt"  TIMESTAMPTZ,
    CONSTRAINT "vault3_vault_kind_check"
        CHECK ("Vault3VaultKind" IN ('personal', 'shared'))
);

CREATE INDEX IF NOT EXISTS "vault3_vault_owner_idx"
    ON "vault3_vault" ("Vault3VaultOwnerUserID");

-- Vault access --------------------------------------------------------------
-- One row per (vault, user): the vault key wrapped for that user. WrapAlgo
-- 'muk' means wrapped under the user's own key-encryption key (the personal
-- vault case); 'rsa-oaep' is reserved for wrapping to another user's public
-- key when shared vaults ship.

CREATE TABLE IF NOT EXISTS "vault3_vault_access" (
    "Vault3VaultAccessID"         UUID        PRIMARY KEY,
    "Vault3VaultAccessVaultID"    UUID        NOT NULL
        REFERENCES "vault3_vault" ("Vault3VaultID") ON DELETE CASCADE,
    "Vault3VaultAccessUserID"     UUID        NOT NULL
        REFERENCES "vault3_user" ("Vault3UserID") ON DELETE CASCADE,
    "Vault3VaultAccessRole"       TEXT        NOT NULL DEFAULT 'owner',
    "Vault3VaultAccessWrapAlgo"   TEXT        NOT NULL DEFAULT 'muk',
    "Vault3VaultAccessWrappedKey" JSONB       NOT NULL,
    "Vault3VaultAccessCreatedAt"  TIMESTAMPTZ NOT NULL DEFAULT now(),
    "Vault3VaultAccessUpdatedAt"  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT "vault3_vault_access_role_check"
        CHECK ("Vault3VaultAccessRole" IN ('owner', 'member')),
    CONSTRAINT "vault3_vault_access_wrap_algo_check"
        CHECK ("Vault3VaultAccessWrapAlgo" IN ('muk', 'rsa-oaep')),
    CONSTRAINT "vault3_vault_access_vault_user_unique"
        UNIQUE ("Vault3VaultAccessVaultID", "Vault3VaultAccessUserID")
);

CREATE INDEX IF NOT EXISTS "vault3_vault_access_user_idx"
    ON "vault3_vault_access" ("Vault3VaultAccessUserID");

-- Items ---------------------------------------------------------------------
-- The server knows an item's id, vault, and timestamps — nothing else. Title,
-- category, username, URLs, secrets, and notes all live inside the two
-- encrypted blobs (Overview for the list view, Details for the reveal), so a
-- database dump discloses only how many items exist and when they changed.
-- DeletedAt is the trash: soft-deleted items are restorable until the
-- scheduler's purge job removes rows older than the retention window.

CREATE TABLE IF NOT EXISTS "vault3_item" (
    "Vault3ItemID"             UUID        PRIMARY KEY,
    "Vault3ItemVaultID"        UUID        NOT NULL
        REFERENCES "vault3_vault" ("Vault3VaultID") ON DELETE CASCADE,
    "Vault3ItemWrappedItemKey" JSONB       NOT NULL,
    "Vault3ItemOverview"       JSONB       NOT NULL,
    "Vault3ItemDetails"        JSONB       NOT NULL,
    "Vault3ItemDeletedAt"      TIMESTAMPTZ,
    "Vault3ItemCreatedAt"      TIMESTAMPTZ NOT NULL DEFAULT now(),
    "Vault3ItemUpdatedAt"      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS "vault3_item_vault_idx"
    ON "vault3_item" ("Vault3ItemVaultID")
    WHERE "Vault3ItemDeletedAt" IS NULL;
CREATE INDEX IF NOT EXISTS "vault3_item_trash_idx"
    ON "vault3_item" ("Vault3ItemDeletedAt")
    WHERE "Vault3ItemDeletedAt" IS NOT NULL;
