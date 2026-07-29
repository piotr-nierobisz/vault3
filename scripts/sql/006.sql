-- 006.sql — schema only.
-- Sharing: item share links and vault invites.
--
-- Both tables follow the same zero-knowledge shape as everything else: the
-- server stores a SHA-256 token hash (the URL carries the raw token) and a
-- client-side CipherEnvelope holding a key wrapped under a secret that ONLY
-- ever exists in the link's URL fragment — fragments are never sent to the
-- server, so the server can authorise redemption but never decrypt.
--
--   * vault3_share_link exposes ONE item: the per-item key re-wrapped under
--     a random share key minted in the sharer's browser. The viewer opens
--     the item key with the fragment key, then the item's live blobs.
--   * vault3_vault_invite carries a vault key wrapped under a random invite
--     key. Accepting re-wraps the vault key under the acceptor's own
--     key-encryption key and inserts a vault3_vault_access row (role
--     'member', wrap algo 'muk') — so every stored vault wrap stays uniform
--     and Master Password rotation re-wraps them all identically.

-- Share links ---------------------------------------------------------------

CREATE TABLE IF NOT EXISTS "vault3_share_link" (
    "Vault3ShareLinkID"              UUID        PRIMARY KEY,
    "Vault3ShareLinkItemID"          UUID        NOT NULL
        REFERENCES "vault3_item" ("Vault3ItemID") ON DELETE CASCADE,
    "Vault3ShareLinkCreatedByUserID" UUID        NOT NULL
        REFERENCES "vault3_user" ("Vault3UserID") ON DELETE CASCADE,
    "Vault3ShareLinkTokenHash"       TEXT        NOT NULL UNIQUE,
    "Vault3ShareLinkWrappedItemKey"  JSONB       NOT NULL,
    "Vault3ShareLinkExpiresAt"       TIMESTAMPTZ NOT NULL,
    "Vault3ShareLinkRevokedAt"       TIMESTAMPTZ,
    "Vault3ShareLinkViewCount"       INTEGER     NOT NULL DEFAULT 0,
    "Vault3ShareLinkCreatedAt"       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS "vault3_share_link_item_idx"
    ON "vault3_share_link" ("Vault3ShareLinkItemID");

-- Vault invites -------------------------------------------------------------
-- Single-use: AcceptedAt marks redemption; RevokedAt kills a pending link.

CREATE TABLE IF NOT EXISTS "vault3_vault_invite" (
    "Vault3VaultInviteID"               UUID        PRIMARY KEY,
    "Vault3VaultInviteVaultID"          UUID        NOT NULL
        REFERENCES "vault3_vault" ("Vault3VaultID") ON DELETE CASCADE,
    "Vault3VaultInviteCreatedByUserID"  UUID        NOT NULL
        REFERENCES "vault3_user" ("Vault3UserID") ON DELETE CASCADE,
    "Vault3VaultInviteTokenHash"        TEXT        NOT NULL UNIQUE,
    "Vault3VaultInviteWrappedVaultKey"  JSONB       NOT NULL,
    "Vault3VaultInviteRole"             TEXT        NOT NULL DEFAULT 'member',
    "Vault3VaultInviteExpiresAt"        TIMESTAMPTZ NOT NULL,
    "Vault3VaultInviteRevokedAt"        TIMESTAMPTZ,
    "Vault3VaultInviteAcceptedAt"       TIMESTAMPTZ,
    "Vault3VaultInviteAcceptedByUserID" UUID
        REFERENCES "vault3_user" ("Vault3UserID") ON DELETE SET NULL,
    "Vault3VaultInviteCreatedAt"        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT "vault3_vault_invite_role_check"
        CHECK ("Vault3VaultInviteRole" IN ('member'))
);

CREATE INDEX IF NOT EXISTS "vault3_vault_invite_vault_idx"
    ON "vault3_vault_invite" ("Vault3VaultInviteVaultID");
