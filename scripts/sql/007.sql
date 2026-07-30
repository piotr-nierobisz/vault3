-- 007.sql — schema only.
-- Removes the account-reset token columns.
--
-- Vault3 has no account recovery or reset flow. The server holds only
-- ciphertext, so a lost Master Password or Secret Phrase is unrecoverable by
-- construction — /security and the terms of service say exactly that, and the
-- Emergency Kit is the user's only way back in. The columns below backed an
-- emailed "reset" that erased the vault and re-ran the onboarding ceremony;
-- that flow is gone, so the storage goes with it.
--
-- Idempotent (IF EXISTS), like every script here: development replays 1..N on
-- each boot.

ALTER TABLE "vault3_user_auth"
    DROP COLUMN IF EXISTS "Vault3UserAuthAccountResetTokenHash";

ALTER TABLE "vault3_user_auth"
    DROP COLUMN IF EXISTS "Vault3UserAuthAccountResetTokenExpiry";