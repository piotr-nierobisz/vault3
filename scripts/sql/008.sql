-- 008: post-quantum key derivation.
--
-- Three changes, all consequences of moving the browser's key hierarchy onto
-- primitives that a quantum adversary does not threaten (docs/security.md).
--
--   1. The per-account asymmetric keypair is removed outright. It was
--      RSA-OAEP-2048 — the only Shor-breakable primitive in the product —
--      and it was never used: sharing shipped on the symmetric link-fragment
--      construction instead, so no ciphertext was ever wrapped to a public
--      key. Deleting it is therefore not a migration of anything, and it
--      leaves Vault3 with no asymmetric cryptography at all.
--
--   2. vault3_user_auth gains the Argon2id cost parameters, alongside the
--      PBKDF2 iteration count it already stored. The browser runs Argon2id
--      over PBKDF2-HMAC-SHA-512; both sets of costs are per-account so they
--      can be raised later without stranding existing registrations.
--
--   3. The vault-access wrap algorithm loses its 'rsa-oaep' option, which
--      existed only to receive keys wrapped to that keypair.
--
-- NOTE ON EXISTING ROWS: this release changes the KDF, the auth-key width,
-- and the auth-key storage hash together, so any account registered before it
-- cannot unlock afterwards — its stored hash is bcrypt over a 43-character key
-- that the browser no longer produces. No data is deleted here, because a
-- migration script is the wrong place to decide that. Accounts predating this
-- release must be removed deliberately.

-- 1. Drop the unused keypair ------------------------------------------------

DROP TABLE IF EXISTS "vault3_user_keys";

-- 2. Argon2id cost parameters ------------------------------------------------
-- Defaults mirror config.Argon2Default* so a row written by an older client
-- reads back as the current profile rather than as zeroes.

ALTER TABLE "vault3_user_auth"
    ADD COLUMN IF NOT EXISTS "Vault3UserAuthArgon2MemoryKiB" INTEGER NOT NULL DEFAULT 65536,
    ADD COLUMN IF NOT EXISTS "Vault3UserAuthArgon2Time"      INTEGER NOT NULL DEFAULT 4,
    ADD COLUMN IF NOT EXISTS "Vault3UserAuthArgon2Lanes"     INTEGER NOT NULL DEFAULT 4;

-- 3. Wrap algorithm: symmetric only ------------------------------------------
-- Every vault key is sealed under its holder's own key-encryption key. There
-- is no longer any other way for one to be wrapped.

ALTER TABLE "vault3_vault_access"
    DROP CONSTRAINT IF EXISTS "vault3_vault_access_wrap_algo_check";

ALTER TABLE "vault3_vault_access"
    ADD CONSTRAINT "vault3_vault_access_wrap_algo_check"
        CHECK ("Vault3VaultAccessWrapAlgo" IN ('muk'));
