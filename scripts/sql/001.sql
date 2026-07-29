-- 001.sql — schema only.
-- Extensions and reference tables. Seeds live in 005.sql so this file is pure
-- DDL and re-readable as the canonical shape of the lookup layer.

-- Extensions ---------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Item categories ----------------------------------------------------------
-- Reference data for the client UI (labels, icons, ordering). Note that an
-- item's actual category lives INSIDE its encrypted overview blob — the
-- server cannot see which category an item belongs to, so there is no FK
-- from vault3_item to this table. The rows only drive the picker and the
-- sidebar, loaded once at startup into view.Lookups.

CREATE TABLE IF NOT EXISTS "vault3_item_category" (
    "Vault3ItemCategoryCode"      TEXT        PRIMARY KEY,
    "Vault3ItemCategoryLabel"     TEXT        NOT NULL,
    "Vault3ItemCategoryIcon"      TEXT        NOT NULL DEFAULT 'key',
    "Vault3ItemCategoryIsActive"  BOOLEAN     NOT NULL DEFAULT TRUE,
    "Vault3ItemCategorySortOrder" INTEGER     NOT NULL DEFAULT 0,
    "Vault3ItemCategoryCreatedAt" TIMESTAMPTZ NOT NULL DEFAULT now()
);
