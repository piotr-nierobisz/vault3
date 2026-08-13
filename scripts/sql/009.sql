-- 009.sql — schema only.
-- Support for the admin console: triage state on the contact inbox, plus the
-- three indexes its listings order by.
--
-- The console is the first reader of platform-wide lists: the newest audit
-- rows regardless of user, the newest accounts, the whole contact inbox.
-- Every index that exists is keyed on a per-user lookup, so an unfiltered
-- ORDER BY … DESC would sort the entire table on each page.
--
-- HandledAt is the only state the inbox needs: an operator marks a message
-- dealt with, and the console's default view stops showing it. There is no
-- assignee, status enum or reply thread, because inbound mail is answered by
-- email and this table is only the record that it arrived.

ALTER TABLE "vault3_contact_inquiry"
    ADD COLUMN IF NOT EXISTS "Vault3ContactInquiryHandledAt" TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS "vault3_contact_inquiry_created_idx"
    ON "vault3_contact_inquiry" ("Vault3ContactInquiryCreatedAt" DESC);

CREATE INDEX IF NOT EXISTS "vault3_audit_log_created_idx"
    ON "vault3_audit_log" ("Vault3AuditLogCreatedAt" DESC);

CREATE INDEX IF NOT EXISTS "vault3_user_created_idx"
    ON "vault3_user" ("Vault3UserCreatedAt" DESC);
