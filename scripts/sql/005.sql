-- 005.sql — seeds only.
-- Idempotent reference data: item categories and platform settings. Reruns
-- update labels/ordering but never clobber an operator-toggled setting value
-- (DO NOTHING on conflict for settings; categories upsert their display
-- columns, which are not operator state).

INSERT INTO "vault3_item_category"
    ("Vault3ItemCategoryCode", "Vault3ItemCategoryLabel", "Vault3ItemCategoryIcon", "Vault3ItemCategorySortOrder")
VALUES
    ('login',       'Login',        'key',      1),
    ('secure_note', 'Secure note',  'note',     2),
    ('card',        'Payment card', 'card',     3),
    ('identity',    'Identity',     'identity', 4)
ON CONFLICT ("Vault3ItemCategoryCode") DO UPDATE SET
    "Vault3ItemCategoryLabel"     = EXCLUDED."Vault3ItemCategoryLabel",
    "Vault3ItemCategoryIcon"      = EXCLUDED."Vault3ItemCategoryIcon",
    "Vault3ItemCategorySortOrder" = EXCLUDED."Vault3ItemCategorySortOrder";

-- Platform settings. email_sending_enabled and email_verification_required
-- ship off so a dev stack with empty Mailgun keys works end to end; flip
-- them on once the production domain sends mail.
INSERT INTO "vault3_platform_setting"
    ("Vault3PlatformSettingKey", "Vault3PlatformSettingValue", "Vault3PlatformSettingKind")
VALUES
    ('public_registration_enabled', 'true',  'bool'),
    ('email_sending_enabled',       'false', 'bool'),
    ('email_verification_required', 'false', 'bool')
ON CONFLICT ("Vault3PlatformSettingKey") DO NOTHING;