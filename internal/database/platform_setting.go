package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	sq "github.com/Masterminds/squirrel"
)

// SelectPlatformSettingValue returns the raw stored value for a key. Returns
// sql.ErrNoRows when the key is unseeded — the runtime accessors translate
// that into their fail-safe default. Never read this table ad hoc; go through
// the (*Runtime) accessors in internal/runtime/platform_setting.go.
func SelectPlatformSettingValue(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	key string,
) (string, error) {
	sqlStr, args, sqlErr := builder.
		Select(`"Vault3PlatformSettingValue"`).
		From(`"vault3_platform_setting"`).
		Where(sq.Eq{`"Vault3PlatformSettingKey"`: key}).
		ToSql()
	if sqlErr != nil {
		return "", fmt.Errorf("build platform setting query: %w", sqlErr)
	}
	var value string
	scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(&value)
	if scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return "", sql.ErrNoRows
		}
		return "", fmt.Errorf("select platform setting: %w", scanErr)
	}
	return value, nil
}

// UpsertPlatformSetting writes a setting value, creating the row if missing.
// Reserved for the future admin console; nothing else may write settings.
func UpsertPlatformSetting(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	key string,
	value string,
	kind string,
) error {
	sqlStr, args, sqlErr := builder.
		Insert(`"vault3_platform_setting"`).
		Columns(
			`"Vault3PlatformSettingKey"`,
			`"Vault3PlatformSettingValue"`,
			`"Vault3PlatformSettingKind"`,
		).
		Values(key, value, kind).
		Suffix(`ON CONFLICT ("Vault3PlatformSettingKey") DO UPDATE SET
			"Vault3PlatformSettingValue" = EXCLUDED."Vault3PlatformSettingValue",
			"Vault3PlatformSettingUpdatedAt" = now()`).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build upsert platform setting: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("upsert platform setting: %w", execErr)
	}
	return nil
}
