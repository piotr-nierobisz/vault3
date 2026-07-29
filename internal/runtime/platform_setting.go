package runtime

import (
	"context"
	"database/sql"
	"errors"

	"vault3/internal/config"
	"vault3/internal/database"

	"go.uber.org/zap"
)

// Platform-setting accessors. Each fails SAFE for its gate: a missing row or
// a read error yields the value that keeps the platform in its most
// conservative state (registration closed, email off, verification not
// enforced — the one gate where "safe" means not locking every user out).
// Never read or write vault3_platform_setting ad hoc; go through these.

// PublicRegistrationEnabled gates /join self-signup. Defaults false on
// missing/error so a broken settings table cannot silently open signup.
func (r *Runtime) PublicRegistrationEnabled(ctx context.Context) bool {
	return r.boolSetting(ctx, config.PublicRegistrationSettingKey, false)
}

// EmailSendingEnabled gates all outbound email. Defaults false on
// missing/error so a misconfigured stack never emails anyone by accident.
func (r *Runtime) EmailSendingEnabled(ctx context.Context) bool {
	return r.boolSetting(ctx, config.EmailSendingSettingKey, false)
}

// EmailVerificationRequired decides whether sign-in refuses unverified
// accounts. Defaults false on missing/error: enforcing verification while
// email delivery is broken would lock users out of their own vaults.
func (r *Runtime) EmailVerificationRequired(ctx context.Context) bool {
	return r.boolSetting(ctx, config.EmailVerificationRequiredSettingKey, false)
}

func (r *Runtime) boolSetting(ctx context.Context, key string, fallback bool) bool {
	value, lookupErr := database.SelectPlatformSettingValue(ctx, r.GetDb(), &r.Builder, key)
	if lookupErr != nil {
		if !errors.Is(lookupErr, sql.ErrNoRows) {
			r.Log.Warn("platform setting lookup failed", zap.String("key", key), zap.Error(lookupErr))
		}
		return fallback
	}
	return value == "true"
}
