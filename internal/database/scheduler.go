package database

import (
	"context"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
)

// Job SQL for cmd/scheduler (see internal/jobs). Every helper here is
// idempotent: the WHERE clause is the claim, so a missed or repeated run only
// ever costs a little extra work.

// DeleteExpiredSessions removes session rows past their expiry, returning how
// many were purged.
func DeleteExpiredSessions(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
) (int64, error) {
	sqlStr, args, sqlErr := builder.
		Delete(`"vault3_session"`).
		Where(sq.Expr(`"Vault3SessionExpiresAt" <= now()`)).
		ToSql()
	if sqlErr != nil {
		return 0, fmt.Errorf("build delete expired sessions: %w", sqlErr)
	}
	result, execErr := db.ExecContext(ctx, sqlStr, args...)
	if execErr != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", execErr)
	}
	affected, _ := result.RowsAffected()
	return affected, nil
}

// PurgeTrashedItems permanently deletes items trashed before the cutoff,
// returning how many were purged.
func PurgeTrashedItems(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cutoff time.Time,
) (int64, error) {
	sqlStr, args, sqlErr := builder.
		Delete(`"vault3_item"`).
		Where(sq.Expr(`"Vault3ItemDeletedAt" IS NOT NULL`)).
		Where(sq.Lt{`"Vault3ItemDeletedAt"`: cutoff}).
		ToSql()
	if sqlErr != nil {
		return 0, fmt.Errorf("build purge trashed items: %w", sqlErr)
	}
	result, execErr := db.ExecContext(ctx, sqlStr, args...)
	if execErr != nil {
		return 0, fmt.Errorf("purge trashed items: %w", execErr)
	}
	affected, _ := result.RowsAffected()
	return affected, nil
}

// PurgeLapsedShareLinks deletes share links that expired or were revoked
// before the cutoff (a short grace so the owner's dialog can still show
// "expired" briefly), returning how many were purged.
func PurgeLapsedShareLinks(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cutoff time.Time,
) (int64, error) {
	sqlStr, args, sqlErr := builder.
		Delete(`"vault3_share_link"`).
		Where(sq.Or{
			sq.Lt{`"Vault3ShareLinkExpiresAt"`: cutoff},
			sq.Lt{`"Vault3ShareLinkRevokedAt"`: cutoff},
		}).
		ToSql()
	if sqlErr != nil {
		return 0, fmt.Errorf("build purge share links: %w", sqlErr)
	}
	result, execErr := db.ExecContext(ctx, sqlStr, args...)
	if execErr != nil {
		return 0, fmt.Errorf("purge share links: %w", execErr)
	}
	affected, _ := result.RowsAffected()
	return affected, nil
}

// PurgeLapsedVaultInvites deletes invites that expired, were revoked, or
// were accepted before the cutoff, returning how many were purged.
func PurgeLapsedVaultInvites(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cutoff time.Time,
) (int64, error) {
	sqlStr, args, sqlErr := builder.
		Delete(`"vault3_vault_invite"`).
		Where(sq.Or{
			sq.Lt{`"Vault3VaultInviteExpiresAt"`: cutoff},
			sq.Lt{`"Vault3VaultInviteRevokedAt"`: cutoff},
			sq.Lt{`"Vault3VaultInviteAcceptedAt"`: cutoff},
		}).
		ToSql()
	if sqlErr != nil {
		return 0, fmt.Errorf("build purge vault invites: %w", sqlErr)
	}
	result, execErr := db.ExecContext(ctx, sqlStr, args...)
	if execErr != nil {
		return 0, fmt.Errorf("purge vault invites: %w", execErr)
	}
	affected, _ := result.RowsAffected()
	return affected, nil
}

// ClearExpiredAuthTokens nulls out lapsed email-verification tokens so stale
// hashes do not linger indefinitely, returning how many rows changed.
func ClearExpiredAuthTokens(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
) (int64, error) {
	sqlStr, args, sqlErr := builder.
		Update(`"vault3_user_auth"`).
		Set(`"Vault3UserAuthEmailVerificationTokenHash"`, nil).
		Set(`"Vault3UserAuthEmailVerificationTokenExpiry"`, nil).
		Where(sq.Expr(`"Vault3UserAuthEmailVerificationTokenExpiry" <= now()`)).
		ToSql()
	if sqlErr != nil {
		return 0, fmt.Errorf("build clear expired tokens: %w", sqlErr)
	}
	result, execErr := db.ExecContext(ctx, sqlStr, args...)
	if execErr != nil {
		return 0, fmt.Errorf("clear expired tokens: %w", execErr)
	}
	affected, _ := result.RowsAffected()
	return affected, nil
}
