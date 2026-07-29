package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"vault3/internal/models"

	sq "github.com/Masterminds/squirrel"
)

// InsertVaultInvite persists a new invite (token already hashed by the
// caller; the raw token is returned to the inviter exactly once).
func InsertVaultInvite(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	invite *models.VaultInvite,
) error {
	sqlStr, args, sqlErr := builder.
		Insert(`"vault3_vault_invite"`).
		Columns(
			`"Vault3VaultInviteID"`,
			`"Vault3VaultInviteVaultID"`,
			`"Vault3VaultInviteCreatedByUserID"`,
			`"Vault3VaultInviteTokenHash"`,
			`"Vault3VaultInviteWrappedVaultKey"`,
			`"Vault3VaultInviteRole"`,
			`"Vault3VaultInviteExpiresAt"`,
		).
		Values(
			invite.ID,
			invite.VaultID,
			invite.CreatedByUserID,
			invite.TokenHash,
			[]byte(invite.WrappedVaultKey),
			invite.Role,
			invite.ExpiresAt,
		).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build insert vault invite: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("insert vault invite: %w", execErr)
	}
	return nil
}

// SelectVaultInvites returns a vault's pending (live) invites, newest first,
// for the members dialog.
func SelectVaultInvites(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	vaultID string,
) ([]models.VaultInvite, error) {
	sqlStr, args, sqlErr := vaultInviteSelect(builder).
		Where(sq.Eq{`"Vault3VaultInviteVaultID"`: vaultID}).
		Where(sq.Expr(`"Vault3VaultInviteAcceptedAt" IS NULL`)).
		Where(sq.Expr(`"Vault3VaultInviteRevokedAt" IS NULL`)).
		Where(sq.Expr(`"Vault3VaultInviteExpiresAt" > now()`)).
		OrderBy(`"Vault3VaultInviteCreatedAt" DESC`).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build vault invites query: %w", sqlErr)
	}

	rows, queryErr := db.QueryContext(ctx, sqlStr, args...)
	if queryErr != nil {
		return nil, queryErr
	}
	defer rows.Close()

	out := make([]models.VaultInvite, 0)
	for rows.Next() {
		invite, scanErr := scanVaultInvite(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, *invite)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, rowsErr
	}
	return out, nil
}

// SelectVaultInviteByID loads one invite. Returns sql.ErrNoRows when absent.
func SelectVaultInviteByID(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	inviteID string,
) (*models.VaultInvite, error) {
	sqlStr, args, sqlErr := vaultInviteSelect(builder).
		Where(sq.Eq{`"Vault3VaultInviteID"`: inviteID}).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build vault invite query: %w", sqlErr)
	}
	invite, scanErr := scanVaultInvite(db.QueryRowContext(ctx, sqlStr, args...))
	if scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("select vault invite: %w", scanErr)
	}
	return invite, nil
}

// SelectLiveVaultInviteByTokenHash resolves a pending invite for the accept
// page's preview. Missing, revoked, expired and already-accepted invites all
// return sql.ErrNoRows — indistinguishable by design.
func SelectLiveVaultInviteByTokenHash(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	tokenHash string,
) (*models.VaultInvite, error) {
	sqlStr, args, sqlErr := vaultInviteSelect(builder).
		Where(sq.Eq{`"Vault3VaultInviteTokenHash"`: tokenHash}).
		Where(sq.Expr(`"Vault3VaultInviteAcceptedAt" IS NULL`)).
		Where(sq.Expr(`"Vault3VaultInviteRevokedAt" IS NULL`)).
		Where(sq.Expr(`"Vault3VaultInviteExpiresAt" > now()`)).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build live invite query: %w", sqlErr)
	}
	invite, scanErr := scanVaultInvite(db.QueryRowContext(ctx, sqlStr, args...))
	if scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("select live vault invite: %w", scanErr)
	}
	return invite, nil
}

// ClaimVaultInvite atomically marks a live invite accepted by one user —
// the WHERE clause is the claim, so two racing accepts cannot both succeed.
// Returns the claimed invite or sql.ErrNoRows if it was no longer live.
func ClaimVaultInvite(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	tokenHash string,
	acceptedByUserID string,
) (*models.VaultInvite, error) {
	sqlStr, args, sqlErr := builder.
		Update(`"vault3_vault_invite"`).
		Set(`"Vault3VaultInviteAcceptedAt"`, sq.Expr(`now()`)).
		Set(`"Vault3VaultInviteAcceptedByUserID"`, acceptedByUserID).
		Where(sq.Eq{`"Vault3VaultInviteTokenHash"`: tokenHash}).
		Where(sq.Expr(`"Vault3VaultInviteAcceptedAt" IS NULL`)).
		Where(sq.Expr(`"Vault3VaultInviteRevokedAt" IS NULL`)).
		Where(sq.Expr(`"Vault3VaultInviteExpiresAt" > now()`)).
		Suffix(`RETURNING "Vault3VaultInviteID", "Vault3VaultInviteVaultID", "Vault3VaultInviteCreatedByUserID",
			"Vault3VaultInviteTokenHash", "Vault3VaultInviteWrappedVaultKey", "Vault3VaultInviteRole",
			"Vault3VaultInviteExpiresAt", "Vault3VaultInviteRevokedAt", "Vault3VaultInviteAcceptedAt",
			"Vault3VaultInviteAcceptedByUserID", "Vault3VaultInviteCreatedAt"`).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build claim vault invite: %w", sqlErr)
	}
	invite, scanErr := scanVaultInvite(db.QueryRowContext(ctx, sqlStr, args...))
	if scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("claim vault invite: %w", scanErr)
	}
	return invite, nil
}

// RevokeVaultInvite kills a pending invite. Idempotent.
func RevokeVaultInvite(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	inviteID string,
) error {
	sqlStr, args, sqlErr := builder.
		Update(`"vault3_vault_invite"`).
		Set(`"Vault3VaultInviteRevokedAt"`, sq.Expr(`now()`)).
		Where(sq.Eq{`"Vault3VaultInviteID"`: inviteID}).
		Where(sq.Expr(`"Vault3VaultInviteRevokedAt" IS NULL`)).
		Where(sq.Expr(`"Vault3VaultInviteAcceptedAt" IS NULL`)).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build revoke vault invite: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("revoke vault invite: %w", execErr)
	}
	return nil
}

// CountActiveVaultInvites counts a vault's live invites, enforcing the
// per-vault cap before an insert.
func CountActiveVaultInvites(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	vaultID string,
) (int, error) {
	sqlStr, args, sqlErr := builder.
		Select(`COUNT(*)`).
		From(`"vault3_vault_invite"`).
		Where(sq.Eq{`"Vault3VaultInviteVaultID"`: vaultID}).
		Where(sq.Expr(`"Vault3VaultInviteAcceptedAt" IS NULL`)).
		Where(sq.Expr(`"Vault3VaultInviteRevokedAt" IS NULL`)).
		Where(sq.Expr(`"Vault3VaultInviteExpiresAt" > now()`)).
		ToSql()
	if sqlErr != nil {
		return 0, fmt.Errorf("build count vault invites: %w", sqlErr)
	}
	var count int
	if scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(&count); scanErr != nil {
		return 0, fmt.Errorf("count vault invites: %w", scanErr)
	}
	return count, nil
}

func vaultInviteSelect(builder *sq.StatementBuilderType) sq.SelectBuilder {
	return builder.
		Select(
			`"Vault3VaultInviteID"`,
			`"Vault3VaultInviteVaultID"`,
			`"Vault3VaultInviteCreatedByUserID"`,
			`"Vault3VaultInviteTokenHash"`,
			`"Vault3VaultInviteWrappedVaultKey"`,
			`"Vault3VaultInviteRole"`,
			`"Vault3VaultInviteExpiresAt"`,
			`"Vault3VaultInviteRevokedAt"`,
			`"Vault3VaultInviteAcceptedAt"`,
			`"Vault3VaultInviteAcceptedByUserID"`,
			`"Vault3VaultInviteCreatedAt"`,
		).
		From(`"vault3_vault_invite"`)
}

func scanVaultInvite(row rowScanner) (*models.VaultInvite, error) {
	invite := &models.VaultInvite{}
	scanErr := row.Scan(
		&invite.ID,
		&invite.VaultID,
		&invite.CreatedByUserID,
		&invite.TokenHash,
		&invite.WrappedVaultKey,
		&invite.Role,
		&invite.ExpiresAt,
		&invite.RevokedAt,
		&invite.AcceptedAt,
		&invite.AcceptedByUserID,
		&invite.CreatedAt,
	)
	if scanErr != nil {
		return nil, scanErr
	}
	return invite, nil
}
