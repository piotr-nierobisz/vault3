package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"vault3/internal/crypto"
	"vault3/internal/models"

	sq "github.com/Masterminds/squirrel"
)

// SelectUserVaults returns the user's vault access rows joined with their
// vaults (one level of FK hydration), oldest first so the personal vault
// created at registration is always first.
func SelectUserVaults(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
) ([]models.UserVault, error) {
	sqlStr, args, sqlErr := builder.
		Select(
			`a."Vault3VaultAccessID"`,
			`a."Vault3VaultAccessVaultID"`,
			`a."Vault3VaultAccessUserID"`,
			`a."Vault3VaultAccessRole"`,
			`a."Vault3VaultAccessWrapAlgo"`,
			`a."Vault3VaultAccessWrappedKey"`,
			`a."Vault3VaultAccessCreatedAt"`,
			`a."Vault3VaultAccessUpdatedAt"`,
			`v."Vault3VaultID"`,
			`v."Vault3VaultOwnerUserID"`,
			`v."Vault3VaultKind"`,
			`v."Vault3VaultEncName"`,
			`v."Vault3VaultCreatedAt"`,
			`v."Vault3VaultUpdatedAt"`,
			`v."Vault3VaultArchivedAt"`,
			`(SELECT COUNT(*) FROM "vault3_vault_access" m
				WHERE m."Vault3VaultAccessVaultID" = v."Vault3VaultID") AS "MemberCount"`,
		).
		From(`"vault3_vault_access" a`).
		Join(`"vault3_vault" v ON v."Vault3VaultID" = a."Vault3VaultAccessVaultID"`).
		Where(sq.Eq{`a."Vault3VaultAccessUserID"`: userID}).
		Where(sq.Expr(`v."Vault3VaultArchivedAt" IS NULL`)).
		OrderBy(`v."Vault3VaultCreatedAt" ASC`).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build user vaults query: %w", sqlErr)
	}

	rows, queryErr := db.QueryContext(ctx, sqlStr, args...)
	if queryErr != nil {
		return nil, queryErr
	}
	defer rows.Close()

	out := make([]models.UserVault, 0)
	for rows.Next() {
		var uv models.UserVault
		scanErr := rows.Scan(
			&uv.Access.ID,
			&uv.Access.VaultID,
			&uv.Access.UserID,
			&uv.Access.Role,
			&uv.Access.WrapAlgo,
			&uv.Access.WrappedKey,
			&uv.Access.CreatedAt,
			&uv.Access.UpdatedAt,
			&uv.Vault.ID,
			&uv.Vault.OwnerUserID,
			&uv.Vault.Kind,
			&uv.Vault.EncName,
			&uv.Vault.CreatedAt,
			&uv.Vault.UpdatedAt,
			&uv.Vault.ArchivedAt,
			&uv.MemberCount,
		)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, uv)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, rowsErr
	}
	return out, nil
}

// SelectVaultAccess returns the access row binding a user to a vault — the
// authorisation check every item mutation runs first. Returns sql.ErrNoRows
// when the user has no access to that vault.
func SelectVaultAccess(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
	vaultID string,
) (*models.VaultAccess, error) {
	sqlStr, args, sqlErr := builder.
		Select(
			`"Vault3VaultAccessID"`,
			`"Vault3VaultAccessVaultID"`,
			`"Vault3VaultAccessUserID"`,
			`"Vault3VaultAccessRole"`,
			`"Vault3VaultAccessWrapAlgo"`,
			`"Vault3VaultAccessWrappedKey"`,
			`"Vault3VaultAccessCreatedAt"`,
			`"Vault3VaultAccessUpdatedAt"`,
		).
		From(`"vault3_vault_access"`).
		Where(sq.Eq{
			`"Vault3VaultAccessUserID"`:  userID,
			`"Vault3VaultAccessVaultID"`: vaultID,
		}).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build vault access query: %w", sqlErr)
	}

	a := &models.VaultAccess{}
	scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(
		&a.ID,
		&a.VaultID,
		&a.UserID,
		&a.Role,
		&a.WrapAlgo,
		&a.WrappedKey,
		&a.CreatedAt,
		&a.UpdatedAt,
	)
	if scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("select vault access: %w", scanErr)
	}
	return a, nil
}

// InsertVault creates a vault hub row.
func InsertVault(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	vault *models.Vault,
) error {
	sqlStr, args, sqlErr := builder.
		Insert(`"vault3_vault"`).
		Columns(
			`"Vault3VaultID"`,
			`"Vault3VaultOwnerUserID"`,
			`"Vault3VaultKind"`,
			`"Vault3VaultEncName"`,
		).
		Values(
			vault.ID,
			vault.OwnerUserID,
			vault.Kind,
			[]byte(vault.EncName),
		).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build insert vault: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("insert vault: %w", execErr)
	}
	return nil
}

// InsertVaultAccess grants a user access to a vault with their wrapped copy
// of the vault key.
func InsertVaultAccess(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	access *models.VaultAccess,
) error {
	sqlStr, args, sqlErr := builder.
		Insert(`"vault3_vault_access"`).
		Columns(
			`"Vault3VaultAccessID"`,
			`"Vault3VaultAccessVaultID"`,
			`"Vault3VaultAccessUserID"`,
			`"Vault3VaultAccessRole"`,
			`"Vault3VaultAccessWrapAlgo"`,
			`"Vault3VaultAccessWrappedKey"`,
		).
		Values(
			access.ID,
			access.VaultID,
			access.UserID,
			access.Role,
			access.WrapAlgo,
			[]byte(access.WrappedKey),
		).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build insert vault access: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("insert vault access: %w", execErr)
	}
	return nil
}

// UpdateVaultAccessWrappedKey replaces one access row's wrapped vault key —
// the per-vault half of a Master Password change, running in the same
// transaction as UpdateUserAuthCredentials.
func UpdateVaultAccessWrappedKey(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
	vaultID string,
	wrappedKey []byte,
) error {
	sqlStr, args, sqlErr := builder.
		Update(`"vault3_vault_access"`).
		Set(`"Vault3VaultAccessWrappedKey"`, wrappedKey).
		Set(`"Vault3VaultAccessUpdatedAt"`, sq.Expr(`now()`)).
		Where(sq.Eq{
			`"Vault3VaultAccessUserID"`:  userID,
			`"Vault3VaultAccessVaultID"`: vaultID,
		}).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build update wrapped key: %w", sqlErr)
	}
	// Scoped to (user, vault), so zero rows means the caller asked to re-wrap
	// a vault this account cannot open. During a Master Password change that
	// must abort the transaction: letting it pass would rotate the
	// credentials while leaving a vault key sealed under the old MUK, which
	// no one — the server least of all — could ever unwrap again.
	return execExpectingRow(ctx, db, sqlStr, args, "update wrapped key")
}

// SelectVaultByID loads one vault hub row. Returns sql.ErrNoRows when
// absent; callers authorise separately via SelectVaultAccess.
func SelectVaultByID(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	vaultID string,
) (*models.Vault, error) {
	sqlStr, args, sqlErr := builder.
		Select(
			`"Vault3VaultID"`,
			`"Vault3VaultOwnerUserID"`,
			`"Vault3VaultKind"`,
			`"Vault3VaultEncName"`,
			`"Vault3VaultCreatedAt"`,
			`"Vault3VaultUpdatedAt"`,
			`"Vault3VaultArchivedAt"`,
		).
		From(`"vault3_vault"`).
		Where(sq.Eq{`"Vault3VaultID"`: vaultID}).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build vault query: %w", sqlErr)
	}
	v := &models.Vault{}
	scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(
		&v.ID,
		&v.OwnerUserID,
		&v.Kind,
		&v.EncName,
		&v.CreatedAt,
		&v.UpdatedAt,
		&v.ArchivedAt,
	)
	if scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("select vault: %w", scanErr)
	}
	return v, nil
}

// UpdateVaultEncName replaces a vault's client-encrypted name (sealed under
// the vault key, so every member can still read it).
func UpdateVaultEncName(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	vaultID string,
	encName []byte,
) error {
	sqlStr, args, sqlErr := builder.
		Update(`"vault3_vault"`).
		Set(`"Vault3VaultEncName"`, encName).
		Set(`"Vault3VaultUpdatedAt"`, sq.Expr(`now()`)).
		Where(sq.Eq{`"Vault3VaultID"`: vaultID}).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build update vault name: %w", sqlErr)
	}
	return execExpectingRow(ctx, db, sqlStr, args, "update vault name")
}

// UpdateVaultKind flips a vault between 'personal' and 'shared' as members
// join and leave, so the stored kind always reflects reality.
func UpdateVaultKind(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	vaultID string,
	kind string,
) error {
	sqlStr, args, sqlErr := builder.
		Update(`"vault3_vault"`).
		Set(`"Vault3VaultKind"`, kind).
		Set(`"Vault3VaultUpdatedAt"`, sq.Expr(`now()`)).
		Where(sq.Eq{`"Vault3VaultID"`: vaultID}).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build update vault kind: %w", sqlErr)
	}
	return execExpectingRow(ctx, db, sqlStr, args, "update vault kind")
}

// DeleteVault removes one vault (items, access rows and invites cascade).
func DeleteVault(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	vaultID string,
) error {
	sqlStr, args, sqlErr := builder.
		Delete(`"vault3_vault"`).
		Where(sq.Eq{`"Vault3VaultID"`: vaultID}).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build delete vault: %w", sqlErr)
	}
	return execExpectingRow(ctx, db, sqlStr, args, "delete vault")
}

// SelectVaultMembers returns everyone with access to a vault (owner first,
// then by join date) with decrypted display names for the members dialog.
func SelectVaultMembers(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cipher *crypto.FieldCipher,
	vaultID string,
) ([]models.VaultMember, error) {
	sqlStr, args, sqlErr := builder.
		Select(
			`a."Vault3VaultAccessUserID"`,
			`u."Vault3UserEmail"`,
			`COALESCE(u."Vault3UserDisplayNameEnc", '')`,
			`a."Vault3VaultAccessRole"`,
			`a."Vault3VaultAccessCreatedAt"`,
		).
		From(`"vault3_vault_access" a`).
		Join(`"vault3_user" u ON u."Vault3UserID" = a."Vault3VaultAccessUserID"`).
		Where(sq.Eq{`a."Vault3VaultAccessVaultID"`: vaultID}).
		OrderBy(`a."Vault3VaultAccessRole" DESC`, `a."Vault3VaultAccessCreatedAt" ASC`).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build vault members query: %w", sqlErr)
	}

	rows, queryErr := db.QueryContext(ctx, sqlStr, args...)
	if queryErr != nil {
		return nil, queryErr
	}
	defer rows.Close()

	out := make([]models.VaultMember, 0)
	for rows.Next() {
		var m models.VaultMember
		var displayNameEnc string
		if scanErr := rows.Scan(&m.UserID, &m.Email, &displayNameEnc, &m.Role, &m.JoinedAt); scanErr != nil {
			return nil, scanErr
		}
		displayName, decryptErr := cipher.DecryptString(displayNameEnc)
		if decryptErr != nil {
			return nil, fmt.Errorf("decrypt member display name: %w", decryptErr)
		}
		m.DisplayName = displayName
		out = append(out, m)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, rowsErr
	}
	return out, nil
}

// SelectVaultUserIDs returns every user with access to a vault — the
// audience of a vault-scoped change signal.
func SelectVaultUserIDs(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	vaultID string,
) ([]string, error) {
	sqlStr, args, sqlErr := builder.
		Select(`"Vault3VaultAccessUserID"`).
		From(`"vault3_vault_access"`).
		Where(sq.Eq{`"Vault3VaultAccessVaultID"`: vaultID}).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build vault user ids query: %w", sqlErr)
	}
	rows, queryErr := db.QueryContext(ctx, sqlStr, args...)
	if queryErr != nil {
		return nil, queryErr
	}
	defer rows.Close()

	out := make([]string, 0)
	for rows.Next() {
		var id string
		if scanErr := rows.Scan(&id); scanErr != nil {
			return nil, scanErr
		}
		out = append(out, id)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, rowsErr
	}
	return out, nil
}

// DeleteVaultAccess removes one user's access row (owner removes a member,
// or a member leaves).
func DeleteVaultAccess(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	vaultID string,
	userID string,
) error {
	sqlStr, args, sqlErr := builder.
		Delete(`"vault3_vault_access"`).
		Where(sq.Eq{
			`"Vault3VaultAccessVaultID"`: vaultID,
			`"Vault3VaultAccessUserID"`:  userID,
		}).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build delete vault access: %w", sqlErr)
	}
	// Both ids come from the request body, so this is the write most exposed
	// to a caller that skipped its authorisation check.
	return execExpectingRow(ctx, db, sqlStr, args, "delete vault access")
}

// CountVaultMembers counts a vault's access rows (owner included).
func CountVaultMembers(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	vaultID string,
) (int, error) {
	sqlStr, args, sqlErr := builder.
		Select(`COUNT(*)`).
		From(`"vault3_vault_access"`).
		Where(sq.Eq{`"Vault3VaultAccessVaultID"`: vaultID}).
		ToSql()
	if sqlErr != nil {
		return 0, fmt.Errorf("build count vault members: %w", sqlErr)
	}
	var count int
	if scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(&count); scanErr != nil {
		return 0, fmt.Errorf("count vault members: %w", scanErr)
	}
	return count, nil
}

// CountUserVaults counts the vaults a user can reach, enforcing the
// per-account cap before a create or accept.
func CountUserVaults(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
) (int, error) {
	sqlStr, args, sqlErr := builder.
		Select(`COUNT(*)`).
		From(`"vault3_vault_access"`).
		Where(sq.Eq{`"Vault3VaultAccessUserID"`: userID}).
		ToSql()
	if sqlErr != nil {
		return 0, fmt.Errorf("build count user vaults: %w", sqlErr)
	}
	var count int
	if scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(&count); scanErr != nil {
		return 0, fmt.Errorf("count user vaults: %w", scanErr)
	}
	return count, nil
}
