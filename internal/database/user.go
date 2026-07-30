package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"vault3/internal/crypto"
	"vault3/internal/models"

	sq "github.com/Masterminds/squirrel"
)

// userLookupColumns is the allowlist of lookup keys accepted by
// SelectUserFullByKeyValue. Values are pre-quoted column identifiers so that
// PostgreSQL preserves their case. Anything outside this set is rejected
// before reaching SQL.
var userLookupColumns = map[string]string{
	"id":    `"Vault3UserID"`,
	"email": `"Vault3UserEmail"`,
}

// SelectUserFullByKeyValue returns the full hub-and-spoke view of a
// vault3_user, looked up by one column/value pair. Supported keys:
//
//   - "id"    -> Vault3UserID
//   - "email" -> Vault3UserEmail
//
// The "full" view bundles the user row plus the auth row (1:1), the keypair
// row (1:1), the admin row if present, and the user's vault access rows each
// paired with its vault. Missing spokes are nil, not an error. The cipher
// decrypts the display name; auth secrets stay encrypted on the struct.
//
// Returns sql.ErrNoRows if no hub row matches.
func SelectUserFullByKeyValue(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cipher *crypto.FieldCipher,
	key string,
	value any,
) (*models.UserFull, error) {
	column, ok := userLookupColumns[strings.ToLower(key)]
	if !ok {
		return nil, fmt.Errorf("unsupported user lookup key: %q", key)
	}

	user, userErr := selectUserRowByColumn(ctx, db, builder, cipher, column, value)
	if userErr != nil {
		return nil, userErr
	}

	full := &models.UserFull{User: *user}

	auth, authErr := SelectUserAuthRow(ctx, db, builder, user.ID)
	if authErr != nil && !errors.Is(authErr, sql.ErrNoRows) {
		return nil, fmt.Errorf("select user auth: %w", authErr)
	}
	if authErr == nil {
		full.Auth = auth
	}

	admin, adminErr := selectAdminRow(ctx, db, builder, user.ID)
	if adminErr != nil && !errors.Is(adminErr, sql.ErrNoRows) {
		return nil, fmt.Errorf("select admin: %w", adminErr)
	}
	if adminErr == nil {
		full.Admin = admin
	}

	vaults, vaultsErr := SelectUserVaults(ctx, db, builder, user.ID)
	if vaultsErr != nil {
		return nil, fmt.Errorf("select user vaults: %w", vaultsErr)
	}
	full.Vaults = vaults

	return full, nil
}

func selectUserRowByColumn(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cipher *crypto.FieldCipher,
	column string,
	value any,
) (*models.User, error) {
	sqlStr, args, sqlErr := builder.
		Select(
			`"Vault3UserID"`,
			`"Vault3UserEmail"`,
			`COALESCE("Vault3UserDisplayNameEnc", '')`,
			`"Vault3UserNotificationPrefs"`,
			`"Vault3UserRevision"`,
			`"Vault3UserIsActive"`,
			`"Vault3UserLastLoginAt"`,
			`"Vault3UserArchivedAt"`,
			`COALESCE("Vault3UserArchivedReason", '')`,
			`"Vault3UserCreatedAt"`,
			`"Vault3UserUpdatedAt"`,
		).
		From(`"vault3_user"`).
		Where(sq.Eq{column: value}).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build user query: %w", sqlErr)
	}

	u := &models.User{}
	var displayNameEnc string
	scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(
		&u.ID,
		&u.Email,
		&displayNameEnc,
		&u.NotificationPrefs,
		&u.Revision,
		&u.IsActive,
		&u.LastLoginAt,
		&u.ArchivedAt,
		&u.ArchivedReason,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	if scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("select user: %w", scanErr)
	}

	displayName, decryptErr := cipher.DecryptString(displayNameEnc)
	if decryptErr != nil {
		return nil, fmt.Errorf("decrypt display name: %w", decryptErr)
	}
	u.DisplayName = displayName
	return u, nil
}

// SelectUserAuthRow loads the full auth spoke. Secrets stay in their stored
// (encrypted/hashed) form on the struct; only the handlers that need the TOTP
// secret decrypt it, via the runtime's cipher.
func SelectUserAuthRow(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
) (*models.UserAuth, error) {
	sqlStr, args, sqlErr := builder.
		Select(
			`"Vault3UserAuthUserID"`,
			`"Vault3UserAuthAuthKeyHash"`,
			`"Vault3UserAuthKdfSalt"`,
			`"Vault3UserAuthKdfIterations"`,
			`"Vault3UserAuthArgon2MemoryKiB"`,
			`"Vault3UserAuthArgon2Time"`,
			`"Vault3UserAuthArgon2Lanes"`,
			`"Vault3UserAuthLastPasswordChangeAt"`,
			`COALESCE("Vault3UserAuthTwoFactorSecretEnc", '')`,
			`COALESCE("Vault3UserAuthTempTwoFactorSecretEnc", '')`,
			`"Vault3UserAuthEmailVerified"`,
			`COALESCE("Vault3UserAuthEmailVerificationTokenHash", '')`,
			`"Vault3UserAuthEmailVerificationTokenExpiry"`,
			`"Vault3UserAuthUpdatedAt"`,
		).
		From(`"vault3_user_auth"`).
		Where(sq.Eq{`"Vault3UserAuthUserID"`: userID}).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build user_auth query: %w", sqlErr)
	}

	a := &models.UserAuth{}
	scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(
		&a.UserID,
		&a.AuthKeyHash,
		&a.KdfSalt,
		&a.KdfIterations,
		&a.Argon2MemoryKiB,
		&a.Argon2Time,
		&a.Argon2Lanes,
		&a.LastPasswordChangeAt,
		&a.TwoFactorSecretEnc,
		&a.TempTwoFactorSecretEnc,
		&a.EmailVerified,
		&a.EmailVerificationTokenHash,
		&a.EmailVerificationTokenExpiry,
		&a.UpdatedAt,
	)
	if scanErr != nil {
		return nil, scanErr
	}
	return a, nil
}

func selectAdminRow(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
) (*models.Admin, error) {
	sqlStr, args, sqlErr := builder.
		Select(
			`"Vault3AdminUserID"`,
			`"Vault3AdminGrantedAt"`,
			`COALESCE("Vault3AdminGrantedByUserID"::text, '')`,
			`COALESCE("Vault3AdminNotes", '')`,
		).
		From(`"vault3_admin"`).
		Where(sq.Eq{`"Vault3AdminUserID"`: userID}).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build admin query: %w", sqlErr)
	}

	a := &models.Admin{}
	scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(
		&a.UserID,
		&a.GrantedAt,
		&a.GrantedByUserID,
		&a.Notes,
	)
	if scanErr != nil {
		return nil, scanErr
	}
	return a, nil
}
