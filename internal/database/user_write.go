package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"vault3/internal/crypto"
	"vault3/internal/models"

	sq "github.com/Masterminds/squirrel"
)

// SelectUserIDByEmail returns the id of any user with this email, regardless
// of active/archived state, so registration can detect an email that is
// already taken (vault3_user.Email is UNIQUE). Returns sql.ErrNoRows when
// none exists.
func SelectUserIDByEmail(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	email string,
) (string, error) {
	sqlStr, args, sqlErr := builder.
		Select(`"Vault3UserID"`).
		From(`"vault3_user"`).
		Where(sq.Eq{`"Vault3UserEmail"`: email}).
		ToSql()
	if sqlErr != nil {
		return "", fmt.Errorf("build select user id by email: %w", sqlErr)
	}
	var id string
	scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(&id)
	if scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return "", sql.ErrNoRows
		}
		return "", fmt.Errorf("select user id by email: %w", scanErr)
	}
	return id, nil
}

// InsertUser creates a user row. Email must already be lower-cased (enforced
// by a column CHECK). DisplayName is encrypted here through the cipher;
// notification prefs are written from the model so registration can persist
// the defaults explicitly.
func InsertUser(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cipher *crypto.FieldCipher,
	user *models.User,
) error {
	displayNameEnc, encErr := cipher.EncryptString(user.DisplayName)
	if encErr != nil {
		return fmt.Errorf("encrypt display name: %w", encErr)
	}
	sqlStr, args, sqlErr := builder.
		Insert(`"vault3_user"`).
		Columns(
			`"Vault3UserID"`,
			`"Vault3UserEmail"`,
			`"Vault3UserDisplayNameEnc"`,
			`"Vault3UserNotificationPrefs"`,
			`"Vault3UserIsActive"`,
		).
		Values(
			user.ID,
			user.Email,
			nullIfEmptyString(displayNameEnc),
			user.NotificationPrefs,
			user.IsActive,
		).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build insert user: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("insert user: %w", execErr)
	}
	return nil
}

// InsertUserAuth creates the auth row paired 1:1 with a user, carrying the
// bcrypt of the client-derived auth key and the public KDF parameters.
func InsertUserAuth(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	auth *models.UserAuth,
) error {
	sqlStr, args, sqlErr := builder.
		Insert(`"vault3_user_auth"`).
		Columns(
			`"Vault3UserAuthUserID"`,
			`"Vault3UserAuthAuthKeyHash"`,
			`"Vault3UserAuthKdfSalt"`,
			`"Vault3UserAuthKdfIterations"`,
			`"Vault3UserAuthEmailVerified"`,
		).
		Values(
			auth.UserID,
			auth.AuthKeyHash,
			auth.KdfSalt,
			auth.KdfIterations,
			auth.EmailVerified,
		).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build insert user auth: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("insert user auth: %w", execErr)
	}
	return nil
}

// InsertUserKeys stores the browser-generated keypair: public JWK in the
// clear, private key as client-side ciphertext.
func InsertUserKeys(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	keys *models.UserKeys,
) error {
	sqlStr, args, sqlErr := builder.
		Insert(`"vault3_user_keys"`).
		Columns(
			`"Vault3UserKeysUserID"`,
			`"Vault3UserKeysAlgo"`,
			`"Vault3UserKeysPublicKey"`,
			`"Vault3UserKeysEncPrivateKey"`,
		).
		Values(
			keys.UserID,
			keys.Algo,
			keys.PublicKey,
			keys.EncPrivateKey,
		).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build insert user keys: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("insert user keys: %w", execErr)
	}
	return nil
}

// BumpUserRevision increments the user's sync revision and returns the new
// value. Call inside the same transaction as the mutation it describes, so a
// rolled-back change never signals other devices.
func BumpUserRevision(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
) (int64, error) {
	sqlStr, args, sqlErr := builder.
		Update(`"vault3_user"`).
		Set(`"Vault3UserRevision"`, sq.Expr(`"Vault3UserRevision" + 1`)).
		Set(`"Vault3UserUpdatedAt"`, sq.Expr(`now()`)).
		Where(sq.Eq{`"Vault3UserID"`: userID}).
		Suffix(`RETURNING "Vault3UserRevision"`).
		ToSql()
	if sqlErr != nil {
		return 0, fmt.Errorf("build bump user revision: %w", sqlErr)
	}
	var revision int64
	if scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(&revision); scanErr != nil {
		return 0, fmt.Errorf("bump user revision: %w", scanErr)
	}
	return revision, nil
}

// SelectUserRevision returns the current sync revision, the polling/reconnect
// half of the change signal.
func SelectUserRevision(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
) (int64, error) {
	sqlStr, args, sqlErr := builder.
		Select(`"Vault3UserRevision"`).
		From(`"vault3_user"`).
		Where(sq.Eq{`"Vault3UserID"`: userID}).
		ToSql()
	if sqlErr != nil {
		return 0, fmt.Errorf("build select user revision: %w", sqlErr)
	}
	var revision int64
	if scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(&revision); scanErr != nil {
		return 0, fmt.Errorf("select user revision: %w", scanErr)
	}
	return revision, nil
}

// MarkUserLoggedIn updates last-login timestamp for a successful sign in.
func MarkUserLoggedIn(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
) error {
	return execUserUpdate(ctx, db, builder, userID, map[string]any{
		`"Vault3UserLastLoginAt"`: sq.Expr(`now()`),
	}, "mark user logged in")
}

// UpdateUserDisplayName re-encrypts and stores the display name.
func UpdateUserDisplayName(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cipher *crypto.FieldCipher,
	userID string,
	displayName string,
) error {
	displayNameEnc, encErr := cipher.EncryptString(displayName)
	if encErr != nil {
		return fmt.Errorf("encrypt display name: %w", encErr)
	}
	return execUserUpdate(ctx, db, builder, userID, map[string]any{
		`"Vault3UserDisplayNameEnc"`: nullIfEmptyString(displayNameEnc),
	}, "update display name")
}

// UpdateUserNotificationPrefs stores the canonical prefs blob.
func UpdateUserNotificationPrefs(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
	prefs []byte,
) error {
	return execUserUpdate(ctx, db, builder, userID, map[string]any{
		`"Vault3UserNotificationPrefs"`: prefs,
	}, "update notification prefs")
}

// DeleteUser removes the user hub row. Foreign keys cascade through auth,
// keys, vaults (and their items via vault3_vault), sessions and
// notifications, so account deletion is one statement.
func DeleteUser(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
) error {
	sqlStr, args, sqlErr := builder.
		Delete(`"vault3_user"`).
		Where(sq.Eq{`"Vault3UserID"`: userID}).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build delete user: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("delete user: %w", execErr)
	}
	return nil
}

// UpdateUserAuthCredentials replaces the auth key hash and KDF parameters —
// the server half of a Master Password change. The client re-wraps its vault
// keys in the same transaction (see UpdateVaultAccessWrappedKey), so the two
// can never diverge.
func UpdateUserAuthCredentials(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
	authKeyHash string,
	kdfSalt string,
	kdfIterations int,
) error {
	return execUserAuthUpdate(ctx, db, builder, userID, map[string]any{
		`"Vault3UserAuthAuthKeyHash"`:          authKeyHash,
		`"Vault3UserAuthKdfSalt"`:              kdfSalt,
		`"Vault3UserAuthKdfIterations"`:        kdfIterations,
		`"Vault3UserAuthLastPasswordChangeAt"`: sq.Expr(`now()`),
	}, "update auth credentials")
}

// SetEmailVerificationToken stores the hash + expiry of a fresh single-use
// verification token, replacing any previous one.
func SetEmailVerificationToken(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
	tokenHash string,
	expiry time.Time,
) error {
	return execUserAuthUpdate(ctx, db, builder, userID, map[string]any{
		`"Vault3UserAuthEmailVerificationTokenHash"`:   tokenHash,
		`"Vault3UserAuthEmailVerificationTokenExpiry"`: expiry,
	}, "set email verification token")
}

// RedeemEmailVerificationToken marks the account verified and clears the
// token, keyed by the token hash so redemption is single-use. Returns the
// user id, or sql.ErrNoRows when the token is unknown or expired.
func RedeemEmailVerificationToken(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	tokenHash string,
) (string, error) {
	sqlStr, args, sqlErr := builder.
		Update(`"vault3_user_auth"`).
		Set(`"Vault3UserAuthEmailVerified"`, true).
		Set(`"Vault3UserAuthEmailVerificationTokenHash"`, nil).
		Set(`"Vault3UserAuthEmailVerificationTokenExpiry"`, nil).
		Set(`"Vault3UserAuthUpdatedAt"`, sq.Expr(`now()`)).
		Where(sq.Eq{`"Vault3UserAuthEmailVerificationTokenHash"`: tokenHash}).
		Where(sq.Expr(`"Vault3UserAuthEmailVerificationTokenExpiry" > now()`)).
		Suffix(`RETURNING "Vault3UserAuthUserID"`).
		ToSql()
	if sqlErr != nil {
		return "", fmt.Errorf("build redeem verification token: %w", sqlErr)
	}
	var userID string
	scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(&userID)
	if scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return "", sql.ErrNoRows
		}
		return "", fmt.Errorf("redeem verification token: %w", scanErr)
	}
	return userID, nil
}

// SetAccountResetToken stores the hash + expiry of a fresh single-use
// account-reset token.
func SetAccountResetToken(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
	tokenHash string,
	expiry time.Time,
) error {
	return execUserAuthUpdate(ctx, db, builder, userID, map[string]any{
		`"Vault3UserAuthAccountResetTokenHash"`:   tokenHash,
		`"Vault3UserAuthAccountResetTokenExpiry"`: expiry,
	}, "set account reset token")
}

// SelectUserIDByResetTokenHash resolves a live (unexpired) account-reset
// token to its user. Returns sql.ErrNoRows when the token is unknown or
// expired; the token is cleared by the reset flow itself.
func SelectUserIDByResetTokenHash(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	tokenHash string,
) (string, error) {
	sqlStr, args, sqlErr := builder.
		Select(`"Vault3UserAuthUserID"`).
		From(`"vault3_user_auth"`).
		Where(sq.Eq{`"Vault3UserAuthAccountResetTokenHash"`: tokenHash}).
		Where(sq.Expr(`"Vault3UserAuthAccountResetTokenExpiry" > now()`)).
		ToSql()
	if sqlErr != nil {
		return "", fmt.Errorf("build select user by reset token: %w", sqlErr)
	}
	var userID string
	scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(&userID)
	if scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return "", sql.ErrNoRows
		}
		return "", fmt.Errorf("select user by reset token: %w", scanErr)
	}
	return userID, nil
}

// ResetAccountAuth replaces the account's entire credential set during a
// zero-knowledge account reset: new auth key hash, new KDF parameters, reset
// token cleared. The caller wipes vaults and replaces the keypair in the same
// transaction; redeeming the emailed token also proves inbox control, so the
// account comes out verified.
func ResetAccountAuth(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
	authKeyHash string,
	kdfSalt string,
	kdfIterations int,
) error {
	return execUserAuthUpdate(ctx, db, builder, userID, map[string]any{
		`"Vault3UserAuthAuthKeyHash"`:             authKeyHash,
		`"Vault3UserAuthKdfSalt"`:                 kdfSalt,
		`"Vault3UserAuthKdfIterations"`:           kdfIterations,
		`"Vault3UserAuthLastPasswordChangeAt"`:    sq.Expr(`now()`),
		`"Vault3UserAuthAccountResetTokenHash"`:   nil,
		`"Vault3UserAuthAccountResetTokenExpiry"`: nil,
		`"Vault3UserAuthEmailVerified"`:           true,
		`"Vault3UserAuthTwoFactorSecretEnc"`:      nil,
		`"Vault3UserAuthTempTwoFactorSecretEnc"`:  nil,
	}, "reset account auth")
}

// ReplaceUserKeys swaps the stored keypair for a new one (account reset, or a
// future key rotation).
func ReplaceUserKeys(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	keys *models.UserKeys,
) error {
	sqlStr, args, sqlErr := builder.
		Update(`"vault3_user_keys"`).
		Set(`"Vault3UserKeysAlgo"`, keys.Algo).
		Set(`"Vault3UserKeysPublicKey"`, []byte(keys.PublicKey)).
		Set(`"Vault3UserKeysEncPrivateKey"`, []byte(keys.EncPrivateKey)).
		Set(`"Vault3UserKeysUpdatedAt"`, sq.Expr(`now()`)).
		Where(sq.Eq{`"Vault3UserKeysUserID"`: keys.UserID}).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build replace user keys: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("replace user keys: %w", execErr)
	}
	return nil
}

// UpdateEncPrivateKey re-stores the private key ciphertext after the client
// re-encrypts it under a new key-encryption key (Master Password change).
func UpdateEncPrivateKey(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
	encPrivateKey []byte,
) error {
	sqlStr, args, sqlErr := builder.
		Update(`"vault3_user_keys"`).
		Set(`"Vault3UserKeysEncPrivateKey"`, encPrivateKey).
		Set(`"Vault3UserKeysUpdatedAt"`, sq.Expr(`now()`)).
		Where(sq.Eq{`"Vault3UserKeysUserID"`: userID}).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build update enc private key: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("update enc private key: %w", execErr)
	}
	return nil
}

// SetTempTwoFactorSecret stashes a pending (unverified) TOTP secret,
// encrypted through the cipher. Verification promotes it via
// PromoteTwoFactorSecret.
func SetTempTwoFactorSecret(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cipher *crypto.FieldCipher,
	userID string,
	secret string,
) error {
	secretEnc, encErr := cipher.EncryptString(secret)
	if encErr != nil {
		return fmt.Errorf("encrypt temp 2fa secret: %w", encErr)
	}
	return execUserAuthUpdate(ctx, db, builder, userID, map[string]any{
		`"Vault3UserAuthTempTwoFactorSecretEnc"`: secretEnc,
	}, "set temp two factor secret")
}

// PromoteTwoFactorSecret moves the pending secret into the enrolled column.
func PromoteTwoFactorSecret(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
) error {
	return execUserAuthUpdate(ctx, db, builder, userID, map[string]any{
		`"Vault3UserAuthTwoFactorSecretEnc"`:     sq.Expr(`"Vault3UserAuthTempTwoFactorSecretEnc"`),
		`"Vault3UserAuthTempTwoFactorSecretEnc"`: nil,
	}, "promote two factor secret")
}

// ClearTwoFactorSecrets disables 2FA entirely (both enrolled and pending).
func ClearTwoFactorSecrets(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
) error {
	return execUserAuthUpdate(ctx, db, builder, userID, map[string]any{
		`"Vault3UserAuthTwoFactorSecretEnc"`:     nil,
		`"Vault3UserAuthTempTwoFactorSecretEnc"`: nil,
	}, "clear two factor secrets")
}

// execUserUpdate applies a column set to one vault3_user row, always bumping
// UpdatedAt.
func execUserUpdate(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
	sets map[string]any,
	operation string,
) error {
	update := builder.Update(`"vault3_user"`)
	for column, value := range sets {
		update = update.Set(column, value)
	}
	update = update.Set(`"Vault3UserUpdatedAt"`, sq.Expr(`now()`))
	sqlStr, args, sqlErr := update.Where(sq.Eq{`"Vault3UserID"`: userID}).ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build %s: %w", operation, sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("%s: %w", operation, execErr)
	}
	return nil
}

// execUserAuthUpdate applies a column set to one vault3_user_auth row, always
// bumping UpdatedAt.
func execUserAuthUpdate(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
	sets map[string]any,
	operation string,
) error {
	update := builder.Update(`"vault3_user_auth"`)
	for column, value := range sets {
		update = update.Set(column, value)
	}
	update = update.Set(`"Vault3UserAuthUpdatedAt"`, sq.Expr(`now()`))
	sqlStr, args, sqlErr := update.Where(sq.Eq{`"Vault3UserAuthUserID"`: userID}).ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build %s: %w", operation, sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("%s: %w", operation, execErr)
	}
	return nil
}
