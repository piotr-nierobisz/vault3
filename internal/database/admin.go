package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"vault3/internal/crypto"
	"vault3/internal/models"

	sq "github.com/Masterminds/squirrel"
)

// Queries backing the admin console. Two properties hold across every one of
// them and must keep holding:
//
//   - Nothing here selects an item blob, a wrapped key, an envelope or a
//     token hash. An operator can count what exists and see when it changed;
//     the server cannot open any of it, and the console must not pretend
//     otherwise by shipping ciphertext to a page that has no key for it.
//   - Every listing is bounded by an explicit limit and offset. There is no
//     unpaged variant to reach for.

// SelectPlatformStats returns the console's overview counts in one round trip.
// Static SQL rather than Squirrel: nothing about it varies per request, and
// sixteen sub-selects read better as the query they are.
func SelectPlatformStats(ctx context.Context, db DbTx) (*models.PlatformStats, error) {
	const statsQuery = `
SELECT
    (SELECT count(*) FROM "vault3_user"),
    (SELECT count(*) FROM "vault3_user"
        WHERE "Vault3UserIsActive" AND "Vault3UserArchivedAt" IS NULL),
    (SELECT count(*) FROM "vault3_user"
        WHERE NOT "Vault3UserIsActive" OR "Vault3UserArchivedAt" IS NOT NULL),
    (SELECT count(*) FROM "vault3_user_auth" WHERE "Vault3UserAuthEmailVerified"),
    (SELECT count(*) FROM "vault3_user_auth"
        WHERE "Vault3UserAuthTwoFactorSecretEnc" IS NOT NULL),
    (SELECT count(*) FROM "vault3_admin"),
    (SELECT count(*) FROM "vault3_user"
        WHERE "Vault3UserCreatedAt" > now() - interval '7 days'),
    (SELECT count(*) FROM "vault3_user"
        WHERE "Vault3UserCreatedAt" > now() - interval '30 days'),
    (SELECT count(*) FROM "vault3_vault"),
    (SELECT count(*) FROM "vault3_vault" WHERE "Vault3VaultKind" = 'shared'),
    (SELECT count(*) FROM "vault3_item" WHERE "Vault3ItemDeletedAt" IS NULL),
    (SELECT count(*) FROM "vault3_item" WHERE "Vault3ItemDeletedAt" IS NOT NULL),
    (SELECT count(*) FROM "vault3_session" WHERE "Vault3SessionExpiresAt" > now()),
    (SELECT count(*) FROM "vault3_share_link"
        WHERE "Vault3ShareLinkRevokedAt" IS NULL AND "Vault3ShareLinkExpiresAt" > now()),
    (SELECT count(*) FROM "vault3_vault_invite"
        WHERE "Vault3VaultInviteRevokedAt" IS NULL
          AND "Vault3VaultInviteAcceptedAt" IS NULL
          AND "Vault3VaultInviteExpiresAt" > now()),
    (SELECT count(*) FROM "vault3_contact_inquiry" WHERE "Vault3ContactInquiryHandledAt" IS NULL)`

	stats := &models.PlatformStats{}
	scanErr := db.QueryRowContext(ctx, statsQuery).Scan(
		&stats.Users,
		&stats.ActiveUsers,
		&stats.SuspendedUsers,
		&stats.VerifiedUsers,
		&stats.TwoFactorUsers,
		&stats.AdminUsers,
		&stats.UsersLast7Days,
		&stats.UsersLast30Days,
		&stats.Vaults,
		&stats.SharedVaults,
		&stats.Items,
		&stats.TrashedItems,
		&stats.ActiveSessions,
		&stats.ActiveShareLinks,
		&stats.PendingInvites,
		&stats.OpenInquiries,
	)
	if scanErr != nil {
		return nil, fmt.Errorf("select platform stats: %w", scanErr)
	}
	return stats, nil
}

// SelectAllPlatformSettings returns every settings row for the console's
// toggles. The fail-safe (*Runtime) accessors remain the only way the
// application *reads a gate*; this exists to show an operator the stored
// state, including a row nothing reads yet.
func SelectAllPlatformSettings(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
) ([]models.PlatformSetting, error) {
	sqlStr, args, sqlErr := builder.
		Select(
			`"Vault3PlatformSettingKey"`,
			`"Vault3PlatformSettingValue"`,
			`"Vault3PlatformSettingKind"`,
			`"Vault3PlatformSettingUpdatedAt"`,
		).
		From(`"vault3_platform_setting"`).
		OrderBy(`"Vault3PlatformSettingKey"`).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build select platform settings: %w", sqlErr)
	}
	rows, queryErr := db.QueryContext(ctx, sqlStr, args...)
	if queryErr != nil {
		return nil, fmt.Errorf("select platform settings: %w", queryErr)
	}
	defer rows.Close()

	settings := make([]models.PlatformSetting, 0, 8)
	for rows.Next() {
		var s models.PlatformSetting
		if scanErr := rows.Scan(&s.Key, &s.Value, &s.Kind, &s.UpdatedAt); scanErr != nil {
			return nil, fmt.Errorf("scan platform setting: %w", scanErr)
		}
		settings = append(settings, s)
	}
	return settings, rows.Err()
}

// adminUserSearch builds the optional email filter shared by the list query
// and its count. `position(… in …)` rather than LIKE: the term is a substring
// to find, not a pattern, so there are no wildcard characters in it to escape
// and no way for one to change what the query means. Emails are stored
// lower-cased (a column CHECK enforces it), so the term is lowered to match.
func adminUserSearch(search string) sq.Sqlizer {
	term := strings.ToLower(strings.TrimSpace(search))
	if term == "" {
		return nil
	}
	return sq.Expr(`position(? in "Vault3UserEmail") > 0`, term)
}

// SelectAdminUsers returns one page of the account list, newest first,
// together with the total matching the same filter so the console can page.
func SelectAdminUsers(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cipher *crypto.FieldCipher,
	search string,
	limit, offset int,
) ([]models.AdminUserRow, int, error) {
	filter := adminUserSearch(search)

	countQuery := builder.Select("count(*)").From(`"vault3_user"`)
	if filter != nil {
		countQuery = countQuery.Where(filter)
	}
	countSQL, countArgs, countSQLErr := countQuery.ToSql()
	if countSQLErr != nil {
		return nil, 0, fmt.Errorf("build count admin users: %w", countSQLErr)
	}
	var total int
	if scanErr := db.QueryRowContext(ctx, countSQL, countArgs...).Scan(&total); scanErr != nil {
		return nil, 0, fmt.Errorf("count admin users: %w", scanErr)
	}

	listQuery := builder.
		Select(
			`u."Vault3UserID"`,
			`u."Vault3UserEmail"`,
			`COALESCE(u."Vault3UserDisplayNameEnc", '')`,
			`u."Vault3UserIsActive"`,
			`COALESCE(a."Vault3UserAuthEmailVerified", false)`,
			`(a."Vault3UserAuthTwoFactorSecretEnc" IS NOT NULL)`,
			`(ad."Vault3AdminUserID" IS NOT NULL)`,
			`(SELECT count(*) FROM "vault3_vault_access" va
				WHERE va."Vault3VaultAccessUserID" = u."Vault3UserID")`,
			`(SELECT count(*) FROM "vault3_item" i
				JOIN "vault3_vault" v ON v."Vault3VaultID" = i."Vault3ItemVaultID"
				WHERE v."Vault3VaultOwnerUserID" = u."Vault3UserID"
				  AND i."Vault3ItemDeletedAt" IS NULL)`,
			`(SELECT count(*) FROM "vault3_session" s
				WHERE s."Vault3SessionUserID" = u."Vault3UserID"
				  AND s."Vault3SessionExpiresAt" > now())`,
			`u."Vault3UserLastLoginAt"`,
			`u."Vault3UserArchivedAt"`,
			`COALESCE(u."Vault3UserArchivedReason", '')`,
			`u."Vault3UserCreatedAt"`,
		).
		From(`"vault3_user" u`).
		LeftJoin(`"vault3_user_auth" a ON a."Vault3UserAuthUserID" = u."Vault3UserID"`).
		LeftJoin(`"vault3_admin" ad ON ad."Vault3AdminUserID" = u."Vault3UserID"`).
		OrderBy(`u."Vault3UserCreatedAt" DESC`).
		Limit(uint64(limit)).
		Offset(uint64(offset))
	if filter != nil {
		listQuery = listQuery.Where(filter)
	}
	listSQL, listArgs, listSQLErr := listQuery.ToSql()
	if listSQLErr != nil {
		return nil, 0, fmt.Errorf("build select admin users: %w", listSQLErr)
	}

	rows, queryErr := db.QueryContext(ctx, listSQL, listArgs...)
	if queryErr != nil {
		return nil, 0, fmt.Errorf("select admin users: %w", queryErr)
	}
	defer rows.Close()

	users := make([]models.AdminUserRow, 0, limit)
	for rows.Next() {
		var row models.AdminUserRow
		var displayNameEnc string
		scanErr := rows.Scan(
			&row.ID,
			&row.Email,
			&displayNameEnc,
			&row.IsActive,
			&row.EmailVerified,
			&row.TwoFactor,
			&row.IsAdmin,
			&row.VaultCount,
			&row.ItemCount,
			&row.SessionCount,
			&row.LastLoginAt,
			&row.ArchivedAt,
			&row.ArchivedReason,
			&row.CreatedAt,
		)
		if scanErr != nil {
			return nil, 0, fmt.Errorf("scan admin user: %w", scanErr)
		}
		displayName, decryptErr := cipher.DecryptString(displayNameEnc)
		if decryptErr != nil {
			return nil, 0, fmt.Errorf("decrypt display name: %w", decryptErr)
		}
		row.DisplayName = displayName
		users = append(users, row)
	}
	return users, total, rows.Err()
}

// SetUserSuspended switches an account off or back on.
//
// The two columns move together on purpose. resolveSession refuses a user
// that is either inactive or archived, so a row carrying one without the
// other is a state nothing distinguishes at sign-in and no screen explains.
// Reactivating clears the reason as well: a stale one would read as a live
// note about an account that is working normally.
func SetUserSuspended(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
	suspended bool,
	reason string,
) error {
	if suspended {
		return execUserUpdate(ctx, db, builder, userID, map[string]any{
			`"Vault3UserIsActive"`:       false,
			`"Vault3UserArchivedAt"`:     sq.Expr(`now()`),
			`"Vault3UserArchivedReason"`: nullIfEmptyString(reason),
		}, "suspend user")
	}
	return execUserUpdate(ctx, db, builder, userID, map[string]any{
		`"Vault3UserIsActive"`:       true,
		`"Vault3UserArchivedAt"`:     nil,
		`"Vault3UserArchivedReason"`: nil,
	}, "reactivate user")
}

// SetEmailVerified marks an address confirmed by operator action and drops any
// outstanding token with it, so a link already in an inbox cannot be redeemed
// afterwards against an account that is verified by other means.
func SetEmailVerified(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
) error {
	return execUserAuthUpdate(ctx, db, builder, userID, map[string]any{
		`"Vault3UserAuthEmailVerified"`:                true,
		`"Vault3UserAuthEmailVerificationTokenHash"`:   nil,
		`"Vault3UserAuthEmailVerificationTokenExpiry"`: nil,
	}, "set email verified")
}

// DeleteUserSessions signs an account out everywhere. Unlike the identity
// writes it must tolerate matching nothing: an account with no live session is
// the ordinary case, not a failure.
func DeleteUserSessions(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
) error {
	sqlStr, args, sqlErr := builder.
		Delete(`"vault3_session"`).
		Where(sq.Eq{`"Vault3SessionUserID"`: userID}).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build delete user sessions: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("delete user sessions: %w", execErr)
	}
	return nil
}

// InsertAdmin grants the platform-admin role. Idempotent: re-granting an
// existing admin is a no-op rather than a unique-violation, so a double click
// cannot fail an action that already succeeded.
func InsertAdmin(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
	grantedByUserID string,
	notes string,
) error {
	sqlStr, args, sqlErr := builder.
		Insert(`"vault3_admin"`).
		Columns(
			`"Vault3AdminUserID"`,
			`"Vault3AdminGrantedByUserID"`,
			`"Vault3AdminNotes"`,
		).
		Values(
			userID,
			nullIfEmptyString(grantedByUserID),
			nullIfEmptyString(notes),
		).
		Suffix(`ON CONFLICT ("Vault3AdminUserID") DO NOTHING`).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build insert admin: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("insert admin: %w", execErr)
	}
	return nil
}

// DeleteAdmin revokes the grant. Also idempotent, for the same reason.
func DeleteAdmin(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
) error {
	sqlStr, args, sqlErr := builder.
		Delete(`"vault3_admin"`).
		Where(sq.Eq{`"Vault3AdminUserID"`: userID}).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build delete admin: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("delete admin: %w", execErr)
	}
	return nil
}

// CountAdmins backs the last-admin guard: revoking the final grant would leave
// the console unreachable by anyone.
func CountAdmins(ctx context.Context, db DbTx, builder *sq.StatementBuilderType) (int, error) {
	sqlStr, args, sqlErr := builder.Select("count(*)").From(`"vault3_admin"`).ToSql()
	if sqlErr != nil {
		return 0, fmt.Errorf("build count admins: %w", sqlErr)
	}
	var count int
	if scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(&count); scanErr != nil {
		return 0, fmt.Errorf("count admins: %w", scanErr)
	}
	return count, nil
}

// GrantAdminByEmail is the bootstrap path: it grants the role to an existing
// account named by email, and reports whether a row was created. Returns
// sql.ErrNoRows when no such account exists — an operator naming an address
// that has not registered yet needs to hear so, not to have it silently
// ignored.
func GrantAdminByEmail(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	email string,
) (bool, error) {
	userID, lookupErr := SelectUserIDByEmail(ctx, db, builder, email)
	if lookupErr != nil {
		return false, lookupErr
	}
	existing, existingErr := selectAdminRow(ctx, db, builder, userID)
	if existingErr != nil && !errors.Is(existingErr, sql.ErrNoRows) {
		return false, fmt.Errorf("check existing admin: %w", existingErr)
	}
	if existing != nil {
		return false, nil
	}
	if insertErr := InsertAdmin(ctx, db, builder, userID, "", "granted by ADMIN_BOOTSTRAP_EMAIL_STRING"); insertErr != nil {
		return false, insertErr
	}
	return true, nil
}

// SelectAuditLog returns one page of the security trail, newest first, with
// the acting account's email joined in. Optionally narrowed to one user.
// IP, user agent and detail are decrypted here, the same way every other
// FieldCipher column is read back.
func SelectAuditLog(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cipher *crypto.FieldCipher,
	userIDOptional string,
	limit, offset int,
) ([]models.AdminAuditRow, error) {
	query := builder.
		Select(
			`l."Vault3AuditLogID"`,
			`COALESCE(l."Vault3AuditLogUserID"::text, '')`,
			`COALESCE(u."Vault3UserEmail", '')`,
			`l."Vault3AuditLogAction"`,
			`COALESCE(l."Vault3AuditLogEntityType", '')`,
			`COALESCE(l."Vault3AuditLogEntityID", '')`,
			`COALESCE(l."Vault3AuditLogIpAddressEnc", '')`,
			`COALESCE(l."Vault3AuditLogUserAgentEnc", '')`,
			`COALESCE(l."Vault3AuditLogDetailEnc", '')`,
			`l."Vault3AuditLogCreatedAt"`,
		).
		From(`"vault3_audit_log" l`).
		LeftJoin(`"vault3_user" u ON u."Vault3UserID" = l."Vault3AuditLogUserID"`).
		OrderBy(`l."Vault3AuditLogCreatedAt" DESC`).
		Limit(uint64(limit)).
		Offset(uint64(offset))
	if userIDOptional != "" {
		query = query.Where(sq.Eq{`l."Vault3AuditLogUserID"`: userIDOptional})
	}
	sqlStr, args, sqlErr := query.ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build select audit log: %w", sqlErr)
	}

	rows, queryErr := db.QueryContext(ctx, sqlStr, args...)
	if queryErr != nil {
		return nil, fmt.Errorf("select audit log: %w", queryErr)
	}
	defer rows.Close()

	entries := make([]models.AdminAuditRow, 0, limit)
	for rows.Next() {
		var row models.AdminAuditRow
		var ipEnc, uaEnc, detailEnc string
		scanErr := rows.Scan(
			&row.ID,
			&row.UserID,
			&row.Email,
			&row.Action,
			&row.EntityType,
			&row.EntityID,
			&ipEnc,
			&uaEnc,
			&detailEnc,
			&row.CreatedAt,
		)
		if scanErr != nil {
			return nil, fmt.Errorf("scan audit log: %w", scanErr)
		}
		decrypted, decryptErr := decryptAll(cipher, ipEnc, uaEnc, detailEnc)
		if decryptErr != nil {
			return nil, fmt.Errorf("decrypt audit row: %w", decryptErr)
		}
		row.IPAddress, row.UserAgent, row.Detail = decrypted[0], decrypted[1], decrypted[2]
		entries = append(entries, row)
	}
	return entries, rows.Err()
}

// SelectContactInquiries returns one page of the contact inbox, newest first,
// with the total so the console can page. openOnly hides messages already
// marked handled.
func SelectContactInquiries(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cipher *crypto.FieldCipher,
	openOnly bool,
	limit, offset int,
) ([]models.ContactInquiry, int, error) {
	countQuery := builder.Select("count(*)").From(`"vault3_contact_inquiry"`)
	listQuery := builder.
		Select(
			`"Vault3ContactInquiryID"`,
			`"Vault3ContactInquiryName"`,
			`"Vault3ContactInquiryEmail"`,
			`"Vault3ContactInquiryMessage"`,
			`COALESCE("Vault3ContactInquiryIpAddressEnc", '')`,
			`COALESCE("Vault3ContactInquiryUserAgentEnc", '')`,
			`"Vault3ContactInquiryHandledAt"`,
			`"Vault3ContactInquiryCreatedAt"`,
		).
		From(`"vault3_contact_inquiry"`).
		OrderBy(`"Vault3ContactInquiryCreatedAt" DESC`).
		Limit(uint64(limit)).
		Offset(uint64(offset))
	if openOnly {
		open := sq.Expr(`"Vault3ContactInquiryHandledAt" IS NULL`)
		countQuery = countQuery.Where(open)
		listQuery = listQuery.Where(open)
	}

	countSQL, countArgs, countSQLErr := countQuery.ToSql()
	if countSQLErr != nil {
		return nil, 0, fmt.Errorf("build count contact inquiries: %w", countSQLErr)
	}
	var total int
	if scanErr := db.QueryRowContext(ctx, countSQL, countArgs...).Scan(&total); scanErr != nil {
		return nil, 0, fmt.Errorf("count contact inquiries: %w", scanErr)
	}

	listSQL, listArgs, listSQLErr := listQuery.ToSql()
	if listSQLErr != nil {
		return nil, 0, fmt.Errorf("build select contact inquiries: %w", listSQLErr)
	}
	rows, queryErr := db.QueryContext(ctx, listSQL, listArgs...)
	if queryErr != nil {
		return nil, 0, fmt.Errorf("select contact inquiries: %w", queryErr)
	}
	defer rows.Close()

	inquiries := make([]models.ContactInquiry, 0, limit)
	for rows.Next() {
		var inquiry models.ContactInquiry
		var ipEnc, uaEnc string
		scanErr := rows.Scan(
			&inquiry.ID,
			&inquiry.Name,
			&inquiry.Email,
			&inquiry.Message,
			&ipEnc,
			&uaEnc,
			&inquiry.HandledAt,
			&inquiry.CreatedAt,
		)
		if scanErr != nil {
			return nil, 0, fmt.Errorf("scan contact inquiry: %w", scanErr)
		}
		decrypted, decryptErr := decryptAll(cipher, ipEnc, uaEnc)
		if decryptErr != nil {
			return nil, 0, fmt.Errorf("decrypt contact inquiry: %w", decryptErr)
		}
		inquiry.IPAddress, inquiry.UserAgent = decrypted[0], decrypted[1]
		inquiries = append(inquiries, inquiry)
	}
	return inquiries, total, rows.Err()
}

// SetContactInquiryHandled marks a message dealt with, or puts it back in the
// open list.
func SetContactInquiryHandled(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	inquiryID string,
	handled bool,
) error {
	var handledAt any
	if handled {
		handledAt = time.Now()
	}
	sqlStr, args, sqlErr := builder.
		Update(`"vault3_contact_inquiry"`).
		Set(`"Vault3ContactInquiryHandledAt"`, handledAt).
		Where(sq.Eq{`"Vault3ContactInquiryID"`: inquiryID}).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build set contact inquiry handled: %w", sqlErr)
	}
	// Pure identity WHERE: matching nothing means the id does not exist, and
	// the console would otherwise report a message triaged that it never
	// touched.
	return execExpectingRow(ctx, db, sqlStr, args, "set contact inquiry handled")
}

// decryptAll decrypts a run of FieldCipher columns from one row, so a scan
// that reads three of them does not spell out three identical error branches.
func decryptAll(cipher *crypto.FieldCipher, values ...string) ([]string, error) {
	out := make([]string, len(values))
	for i, value := range values {
		plain, decryptErr := cipher.DecryptString(value)
		if decryptErr != nil {
			return nil, decryptErr
		}
		out[i] = plain
	}
	return out, nil
}
