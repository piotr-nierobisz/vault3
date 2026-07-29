package database

import (
	"context"
	"fmt"

	"vault3/internal/crypto"
	"vault3/internal/models"

	sq "github.com/Masterminds/squirrel"
)

// InsertNotification writes one in-app notification, encrypting title and
// body at rest through the cipher.
func InsertNotification(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cipher *crypto.FieldCipher,
	notification *models.Notification,
) error {
	titleEnc, titleErr := cipher.EncryptString(notification.Title)
	if titleErr != nil {
		return fmt.Errorf("encrypt notification title: %w", titleErr)
	}
	bodyEnc, bodyErr := cipher.EncryptString(notification.Body)
	if bodyErr != nil {
		return fmt.Errorf("encrypt notification body: %w", bodyErr)
	}
	metadata := notification.Metadata
	if len(metadata) == 0 {
		metadata = []byte(`{}`)
	}

	sqlStr, args, sqlErr := builder.
		Insert(`"vault3_notification"`).
		Columns(
			`"Vault3NotificationID"`,
			`"Vault3NotificationUserID"`,
			`"Vault3NotificationKind"`,
			`"Vault3NotificationTitleEnc"`,
			`"Vault3NotificationBodyEnc"`,
			`"Vault3NotificationMetadata"`,
		).
		Values(
			notification.ID,
			notification.UserID,
			notification.Kind,
			titleEnc,
			bodyEnc,
			[]byte(metadata),
		).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build insert notification: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("insert notification: %w", execErr)
	}
	return nil
}

// SelectUserNotifications returns the newest notifications for a user,
// decrypted for display, plus the unread count across the whole set (not
// just the page) so the bell badge is accurate.
func SelectUserNotifications(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cipher *crypto.FieldCipher,
	userID string,
	limit int,
) ([]models.Notification, int, error) {
	sqlStr, args, sqlErr := builder.
		Select(
			`"Vault3NotificationID"`,
			`"Vault3NotificationUserID"`,
			`"Vault3NotificationKind"`,
			`"Vault3NotificationTitleEnc"`,
			`"Vault3NotificationBodyEnc"`,
			`"Vault3NotificationIsRead"`,
			`"Vault3NotificationReadAt"`,
			`"Vault3NotificationMetadata"`,
			`"Vault3NotificationCreatedAt"`,
		).
		From(`"vault3_notification"`).
		Where(sq.Eq{`"Vault3NotificationUserID"`: userID}).
		OrderBy(`"Vault3NotificationCreatedAt" DESC`).
		Limit(uint64(limit)).
		ToSql()
	if sqlErr != nil {
		return nil, 0, fmt.Errorf("build notifications query: %w", sqlErr)
	}

	rows, queryErr := db.QueryContext(ctx, sqlStr, args...)
	if queryErr != nil {
		return nil, 0, queryErr
	}
	defer rows.Close()

	out := make([]models.Notification, 0)
	for rows.Next() {
		var n models.Notification
		var titleEnc, bodyEnc string
		scanErr := rows.Scan(
			&n.ID,
			&n.UserID,
			&n.Kind,
			&titleEnc,
			&bodyEnc,
			&n.IsRead,
			&n.ReadAt,
			&n.Metadata,
			&n.CreatedAt,
		)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		title, titleErr := cipher.DecryptString(titleEnc)
		if titleErr != nil {
			return nil, 0, fmt.Errorf("decrypt notification title: %w", titleErr)
		}
		body, bodyErr := cipher.DecryptString(bodyEnc)
		if bodyErr != nil {
			return nil, 0, fmt.Errorf("decrypt notification body: %w", bodyErr)
		}
		n.Title = title
		n.Body = body
		out = append(out, n)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, 0, rowsErr
	}

	unread, unreadErr := countUnreadNotifications(ctx, db, builder, userID)
	if unreadErr != nil {
		return nil, 0, unreadErr
	}
	return out, unread, nil
}

func countUnreadNotifications(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
) (int, error) {
	sqlStr, args, sqlErr := builder.
		Select(`COUNT(*)`).
		From(`"vault3_notification"`).
		Where(sq.Eq{
			`"Vault3NotificationUserID"`: userID,
			`"Vault3NotificationIsRead"`: false,
		}).
		ToSql()
	if sqlErr != nil {
		return 0, fmt.Errorf("build unread count: %w", sqlErr)
	}
	var count int
	if scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(&count); scanErr != nil {
		return 0, fmt.Errorf("count unread notifications: %w", scanErr)
	}
	return count, nil
}

// MarkNotificationRead flips one notification read, scoped to its owner.
func MarkNotificationRead(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
	notificationID string,
) error {
	sqlStr, args, sqlErr := builder.
		Update(`"vault3_notification"`).
		Set(`"Vault3NotificationIsRead"`, true).
		Set(`"Vault3NotificationReadAt"`, sq.Expr(`now()`)).
		Where(sq.Eq{
			`"Vault3NotificationID"`:     notificationID,
			`"Vault3NotificationUserID"`: userID,
		}).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build mark notification read: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("mark notification read: %w", execErr)
	}
	return nil
}

// MarkAllNotificationsRead clears the user's unread set.
func MarkAllNotificationsRead(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
) error {
	sqlStr, args, sqlErr := builder.
		Update(`"vault3_notification"`).
		Set(`"Vault3NotificationIsRead"`, true).
		Set(`"Vault3NotificationReadAt"`, sq.Expr(`now()`)).
		Where(sq.Eq{
			`"Vault3NotificationUserID"`: userID,
			`"Vault3NotificationIsRead"`: false,
		}).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build mark all read: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("mark all notifications read: %w", execErr)
	}
	return nil
}

// SelectUserNotificationRecipient returns the contact details and raw prefs
// blob notify.go needs to deliver to one user.
func SelectUserNotificationRecipient(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cipher *crypto.FieldCipher,
	userID string,
) (email string, displayName string, prefsRaw []byte, err error) {
	sqlStr, args, sqlErr := builder.
		Select(
			`"Vault3UserEmail"`,
			`COALESCE("Vault3UserDisplayNameEnc", '')`,
			`"Vault3UserNotificationPrefs"`,
		).
		From(`"vault3_user"`).
		Where(sq.Eq{`"Vault3UserID"`: userID}).
		ToSql()
	if sqlErr != nil {
		return "", "", nil, fmt.Errorf("build recipient query: %w", sqlErr)
	}
	var displayNameEnc string
	scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(&email, &displayNameEnc, &prefsRaw)
	if scanErr != nil {
		return "", "", nil, fmt.Errorf("select recipient: %w", scanErr)
	}
	displayName, decErr := cipher.DecryptString(displayNameEnc)
	if decErr != nil {
		return "", "", nil, fmt.Errorf("decrypt recipient name: %w", decErr)
	}
	return email, displayName, prefsRaw, nil
}
