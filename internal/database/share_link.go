package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"vault3/internal/models"

	sq "github.com/Masterminds/squirrel"
)

// InsertShareLink persists a new share link (token already hashed by the
// caller; the raw token is returned to the client exactly once).
func InsertShareLink(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	link *models.ShareLink,
) error {
	sqlStr, args, sqlErr := builder.
		Insert(`"vault3_share_link"`).
		Columns(
			`"Vault3ShareLinkID"`,
			`"Vault3ShareLinkItemID"`,
			`"Vault3ShareLinkCreatedByUserID"`,
			`"Vault3ShareLinkTokenHash"`,
			`"Vault3ShareLinkWrappedItemKey"`,
			`"Vault3ShareLinkExpiresAt"`,
		).
		Values(
			link.ID,
			link.ItemID,
			link.CreatedByUserID,
			link.TokenHash,
			[]byte(link.WrappedItemKey),
			link.ExpiresAt,
		).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build insert share link: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("insert share link: %w", execErr)
	}
	return nil
}

// SelectItemShareLinks returns an item's share links, newest first, for the
// management dialog (revoked and expired included so the owner sees history).
func SelectItemShareLinks(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	itemID string,
) ([]models.ShareLink, error) {
	sqlStr, args, sqlErr := shareLinkSelect(builder).
		Where(sq.Eq{`"Vault3ShareLinkItemID"`: itemID}).
		OrderBy(`"Vault3ShareLinkCreatedAt" DESC`).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build item share links query: %w", sqlErr)
	}

	rows, queryErr := db.QueryContext(ctx, sqlStr, args...)
	if queryErr != nil {
		return nil, queryErr
	}
	defer rows.Close()

	out := make([]models.ShareLink, 0)
	for rows.Next() {
		link, scanErr := scanShareLink(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, *link)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, rowsErr
	}
	return out, nil
}

// SelectShareLinkByID loads one share link. Returns sql.ErrNoRows when
// absent; callers authorise via the item's vault access.
func SelectShareLinkByID(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	linkID string,
) (*models.ShareLink, error) {
	sqlStr, args, sqlErr := shareLinkSelect(builder).
		Where(sq.Eq{`"Vault3ShareLinkID"`: linkID}).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build share link query: %w", sqlErr)
	}
	link, scanErr := scanShareLink(db.QueryRowContext(ctx, sqlStr, args...))
	if scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("select share link: %w", scanErr)
	}
	return link, nil
}

// RedeemShareLink resolves a live (unrevoked, unexpired) link by token hash
// and bumps its view counter in the same statement. Returns sql.ErrNoRows
// for anything else — missing, revoked and expired are indistinguishable by
// design.
func RedeemShareLink(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	tokenHash string,
) (*models.ShareLink, error) {
	sqlStr, args, sqlErr := builder.
		Update(`"vault3_share_link"`).
		Set(`"Vault3ShareLinkViewCount"`, sq.Expr(`"Vault3ShareLinkViewCount" + 1`)).
		Where(sq.Eq{`"Vault3ShareLinkTokenHash"`: tokenHash}).
		Where(sq.Expr(`"Vault3ShareLinkRevokedAt" IS NULL`)).
		Where(sq.Expr(`"Vault3ShareLinkExpiresAt" > now()`)).
		Suffix(`RETURNING "Vault3ShareLinkID", "Vault3ShareLinkItemID", "Vault3ShareLinkCreatedByUserID",
			"Vault3ShareLinkTokenHash", "Vault3ShareLinkWrappedItemKey", "Vault3ShareLinkExpiresAt",
			"Vault3ShareLinkRevokedAt", "Vault3ShareLinkViewCount", "Vault3ShareLinkCreatedAt"`).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build redeem share link: %w", sqlErr)
	}
	link, scanErr := scanShareLink(db.QueryRowContext(ctx, sqlStr, args...))
	if scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("redeem share link: %w", scanErr)
	}
	return link, nil
}

// RevokeShareLink kills a link. Idempotent: an already-revoked link stays
// revoked at its original timestamp.
func RevokeShareLink(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	linkID string,
) error {
	sqlStr, args, sqlErr := builder.
		Update(`"vault3_share_link"`).
		Set(`"Vault3ShareLinkRevokedAt"`, sq.Expr(`now()`)).
		Where(sq.Eq{`"Vault3ShareLinkID"`: linkID}).
		Where(sq.Expr(`"Vault3ShareLinkRevokedAt" IS NULL`)).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build revoke share link: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("revoke share link: %w", execErr)
	}
	return nil
}

// CountActiveItemShareLinks counts an item's live links, enforcing the
// per-item cap before an insert.
func CountActiveItemShareLinks(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	itemID string,
) (int, error) {
	sqlStr, args, sqlErr := builder.
		Select(`COUNT(*)`).
		From(`"vault3_share_link"`).
		Where(sq.Eq{`"Vault3ShareLinkItemID"`: itemID}).
		Where(sq.Expr(`"Vault3ShareLinkRevokedAt" IS NULL`)).
		Where(sq.Expr(`"Vault3ShareLinkExpiresAt" > now()`)).
		ToSql()
	if sqlErr != nil {
		return 0, fmt.Errorf("build count share links: %w", sqlErr)
	}
	var count int
	if scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(&count); scanErr != nil {
		return 0, fmt.Errorf("count share links: %w", scanErr)
	}
	return count, nil
}

func shareLinkSelect(builder *sq.StatementBuilderType) sq.SelectBuilder {
	return builder.
		Select(
			`"Vault3ShareLinkID"`,
			`"Vault3ShareLinkItemID"`,
			`"Vault3ShareLinkCreatedByUserID"`,
			`"Vault3ShareLinkTokenHash"`,
			`"Vault3ShareLinkWrappedItemKey"`,
			`"Vault3ShareLinkExpiresAt"`,
			`"Vault3ShareLinkRevokedAt"`,
			`"Vault3ShareLinkViewCount"`,
			`"Vault3ShareLinkCreatedAt"`,
		).
		From(`"vault3_share_link"`)
}

func scanShareLink(row rowScanner) (*models.ShareLink, error) {
	link := &models.ShareLink{}
	scanErr := row.Scan(
		&link.ID,
		&link.ItemID,
		&link.CreatedByUserID,
		&link.TokenHash,
		&link.WrappedItemKey,
		&link.ExpiresAt,
		&link.RevokedAt,
		&link.ViewCount,
		&link.CreatedAt,
	)
	if scanErr != nil {
		return nil, scanErr
	}
	return link, nil
}
