package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"vault3/internal/models"

	sq "github.com/Masterminds/squirrel"
)

// SelectVaultItems returns a vault's items, trashed included (the client owns
// filtering: item metadata is ciphertext, so the server cannot slice by
// category, favourite, or anything else). Ordered by UpdatedAt so the client
// has a stable recency signal without decrypting.
func SelectVaultItems(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	vaultID string,
) ([]models.Item, error) {
	sqlStr, args, sqlErr := itemSelect(builder).
		Where(sq.Eq{`"Vault3ItemVaultID"`: vaultID}).
		OrderBy(`"Vault3ItemUpdatedAt" DESC`).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build vault items query: %w", sqlErr)
	}

	rows, queryErr := db.QueryContext(ctx, sqlStr, args...)
	if queryErr != nil {
		return nil, queryErr
	}
	defer rows.Close()

	out := make([]models.Item, 0)
	for rows.Next() {
		item, scanErr := scanItem(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, *item)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, rowsErr
	}
	return out, nil
}

// SelectItemByID loads one item. Returns sql.ErrNoRows when absent. Callers
// authorise separately via SelectVaultAccess on the item's vault.
func SelectItemByID(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	itemID string,
) (*models.Item, error) {
	sqlStr, args, sqlErr := itemSelect(builder).
		Where(sq.Eq{`"Vault3ItemID"`: itemID}).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build item query: %w", sqlErr)
	}
	item, scanErr := scanItem(db.QueryRowContext(ctx, sqlStr, args...))
	if scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("select item: %w", scanErr)
	}
	return item, nil
}

// CountVaultItems counts a vault's non-trashed items, enforcing the per-vault
// cap before an insert.
func CountVaultItems(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	vaultID string,
) (int, error) {
	sqlStr, args, sqlErr := builder.
		Select(`COUNT(*)`).
		From(`"vault3_item"`).
		Where(sq.Eq{`"Vault3ItemVaultID"`: vaultID}).
		Where(sq.Expr(`"Vault3ItemDeletedAt" IS NULL`)).
		ToSql()
	if sqlErr != nil {
		return 0, fmt.Errorf("build count vault items: %w", sqlErr)
	}
	var count int
	if scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(&count); scanErr != nil {
		return 0, fmt.Errorf("count vault items: %w", scanErr)
	}
	return count, nil
}

// InsertItem persists a new encrypted item.
func InsertItem(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	item *models.Item,
) error {
	sqlStr, args, sqlErr := builder.
		Insert(`"vault3_item"`).
		Columns(
			`"Vault3ItemID"`,
			`"Vault3ItemVaultID"`,
			`"Vault3ItemWrappedItemKey"`,
			`"Vault3ItemOverview"`,
			`"Vault3ItemDetails"`,
		).
		Values(
			item.ID,
			item.VaultID,
			[]byte(item.WrappedItemKey),
			[]byte(item.Overview),
			[]byte(item.Details),
		).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build insert item: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("insert item: %w", execErr)
	}
	return nil
}

// UpdateItemBlobs replaces an item's encrypted blobs (an edit re-seals both
// under the existing item key client-side).
func UpdateItemBlobs(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	itemID string,
	overview []byte,
	details []byte,
) error {
	sqlStr, args, sqlErr := builder.
		Update(`"vault3_item"`).
		Set(`"Vault3ItemOverview"`, overview).
		Set(`"Vault3ItemDetails"`, details).
		Set(`"Vault3ItemUpdatedAt"`, sq.Expr(`now()`)).
		Where(sq.Eq{`"Vault3ItemID"`: itemID}).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build update item: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("update item: %w", execErr)
	}
	return nil
}

// TrashItem soft-deletes an item; RestoreItem brings it back. Both are
// idempotent single-column flips.
func TrashItem(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	itemID string,
) error {
	return execItemUpdate(ctx, db, builder, itemID, map[string]any{
		`"Vault3ItemDeletedAt"`: sq.Expr(`now()`),
	}, "trash item")
}

func RestoreItem(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	itemID string,
) error {
	return execItemUpdate(ctx, db, builder, itemID, map[string]any{
		`"Vault3ItemDeletedAt"`: nil,
	}, "restore item")
}

// DeleteItem permanently removes an item row (empty-trash / delete-forever).
func DeleteItem(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	itemID string,
) error {
	sqlStr, args, sqlErr := builder.
		Delete(`"vault3_item"`).
		Where(sq.Eq{`"Vault3ItemID"`: itemID}).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build delete item: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("delete item: %w", execErr)
	}
	return nil
}

func itemSelect(builder *sq.StatementBuilderType) sq.SelectBuilder {
	return builder.
		Select(
			`"Vault3ItemID"`,
			`"Vault3ItemVaultID"`,
			`"Vault3ItemWrappedItemKey"`,
			`"Vault3ItemOverview"`,
			`"Vault3ItemDetails"`,
			`"Vault3ItemDeletedAt"`,
			`"Vault3ItemCreatedAt"`,
			`"Vault3ItemUpdatedAt"`,
		).
		From(`"vault3_item"`)
}

func scanItem(row rowScanner) (*models.Item, error) {
	item := &models.Item{}
	scanErr := row.Scan(
		&item.ID,
		&item.VaultID,
		&item.WrappedItemKey,
		&item.Overview,
		&item.Details,
		&item.DeletedAt,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if scanErr != nil {
		return nil, scanErr
	}
	return item, nil
}

func execItemUpdate(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	itemID string,
	sets map[string]any,
	operation string,
) error {
	update := builder.Update(`"vault3_item"`)
	for column, value := range sets {
		update = update.Set(column, value)
	}
	update = update.Set(`"Vault3ItemUpdatedAt"`, sq.Expr(`now()`))
	sqlStr, args, sqlErr := update.Where(sq.Eq{`"Vault3ItemID"`: itemID}).ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build %s: %w", operation, sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("%s: %w", operation, execErr)
	}
	return nil
}
