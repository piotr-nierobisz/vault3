package database

import (
	"context"
	"fmt"

	"vault3/internal/models"

	sq "github.com/Masterminds/squirrel"
)

// SelectAllItemCategories returns the item-category reference rows in display
// order, loaded once at startup into view.Lookups.
func SelectAllItemCategories(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
) ([]models.ItemCategory, error) {
	sqlStr, args, sqlErr := builder.
		Select(
			`"Vault3ItemCategoryCode"`,
			`"Vault3ItemCategoryLabel"`,
			`"Vault3ItemCategoryIcon"`,
			`"Vault3ItemCategoryIsActive"`,
			`"Vault3ItemCategorySortOrder"`,
			`"Vault3ItemCategoryCreatedAt"`,
		).
		From(`"vault3_item_category"`).
		OrderBy(`"Vault3ItemCategorySortOrder" ASC`).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build item categories query: %w", sqlErr)
	}

	rows, queryErr := db.QueryContext(ctx, sqlStr, args...)
	if queryErr != nil {
		return nil, queryErr
	}
	defer rows.Close()

	out := make([]models.ItemCategory, 0)
	for rows.Next() {
		var c models.ItemCategory
		scanErr := rows.Scan(
			&c.Code,
			&c.Label,
			&c.Icon,
			&c.IsActive,
			&c.SortOrder,
			&c.CreatedAt,
		)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, c)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, rowsErr
	}
	return out, nil
}
