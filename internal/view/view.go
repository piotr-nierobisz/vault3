// Package view turns hydrated models into the small, display oriented
// shapes templates and React payloads consume. It is the canonical home for
// "shape data for the UI" logic so handlers and .gohtml files do not
// redeclare the same helpers, and the choke point that keeps secrets out of
// window.__BUNGO_DATA__: never hand a raw *models.UserFull to a client —
// build the projection here.
package view

import (
	"context"
	"fmt"

	"vault3/internal/database"
	"vault3/internal/models"

	sq "github.com/Masterminds/squirrel"
)

// Lookups holds in-memory copies of reference tables that presenters need
// before data reaches a template. Built once at runtime startup via
// NewLookups and treated as read-only for the process lifetime; restart to
// pick up reference-table changes.
type Lookups struct {
	// ItemCategories in display order, and by code for direct resolution.
	ItemCategories  []models.ItemCategory
	ItemCategoryMap map[string]models.ItemCategory
}

// NewLookups loads every reference table the view layer depends on and
// returns a ready-to-use Lookups. Returns an error so the caller (runtime
// startup) can fail fast rather than serving requests with empty maps.
func NewLookups(ctx context.Context, db database.DbTx, builder *sq.StatementBuilderType) (*Lookups, error) {
	categories, categoriesErr := database.SelectAllItemCategories(ctx, db, builder)
	if categoriesErr != nil {
		return nil, fmt.Errorf("load item categories: %w", categoriesErr)
	}
	if len(categories) == 0 {
		return nil, fmt.Errorf("no item categories loaded; seed scripts/sql/005.sql must run first")
	}

	categoryMap := make(map[string]models.ItemCategory, len(categories))
	for _, c := range categories {
		categoryMap[c.Code] = c
	}

	return &Lookups{
		ItemCategories:  categories,
		ItemCategoryMap: categoryMap,
	}, nil
}

// ItemCategory returns the canonical category row for a code, or nil when
// the code is unknown.
func (l *Lookups) ItemCategory(code string) *models.ItemCategory {
	if l == nil {
		return nil
	}
	if c, ok := l.ItemCategoryMap[code]; ok {
		return &c
	}
	return nil
}

// CategoryOption is the client-facing shape of one item category.
type CategoryOption struct {
	Code  string `json:"code"`
	Label string `json:"label"`
	Icon  string `json:"icon"`
}

// CategoryOptions projects the active categories for a page payload.
func (l *Lookups) CategoryOptions() []CategoryOption {
	if l == nil {
		return nil
	}
	out := make([]CategoryOption, 0, len(l.ItemCategories))
	for _, c := range l.ItemCategories {
		if !c.IsActive {
			continue
		}
		out = append(out, CategoryOption{Code: c.Code, Label: c.Label, Icon: c.Icon})
	}
	return out
}
