package models

import "time"

// ItemCategory mirrors vault3_item_category (see scripts/sql/001.sql).
// Reference data for the client UI only — an item's category lives inside
// its encrypted overview, so no server-side table references this by FK.
type ItemCategory struct {
	Code      string    `json:"code" db:"Vault3ItemCategoryCode"`
	Label     string    `json:"label" db:"Vault3ItemCategoryLabel"`
	Icon      string    `json:"icon" db:"Vault3ItemCategoryIcon"`
	IsActive  bool      `json:"isActive" db:"Vault3ItemCategoryIsActive"`
	SortOrder int       `json:"sortOrder" db:"Vault3ItemCategorySortOrder"`
	CreatedAt time.Time `json:"createdAt" db:"Vault3ItemCategoryCreatedAt"`
}
