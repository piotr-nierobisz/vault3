package view

import (
	"encoding/json"
	"time"

	"vault3/internal/models"
)

// ItemRow is the client-facing projection of one encrypted item. It looks
// close to models.Item because the model is already ciphertext-only, but the
// projection exists so the client contract is explicit and the model can
// grow server-side fields without leaking them.
type ItemRow struct {
	ID             string          `json:"id"`
	VaultID        string          `json:"vaultId"`
	WrappedItemKey json.RawMessage `json:"wrappedItemKey"`
	Overview       json.RawMessage `json:"overview"`
	Details        json.RawMessage `json:"details"`
	Trashed        bool            `json:"trashed"`
	TrashedAt      *time.Time      `json:"trashedAt,omitempty"`
	CreatedAt      time.Time       `json:"createdAt"`
	UpdatedAt      time.Time       `json:"updatedAt"`
}

// NewItemRow projects one model row.
func NewItemRow(item *models.Item) ItemRow {
	return ItemRow{
		ID:             item.ID,
		VaultID:        item.VaultID,
		WrappedItemKey: item.WrappedItemKey,
		Overview:       item.Overview,
		Details:        item.Details,
		Trashed:        item.DeletedAt != nil,
		TrashedAt:      item.DeletedAt,
		CreatedAt:      item.CreatedAt,
		UpdatedAt:      item.UpdatedAt,
	}
}

// NewItemRows projects a slice.
func NewItemRows(items []models.Item) []ItemRow {
	out := make([]ItemRow, 0, len(items))
	for i := range items {
		out = append(out, NewItemRow(&items[i]))
	}
	return out
}
