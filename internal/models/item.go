package models

import (
	"encoding/json"
	"time"
)

// Item mirrors vault3_item (see scripts/sql/003.sql).
// The server-visible surface of an item is deliberately tiny: id, vault,
// timestamps, trash state. Everything meaningful — title, category, username,
// URLs, secrets, notes — lives inside the two CipherEnvelope blobs sealed
// under the per-item key, which is itself wrapped by the vault key.
type Item struct {
	ID             string          `json:"id" db:"Vault3ItemID"`
	VaultID        string          `json:"vaultId" db:"Vault3ItemVaultID"`
	WrappedItemKey json.RawMessage `json:"wrappedItemKey" db:"Vault3ItemWrappedItemKey"`
	Overview       json.RawMessage `json:"overview" db:"Vault3ItemOverview"`
	Details        json.RawMessage `json:"details" db:"Vault3ItemDetails"`
	DeletedAt      *time.Time      `json:"deletedAt,omitempty" db:"Vault3ItemDeletedAt"`
	CreatedAt      time.Time       `json:"createdAt" db:"Vault3ItemCreatedAt"`
	UpdatedAt      time.Time       `json:"updatedAt" db:"Vault3ItemUpdatedAt"`
}
