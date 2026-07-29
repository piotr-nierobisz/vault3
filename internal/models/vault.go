package models

import (
	"encoding/json"
	"time"
)

// Vault mirrors vault3_vault (see scripts/sql/003.sql).
// EncName is a client-side CipherEnvelope sealed under the vault key: even
// the vault's name is unreadable server-side.
type Vault struct {
	ID          string          `json:"id" db:"Vault3VaultID"`
	OwnerUserID string          `json:"ownerUserId" db:"Vault3VaultOwnerUserID"`
	Kind        string          `json:"kind" db:"Vault3VaultKind"`
	EncName     json.RawMessage `json:"encName" db:"Vault3VaultEncName"`
	CreatedAt   time.Time       `json:"createdAt" db:"Vault3VaultCreatedAt"`
	UpdatedAt   time.Time       `json:"updatedAt" db:"Vault3VaultUpdatedAt"`
	ArchivedAt  *time.Time      `json:"archivedAt,omitempty" db:"Vault3VaultArchivedAt"`
}
