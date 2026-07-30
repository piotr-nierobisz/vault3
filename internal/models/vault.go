package models

import (
	"encoding/json"
	"time"
)

// Vault kinds. These are the only values the Vault3VaultKind CHECK
// constraint accepts (scripts/sql/003.sql); the kind tracks whether anyone
// besides the owner currently holds access, and flips as members join and
// leave. Reference these rather than the bare strings so a typo is a compile
// error instead of a row that silently fails its constraint.
const (
	VaultKindPersonal = "personal"
	VaultKindShared   = "shared"
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
