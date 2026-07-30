package models

import (
	"encoding/json"
	"time"
)

// Vault access roles and wrap algorithms — the only values the
// Vault3VaultAccessRole and Vault3VaultAccessWrapAlgo CHECK constraints
// accept (scripts/sql/003.sql).
//
// RoleOwner is the authorisation boundary for every vault and item mutation:
// members read, owners write. Because that comparison is what stands between
// a member and someone else's data, it must never be spelled out by hand —
// a mistyped literal would compare unequal and quietly deny, or worse, be
// inverted somewhere and quietly allow.
const (
	RoleOwner   = "owner"
	RoleMember  = "member"
	WrapAlgoMUK = "muk"
)

// VaultAccess mirrors vault3_vault_access (see scripts/sql/003.sql).
// One row per (vault, user): the vault key wrapped for that user. WrapAlgo is
// always 'muk' — wrapped under that user's own key-encryption key. It is the
// only value the CHECK constraint accepts, and the column is kept as an
// explicit record of which construction sealed the row rather than as a
// branch point.
// VaultMember is the members-dialog projection of one access row joined
// with its user: who can open the vault and with what role. DisplayName is
// decrypted from FieldCipher storage by the database layer.
type VaultMember struct {
	UserID      string    `json:"userId"`
	Email       string    `json:"email"`
	DisplayName string    `json:"displayName"`
	Role        string    `json:"role"`
	JoinedAt    time.Time `json:"joinedAt"`
}

type VaultAccess struct {
	ID         string          `json:"id" db:"Vault3VaultAccessID"`
	VaultID    string          `json:"vaultId" db:"Vault3VaultAccessVaultID"`
	UserID     string          `json:"userId" db:"Vault3VaultAccessUserID"`
	Role       string          `json:"role" db:"Vault3VaultAccessRole"`
	WrapAlgo   string          `json:"wrapAlgo" db:"Vault3VaultAccessWrapAlgo"`
	WrappedKey json.RawMessage `json:"wrappedKey" db:"Vault3VaultAccessWrappedKey"`
	CreatedAt  time.Time       `json:"createdAt" db:"Vault3VaultAccessCreatedAt"`
	UpdatedAt  time.Time       `json:"updatedAt" db:"Vault3VaultAccessUpdatedAt"`
}
