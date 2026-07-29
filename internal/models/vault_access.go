package models

import (
	"encoding/json"
	"time"
)

// VaultAccess mirrors vault3_vault_access (see scripts/sql/003.sql).
// One row per (vault, user): the vault key wrapped for that user.
// WrapAlgo 'muk' = wrapped under the user's own key-encryption key;
// 'rsa-oaep' is reserved for wrapping to another user's public key when
// shared vaults ship.
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
