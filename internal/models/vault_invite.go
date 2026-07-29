package models

import (
	"encoding/json"
	"time"
)

// VaultInvite mirrors vault3_vault_invite (see scripts/sql/006.sql).
// WrappedVaultKey is the vault key sealed (client-side, A256GCM) under a
// random invite key that exists only in the invite URL's fragment. Accepting
// re-wraps the vault key under the acceptor's own key-encryption key and
// inserts the vault3_vault_access row; the invite is single-use.
type VaultInvite struct {
	ID               string          `json:"id" db:"Vault3VaultInviteID"`
	VaultID          string          `json:"vaultId" db:"Vault3VaultInviteVaultID"`
	CreatedByUserID  string          `json:"createdByUserId" db:"Vault3VaultInviteCreatedByUserID"`
	TokenHash        string          `json:"-" db:"Vault3VaultInviteTokenHash"`
	WrappedVaultKey  json.RawMessage `json:"wrappedVaultKey" db:"Vault3VaultInviteWrappedVaultKey"`
	Role             string          `json:"role" db:"Vault3VaultInviteRole"`
	ExpiresAt        time.Time       `json:"expiresAt" db:"Vault3VaultInviteExpiresAt"`
	RevokedAt        *time.Time      `json:"revokedAt,omitempty" db:"Vault3VaultInviteRevokedAt"`
	AcceptedAt       *time.Time      `json:"acceptedAt,omitempty" db:"Vault3VaultInviteAcceptedAt"`
	AcceptedByUserID *string         `json:"acceptedByUserId,omitempty" db:"Vault3VaultInviteAcceptedByUserID"`
	CreatedAt        time.Time       `json:"createdAt" db:"Vault3VaultInviteCreatedAt"`
}
