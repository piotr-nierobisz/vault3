package models

import (
	"encoding/json"
	"time"
)

// UserKeys mirrors vault3_user_keys (see scripts/sql/002.sql).
// The user's asymmetric keypair, generated in the browser at registration.
// PublicKey is a plaintext JWK anyone may wrap to; EncPrivateKey is a
// client-side CipherEnvelope sealed under the account's key-encryption key.
// Exists so sharing (vaults, share links) can ship without a migration.
type UserKeys struct {
	UserID        string          `json:"userId" db:"Vault3UserKeysUserID"`
	Algo          string          `json:"algo" db:"Vault3UserKeysAlgo"`
	PublicKey     json.RawMessage `json:"publicKey" db:"Vault3UserKeysPublicKey"`
	EncPrivateKey json.RawMessage `json:"encPrivateKey" db:"Vault3UserKeysEncPrivateKey"`
	CreatedAt     time.Time       `json:"createdAt" db:"Vault3UserKeysCreatedAt"`
	UpdatedAt     time.Time       `json:"updatedAt" db:"Vault3UserKeysUpdatedAt"`
}
