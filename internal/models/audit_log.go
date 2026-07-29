package models

import "time"

// AuditLog mirrors vault3_audit_log (see scripts/sql/004.sql).
// Append-only security trail. IPAddress, UserAgent and Detail carry decrypted
// values (stored as FieldCipher ciphertext). Detail is a small JSON string of
// contextual fields; item content never appears here — the server never has it.
type AuditLog struct {
	ID         string    `json:"id" db:"Vault3AuditLogID"`
	UserID     string    `json:"userId,omitempty" db:"Vault3AuditLogUserID"`
	Action     string    `json:"action" db:"Vault3AuditLogAction"`
	EntityType string    `json:"entityType,omitempty" db:"Vault3AuditLogEntityType"`
	EntityID   string    `json:"entityId,omitempty" db:"Vault3AuditLogEntityID"`
	IPAddress  string    `json:"ipAddress,omitempty" db:"Vault3AuditLogIpAddressEnc"`
	UserAgent  string    `json:"userAgent,omitempty" db:"Vault3AuditLogUserAgentEnc"`
	Detail     string    `json:"detail,omitempty" db:"Vault3AuditLogDetailEnc"`
	CreatedAt  time.Time `json:"createdAt" db:"Vault3AuditLogCreatedAt"`
}
