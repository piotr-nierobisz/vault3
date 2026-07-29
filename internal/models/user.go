package models

import (
	"encoding/json"
	"time"
)

// User mirrors vault3_user (see scripts/sql/002.sql).
// Identity, lifecycle, notification prefs, and the per-user Revision counter
// behind the cross-device sync signal. Auth-sensitive fields live separately
// in vault3_user_auth. DisplayName is stored server-encrypted
// (Vault3UserDisplayNameEnc); the struct carries the decrypted value, which
// the database layer produces via the runtime's FieldCipher.
type User struct {
	ID                string          `json:"id" db:"Vault3UserID"`
	Email             string          `json:"email" db:"Vault3UserEmail"`
	DisplayName       string          `json:"displayName,omitempty" db:"Vault3UserDisplayNameEnc"`
	NotificationPrefs json.RawMessage `json:"notificationPrefs" db:"Vault3UserNotificationPrefs"`
	Revision          int64           `json:"revision" db:"Vault3UserRevision"`
	IsActive          bool            `json:"isActive" db:"Vault3UserIsActive"`
	LastLoginAt       *time.Time      `json:"lastLoginAt,omitempty" db:"Vault3UserLastLoginAt"`
	ArchivedAt        *time.Time      `json:"archivedAt,omitempty" db:"Vault3UserArchivedAt"`
	ArchivedReason    string          `json:"archivedReason,omitempty" db:"Vault3UserArchivedReason"`
	CreatedAt         time.Time       `json:"createdAt" db:"Vault3UserCreatedAt"`
	UpdatedAt         time.Time       `json:"updatedAt" db:"Vault3UserUpdatedAt"`
}
