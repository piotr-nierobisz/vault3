package models

import (
	"encoding/json"
	"time"
)

// Notification mirrors vault3_notification (see scripts/sql/004.sql).
// Title and Body carry the decrypted values (stored as FieldCipher
// ciphertext); Metadata holds only non-sensitive routing keys such as href.
type Notification struct {
	ID        string          `json:"id" db:"Vault3NotificationID"`
	UserID    string          `json:"userId" db:"Vault3NotificationUserID"`
	Kind      string          `json:"kind" db:"Vault3NotificationKind"`
	Title     string          `json:"title" db:"Vault3NotificationTitleEnc"`
	Body      string          `json:"body" db:"Vault3NotificationBodyEnc"`
	IsRead    bool            `json:"isRead" db:"Vault3NotificationIsRead"`
	ReadAt    *time.Time      `json:"readAt,omitempty" db:"Vault3NotificationReadAt"`
	Metadata  json.RawMessage `json:"metadata" db:"Vault3NotificationMetadata"`
	CreatedAt time.Time       `json:"createdAt" db:"Vault3NotificationCreatedAt"`
}
