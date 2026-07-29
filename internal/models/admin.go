package models

import "time"

// Admin mirrors vault3_admin (see scripts/sql/002.sql).
// Platform-admin grant for the future management console. Presence of a row
// is the grant; the console routes will gate on it when they ship.
type Admin struct {
	UserID          string    `json:"userId" db:"Vault3AdminUserID"`
	GrantedAt       time.Time `json:"grantedAt" db:"Vault3AdminGrantedAt"`
	GrantedByUserID string    `json:"grantedByUserId,omitempty" db:"Vault3AdminGrantedByUserID"`
	Notes           string    `json:"notes,omitempty" db:"Vault3AdminNotes"`
}
