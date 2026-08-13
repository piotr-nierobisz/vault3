package models

import "time"

// Admin mirrors vault3_admin (see scripts/sql/002.sql).
// Platform-admin grant: presence of a row is the grant, and the require_admin
// security layer gates the management console on nothing else.
type Admin struct {
	UserID          string    `json:"userId" db:"Vault3AdminUserID"`
	GrantedAt       time.Time `json:"grantedAt" db:"Vault3AdminGrantedAt"`
	GrantedByUserID string    `json:"grantedByUserId,omitempty" db:"Vault3AdminGrantedByUserID"`
	Notes           string    `json:"notes,omitempty" db:"Vault3AdminNotes"`
}

// PlatformStats is the operational snapshot the admin console opens on.
//
// Every figure here is a row count. That is not a limitation of the query —
// it is the whole shape of what an operator can know: the server holds item
// blobs it cannot open, so it can say how many items exist and when they
// changed, and nothing whatever about what any of them is. Do not grow this
// struct towards content.
type PlatformStats struct {
	Users           int `json:"users"`
	ActiveUsers     int `json:"activeUsers"`
	SuspendedUsers  int `json:"suspendedUsers"`
	VerifiedUsers   int `json:"verifiedUsers"`
	TwoFactorUsers  int `json:"twoFactorUsers"`
	AdminUsers      int `json:"adminUsers"`
	UsersLast7Days  int `json:"usersLast7Days"`
	UsersLast30Days int `json:"usersLast30Days"`

	Vaults       int `json:"vaults"`
	SharedVaults int `json:"sharedVaults"`
	Items        int `json:"items"`
	TrashedItems int `json:"trashedItems"`

	ActiveSessions   int `json:"activeSessions"`
	ActiveShareLinks int `json:"activeShareLinks"`
	PendingInvites   int `json:"pendingInvites"`
	OpenInquiries    int `json:"openInquiries"`
}

// AdminUserRow is one line of the console's account list: the hub row plus the
// handful of facts an operator acts on, aggregated in SQL so the list costs
// one query. Same rule as PlatformStats — counts and account state, never
// anything from inside a vault.
type AdminUserRow struct {
	ID             string     `json:"id"`
	Email          string     `json:"email"`
	DisplayName    string     `json:"displayName,omitempty"`
	IsActive       bool       `json:"isActive"`
	EmailVerified  bool       `json:"emailVerified"`
	TwoFactor      bool       `json:"twoFactor"`
	IsAdmin        bool       `json:"isAdmin"`
	VaultCount     int        `json:"vaultCount"`
	ItemCount      int        `json:"itemCount"`
	SessionCount   int        `json:"sessionCount"`
	LastLoginAt    *time.Time `json:"lastLoginAt,omitempty"`
	ArchivedAt     *time.Time `json:"archivedAt,omitempty"`
	ArchivedReason string     `json:"archivedReason,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
}

// AdminAuditRow is one audit entry with the acting account's email resolved,
// so the trail reads without a lookup per line. Email is empty when the row
// predates a deleted account (the FK is ON DELETE SET NULL, by design: the
// event survives the account).
type AdminAuditRow struct {
	AuditLog
	Email string `json:"email,omitempty"`
}
