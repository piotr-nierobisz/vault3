package models

import "time"

// Session mirrors vault3_session (see scripts/sql/004.sql).
// Server-side session store. The cookie holds the opaque token; TokenHash is
// the lookup key here. IPAddress and UserAgent carry the decrypted values
// (the database layer decrypts the *_Enc columns through the FieldCipher);
// IpHash is the deterministic blind used for new-device detection.
type Session struct {
	ID         string    `json:"id" db:"Vault3SessionID"`
	TokenHash  string    `json:"-" db:"Vault3SessionTokenHash"`
	UserID     string    `json:"userId" db:"Vault3SessionUserID"`
	IPAddress  string    `json:"ipAddress,omitempty" db:"Vault3SessionIpAddressEnc"`
	IPHash     string    `json:"-" db:"Vault3SessionIpHash"`
	UserAgent  string    `json:"userAgent,omitempty" db:"Vault3SessionUserAgentEnc"`
	ExpiresAt  time.Time `json:"expiresAt" db:"Vault3SessionExpiresAt"`
	CreatedAt  time.Time `json:"createdAt" db:"Vault3SessionCreatedAt"`
	LastSeenAt time.Time `json:"lastSeenAt" db:"Vault3SessionLastSeenAt"`
}
