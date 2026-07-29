package models

import (
	"encoding/json"
	"time"
)

// ShareLink mirrors vault3_share_link (see scripts/sql/006.sql).
// WrappedItemKey is the item's per-item key sealed (client-side, A256GCM)
// under a random share key that exists only in the share URL's fragment —
// the server stores the wrap and the token hash but can never decrypt.
type ShareLink struct {
	ID              string          `json:"id" db:"Vault3ShareLinkID"`
	ItemID          string          `json:"itemId" db:"Vault3ShareLinkItemID"`
	CreatedByUserID string          `json:"createdByUserId" db:"Vault3ShareLinkCreatedByUserID"`
	TokenHash       string          `json:"-" db:"Vault3ShareLinkTokenHash"`
	WrappedItemKey  json.RawMessage `json:"wrappedItemKey" db:"Vault3ShareLinkWrappedItemKey"`
	ExpiresAt       time.Time       `json:"expiresAt" db:"Vault3ShareLinkExpiresAt"`
	RevokedAt       *time.Time      `json:"revokedAt,omitempty" db:"Vault3ShareLinkRevokedAt"`
	ViewCount       int             `json:"viewCount" db:"Vault3ShareLinkViewCount"`
	CreatedAt       time.Time       `json:"createdAt" db:"Vault3ShareLinkCreatedAt"`
}
