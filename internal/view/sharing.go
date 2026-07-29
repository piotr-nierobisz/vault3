package view

import (
	"time"

	"vault3/internal/models"
)

// ShareLinkRow is the owner-facing projection of one share link. The wrapped
// item key and token hash stay server-side: the owner already has the item,
// and a listed link must never resurrect its secret.
type ShareLinkRow struct {
	ID        string     `json:"id"`
	ItemID    string     `json:"itemId"`
	ExpiresAt time.Time  `json:"expiresAt"`
	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
	ViewCount int        `json:"viewCount"`
	CreatedAt time.Time  `json:"createdAt"`
}

// NewShareLinkRow projects one model row.
func NewShareLinkRow(link *models.ShareLink) ShareLinkRow {
	return ShareLinkRow{
		ID:        link.ID,
		ItemID:    link.ItemID,
		ExpiresAt: link.ExpiresAt,
		Revoked:   link.RevokedAt != nil,
		RevokedAt: link.RevokedAt,
		ViewCount: link.ViewCount,
		CreatedAt: link.CreatedAt,
	}
}

// NewShareLinkRows projects a slice.
func NewShareLinkRows(links []models.ShareLink) []ShareLinkRow {
	out := make([]ShareLinkRow, 0, len(links))
	for i := range links {
		out = append(out, NewShareLinkRow(&links[i]))
	}
	return out
}

// VaultInviteRow is the owner-facing projection of one pending invite.
type VaultInviteRow struct {
	ID        string    `json:"id"`
	VaultID   string    `json:"vaultId"`
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
}

// NewVaultInviteRow projects one model row.
func NewVaultInviteRow(invite *models.VaultInvite) VaultInviteRow {
	return VaultInviteRow{
		ID:        invite.ID,
		VaultID:   invite.VaultID,
		ExpiresAt: invite.ExpiresAt,
		CreatedAt: invite.CreatedAt,
	}
}

// NewVaultInviteRows projects a slice.
func NewVaultInviteRows(invites []models.VaultInvite) []VaultInviteRow {
	out := make([]VaultInviteRow, 0, len(invites))
	for i := range invites {
		out = append(out, NewVaultInviteRow(&invites[i]))
	}
	return out
}
