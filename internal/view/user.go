package view

import (
	"strings"

	"vault3/internal/models"
)

// UserSummary is the display-oriented projection of a UserFull, built once
// per request by the load_viewer security layer and read via rt.Viewer(req).
type UserSummary struct {
	User *models.User
	// Auth carries token hashes and encrypted TOTP secrets. It is excluded
	// from JSON so it never reaches the client: BunGo serialises the whole
	// handler map (Viewer included) into window.__BUNGO_DATA__ on any page
	// with non-empty data, so an exported Auth field would leak secrets.
	Auth    *models.UserAuth `json:"-"`
	IsAdmin bool
	// VaultCount is the only vault fact templates need; the full keyset is a
	// separate, deliberate payload (view.Keyset) on the pages that unlock.
	VaultCount int
}

// NewUserSummary builds a UserSummary from a hydrated UserFull. Returns nil
// when the input is nil so handlers can short-circuit unauthenticated
// requests without an extra branch.
func NewUserSummary(uf *models.UserFull) *UserSummary {
	if uf == nil {
		return nil
	}
	return &UserSummary{
		User:       &uf.User,
		Auth:       uf.Auth,
		IsAdmin:    uf.Admin != nil,
		VaultCount: len(uf.Vaults),
	}
}

// EmailUnverified reports whether the viewer's email address still needs
// confirming; it drives the reminder banner in the app header. A missing
// Auth row fails open so a lookup hiccup cannot nag or gate anyone.
func (s *UserSummary) EmailUnverified() bool {
	return s != nil && s.Auth != nil && !s.Auth.EmailVerified
}

// TwoFactorEnabled reports whether a promoted TOTP secret is on file, for
// the profile security panel.
func (s *UserSummary) TwoFactorEnabled() bool {
	return s != nil && s.Auth != nil && s.Auth.TwoFactorEnabled()
}

// Name returns the display name, falling back to the email's local part so
// the header always has something to greet with.
func (s *UserSummary) Name() string {
	if s == nil || s.User == nil {
		return ""
	}
	if s.User.DisplayName != "" {
		return s.User.DisplayName
	}
	local, _, _ := strings.Cut(s.User.Email, "@")
	return local
}

// Initials returns up to two uppercased initials from the display name,
// falling back to the email's first character. Used by the header avatar.
func (s *UserSummary) Initials() string {
	if s == nil || s.User == nil {
		return ""
	}
	fields := strings.Fields(s.User.DisplayName)
	switch {
	case len(fields) >= 2:
		return strings.ToUpper(initial(fields[0]) + initial(fields[len(fields)-1]))
	case len(fields) == 1:
		return strings.ToUpper(initial(fields[0]))
	default:
		return strings.ToUpper(initial(s.User.Email))
	}
}

// Email returns the account email, empty when no user is loaded.
func (s *UserSummary) Email() string {
	if s == nil || s.User == nil {
		return ""
	}
	return s.User.Email
}

func initial(value string) string {
	value = strings.TrimSpace(value)
	for _, r := range value {
		return string(r)
	}
	return ""
}
