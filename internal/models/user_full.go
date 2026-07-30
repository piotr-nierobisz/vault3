package models

// UserFull is the hub-and-spoke composite for vault3_user: the hub row, its
// 1:1 spokes, and the user's vault access rows (each paired with its vault).
// Built by database.SelectUserFullByKeyValue; spokes that do not exist stay
// nil rather than erroring.
type UserFull struct {
	User
	Auth   *UserAuth   `json:"auth,omitempty"`
	Admin  *Admin      `json:"admin,omitempty"`
	Vaults []UserVault `json:"vaults"`
}

// UserVault pairs one vault3_vault_access row with its vault3_vault hub row —
// one level of FK hydration, per the composite-getter convention.
// MemberCount is the vault's total access rows (owner included), computed by
// SelectUserVaults so the client can badge shared vaults without a second
// query.
type UserVault struct {
	Access      VaultAccess `json:"access"`
	Vault       Vault       `json:"vault"`
	MemberCount int         `json:"memberCount"`
}
