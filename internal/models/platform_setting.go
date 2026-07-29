package models

import "time"

// PlatformSetting mirrors vault3_platform_setting (see scripts/sql/004.sql).
// Read and written only through the fail-safe accessors in
// internal/runtime/platform_setting.go.
type PlatformSetting struct {
	Key       string    `json:"key" db:"Vault3PlatformSettingKey"`
	Value     string    `json:"value" db:"Vault3PlatformSettingValue"`
	Kind      string    `json:"kind" db:"Vault3PlatformSettingKind"`
	UpdatedAt time.Time `json:"updatedAt" db:"Vault3PlatformSettingUpdatedAt"`
}
