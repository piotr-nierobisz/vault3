package models

import "encoding/json"

// Notification preference categories. The in-app bell can never be disabled;
// these gate the email channel only (see runtime/notify.go).
const (
	NotifCategorySecurityAlerts = "securityAlerts"
	NotifCategoryProductUpdates = "productUpdates"
)

// NotificationPrefs is the canonical decoded shape of
// vault3_user.Vault3UserNotificationPrefs. The profile page reads and writes
// exactly this struct, and notify.go consults it before emailing.
type NotificationPrefs struct {
	EmailEnabled   bool `json:"emailEnabled"`
	SecurityAlerts bool `json:"securityAlerts"`
	ProductUpdates bool `json:"productUpdates"`
}

// DefaultNotificationPrefs are applied to new accounts and whenever a stored
// blob cannot be decoded: email on, security alerts on, product updates off.
func DefaultNotificationPrefs() NotificationPrefs {
	return NotificationPrefs{EmailEnabled: true, SecurityAlerts: true, ProductUpdates: false}
}

// DecodeNotificationPrefs parses a stored prefs blob, falling back to the
// defaults on empty or malformed input so a bad row never silences security
// email by accident.
func DecodeNotificationPrefs(raw json.RawMessage) NotificationPrefs {
	prefs := DefaultNotificationPrefs()
	if len(raw) == 0 {
		return prefs
	}
	if unmarshalErr := json.Unmarshal(raw, &prefs); unmarshalErr != nil {
		return DefaultNotificationPrefs()
	}
	return prefs
}

// EmailAllowed reports whether email may be sent for the given category. The
// master toggle gates everything; an empty category applies the master toggle
// alone (a new kind is never silenced before it gets its own toggle).
func (p NotificationPrefs) EmailAllowed(category string) bool {
	if !p.EmailEnabled {
		return false
	}
	switch category {
	case NotifCategorySecurityAlerts:
		return p.SecurityAlerts
	case NotifCategoryProductUpdates:
		return p.ProductUpdates
	default:
		return true
	}
}
