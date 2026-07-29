package view

import (
	"encoding/json"
	"fmt"
	"time"

	"vault3/internal/models"
)

// NotificationItem is the client-facing shape the header bell and the
// notifications centre render. Title and body arrive already decrypted from
// the database layer; Href is pulled out of the metadata blob so the client
// never parses metadata itself.
type NotificationItem struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	IsRead    bool   `json:"isRead"`
	TimeLabel string `json:"timeLabel"`
	Href      string `json:"href,omitempty"`
	Icon      string `json:"icon"`
}

// NewNotificationItems projects a slice of decrypted notifications.
func NewNotificationItems(notifications []models.Notification) []NotificationItem {
	out := make([]NotificationItem, 0, len(notifications))
	for i := range notifications {
		out = append(out, newNotificationItem(&notifications[i]))
	}
	return out
}

func newNotificationItem(n *models.Notification) NotificationItem {
	item := NotificationItem{
		ID:        n.ID,
		Kind:      n.Kind,
		Title:     n.Title,
		Body:      n.Body,
		IsRead:    n.IsRead,
		TimeLabel: relativeTimeLabel(n.CreatedAt),
		Icon:      iconForKind(n.Kind),
	}
	if len(n.Metadata) > 0 {
		var meta struct {
			Href string `json:"href"`
		}
		if unmarshalErr := json.Unmarshal(n.Metadata, &meta); unmarshalErr == nil {
			item.Href = meta.Href
		}
	}
	return item
}

// iconForKind maps a notification kind to the client icon token the bell
// renders (see the ICONS map in web/layouts/base.gohtml).
func iconForKind(kind string) string {
	switch kind {
	case "new_device_login":
		return "device"
	case "password_changed", "two_factor_enabled", "two_factor_disabled":
		return "shield"
	case "email_verification", "welcome":
		return "seal"
	case "product_update":
		return "sparkle"
	default:
		return "bell"
	}
}

// relativeTimeLabel renders a compact "just now / 5m / 3h / 2d / 12 Jan"
// label for notification rows.
func relativeTimeLabel(at time.Time) string {
	elapsed := time.Since(at)
	switch {
	case elapsed < time.Minute:
		return "just now"
	case elapsed < time.Hour:
		return fmt.Sprintf("%dm", int(elapsed.Minutes()))
	case elapsed < 24*time.Hour:
		return fmt.Sprintf("%dh", int(elapsed.Hours()))
	case elapsed < 14*24*time.Hour:
		return fmt.Sprintf("%dd", int(elapsed.Hours()/24))
	default:
		return at.Format("2 Jan")
	}
}
