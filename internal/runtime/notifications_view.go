package runtime

import (
	"strings"

	"vault3/internal/database"
	"vault3/internal/view"

	bungo "github.com/piotr-nierobisz/BunGo"
)

// The header bell and the notifications centre share one data shape
// (view.NotificationItem). The bell polls the list API; the centre page
// server-renders the same projection.

// notificationListLimit caps how many rows the bell and centre load — the
// feed is recency-oriented, not an archive.
const notificationListLimit = 50

// NotificationsPage renders /app/notifications.
func (r *Runtime) NotificationsPage(req *bungo.Request) (map[string]any, error) {
	user := CurrentUser(req)
	notifications, unread, listErr := database.SelectUserNotifications(
		req.Context, r.GetDb(), &r.Builder, r.Cipher, user.ID, notificationListLimit)
	if listErr != nil {
		return nil, listErr
	}
	return r.PageData(map[string]any{
		"PageTitle":     "Notifications | Vault3",
		"Viewer":        r.Viewer(req),
		"ActiveNav":     "notifications",
		"NoIndex":       true,
		"Notifications": view.NewNotificationItems(notifications),
		"UnreadCount":   unread,
	}), nil
}

// NotificationsAPI handles GET /api/v1/notifications: the bell's poll.
func (r *Runtime) NotificationsAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	notifications, unread, listErr := database.SelectUserNotifications(
		req.Context, r.GetDb(), &r.Builder, r.Cipher, user.ID, notificationListLimit)
	if listErr != nil {
		return bungo.APIResponse{}, listErr
	}
	return bungo.APIResponse{
		StatusCode: 200,
		Body: map[string]any{
			"items":       view.NewNotificationItems(notifications),
			"unreadCount": unread,
		},
	}, nil
}

// MarkNotificationReadAPI handles POST /api/v1/notifications/read {id}.
func (r *Runtime) MarkNotificationReadAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	payload, deny := decodeBody[idPayload](req)
	if deny != nil {
		return *deny, nil
	}
	if strings.TrimSpace(payload.ID) == "" {
		return apiError(400, "id is required."), nil
	}
	if markErr := database.MarkNotificationRead(req.Context, r.GetDb(), &r.Builder, user.ID, payload.ID); markErr != nil {
		return bungo.APIResponse{}, markErr
	}
	return bungo.APIResponse{StatusCode: 200, Body: map[string]any{"ok": true}}, nil
}

// MarkAllNotificationsReadAPI handles POST /api/v1/notifications/read-all.
func (r *Runtime) MarkAllNotificationsReadAPI(req *bungo.Request) (bungo.APIResponse, error) {
	user := CurrentUser(req)
	if markErr := database.MarkAllNotificationsRead(req.Context, r.GetDb(), &r.Builder, user.ID); markErr != nil {
		return bungo.APIResponse{}, markErr
	}
	return bungo.APIResponse{StatusCode: 200, Body: map[string]any{"ok": true}}, nil
}
