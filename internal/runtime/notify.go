package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"vault3/internal/database"
	"vault3/internal/models"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Notifications run through one thin abstraction so handlers never decide
// who gets told, over which channels, or against whose preferences. A
// handler that makes something notification-worthy happen builds the
// matching event and calls r.Notify(ctx, event); everything below stays
// here.
//
// An event knows how to expand itself into the concrete notifications it
// implies (recipients + rendered title/body + requested channels). Notify
// then, per recipient and per channel, consults that recipient's contact
// preferences and dispatches only the channels they have opted into. In-app
// delivery writes a vault3_notification row (encrypted at rest); email goes
// through the Mailgun template named on the planned notification (email.go)
// and is skipped with a log line while email_sending_enabled is off.
//
// Call Notify AFTER the triggering write commits: notifications are a side
// effect, never a reason to roll back a user's action.

// NotificationChannel is a delivery channel a notification can travel over.
type NotificationChannel string

const (
	ChannelInApp NotificationChannel = "in_app"
	ChannelEmail NotificationChannel = "email"
)

// NotificationEvent is something worth telling users about. Implementations
// resolve their own recipients and content so the abstraction owns the
// "who/what/which channel" decisions, not the calling handler.
type NotificationEvent interface {
	plan(ctx context.Context, r *Runtime) ([]plannedNotification, error)
}

// plannedNotification is one rendered notification bound for one recipient
// over a set of requested channels (before preference filtering).
// EmailTemplate names the template in email_templates.go and EmailData
// carries its variables; a requested email channel without a template is
// skipped at debug.
type plannedNotification struct {
	UserID        string
	Kind          string
	Title         string
	Body          string
	Channels      []NotificationChannel
	Metadata      json.RawMessage
	EmailTemplate string
	EmailData     map[string]any
}

// notificationRecipient is one recipient's contact details and decoded
// preferences, loaded once per planned notification.
type notificationRecipient struct {
	Email       string
	DisplayName string
	Prefs       models.NotificationPrefs
}

// Notify expands an event and delivers each resulting notification on the
// channels the recipient has opted into. Delivery is best-effort per
// recipient/channel: one failed send is logged and skipped so it never
// blocks the others or the action that triggered it. Only a failure to
// expand the event (a programming error) is returned.
func (r *Runtime) Notify(ctx context.Context, event NotificationEvent) error {
	planned, planErr := event.plan(ctx, r)
	if planErr != nil {
		return fmt.Errorf("plan notifications: %w", planErr)
	}
	for _, p := range planned {
		if p.UserID == "" {
			continue
		}
		recipient := r.recipientDetails(ctx, p.UserID)
		for _, channel := range p.Channels {
			if !channelAllowed(recipient.Prefs, p.Kind, channel) {
				continue
			}
			if dispatchErr := r.dispatch(ctx, channel, &p, &recipient); dispatchErr != nil {
				r.Log.Error("notification dispatch failed",
					zap.String("kind", p.Kind),
					zap.String("channel", string(channel)),
					zap.String("user_id", p.UserID),
					zap.Error(dispatchErr),
				)
			}
		}
	}
	return nil
}

// dispatch delivers one planned notification over one channel.
func (r *Runtime) dispatch(ctx context.Context, channel NotificationChannel, p *plannedNotification, recipient *notificationRecipient) error {
	switch channel {
	case ChannelInApp:
		id, idErr := uuid.NewV7()
		if idErr != nil {
			return fmt.Errorf("generate notification id: %w", idErr)
		}
		return database.InsertNotification(ctx, r.GetDb(), &r.Builder, r.Cipher, &models.Notification{
			ID:       id.String(),
			UserID:   p.UserID,
			Kind:     p.Kind,
			Title:    p.Title,
			Body:     p.Body,
			Metadata: p.Metadata,
		})
	case ChannelEmail:
		if p.EmailTemplate == "" {
			r.Log.Debug("email requested but no template modelled; skipping",
				zap.String("kind", p.Kind), zap.String("user_id", p.UserID))
			return nil
		}
		return r.SendTemplateEmail(ctx, recipient.Email, recipient.DisplayName, p.EmailTemplate, p.Kind, p.EmailData)
	default:
		return nil
	}
}

// recipientDetails loads a recipient's contact details and decoded
// notification preferences, falling back to the permissive defaults if the
// lookup fails so a preferences hiccup never silently swallows a security
// notice. A failed lookup leaves the email address empty, which the email
// sender reports as a delivery failure for that recipient.
func (r *Runtime) recipientDetails(ctx context.Context, userID string) notificationRecipient {
	email, displayName, raw, lookupErr := database.SelectUserNotificationRecipient(ctx, r.GetDb(), &r.Builder, r.Cipher, userID)
	if lookupErr != nil {
		r.Log.Warn("notification recipient lookup failed; assuming defaults",
			zap.String("user_id", userID), zap.Error(lookupErr))
		return notificationRecipient{Prefs: models.DefaultNotificationPrefs()}
	}
	return notificationRecipient{
		Email:       email,
		DisplayName: displayName,
		Prefs:       models.DecodeNotificationPrefs(raw),
	}
}

// alwaysEmailKinds are the notification kinds whose email has no opt-out:
// account-integrity messages a user must receive regardless of preferences.
var alwaysEmailKinds = map[string]bool{
	"welcome":            true,
	"email_verification": true,
	"account_reset":      true,
	"password_changed":   true,
}

// channelAllowed reports whether a recipient wants this notification kind on
// this channel. The in-app bell can never be disabled; the email channel is
// gated by the master toggle and the per-kind category toggle, except for
// the always-sent kinds which bypass preferences entirely.
func channelAllowed(prefs models.NotificationPrefs, kind string, channel NotificationChannel) bool {
	switch channel {
	case ChannelInApp:
		return true
	case ChannelEmail:
		if alwaysEmailKinds[kind] {
			return true
		}
		return prefs.EmailAllowed(emailCategoryForKind(kind))
	default:
		return false
	}
}

// emailCategoryForKind maps a notification kind to the preference category
// that gates its email. An unknown kind returns "" so EmailAllowed applies
// only the master toggle (a new kind is never silenced before it gets its
// own toggle).
func emailCategoryForKind(kind string) string {
	switch kind {
	case "new_device_login", "two_factor_enabled", "two_factor_disabled":
		return models.NotifCategorySecurityAlerts
	case "product_update":
		return models.NotifCategoryProductUpdates
	default:
		return ""
	}
}

// --- Events -----------------------------------------------------------------

// Welcome greets a freshly registered account (in-app + email).
type Welcome struct {
	UserID string
}

func (e *Welcome) plan(_ context.Context, _ *Runtime) ([]plannedNotification, error) {
	meta, _ := json.Marshal(map[string]string{"href": "/app"})
	return []plannedNotification{{
		UserID:        e.UserID,
		Kind:          "welcome",
		Title:         "Welcome to Vault3",
		Body:          "Your vault is sealed and ready. Keep your Emergency Kit somewhere safe — it is the only way back in.",
		Channels:      []NotificationChannel{ChannelInApp, ChannelEmail},
		Metadata:      meta,
		EmailTemplate: "WELCOME",
	}}, nil
}

// EmailVerification carries the single-use confirm link (email only — the
// recipient cannot see in-app notifications before signing in).
type EmailVerification struct {
	UserID    string
	VerifyURL string
}

func (e *EmailVerification) plan(_ context.Context, _ *Runtime) ([]plannedNotification, error) {
	return []plannedNotification{{
		UserID:        e.UserID,
		Kind:          "email_verification",
		Title:         "Confirm your email address",
		Body:          "A confirmation link was sent to your inbox.",
		Channels:      []NotificationChannel{ChannelEmail},
		EmailTemplate: "EMAIL_VERIFICATION",
		EmailData:     map[string]any{"verifyUrl": e.VerifyURL},
	}}, nil
}

// AccountReset carries the destructive reset link (email only).
type AccountReset struct {
	UserID   string
	ResetURL string
}

func (e *AccountReset) plan(_ context.Context, _ *Runtime) ([]plannedNotification, error) {
	return []plannedNotification{{
		UserID:        e.UserID,
		Kind:          "account_reset",
		Title:         "Account reset requested",
		Body:          "An account reset was requested for your address.",
		Channels:      []NotificationChannel{ChannelEmail},
		EmailTemplate: "ACCOUNT_RESET",
		EmailData:     map[string]any{"resetUrl": e.ResetURL},
	}}, nil
}

// NewDeviceLogin alerts on a sign-in from an unseen IP (in-app + email).
type NewDeviceLogin struct {
	UserID    string
	IPAddress string
	UserAgent string
	At        time.Time
}

func (e *NewDeviceLogin) plan(_ context.Context, _ *Runtime) ([]plannedNotification, error) {
	detail := fmt.Sprintf("%s · %s · %s", e.At.UTC().Format("2 Jan 2006 15:04 MST"), e.IPAddress, compactUserAgent(e.UserAgent))
	meta, _ := json.Marshal(map[string]string{"href": "/app/settings"})
	return []plannedNotification{{
		UserID:        e.UserID,
		Kind:          "new_device_login",
		Title:         "New sign-in to your account",
		Body:          "Your account was opened from a device or network we haven't seen before. " + detail,
		Channels:      []NotificationChannel{ChannelInApp, ChannelEmail},
		Metadata:      meta,
		EmailTemplate: "NEW_DEVICE_LOGIN",
		EmailData:     map[string]any{"loginDetail": detail},
	}}, nil
}

// PasswordChanged confirms a Master Password rotation (in-app + email).
type PasswordChanged struct {
	UserID string
}

func (e *PasswordChanged) plan(_ context.Context, _ *Runtime) ([]plannedNotification, error) {
	meta, _ := json.Marshal(map[string]string{"href": "/app/settings"})
	return []plannedNotification{{
		UserID:        e.UserID,
		Kind:          "password_changed",
		Title:         "Master Password changed",
		Body:          "Your Master Password was changed and every other session was signed out.",
		Channels:      []NotificationChannel{ChannelInApp, ChannelEmail},
		Metadata:      meta,
		EmailTemplate: "PASSWORD_CHANGED",
	}}, nil
}

// TwoFactorChanged reports 2FA being enabled or disabled (in-app + email,
// gated by the security-alerts preference).
type TwoFactorChanged struct {
	UserID  string
	Enabled bool
}

func (e *TwoFactorChanged) plan(_ context.Context, _ *Runtime) ([]plannedNotification, error) {
	kind, title, body, template := "two_factor_enabled",
		"Two-factor authentication enabled",
		"Sign-ins now require a code from your authenticator app.",
		"TWO_FACTOR_ENABLED"
	if !e.Enabled {
		kind, title, body, template = "two_factor_disabled",
			"Two-factor authentication disabled",
			"Two-factor authentication was removed from your account.",
			"TWO_FACTOR_DISABLED"
	}
	meta, _ := json.Marshal(map[string]string{"href": "/app/settings"})
	return []plannedNotification{{
		UserID:        e.UserID,
		Kind:          kind,
		Title:         title,
		Body:          body,
		Channels:      []NotificationChannel{ChannelInApp, ChannelEmail},
		Metadata:      meta,
		EmailTemplate: template,
	}}, nil
}

// VaultMemberJoined tells a vault owner that an invite was accepted
// (in-app; vault names are ciphertext, so bodies stay generic).
type VaultMemberJoined struct {
	OwnerUserID string
	MemberEmail string
}

func (e *VaultMemberJoined) plan(_ context.Context, _ *Runtime) ([]plannedNotification, error) {
	meta, _ := json.Marshal(map[string]string{"href": "/app"})
	return []plannedNotification{{
		UserID:   e.OwnerUserID,
		Kind:     "vault_member_joined",
		Title:    "Someone joined your shared vault",
		Body:     e.MemberEmail + " accepted your invite and can now view the vault.",
		Channels: []NotificationChannel{ChannelInApp},
		Metadata: meta,
	}}, nil
}

// VaultMemberLeft tells a vault owner that a member left (in-app).
type VaultMemberLeft struct {
	OwnerUserID string
	MemberEmail string
}

func (e *VaultMemberLeft) plan(_ context.Context, _ *Runtime) ([]plannedNotification, error) {
	meta, _ := json.Marshal(map[string]string{"href": "/app"})
	return []plannedNotification{{
		UserID:   e.OwnerUserID,
		Kind:     "vault_member_left",
		Title:    "Someone left your shared vault",
		Body:     e.MemberEmail + " left a vault you own and can no longer view it.",
		Channels: []NotificationChannel{ChannelInApp},
		Metadata: meta,
	}}, nil
}

// VaultAccessEnded tells a member their access to a shared vault ended —
// removed by the owner, or the vault was deleted (in-app).
type VaultAccessEnded struct {
	MemberUserID string
	Reason       string // "removed" | "deleted"
}

func (e *VaultAccessEnded) plan(_ context.Context, _ *Runtime) ([]plannedNotification, error) {
	body := "Your access to a shared vault was removed by its owner."
	if e.Reason == "deleted" {
		body = "A shared vault you could view was deleted by its owner."
	}
	meta, _ := json.Marshal(map[string]string{"href": "/app"})
	return []plannedNotification{{
		UserID:   e.MemberUserID,
		Kind:     "vault_access_ended",
		Title:    "Shared vault access ended",
		Body:     body,
		Channels: []NotificationChannel{ChannelInApp},
		Metadata: meta,
	}}, nil
}

// compactUserAgent trims a UA string to something a human can scan in a
// notification row.
func compactUserAgent(ua string) string {
	if len(ua) > 80 {
		return ua[:77] + "…"
	}
	if ua == "" {
		return "unknown device"
	}
	return ua
}
