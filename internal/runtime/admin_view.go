package runtime

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"vault3/internal/config"
	"vault3/internal/database"
	"vault3/internal/models"

	bungo "github.com/piotr-nierobisz/BunGo"
	"go.uber.org/zap"
)

// The management console (config.AdminConsolePath). Everything here sits
// behind require_admin, and three rules shape all of it:
//
//   - An admin is an operator, not a super-user over vaults. There is no
//     endpoint in this file that reads an item, a wrapped key or an envelope,
//     and there cannot be a useful one: the server holds no key to open them.
//     What an operator can do is exactly what the *server* can do — count
//     rows, flip platform gates, and change account state.
//   - Every mutation is attributed. Admin actions run through the ordinary
//     commit pipeline with the ADMIN as actor and the target user as the
//     signalled audience, so the audit trail says who did it and the target's
//     own devices refresh.
//   - The console cannot lock itself out. An admin may not suspend, delete or
//     de-admin themselves, and the last remaining grant cannot be revoked.

// adminSettingKinds is the allowlist of settings the console may write, with
// the kind each one is stored as. An operator UI that could write arbitrary
// keys would turn a typo into a silently dead gate — and since every reader
// fails safe on a missing row, a misspelled key reads as "off" rather than as
// an error anyone would notice.
var adminSettingKinds = map[string]string{
	config.PublicRegistrationSettingKey:        "bool",
	config.EmailSendingSettingKey:              "bool",
	config.EmailVerificationRequiredSettingKey: "bool",
}

// AdminConsolePage renders the console shell with the overview already in
// hand. The lists (accounts, trail, inbox) are fetched per tab rather than
// shipped here: they page, and only one of them is ever on screen.
func (r *Runtime) AdminConsolePage(req *bungo.Request) (map[string]any, error) {
	overview, overviewErr := r.adminOverview(req.Context)
	if overviewErr != nil {
		return nil, overviewErr
	}
	return r.PageData(map[string]any{
		"PageTitle": "Console | Vault3",
		"Viewer":    r.Viewer(req),
		"ActiveNav": "admin",
		"NoIndex":   true,
		"Stats":     overview["stats"],
		"Settings":  overview["settings"],
		"PageSize":  config.AdminPageSize,
		// SelfID lets the account list hide the controls this admin's own row
		// can never use. The server refuses them regardless — this only keeps
		// the console from offering a button whose one outcome is a refusal.
		"SelfID": CurrentUser(req).ID,
	}), nil
}

// AdminOverviewAPI handles GET /api/v1/admin/overview: the same payload the
// page opened with, for refreshing after a change.
func (r *Runtime) AdminOverviewAPI(req *bungo.Request) (bungo.APIResponse, error) {
	overview, overviewErr := r.adminOverview(req.Context)
	if overviewErr != nil {
		return bungo.APIResponse{}, overviewErr
	}
	return bungo.APIResponse{StatusCode: 200, Body: overview}, nil
}

func (r *Runtime) adminOverview(ctx context.Context) (map[string]any, error) {
	stats, statsErr := database.SelectPlatformStats(ctx, r.GetDb())
	if statsErr != nil {
		return nil, statsErr
	}
	settings, settingsErr := database.SelectAllPlatformSettings(ctx, r.GetDb(), &r.Builder)
	if settingsErr != nil {
		return nil, settingsErr
	}
	return map[string]any{"stats": stats, "settings": settings}, nil
}

type adminSettingPayload struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// AdminUpdateSettingAPI handles POST /api/v1/admin/settings {key, value}.
func (r *Runtime) AdminUpdateSettingAPI(req *bungo.Request) (bungo.APIResponse, error) {
	admin := CurrentUser(req)
	payload, deny := decodeBody[adminSettingPayload](req)
	if deny != nil {
		return *deny, nil
	}

	key := strings.TrimSpace(payload.Key)
	kind, known := adminSettingKinds[key]
	if !known {
		return apiError(400, "Unknown platform setting."), nil
	}
	value := strings.TrimSpace(payload.Value)
	if kind == "bool" && value != "true" && value != "false" {
		return apiError(400, "A switch takes true or false."), nil
	}

	if upsertErr := database.UpsertPlatformSetting(req.Context, r.GetDb(), &r.Builder, key, value, kind); upsertErr != nil {
		return bungo.APIResponse{}, upsertErr
	}
	// No revision to bump: a platform setting belongs to nobody's account, so
	// there is no audience to signal. The audit row is the whole record.
	r.audit(req, admin.ID, "platform_setting_changed", "platform_setting", key, value)
	r.Log.Info("platform setting changed",
		zap.String("key", key), zap.String("value", value), zap.String("admin_id", admin.ID))

	return bungo.APIResponse{StatusCode: 200, Body: map[string]any{"saved": true}}, nil
}

// AdminUsersAPI handles GET /api/v1/admin/users?q=&page=.
func (r *Runtime) AdminUsersAPI(req *bungo.Request) (bungo.APIResponse, error) {
	page := adminPageParam(req.Params["page"])
	users, total, listErr := database.SelectAdminUsers(
		req.Context, r.GetDb(), &r.Builder, r.Cipher,
		req.Params["q"], config.AdminPageSize, page*config.AdminPageSize,
	)
	if listErr != nil {
		return bungo.APIResponse{}, listErr
	}
	return bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]any{"users": users, "total": total, "page": page},
	}, nil
}

type adminSuspendPayload struct {
	UserID  string `json:"userId"`
	Suspend bool   `json:"suspend"`
	Reason  string `json:"reason"`
}

// AdminSuspendUserAPI handles POST /api/v1/admin/users/suspend
// {userId, suspend, reason}. Suspending signs the account out everywhere in
// the same transaction: resolveSession already refuses an inactive user on the
// next request, but leaving the session rows behind would show the account as
// still signed in on a screen whose whole job is to say otherwise.
func (r *Runtime) AdminSuspendUserAPI(req *bungo.Request) (bungo.APIResponse, error) {
	admin := CurrentUser(req)
	payload, deny := decodeBody[adminSuspendPayload](req)
	if deny != nil {
		return *deny, nil
	}
	target, targetDeny := r.adminTarget(req, payload.UserID)
	if targetDeny != nil {
		return *targetDeny, nil
	}
	if payload.Suspend && target.ID == admin.ID {
		return apiError(400, "You can't suspend your own account."), nil
	}

	// Refused rather than truncated: slicing a byte count off free text can
	// cut a multi-byte character in half, and Postgres rejects the invalid
	// sequence that produces — a 500 in place of the 400 this is.
	reason := strings.TrimSpace(payload.Reason)
	if len(reason) > config.MaxSuspensionReasonChars {
		return apiError(400, "That reason is too long."), nil
	}
	action := "admin_user_reactivated"
	if payload.Suspend {
		action = "admin_user_suspended"
	}

	if _, commitErr := r.commitAudienceChange(req, admin.ID, []string{target.ID},
		action, "user", target.ID,
		func(txRt *Runtime) error {
			if setErr := database.SetUserSuspended(req.Context, txRt.GetDb(), &txRt.Builder,
				target.ID, payload.Suspend, reason); setErr != nil {
				return setErr
			}
			if !payload.Suspend {
				return nil
			}
			return database.DeleteUserSessions(req.Context, txRt.GetDb(), &txRt.Builder, target.ID)
		}); commitErr != nil {
		return bungo.APIResponse{}, commitErr
	}

	r.Log.Info("admin changed account state",
		zap.String("admin_id", admin.ID), zap.String("user_id", target.ID), zap.Bool("suspended", payload.Suspend))
	return bungo.APIResponse{StatusCode: 200, Body: map[string]any{"suspended": payload.Suspend}}, nil
}

// AdminRevokeSessionsAPI handles POST /api/v1/admin/users/sessions/revoke
// {userId}: sign one account out of every device.
func (r *Runtime) AdminRevokeSessionsAPI(req *bungo.Request) (bungo.APIResponse, error) {
	admin := CurrentUser(req)
	payload, deny := decodeBody[idPayload](req)
	if deny != nil {
		return *deny, nil
	}
	target, targetDeny := r.adminTarget(req, payload.ID)
	if targetDeny != nil {
		return *targetDeny, nil
	}

	if _, commitErr := r.commitAudienceChange(req, admin.ID, []string{target.ID},
		"admin_sessions_revoked", "user", target.ID,
		func(txRt *Runtime) error {
			return database.DeleteUserSessions(req.Context, txRt.GetDb(), &txRt.Builder, target.ID)
		}); commitErr != nil {
		return bungo.APIResponse{}, commitErr
	}
	return bungo.APIResponse{StatusCode: 200, Body: map[string]any{"revoked": true}}, nil
}

// AdminVerifyEmailAPI handles POST /api/v1/admin/users/verify-email {userId}:
// confirm an address by hand. The escape hatch for the account that registered
// while email delivery was down — the alternative is an operator running an
// UPDATE against production.
func (r *Runtime) AdminVerifyEmailAPI(req *bungo.Request) (bungo.APIResponse, error) {
	admin := CurrentUser(req)
	payload, deny := decodeBody[idPayload](req)
	if deny != nil {
		return *deny, nil
	}
	target, targetDeny := r.adminTarget(req, payload.ID)
	if targetDeny != nil {
		return *targetDeny, nil
	}
	if target.Auth != nil && target.Auth.EmailVerified {
		return apiError(400, "That address is already verified."), nil
	}

	if _, commitErr := r.commitAudienceChange(req, admin.ID, []string{target.ID},
		"admin_email_verified", "user", target.ID,
		func(txRt *Runtime) error {
			return database.SetEmailVerified(req.Context, txRt.GetDb(), &txRt.Builder, target.ID)
		}); commitErr != nil {
		return bungo.APIResponse{}, commitErr
	}
	return bungo.APIResponse{StatusCode: 200, Body: map[string]any{"verified": true}}, nil
}

// AdminResendVerificationAPI handles POST
// /api/v1/admin/users/resend-verification {userId}. Unlike the public resend,
// this one names the account it acted on: the operator already knows it
// exists, so there is nothing left for a neutral answer to protect.
func (r *Runtime) AdminResendVerificationAPI(req *bungo.Request) (bungo.APIResponse, error) {
	admin := CurrentUser(req)
	payload, deny := decodeBody[idPayload](req)
	if deny != nil {
		return *deny, nil
	}
	target, targetDeny := r.adminTarget(req, payload.ID)
	if targetDeny != nil {
		return *targetDeny, nil
	}
	if target.Auth != nil && target.Auth.EmailVerified {
		return apiError(400, "That address is already verified."), nil
	}

	r.sendVerificationEmail(req.Context, req, target.ID)
	r.audit(req, admin.ID, "admin_verification_resent", "user", target.ID, "")

	// Delivery is best-effort by design (and skipped entirely while the
	// email_sending_enabled gate is off), so say which it was rather than
	// reporting a send that only reached the log.
	return bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]any{"sent": r.EmailSendingEnabled(req.Context)},
	}, nil
}

type adminGrantPayload struct {
	UserID string `json:"userId"`
	Grant  bool   `json:"grant"`
}

// AdminGrantAPI handles POST /api/v1/admin/users/admin {userId, grant}:
// grant or revoke the console role.
func (r *Runtime) AdminGrantAPI(req *bungo.Request) (bungo.APIResponse, error) {
	admin := CurrentUser(req)
	payload, deny := decodeBody[adminGrantPayload](req)
	if deny != nil {
		return *deny, nil
	}
	target, targetDeny := r.adminTarget(req, payload.UserID)
	if targetDeny != nil {
		return *targetDeny, nil
	}

	if !payload.Grant {
		if target.ID == admin.ID {
			return apiError(400, "You can't revoke your own admin access."), nil
		}
		// Guarded rather than merely discouraged: with no grants left, the
		// console is unreachable by anyone and the only way back is the
		// bootstrap environment variable and a restart.
		count, countErr := database.CountAdmins(req.Context, r.GetDb(), &r.Builder)
		if countErr != nil {
			return bungo.APIResponse{}, countErr
		}
		if count <= 1 {
			return apiError(400, "This is the last admin. Grant another one first."), nil
		}
	}

	action := "admin_granted"
	if !payload.Grant {
		action = "admin_revoked"
	}
	if _, commitErr := r.commitAudienceChange(req, admin.ID, []string{target.ID},
		action, "user", target.ID,
		func(txRt *Runtime) error {
			if payload.Grant {
				return database.InsertAdmin(req.Context, txRt.GetDb(), &txRt.Builder, target.ID, admin.ID, "")
			}
			return database.DeleteAdmin(req.Context, txRt.GetDb(), &txRt.Builder, target.ID)
		}); commitErr != nil {
		return bungo.APIResponse{}, commitErr
	}

	r.Log.Info("admin grant changed",
		zap.String("admin_id", admin.ID), zap.String("user_id", target.ID), zap.Bool("granted", payload.Grant))
	return bungo.APIResponse{StatusCode: 200, Body: map[string]any{"isAdmin": payload.Grant}}, nil
}

type adminDeleteUserPayload struct {
	UserID string `json:"userId"`
	Email  string `json:"email"`
}

// AdminDeleteUserAPI handles POST /api/v1/admin/users/delete {userId, email}:
// erasure, for the GDPR request the operator has to be able to honour.
//
// The email must be typed and must match the account. Deletion cascades
// through vaults, items, sessions and notifications, and no backup of any of
// it exists that could be restored — the server never held a key to it. A
// mistyped id with a confirming click would be unrecoverable, so the id alone
// is not enough to fire this.
func (r *Runtime) AdminDeleteUserAPI(req *bungo.Request) (bungo.APIResponse, error) {
	admin := CurrentUser(req)
	payload, deny := decodeBody[adminDeleteUserPayload](req)
	if deny != nil {
		return *deny, nil
	}
	target, targetDeny := r.adminTarget(req, payload.UserID)
	if targetDeny != nil {
		return *targetDeny, nil
	}
	if target.ID == admin.ID {
		return apiError(400, "Delete your own account from Settings, not here."), nil
	}
	if !strings.EqualFold(strings.TrimSpace(payload.Email), target.Email) {
		return apiError(400, "The typed email doesn't match that account."), nil
	}

	// Audited before the delete, like the self-service path: the audit row's
	// user id is the ADMIN's and survives, while the deleted account's id
	// stays readable in the entity column, which has no foreign key.
	r.audit(req, admin.ID, "admin_user_deleted", "user", target.ID, target.Email)
	if deleteErr := database.DeleteUser(req.Context, r.GetDb(), &r.Builder, target.ID); deleteErr != nil {
		return bungo.APIResponse{}, deleteErr
	}
	r.Log.Warn("admin deleted account",
		zap.String("admin_id", admin.ID), zap.String("user_id", target.ID))
	return bungo.APIResponse{StatusCode: 200, Body: map[string]any{"deleted": true}}, nil
}

// AdminAuditAPI handles GET /api/v1/admin/audit?page=&userId=.
func (r *Runtime) AdminAuditAPI(req *bungo.Request) (bungo.APIResponse, error) {
	page := adminPageParam(req.Params["page"])
	entries, listErr := database.SelectAuditLog(
		req.Context, r.GetDb(), &r.Builder, r.Cipher,
		strings.TrimSpace(req.Params["userId"]), config.AdminPageSize, page*config.AdminPageSize,
	)
	if listErr != nil {
		return bungo.APIResponse{}, listErr
	}
	return bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]any{"entries": entries, "page": page},
	}, nil
}

// AdminInquiriesAPI handles GET /api/v1/admin/inquiries?page=&all=.
func (r *Runtime) AdminInquiriesAPI(req *bungo.Request) (bungo.APIResponse, error) {
	page := adminPageParam(req.Params["page"])
	inquiries, total, listErr := database.SelectContactInquiries(
		req.Context, r.GetDb(), &r.Builder, r.Cipher,
		req.Params["all"] != "1", config.AdminPageSize, page*config.AdminPageSize,
	)
	if listErr != nil {
		return bungo.APIResponse{}, listErr
	}
	return bungo.APIResponse{
		StatusCode: 200,
		Body:       map[string]any{"inquiries": inquiries, "total": total, "page": page},
	}, nil
}

type adminInquiryHandledPayload struct {
	ID      string `json:"id"`
	Handled bool   `json:"handled"`
}

// AdminInquiryHandledAPI handles POST /api/v1/admin/inquiries/handled
// {id, handled}.
func (r *Runtime) AdminInquiryHandledAPI(req *bungo.Request) (bungo.APIResponse, error) {
	admin := CurrentUser(req)
	payload, deny := decodeBody[adminInquiryHandledPayload](req)
	if deny != nil {
		return *deny, nil
	}
	if strings.TrimSpace(payload.ID) == "" {
		return apiError(400, "id is required."), nil
	}
	if setErr := database.SetContactInquiryHandled(req.Context, r.GetDb(), &r.Builder, payload.ID, payload.Handled); setErr != nil {
		if errors.Is(setErr, database.ErrNoRowsAffected) {
			return apiError(404, "That message no longer exists."), nil
		}
		return bungo.APIResponse{}, setErr
	}
	r.audit(req, admin.ID, "admin_inquiry_triaged", "contact_inquiry", payload.ID, strconv.FormatBool(payload.Handled))
	return bungo.APIResponse{StatusCode: 200, Body: map[string]any{"handled": payload.Handled}}, nil
}

// adminTarget resolves the account an admin action names, or hands back a
// ready-to-return denial. It is this file's counterpart to the require*
// helpers in vault_view.go: every handler above opens with it, so none of them
// re-implements the lookup or invents its own wording for a stale id.
func (r *Runtime) adminTarget(req *bungo.Request, userID string) (*models.UserFull, *bungo.APIResponse) {
	id := strings.TrimSpace(userID)
	if id == "" {
		deny := apiError(400, "userId is required.")
		return nil, &deny
	}
	target, lookupErr := database.SelectUserFullByKeyValue(req.Context, r.GetDb(), &r.Builder, r.Cipher, "id", id)
	if lookupErr != nil {
		if errors.Is(lookupErr, sql.ErrNoRows) {
			deny := apiError(404, "No such account.")
			return nil, &deny
		}
		// A malformed uuid reaches Postgres as a cast error rather than as
		// zero rows, and the console has no more business distinguishing the
		// two than any other caller does.
		r.Log.Warn("admin: target lookup failed", zap.Error(lookupErr))
		deny := apiError(404, "No such account.")
		return nil, &deny
	}
	return target, nil
}

// adminPageParam parses a zero-based page index, clamping anything absent,
// unparseable or negative to the first page.
func adminPageParam(raw string) int {
	page, parseErr := strconv.Atoi(strings.TrimSpace(raw))
	if parseErr != nil || page < 0 {
		return 0
	}
	return page
}

// bootstrapAdmin grants the console role to the account named by
// ADMIN_BOOTSTRAP_EMAIL_STRING, if it is set. Called once by Start().
//
// It exists because vault3_admin ships empty and the console gates on nothing
// else: without this, a fresh deployment has no way in short of an operator
// running SQL against production, and an operator who revokes the last grant
// has no way back at all. Unset is the normal state; setting it grants a role
// to somebody who can already read the database, so it opens nothing that was
// closed.
func (r *Runtime) bootstrapAdmin(ctx context.Context) {
	email, ok := r.Config.LookupString(config.AdminBootstrapEmailEnv)
	if !ok {
		return
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return
	}

	granted, grantErr := database.GrantAdminByEmail(ctx, r.GetDb(), &r.Builder, email)
	if grantErr != nil {
		if errors.Is(grantErr, sql.ErrNoRows) {
			// Loud, because the operator who set this expects to be an admin
			// on the next request and otherwise finds a 401 with no reason.
			r.Log.Warn("admin bootstrap: no account with that email — register it, then restart",
				zap.String("email", email))
			return
		}
		r.Log.Error("admin bootstrap failed", zap.Error(grantErr))
		return
	}
	if granted {
		r.Log.Info("admin bootstrap: granted console access", zap.String("email", email))
	}
}
