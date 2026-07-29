package main

import (
	"fmt"
	"net/http"

	"vault3/internal/runtime"

	bungo "github.com/piotr-nierobisz/BunGo"
	"github.com/piotr-nierobisz/BunGo/engine"
	"go.uber.org/zap"
)

func main() {
	rt := runtime.Start()
	defer rt.Stop()

	engineInstance := engine.NewHTTPEngine()
	srv := bungo.NewServer(engineInstance, "./web")

	srv.Security(bungo.SecurityLayer{
		Name:    "require_auth",
		Handler: rt.RequireAuth,
	})

	// load_viewer runs after require_auth (or optional_auth) and builds the
	// view.UserSummary into req.Internal so handlers read it via
	// rt.Viewer(req).
	srv.Security(bungo.SecurityLayer{
		Name:    "load_viewer",
		Handler: rt.LoadViewer,
	})

	// optional_auth loads the session + user when the visitor is signed in
	// but never rejects, so otherwise-public pages (the legal and security
	// docs) can render the authenticated app header. Pair it with
	// load_viewer.
	srv.Security(bungo.SecurityLayer{
		Name:    "optional_auth",
		Handler: rt.OptionalAuth,
	})

	srv.SetDefaultLayout("base.gohtml")

	// --- Marketing and public pages ---
	// publicLayers = optional_auth + load_viewer: never rejects, but gives the
	// marketing header a .Viewer so a signed-in visitor is offered the way back
	// into /app instead of a sign-up pair. Every public page shares it.
	publicLayers := []string{"optional_auth", "load_viewer"}

	srv.Page(bungo.PageRoute{
		Path:          "/",
		Template:      "index.gohtml",
		View:          "landing.ts",
		SecurityLayer: publicLayers,
		Handler:       rt.LandingPage,
	})

	srv.Page(bungo.PageRoute{
		Path:          "/contact",
		Template:      "contact.gohtml",
		View:          "contact.tsx",
		SecurityLayer: publicLayers,
		Handler:       rt.ContactPage,
	})

	srv.Api(bungo.ApiRoute{
		Path:    "/contact",
		Version: "v1",
		Method:  "POST",
		Handler: rt.ContactSubmitAPI,
	})

	// --- Authentication ---

	srv.Page(bungo.PageRoute{
		Path:     "/login",
		Template: "login.gohtml",
		View:     "login.tsx",
		Handler:  rt.LoginPage,
	})

	// The pre-login KDF parameter exchange: public by necessity, throttled
	// by the middleware, and enumeration-safe (decoy parameters for unknown
	// emails).
	srv.Api(bungo.ApiRoute{
		Path:    "/auth/params",
		Version: "v1",
		Method:  "POST",
		Handler: rt.AuthParamsAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:    "/auth/login",
		Version: "v1",
		Method:  "POST",
		Handler: rt.LoginAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:    "/auth/logout",
		Version: "v1",
		Method:  "POST",
		Handler: rt.LogoutAPI,
	})

	// Onboarding: /join runs the whole crypto ceremony client-side and the
	// register API persists the resulting bundle. The page is public; the
	// API re-checks the public_registration_enabled platform gate.
	srv.Page(bungo.PageRoute{
		Path:     "/join",
		Template: "join.gohtml",
		View:     "join.tsx",
		Handler:  rt.JoinPage,
	})

	srv.Api(bungo.ApiRoute{
		Path:    "/auth/register",
		Version: "v1",
		Method:  "POST",
		Handler: rt.RegisterAPI,
	})

	// Email verification: /verify-email redeems the emailed single-use token
	// (?token=…) or requests a fresh link. The verify API is authenticated
	// by the token it redeems; the resend API answers neutrally either way.
	srv.Page(bungo.PageRoute{
		Path:     "/verify-email",
		Template: "verify-email.gohtml",
		View:     "verify-email.tsx",
		Handler:  rt.VerifyEmailPage,
	})

	srv.Api(bungo.ApiRoute{
		Path:    "/auth/verify-email",
		Version: "v1",
		Method:  "POST",
		Handler: rt.VerifyEmailAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:    "/auth/resend-verification",
		Version: "v1",
		Method:  "POST",
		Handler: rt.ResendVerificationAPI,
	})

	// Account recovery: zero-knowledge means no password reset — /recover is
	// an explicit, emailed, single-use account RESET that wipes the vault
	// and reruns the crypto onboarding. The page says so in large letters.
	srv.Page(bungo.PageRoute{
		Path:     "/recover",
		Template: "recover.gohtml",
		View:     "recover.tsx",
		Handler:  rt.RecoverPage,
	})

	srv.Api(bungo.ApiRoute{
		Path:    "/auth/recover/request",
		Version: "v1",
		Method:  "POST",
		Handler: rt.RecoverRequestAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:    "/auth/recover/confirm",
		Version: "v1",
		Method:  "POST",
		Handler: rt.RecoverConfirmAPI,
	})

	// --- The vault ---

	authLayers := []string{"require_auth", "load_viewer"}

	srv.Page(bungo.PageRoute{
		Path:          "/app",
		Template:      "app/index.gohtml",
		View:          "vault.tsx",
		SecurityLayer: authLayers,
		Handler:       rt.AppVaultPage,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/items",
		Version:       "v1",
		Method:        "GET",
		SecurityLayer: authLayers,
		Handler:       rt.ItemsAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/items/create",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.CreateItemAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/items/update",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.UpdateItemAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/items/trash",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.TrashItemAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/items/restore",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.RestoreItemAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/items/delete",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.DeleteItemAPI,
	})

	// --- Multiple vaults and membership ---

	srv.Api(bungo.ApiRoute{
		Path:          "/vaults",
		Version:       "v1",
		Method:        "GET",
		SecurityLayer: authLayers,
		Handler:       rt.VaultsAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/vaults/create",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.CreateVaultAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/vaults/rename",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.RenameVaultAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/vaults/delete",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.DeleteVaultAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/vaults/members",
		Version:       "v1",
		Method:        "GET",
		SecurityLayer: authLayers,
		Handler:       rt.VaultMembersAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/vaults/members/remove",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.RemoveVaultMemberAPI,
	})

	// Vault invites: create/revoke are owner actions; preview/accept run as
	// the signed-in invitee. The decryption secret lives in the invite URL's
	// fragment and never reaches these endpoints.
	srv.Api(bungo.ApiRoute{
		Path:          "/vaults/invites/create",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.CreateVaultInviteAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/vaults/invites/revoke",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.RevokeVaultInviteAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/vaults/invites/preview",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.InvitePreviewAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/vaults/invites/accept",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.AcceptVaultInviteAPI,
	})

	// The invite landing page: optional_auth so a signed-out recipient gets
	// a sign-in prompt rather than a bare 401.
	srv.Page(bungo.PageRoute{
		Path:          "/app/invite",
		Template:      "app/invite.gohtml",
		View:          "invite.tsx",
		SecurityLayer: []string{"optional_auth", "load_viewer"},
		Handler:       rt.InvitePage,
	})

	// --- Share links ---

	srv.Api(bungo.ApiRoute{
		Path:          "/shares/create",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.CreateShareLinkAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/shares",
		Version:       "v1",
		Method:        "GET",
		SecurityLayer: authLayers,
		Handler:       rt.ItemShareLinksAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/shares/revoke",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.RevokeShareLinkAPI,
	})

	// The one public sharing endpoint (fronted by the middleware throttle):
	// redeems a share token for ciphertext only.
	srv.Api(bungo.ApiRoute{
		Path:    "/share/open",
		Version: "v1",
		Method:  "POST",
		Handler: rt.OpenShareAPI,
	})

	srv.Page(bungo.PageRoute{
		Path:     "/share",
		Template: "share.gohtml",
		View:     "share.tsx",
		Handler:  rt.SharePage,
	})

	// Change-signal fallback: /events (SSE) is mounted on the outer mux
	// below; this is the poll/reconnect endpoint.
	srv.Api(bungo.ApiRoute{
		Path:          "/sync/revision",
		Version:       "v1",
		Method:        "GET",
		SecurityLayer: authLayers,
		Handler:       rt.SyncRevisionAPI,
	})

	// --- Settings and account ---

	srv.Page(bungo.PageRoute{
		Path:          "/app/settings",
		Template:      "app/settings.gohtml",
		View:          "settings.tsx",
		SecurityLayer: authLayers,
		Handler:       rt.SettingsPage,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/account/profile",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.UpdateProfileAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/account/notifications",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.UpdateNotificationPrefsAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/account/password",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.ChangePasswordAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/account/2fa/setup",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.TwoFactorSetupAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/account/2fa/verify",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.TwoFactorVerifyAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/account/2fa/disable",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.TwoFactorDisableAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/account/sessions/revoke",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.RevokeSessionAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/account/delete",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.DeleteAccountAPI,
	})

	// --- Notifications ---

	srv.Page(bungo.PageRoute{
		Path:          "/app/notifications",
		Template:      "app/notifications.gohtml",
		View:          "notifications.tsx",
		SecurityLayer: authLayers,
		Handler:       rt.NotificationsPage,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/notifications",
		Version:       "v1",
		Method:        "GET",
		SecurityLayer: authLayers,
		Handler:       rt.NotificationsAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/notifications/read",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.MarkNotificationReadAPI,
	})

	srv.Api(bungo.ApiRoute{
		Path:          "/notifications/read-all",
		Version:       "v1",
		Method:        "POST",
		SecurityLayer: authLayers,
		Handler:       rt.MarkAllNotificationsReadAPI,
	})

	// --- Legal and security docs ---
	// Part of the public surface, so they carry publicLayers too: the marketing
	// header, with the vault link swapped in for signed-in readers.

	srv.Page(bungo.PageRoute{
		Path:          "/security",
		Template:      "legal/security.gohtml",
		View:          "security.ts",
		SecurityLayer: publicLayers,
		Handler:       rt.SecurityPage,
	})
	srv.Page(bungo.PageRoute{
		Path:          "/legal/terms",
		Template:      "legal/terms.gohtml",
		SecurityLayer: publicLayers,
		Handler:       rt.LegalTermsPage,
	})
	srv.Page(bungo.PageRoute{
		Path:          "/legal/privacy",
		Template:      "legal/privacy.gohtml",
		SecurityLayer: publicLayers,
		Handler:       rt.LegalPrivacyPage,
	})
	srv.Page(bungo.PageRoute{
		Path:          "/legal/cookies",
		Template:      "legal/cookies.gohtml",
		SecurityLayer: publicLayers,
		Handler:       rt.LegalCookiesPage,
	})

	// BunGo compiles views and builds its route mux through the engine's
	// public CreateHandler; the runtime middleware then wraps it with the
	// transport hygiene BunGo has no hooks for (security headers, auth
	// throttling, socket-IP injection), and the SSE change-signal endpoint
	// mounts alongside — BunGo responses cannot stream. srv.Serve would do
	// none of that, so the listener is assembled here instead.
	handler, handlerErr := engineInstance.CreateHandler(srv)
	if handlerErr != nil {
		rt.Log.Fatal("failed to build handler", zap.Error(handlerErr))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/events", rt.EventsHandler())
	mux.Handle("/", handler)

	port := rt.Config.MustInt("PORT_INT")
	rt.Log.Info("Vault3 starting", zap.Int("port", port))
	if serveErr := http.ListenAndServe(fmt.Sprintf(":%d", port), rt.WrapHandler(mux)); serveErr != nil {
		rt.Log.Fatal("server stopped", zap.Error(serveErr))
	}
}
