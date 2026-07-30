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

	authLayers := []string{"require_auth", "load_viewer"}
	// viewerLayers never rejects, but gives a public page a .Viewer so a
	// signed-in visitor is offered the way back into /app instead of a
	// sign-up pair.
	viewerLayers := []string{"optional_auth", "load_viewer"}

	// --- Route registration ---
	//
	// Authentication is the default here, not a field each registration has
	// to remember. api() and page() attach require_auth; the only way to
	// publish something reachable without a session is to say so in the
	// verb — openAPI, viewerPage, anonPage.
	//
	// That inversion is the point. In a flat list of ~40 routes, a missing
	// `SecurityLayer:` line is invisible in review and ships an
	// unauthenticated endpoint over the vault; a missing `open` prefix is a
	// word that is not there in a name you are already reading. It also
	// makes the entire public surface auditable in one command:
	//
	//	grep -n 'openAPI\|viewerPage\|anonPage' cmd/vault3/main.go

	api := func(method, path string, handler func(*bungo.Request) (bungo.APIResponse, error)) {
		srv.Api(bungo.ApiRoute{
			Path: path, Version: "v1", Method: method,
			SecurityLayer: authLayers, Handler: handler,
		})
	}
	openAPI := func(method, path string, handler func(*bungo.Request) (bungo.APIResponse, error)) {
		srv.Api(bungo.ApiRoute{
			Path: path, Version: "v1", Method: method,
			Handler: handler,
		})
	}
	page := func(path, template, view string, handler func(*bungo.Request) (map[string]any, error)) {
		srv.Page(bungo.PageRoute{
			Path: path, Template: template, View: view,
			SecurityLayer: authLayers, Handler: handler,
		})
	}
	// viewerPage: public, but adapts when the visitor happens to be signed in.
	viewerPage := func(path, template, view string, handler func(*bungo.Request) (map[string]any, error)) {
		srv.Page(bungo.PageRoute{
			Path: path, Template: template, View: view,
			SecurityLayer: viewerLayers, Handler: handler,
		})
	}
	// anonPage: public with no session lookup at all — the pre-sign-in pages
	// and the share viewer, which must render for someone with no account.
	anonPage := func(path, template, view string, handler func(*bungo.Request) (map[string]any, error)) {
		srv.Page(bungo.PageRoute{
			Path: path, Template: template, View: view,
			Handler: handler,
		})
	}

	// --- Marketing and public pages ---

	viewerPage("/", "index.gohtml", "landing.ts", rt.LandingPage)
	viewerPage("/contact", "contact.gohtml", "contact.tsx", rt.ContactPage)
	openAPI("POST", "/contact", rt.ContactSubmitAPI)

	// --- Authentication ---

	anonPage("/login", "login.gohtml", "login.tsx", rt.LoginPage)

	// The pre-login KDF parameter exchange: public by necessity and
	// enumeration-safe (decoy parameters for unknown emails).
	openAPI("POST", "/auth/params", rt.AuthParamsAPI)
	openAPI("POST", "/auth/login", rt.LoginAPI)
	// Logout reads the cookie itself and is idempotent, so it needs no layer.
	openAPI("POST", "/auth/logout", rt.LogoutAPI)

	// Onboarding: /join runs the whole crypto ceremony client-side and the
	// register API persists the resulting bundle. The page is public; the
	// API re-checks the public_registration_enabled platform gate.
	anonPage("/join", "join.gohtml", "join.tsx", rt.JoinPage)
	openAPI("POST", "/auth/register", rt.RegisterAPI)

	// Email verification: /verify-email redeems the emailed single-use token
	// (?token=…) or requests a fresh link. The verify API is authenticated
	// by the token it redeems; the resend API answers neutrally either way.
	anonPage("/verify-email", "verify-email.gohtml", "verify-email.tsx", rt.VerifyEmailPage)
	openAPI("POST", "/auth/verify-email", rt.VerifyEmailAPI)
	openAPI("POST", "/auth/resend-verification", rt.ResendVerificationAPI)

	// There is deliberately no account recovery or reset flow: the server
	// holds only ciphertext, so a lost Master Password or Secret Phrase is
	// unrecoverable by construction. /security and the terms say exactly
	// that, and the Emergency Kit is the user's only way back in.

	// --- The vault ---

	page("/app", "app/index.gohtml", "vault.tsx", rt.AppVaultPage)

	api("GET", "/items", rt.ItemsAPI)
	api("POST", "/items/create", rt.CreateItemAPI)
	api("POST", "/items/update", rt.UpdateItemAPI)
	api("POST", "/items/trash", rt.TrashItemAPI)
	api("POST", "/items/restore", rt.RestoreItemAPI)
	api("POST", "/items/delete", rt.DeleteItemAPI)

	// --- Multiple vaults and membership ---

	api("GET", "/vaults", rt.VaultsAPI)
	api("POST", "/vaults/create", rt.CreateVaultAPI)
	api("POST", "/vaults/rename", rt.RenameVaultAPI)
	api("POST", "/vaults/delete", rt.DeleteVaultAPI)
	api("GET", "/vaults/members", rt.VaultMembersAPI)
	api("POST", "/vaults/members/remove", rt.RemoveVaultMemberAPI)

	// Vault invites: create/revoke are owner actions; preview/accept run as
	// the signed-in invitee. The decryption secret lives in the invite URL's
	// fragment and never reaches these endpoints.
	api("POST", "/vaults/invites/create", rt.CreateVaultInviteAPI)
	api("POST", "/vaults/invites/revoke", rt.RevokeVaultInviteAPI)
	api("POST", "/vaults/invites/preview", rt.InvitePreviewAPI)
	api("POST", "/vaults/invites/accept", rt.AcceptVaultInviteAPI)

	// The invite landing page takes optional_auth so a signed-out recipient
	// gets a sign-in prompt rather than a bare 401.
	viewerPage("/app/invite", "app/invite.gohtml", "invite.tsx", rt.InvitePage)

	// --- Share links ---

	api("POST", "/shares/create", rt.CreateShareLinkAPI)
	api("GET", "/shares", rt.ItemShareLinksAPI)
	api("POST", "/shares/revoke", rt.RevokeShareLinkAPI)

	// The one public sharing endpoint: redeems a share token for ciphertext
	// only. The key to open it never leaves the recipient's URL fragment.
	openAPI("POST", "/share/open", rt.OpenShareAPI)
	anonPage("/share", "share.gohtml", "share.tsx", rt.SharePage)

	// Change-signal fallback: /events (SSE) is mounted on the outer mux
	// below; this is the poll/reconnect endpoint.
	api("GET", "/sync/revision", rt.SyncRevisionAPI)

	// --- Settings and account ---

	page("/app/settings", "app/settings.gohtml", "settings.tsx", rt.SettingsPage)

	api("POST", "/account/profile", rt.UpdateProfileAPI)
	api("POST", "/account/notifications", rt.UpdateNotificationPrefsAPI)
	api("POST", "/account/password", rt.ChangePasswordAPI)
	api("POST", "/account/2fa/setup", rt.TwoFactorSetupAPI)
	api("POST", "/account/2fa/verify", rt.TwoFactorVerifyAPI)
	api("POST", "/account/2fa/disable", rt.TwoFactorDisableAPI)
	api("POST", "/account/sessions/revoke", rt.RevokeSessionAPI)
	api("POST", "/account/delete", rt.DeleteAccountAPI)

	// --- Notifications ---

	page("/app/notifications", "app/notifications.gohtml", "notifications.tsx", rt.NotificationsPage)

	api("GET", "/notifications", rt.NotificationsAPI)
	api("POST", "/notifications/read", rt.MarkNotificationReadAPI)
	api("POST", "/notifications/read-all", rt.MarkAllNotificationsReadAPI)

	// --- Legal and security docs ---
	// Part of the public surface, so they carry the viewer layers too: the
	// marketing header, with the vault link swapped in for signed-in readers.

	viewerPage("/security", "legal/security.gohtml", "security.ts", rt.SecurityPage)
	viewerPage("/legal/terms", "legal/terms.gohtml", "", rt.LegalTermsPage)
	viewerPage("/legal/privacy", "legal/privacy.gohtml", "", rt.LegalPrivacyPage)
	viewerPage("/legal/cookies", "legal/cookies.gohtml", "", rt.LegalCookiesPage)

	// BunGo compiles views and builds its route mux through the engine's
	// public CreateHandler; the runtime middleware then wraps it with the
	// transport hygiene BunGo has no hooks for (security headers,
	// cross-origin rejection, socket-IP injection), and the SSE change-signal
	// endpoint mounts alongside — BunGo responses cannot stream. srv.Serve
	// would do none of that, so the listener is assembled here instead.
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
