package main

import (
	"fmt"
	"net/http"

	"vault3/internal/config"
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

	// require_admin gates the management console on a vault3_admin row. It
	// reads the spoke require_auth already loaded, so it must come after it.
	srv.Security(bungo.SecurityLayer{
		Name:    "require_admin",
		Handler: rt.RequireAdmin,
	})

	// require_human is the Cloudflare Turnstile bot check. It stands alone —
	// it authorises nobody and pairs with no other layer — and guards the two
	// endpoints anyone can reach without an account: sign-in and registration.
	// See internal/runtime/turnstile.go.
	srv.Security(bungo.SecurityLayer{
		Name:    "require_human",
		Handler: rt.RequireHuman,
	})

	srv.SetDefaultLayout("base.gohtml")

	// Transport-security headers on every response BunGo writes — pages, APIs,
	// static files and the WebSocket handshake alike. Stated once here rather
	// than in a wrapper, so a listener assembled without the wrapper cannot
	// serve the app bare-headed. See runtime.SecurityHeaders for each directive.
	srv.SetResponseHeaders(rt.SecurityHeaders())

	// In production, serve compiled views from content-hashed
	// /_bungo/<view>.<hash>.js URLs so browsers cache them for a year and pick
	// up a new bundle the moment its content changes. Left off in dev, where
	// inline bundles are what the live-reload loop rebuilds.
	srv.SetAssetOptimization(rt.Config.MustBool("PRODUCTION_BOOL"))

	// Crawler files have to answer at the site root, not under /static/, so
	// they are aliased onto the files that already live in web/static.
	srv.StaticAlias("/robots.txt", "robots.txt")
	srv.StaticAlias("/sitemap.xml", "sitemap.xml")

	authLayers := []string{"require_auth", "load_viewer"}
	// viewerLayers never rejects, but gives a public page a .Viewer so a
	// signed-in visitor is offered the way back into /app instead of a
	// sign-up pair.
	viewerLayers := []string{"optional_auth", "load_viewer"}
	// adminLayers is authLayers plus the platform-admin check.
	adminLayers := []string{"require_auth", "load_viewer", "require_admin"}

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
	//	grep -n 'openAPI\|challengedAPI\|viewerPage\|anonPage' cmd/vault3/main.go

	// checkOrigin returns the CSRF hook for a registration, or nil for the
	// read-only methods that cannot be a CSRF target. BunGo runs it before the
	// security layers and answers 403 on refusal, so the rejection never
	// reaches a handler — and because it is attached here, in the four helpers
	// every route goes through, a new endpoint cannot be registered without it.
	checkOrigin := func(method string) func(*bungo.Request) bool {
		switch method {
		case "GET", "HEAD", "OPTIONS":
			return nil
		}
		return rt.SameOriginWrite
	}

	api := func(method, path string, handler func(*bungo.Request) (bungo.APIResponse, error)) {
		srv.Api(bungo.ApiRoute{
			Path: path, Version: "v1", Method: method,
			CheckOrigin:   checkOrigin(method),
			SecurityLayer: authLayers, Handler: runtime.NoStore(handler),
		})
	}
	openAPI := func(method, path string, handler func(*bungo.Request) (bungo.APIResponse, error)) {
		srv.Api(bungo.ApiRoute{
			Path: path, Version: "v1", Method: method,
			CheckOrigin: checkOrigin(method),
			Handler:     runtime.NoStore(handler),
		})
	}
	// challengedAPI: public, but behind the Turnstile bot check. It is an
	// eighth named helper rather than a layer list at two call sites for the
	// reason the others exist — the requirement is a word in the name, so an
	// endpoint that loses the check loses a word rather than a line. Reserved
	// for the endpoints an attacker can automate without an account; an
	// authenticated endpoint has a session to throttle instead.
	challengedAPI := func(method, path string, handler func(*bungo.Request) (bungo.APIResponse, error)) {
		srv.Api(bungo.ApiRoute{
			Path: path, Version: "v1", Method: method,
			CheckOrigin:   checkOrigin(method),
			SecurityLayer: []string{"require_human"}, Handler: runtime.NoStore(handler),
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
	// adminAPI / adminPage: the management console. A sixth and seventh named
	// helper rather than a layer list at the call site, for the same reason as
	// the five above — the requirement is a word in the name.
	adminAPI := func(method, path string, handler func(*bungo.Request) (bungo.APIResponse, error)) {
		srv.Api(bungo.ApiRoute{
			Path: path, Version: "v1", Method: method,
			CheckOrigin:   checkOrigin(method),
			SecurityLayer: adminLayers, Handler: runtime.NoStore(handler),
		})
	}
	adminPage := func(path, template, view string, handler func(*bungo.Request) (map[string]any, error)) {
		srv.Page(bungo.PageRoute{
			Path: path, Template: template, View: view,
			SecurityLayer: adminLayers, Handler: handler,
		})
	}

	// --- Marketing and public pages ---

	viewerPage("/", "index.gohtml", "landing.ts", rt.LandingPage)
	viewerPage("/features", "features.gohtml", "features.ts", rt.FeaturesPage)
	viewerPage("/contact", "contact.gohtml", "contact.tsx", rt.ContactPage)
	openAPI("POST", "/contact", rt.ContactSubmitAPI)

	// --- Authentication ---

	anonPage(config.LoginPath, "login.gohtml", "login.tsx", rt.LoginPage)

	// The pre-login KDF parameter exchange: public by necessity and
	// enumeration-safe (decoy parameters for unknown emails). It stays
	// unchallenged on purpose — a Turnstile token is single-use, so spending
	// one here would leave none for the login it precedes, and this endpoint
	// answers every email identically anyway.
	openAPI("POST", "/auth/params", rt.AuthParamsAPI)
	challengedAPI("POST", "/auth/login", rt.LoginAPI)
	// Logout reads the cookie itself and is idempotent, so it needs no layer.
	openAPI("POST", "/auth/logout", rt.LogoutAPI)

	// Onboarding: /join runs the whole crypto ceremony client-side and the
	// register API persists the resulting bundle. The page is public; the
	// API re-checks the public_registration_enabled platform gate.
	anonPage(config.JoinPath, "join.gohtml", "join.tsx", rt.JoinPage)
	challengedAPI("POST", "/auth/register", rt.RegisterAPI)

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

	// Change signal: the WebSocket route every signed-in client subscribes to
	// (see internal/runtime/signal.go). Registration hands back the hub the
	// commit helpers publish through, so the runtime gets it here rather than
	// building one of its own. /sync/revision is the poll fallback.
	rt.Signals = srv.WebSocket(rt.ChangeSignalRoute())

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

	// --- Management console ---
	//
	// One page behind require_admin, at a path product.md reserved. Nothing
	// here can read a vault: the endpoints count rows, flip platform gates and
	// change account state, which is the whole of what the server itself can
	// do. See internal/runtime/admin_view.go.

	adminPage(config.AdminConsolePath, "app/admin.gohtml", "admin.tsx", rt.AdminConsolePage)

	adminAPI("GET", "/admin/overview", rt.AdminOverviewAPI)
	adminAPI("POST", "/admin/settings", rt.AdminUpdateSettingAPI)

	adminAPI("GET", "/admin/users", rt.AdminUsersAPI)
	adminAPI("POST", "/admin/users/suspend", rt.AdminSuspendUserAPI)
	adminAPI("POST", "/admin/users/sessions/revoke", rt.AdminRevokeSessionsAPI)
	adminAPI("POST", "/admin/users/verify-email", rt.AdminVerifyEmailAPI)
	adminAPI("POST", "/admin/users/resend-verification", rt.AdminResendVerificationAPI)
	adminAPI("POST", "/admin/users/admin", rt.AdminGrantAPI)
	adminAPI("POST", "/admin/users/delete", rt.AdminDeleteUserAPI)

	adminAPI("GET", "/admin/audit", rt.AdminAuditAPI)
	adminAPI("GET", "/admin/inquiries", rt.AdminInquiriesAPI)
	adminAPI("POST", "/admin/inquiries/handled", rt.AdminInquiryHandledAPI)

	// --- Trust and legal docs ---
	// Part of the public surface, so they carry the viewer layers too: the
	// marketing header, with the vault link swapped in for signed-in readers.
	// /security and /whitepaper are the same argument at two depths — the
	// overview a visitor arrives for, and the construction behind it.

	// The custom not-found page. Registered at BunGo's sentinel path rather
	// than a URL of its own, so every unmatched path renders it with a real
	// 404 instead of falling through to the landing page on 200 — which is
	// what the "/" subtree root would otherwise do, and what search engines
	// were being told to index.
	viewerPage(bungo.NotFoundPath, "404.gohtml", "", rt.NotFoundPage)

	viewerPage("/security", "legal/security.gohtml", "security.ts", rt.SecurityPage)
	viewerPage("/whitepaper", "legal/whitepaper.gohtml", "whitepaper.ts", rt.WhitepaperPage)
	viewerPage("/legal/terms", "legal/terms.gohtml", "", rt.LegalTermsPage)
	viewerPage("/legal/privacy", "legal/privacy.gohtml", "", rt.LegalPrivacyPage)
	viewerPage("/legal/cookies", "legal/cookies.gohtml", "", rt.LegalCookiesPage)

	// BunGo compiles views and builds its route mux through the engine's
	// public CreateHandler. Security headers and cross-origin rejection are
	// BunGo's own now (SetResponseHeaders above, CheckOrigin per route), so the
	// only thing left in the wrapper is what bungo.Request structurally cannot
	// carry: the socket address, which the dev stack has no proxy to turn into
	// a forwarding header. srv.Serve would skip that one fixup, so the listener
	// is still assembled here. Everything the app serves — pages, APIs, static
	// aliases and the change-signal socket — is inside the BunGo handler.
	handler, handlerErr := engineInstance.CreateHandler(srv)
	if handlerErr != nil {
		rt.Log.Fatal("failed to build handler", zap.Error(handlerErr))
	}

	port := rt.Config.MustInt("PORT_INT")
	rt.Log.Info("Vault3 starting", zap.Int("port", port))
	if serveErr := http.ListenAndServe(fmt.Sprintf(":%d", port), rt.WrapHandler(handler)); serveErr != nil {
		rt.Log.Fatal("server stopped", zap.Error(serveErr))
	}
}
