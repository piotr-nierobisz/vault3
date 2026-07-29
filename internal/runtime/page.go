package runtime

import (
	"time"

	"vault3/internal/config"

	bungo "github.com/piotr-nierobisz/BunGo"
)

// PageData returns the base template payload seeded with site-wide defaults.
// Handlers pass overrides (PageTitle, PageDescription, CanonicalURL, OGTitle,
// OGDescription, OGImage, Viewer, …) to specialise a page. Keys in overrides
// win.
//
// All template references to brand URL, name, tagline, description, and OG
// image flow through the .Site map populated here, so config.SITE_* is the
// single source of truth.
func (r *Runtime) PageData(overrides ...map[string]any) map[string]any {
	site := map[string]any{
		"URL":              config.SITE_URL,
		"Name":             config.SITE_NAME,
		"Tagline":          config.SITE_TAGLINE,
		"Description":      config.SITE_DESCRIPTION,
		"OGImage":          config.SITE_URL + config.SITE_OG_IMAGE_PATH,
		"Favicon":          config.SITE_FAVICON_PATH,
		"ContactEmail":     config.SITE_CONTACT_EMAIL,
		"CompanyLegalName": config.SITE_COMPANY_LEGAL_NAME,
		"CompanyName":      config.SITE_COMPANY_NAME,
		"CompanyURL":       config.SITE_COMPANY_URL,
		"RepoURL":          config.SITE_REPO_URL,
	}

	data := map[string]any{
		"Site":            site,
		"Year":            time.Now().Year(),
		"PageTitle":       config.SITE_NAME,
		"PageDescription": config.SITE_DESCRIPTION,
		"CanonicalURL":    config.SITE_URL,
		"OGTitle":         config.SITE_TAGLINE,
		"OGDescription":   config.SITE_DESCRIPTION,
		"OGImage":         config.SITE_URL + config.SITE_OG_IMAGE_PATH,
		// NoIndex marks pages search engines must not index: everything
		// authenticated or token-bearing. Public marketing pages override
		// CanonicalURL per route instead.
		"NoIndex": false,
	}

	for _, override := range overrides {
		for k, v := range override {
			data[k] = v
		}
	}
	return data
}

// --- Marketing and public ---

// Public pages carry the optional Viewer (populated by optional_auth when the
// visitor happens to be signed in) purely so the marketing header can offer
// the way back into /app. Nothing else about the page changes, and an
// anonymous visitor — crawlers included — sees the same markup as before.

// The <title> carries the search keyword ("zero-knowledge password
// manager") while OGTitle keeps the brand line — a result page and a shared
// card are read by different audiences and deserve different sentences.
func (r *Runtime) LandingPage(req *bungo.Request) (map[string]any, error) {
	return r.PageData(map[string]any{
		"PageTitle": "Vault3 — Zero-knowledge password manager",
		"OGTitle":   "Your secrets, sealed.",
		"Viewer":    r.Viewer(req),
	}), nil
}

func (r *Runtime) ContactPage(req *bungo.Request) (map[string]any, error) {
	return r.PageData(map[string]any{
		"PageTitle":       "Contact | Vault3",
		"PageDescription": "Questions, feedback or security reports — talk to the Vault3 team.",
		"CanonicalURL":    config.SITE_URL + "/contact",
		"Viewer":          r.Viewer(req),
	}), nil
}

// --- Authentication ---

func (r *Runtime) LoginPage(_ *bungo.Request) (map[string]any, error) {
	return r.PageData(map[string]any{
		"PageTitle":    "Unlock | Vault3",
		"CanonicalURL": config.SITE_URL + "/login",
		"NoIndex":      true,
	}), nil
}

// JoinPage lives in register_view.go, VerifyEmailPage in
// email_verification_view.go, and RecoverPage in recover_view.go, each
// alongside the APIs they share token/crypto handling with. AppVaultPage
// lives in vault_view.go, SettingsPage in account_view.go, and
// NotificationsPage in notifications_view.go, same rule.

// --- Legal and security docs ---

// legalPageData assembles the shared payload for a document page. Like the
// other public pages it carries the optional Viewer, for the header only —
// these documents render the marketing surface for everyone.
//
// Every document names its own description: these pages are indexable and a
// shared site-wide description would have them all compete for the same
// snippet. The social title reuses the page title minus the brand suffix,
// which the card already shows as the site name.
func (r *Runtime) legalPageData(req *bungo.Request, title, ogTitle, description, slug string) map[string]any {
	canonicalPath := "/legal/" + slug
	if slug == "security" {
		canonicalPath = "/security"
	}
	return r.PageData(map[string]any{
		"PageTitle":       title,
		"PageDescription": description,
		"OGTitle":         ogTitle,
		"OGDescription":   description,
		"LegalSlug":       slug,
		"Viewer":          r.Viewer(req),
		"CanonicalURL":    config.SITE_URL + canonicalPath,
	})
}

func (r *Runtime) LegalTermsPage(req *bungo.Request) (map[string]any, error) {
	return r.legalPageData(req,
		"Terms of Service | Vault3",
		"Terms of Service",
		"The agreement between you and Octa Systems Ltd (trading as Octa Digital) for using Vault3 — short, readable, and plain about what zero knowledge means for your account.",
		"terms"), nil
}

func (r *Runtime) LegalPrivacyPage(req *bungo.Request) (map[string]any, error) {
	return r.legalPageData(req,
		"Privacy Policy | Vault3",
		"Privacy Policy",
		"Exactly what Vault3 can and cannot see, the short list of data we process and why, how long we keep it, and your GDPR rights. Your vault is ciphertext to us.",
		"privacy"), nil
}

func (r *Runtime) LegalCookiesPage(req *bungo.Request) (map[string]any, error) {
	return r.legalPageData(req,
		"Cookie Policy | Vault3",
		"Cookie Policy",
		"Vault3 sets exactly one strictly necessary cookie and runs no analytics, advertising or third-party trackers. What it does, what stays on your device, and why there is no consent gate.",
		"cookies"), nil
}

// SecurityPage is the public security overview: how the encryption works,
// what the server stores, and what that means in practice. It doubles as
// marketing, so it lives at /security rather than under /legal.
func (r *Runtime) SecurityPage(req *bungo.Request) (map[string]any, error) {
	return r.legalPageData(req,
		"Security — how Vault3 encrypts your vault | Vault3",
		"How Vault3 protects you",
		"How Vault3's zero-knowledge encryption works: two secrets combined in your browser, 650,000 PBKDF2 rounds, AES-256-GCM on every item, and what a breach of our servers would actually yield.",
		"security"), nil
}
