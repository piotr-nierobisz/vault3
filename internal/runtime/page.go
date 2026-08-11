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

// FeaturesPage is the full product surface: everything the vault does, in one
// place. The landing page keeps a highlight grid and sends the reader here for
// the rest, so neither has to carry the whole inventory.
func (r *Runtime) FeaturesPage(req *bungo.Request) (map[string]any, error) {
	return r.PageData(map[string]any{
		"PageTitle":       "Features | Vault3",
		"PageDescription": "Every feature of Vault3's zero-knowledge vault: logins, notes, cards and identities, multiple vaults, shared vaults, single-item share links, one-time codes, live sync, two-factor authentication and a 30-day trash — all encrypted on your device.",
		"OGTitle":         "Features",
		"OGDescription":   "Logins, notes, cards and identities. Multiple vaults, shared vaults and share links. Live sync and two-factor authentication — with every item encrypted before it leaves your device.",
		"CanonicalURL":    config.SITE_URL + "/features",
		"Viewer":          r.Viewer(req),
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
		"PageTitle":    "Login | Vault3",
		"CanonicalURL": config.SITE_URL + "/login",
		"NoIndex":      true,
	}), nil
}

// JoinPage lives in register_view.go and VerifyEmailPage in
// email_verification_view.go, each
// alongside the APIs they share token/crypto handling with. AppVaultPage
// lives in vault_view.go, SettingsPage in account_view.go, and
// NotificationsPage in notifications_view.go, same rule.

// --- Legal and security docs ---

// trustDocPaths holds the documents that sit at the top level rather than
// under /legal. They share the legal template furniture — the sidebar, the
// per-document description — but they are the product's own argument rather
// than its contract, and their URLs say so. Anything absent takes the
// /legal/<slug> path its slug implies.
var trustDocPaths = map[string]string{
	"security":   "/security",
	"whitepaper": "/whitepaper",
}

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
	if trustPath, ok := trustDocPaths[slug]; ok {
		canonicalPath = trustPath
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
		"The agreement between you and Octa Systems Ltd (trading as Octa Digital) for using Vault3 — short, readable, and plain about what holding the only keys to your vault means for your account.",
		"terms"), nil
}

func (r *Runtime) LegalPrivacyPage(req *bungo.Request) (map[string]any, error) {
	return r.legalPageData(req,
		"Privacy Policy | Vault3",
		"Privacy Policy",
		"Exactly what Vault3 can and cannot see, the short list of what we hold and why, how long we keep it, and your GDPR rights. Your vault reaches us already locked, and we have no way to open it.",
		"privacy"), nil
}

func (r *Runtime) LegalCookiesPage(req *bungo.Request) (map[string]any, error) {
	return r.legalPageData(req,
		"Cookie Policy | Vault3",
		"Cookie Policy",
		"Vault3 sets exactly one strictly necessary cookie and runs no analytics, advertising or third-party trackers. What it does, what stays on your device, and why there is no consent gate.",
		"cookies"), nil
}

// SecurityPage is the public security overview: what the server holds, what
// that makes impossible, and what it does not protect you from. It doubles as
// marketing, so it lives at /security rather than under /legal, and it answers
// the question a visitor arrives with. The reader who wants the construction
// itself is sent to the whitepaper below.
func (r *Runtime) SecurityPage(req *bungo.Request) (map[string]any, error) {
	return r.legalPageData(req,
		"Security | Vault3",
		"Security",
		"How Vault3's zero-knowledge encryption works, in plain language: your vault is locked on your device with keys we never receive, so a breach of our servers yields scrambled text — and there is no reset link, because there is nothing to reset.",
		"security"), nil
}

// WhitepaperPage is the same argument for a reader who wants the primitives:
// the key hierarchy, the envelope format, the sharing construction, the
// post-quantum reasoning and the threat model. /security stays short because
// this page exists; every claim on both must match docs/security.md.
func (r *Runtime) WhitepaperPage(req *bungo.Request) (map[string]any, error) {
	return r.legalPageData(req,
		"Whitepaper | Vault3",
		"Whitepaper",
		"The complete Vault3 design: two-secret key derivation (PBKDF2-SHA512 at 1,000,000 rounds into Argon2id at 64 MiB, combined with a 132-bit Secret Phrase), the AES-256-GCM envelope, the link-fragment sharing construction, the post-quantum reasoning, and the threat model.",
		"whitepaper"), nil
}
