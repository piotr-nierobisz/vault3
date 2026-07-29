# Vault3 Frontend Guide

React views, layouts, styling, the client-side crypto layer, and client patterns served through BunGo. Read this for work under `web/` (layouts, views, components, lib, types, static).

For agent routing, see [claude.md](../claude.md). For the cryptography the client implements — key hierarchy, envelope format, custody trade-offs — see [security.md](./security.md) (**required** before touching `web/lib/crypto.ts` or `keystore.ts`). For Go handlers and APIs, see [backend.md](./backend.md). For BunGo server setup, routes, layouts, script injection, and `_bungoRender`, read [bungo.md](./bungo.md) — **required** when adding or changing pages, layouts, or view entry files.

---

## How the frontend is delivered

Vault3 does **not** use a separate Node/Vite app. React is compiled by BunGo (embedded esbuild) and served by the Go binary.

- **No** npm, `package.json`, `node_modules`, or Vite dev server.
- Third-party client dependencies would use Deno-style URL imports (`https://esm.sh/...`) wrapped once under `web/lib/` — but Vault3 currently has **zero** of them, and the CSP (`script-src`/`connect-src` allow esm.sh only) is the only door. Prefer keeping it that way: a password manager's bundle should be auditable.
- BunGo injects view scripts and `window.__BUNGO_DATA__` automatically — see [bungo.md](./bungo.md).

## Stack

| Layer | Choice |
|-------|--------|
| Runtime | React 18.2 (embedded via BunGo) |
| Language | TypeScript / TSX |
| Crypto | WebCrypto only (`web/lib/crypto.ts`) — no crypto libraries |
| Styling | theme.css design tokens + local Tailwind Play runtime (`web/static/tailwind.js`) |
| Components | shadcn/ui-inspired local primitives (no shadcn CLI or npm) |
| Data fetching | `web/lib/api.ts` (`postJSON`/`getJSON`) |
| Live updates | `web/lib/sync.ts` (EventSource on `/events`) |

## `web/` layout

```text
web/
  layouts/        .gohtml templates; base.gohtml holds head/SEO + shared defines
    app/          authenticated pages (vault, settings, notifications)
    legal/        terms, privacy, cookies, security (server-rendered prose)
  views/          one .tsx/.ts entry per page
  types/          one file per view, named to match it (see "Type files")
  components/
    icons.tsx     shared lucide-matched icon set (see "Shared icons")
    ui/           token primitives: password-input, copy-button, dialog, toast, field-error
    auth/         join/recover ceremony pieces: phrase-grid, strength-meter, emergency-kit
    vault/        the vault surface: lock-screen, item-form, item-detail, generator-popover
  lib/            shared client glue: api.ts, crypto.ts, keystore.ts, sync.ts,
                  generator.ts, totp.ts, wordlist.ts, motion.ts
  static/         theme.css (all tokens), styles.css (page styles), tailwind.js,
                  favicon.svg, og-image.png, robots.txt, sitemap.xml
```

Conventions the tree encodes:

- `views/` holds one entry per page; anything reusable moves into `components/<feature>/` or `components/ui/`.
- `types/` mirrors the view file name (`views/vault.tsx` ↔ `types/vault.ts`); shared cross-view shapes get their own non-view file and are imported by name, never re-declared.
- `lib/` is the single home for client glue. **All cryptography goes through `lib/crypto.ts`** — no view or component calls WebCrypto directly, ever. All key custody goes through `lib/keystore.ts`.
- `static/` is public and bypasses security layers — never put secrets or user-specific files there.

## The crypto layer (client)

- `lib/crypto.ts` — the 2SKD derivation, envelope seal/open, keypair generation, the registration bundle, item sealing. Constants (info strings, iteration default, phrase length) are part of the wire contract with the server; see the change checklist in [security.md](./security.md).
- `lib/wordlist.ts` — the 2048-word Secret Phrase list. Append-only in spirit: existing phrases must keep validating forever.
- `lib/keystore.ts` — sessionStorage keys per tab, localStorage remembered identity, auto-lock, and the per-tab `clientID()` the api layer sends as `X-Vault3-Client`.
- `lib/sync.ts` — subscribes to `/events`, ignores this tab's own echoes, hands the new revision to the view for refetch.
- `lib/generator.ts` — password/passphrase generation with uniform CSPRNG sampling. `enabledClasses`/`classify` are the single source of truth for the letters/digits/symbols split, so the toggles, the entropy estimate and the colour-coded preview can never disagree.
- `lib/totp.ts` — RFC 6238 codes for seeds stored on items, computed in the browser and **only** there. Read the two-kinds-of-TOTP table in [security.md](./security.md) before touching it; the account 2FA secret is server-side and does not belong here.
- `lib/motion.ts` — the shared brand-motion primitives the server-rendered public pages enhance themselves with (`initScrollReveal`, `scrambleInto`, `randomB64`). Everything there is garnish and no-ops under `prefers-reduced-motion`; a public page must read correctly with JS disabled.

Patterns to preserve:

- **Decrypt late, hold briefly.** Item overviews decrypt for the list; details decrypt on selection; secrets render blurred (`secret-blur`) until revealed and are copied without necessarily revealing.
- **Copying is one code path.** Everything that writes to the clipboard goes through `useCopy()` in `components/ui/copy-button.tsx` — `CopyButton` and the click-to-copy secret values alike. A displayed secret should be clickable to copy: revealing a password on screen in order to select it is the habit not to design for.
- **Rendering a secret is one component.** Any password or key shown as readable text goes through `SecretText` (`components/ui/secret-text.tsx`), which tints every character by the class `lib/generator`'s `classify` puts it in — letters neutral, digits `--accent-2`, symbols `--accent-3`. Never hand-roll a `<code>` or `font-mono` span for a secret: a password must look identical in the generator that made it, the item that stores it, and the share page that received it. `CHARACTER_CLASS_STYLE` is the one tint table, and the generator's toggles read from it too, so the colours can never disagree with the classes they describe. Masks (`••••`) stay untinted — bullets aren't the secret's characters. Editable `<input>`s can't tint per character; that's the known limit, not an oversight.
- **Locking is local.** Sign-out and Lock clear the keystore *before* any network call.
- **Unlock proof is local.** Wrong credentials are detected by GCM authentication failure when unwrapping, never by asking the server.
- Ciphertext payloads (`Keyset`, `ItemRow`) may ride `__BUNGO_DATA__` freely — they are exactly what a database dump already contains. Plaintext secrets must never appear in a handler map.

## Templates and layouts

All `.gohtml` files live in `web/layouts/`. Full rules: [bungo.md](./bungo.md).

- Every `PageRoute` requires a `Template`; `base.gohtml` is the default Layout (head, SEO/OG/robots meta, the site-wide JSON-LD graph, the wordmark's gradient paint servers) and holds the shared defines: `wordmark`, `publicHeader` (with its below-`sm` nav disclosure), `siteFooter` (with the colophon), `appHeader` (nav row, bell, lock and sign-out buttons — all inline scripts by design), `legalSidebar`, `cookieNotice`.
- **The public site and `/app` are two surfaces, and their chrome never mixes.** Public pages render `publicHeader` + `siteFooter` for everyone, signed in or not; `/app/*` renders `appHeader` and links to no public page but the wordmark, which leaves for `/`. Each surface offers exactly one door to the other: `publicHeader` swaps its sign-up pair for "Open your vault" when `.Viewer` is set, and the app wordmark goes to `/`. Do not add a second crossing (a marketing link in the app header, a back-to-vault link in a sidebar) — that is the mixing this rule exists to prevent. The compliance-driven `cookieNotice` is the one exception, and it is a notice rather than navigation.
- `appHeader` has no account menu: every destination and account action sits in the bar itself at all widths, collapsing to icon-only below `sm` (label spans are `hidden sm:inline`). Anything added there must survive that collapse — a phone shows the icons, not a menu — so keep the bar to items that earn a permanent slot.
- Do **not** manually inject BunGo script tags or `window.__BUNGO_DATA__`.
- SEO is data-driven: handlers override `PageTitle`, `PageDescription`, `CanonicalURL`, and set `NoIndex: true` on every authenticated or token-bearing page. Give each indexable page its own title and description — a shared one has them competing for the same snippet — and keep `<title>` keyword-first while `OGTitle` keeps the brand line.
- Structured data is a graph, not a pile: `base.gohtml` emits `WebSite` + `Organization` + `WebPage` with stable `@id`s on every page, and page templates add their own entity (`SoftwareApplication` on the landing, `TechArticle` on `/security`) referencing those `@id`s instead of redeclaring them. `robots.txt` names the AI/answer-engine crawlers explicitly and `sitemap.xml` lists only indexable URLs — a page that carries `NoIndex` never appears there.

## React views

- Every mounted view calls `_bungoRender(Component, "<mount-id>")`; do not import `_bungoRender` or `useBungoData` (BunGo injects them; declarations in root `bungo-env.d.ts`).
- Two shapes: **mounted views** (React renders the page body — vault, settings, auth flows) and **enhancement views** (a `.ts` that augments server-rendered DOM and renders no React — `landing.ts`, `security.ts`; shared effects live in `lib/motion.ts`). Marketing/legal pages stay server-rendered for SEO; client-only marketing is a regression.
- Break large views into `components/<feature>/`; keep the view a thin orchestrator (`vault.tsx` owns state and mutations; rendering lives in its components).
- Client interactivity lives in `web/views`, never inline `<script>` in templates — the sole exception is `base.gohtml`'s shared, every-page chrome, which is deliberately payload-free: the header behaviours (mobile nav disclosure, bell poll, account menu, lock button) and the cookie notice.

## Styling

**The single source of truth for all design tokens is `web/static/theme.css`** — colours (light + dark), typography, spacing, radii, shadows, and the brand motion keyframes. Never hardcode colour values; use tokens or the token utility classes theme.css defines (`bg-card`, `text-accent`, `border-border`, `btn`, `input`, `checkbox`, `slider`, `badge-*`).

- **Form controls are painted, not native.** `.checkbox` and `.slider` replace browser chrome with token styling (`appearance: none`) while staying real inputs, so labels, keyboard and form semantics survive. Both take a caller-set custom property for the parts CSS cannot know — `--check-tint` to theme a box to what it toggles, `--slider-pct` for the filled portion of a track. Use the `Checkbox`/`CheckboxBox` primitives rather than a bare `<input type="checkbox">`; `accentColor` is not a substitute.

- **One theme, dark.** The tokens in `theme.css` are literal colours under `:root`; there is no light palette, no `.dark` class, no theme switch and no `dark:` variants. A new colour is a token, never a per-theme pair.
- **The spectrum.** `--accent` (violet) is the brand. `--accent-2` (signal cyan) and `--accent-3` (sealed magenta) exist for gradients, ambient light and accent-on-accent detail — never as a second brand colour standing alone. `--gradient-brand` (magenta → violet → cyan) is the one gradient; reach for the primitives that already apply it (`.text-gradient`, `.bg-gradient-brand`, `.rule-gradient`, `.eyebrow`, `.step-chip`, `.stat-value`) rather than writing new `linear-gradient()` calls. Never on body text.
- **Surfaces.** `.card` is the plain app surface; `.panel` is the marketing-weight one (accent-lit wash, gradient top hairline), and `.panel-interactive` adds the hover lift. Public pages sit on `.site-canvas` — one fixed layer holding the grid, grain and `.glow-orb` ambient colour — so no section paints its own background.
- **Marketing tiles argue, they don't decorate.** A feature tile on `/` or `/security` carries a small figure of its own claim — sealed item titles, the nine words in their slots, an authenticator counting down, the real response headers — not a generic glyph in an `.icon-tile`. The bento grids size each tile to its figure (`lg:grid-cols-6` + spans), and the figure parts in `styles.css` (`.fig`, `.seal-bar`, `.phrase-grid`, `.otp`, `.trail`, `.kv`, …) are deliberately small and combinable: a new tile composes a new figure rather than reusing a finished one. Figures are `aria-hidden` garnish — the copy beside one must state the claim on its own — and should quote what the product actually produces (a real column, a real header), because a false figure is a false claim.
- Monospace = secret material. `data-secret` inputs and `.font-mono` get the mono stack; keep that signal consistent.
- Motion language: sealing/unsealing. Use the provided classes — `animate-unseal`, `animate-seal`, `animate-rise` (+ `--stagger-i`), `animate-pop`, `animate-shake`, `animate-glow`, `.scroll-reveal` — rather than inventing new keyframes per view. Everything respects `prefers-reduced-motion`.
- `styles.css` is for page-specific styles (landing visuals, legal prose, app helpers); it must never redeclare a token.

## Data flow

- **Initial page state**: server handler map → template + `useBungoData()`.
- **Mutations and refetches**: through `lib/api.ts` only (`postJSON`/`getJSON`; they never throw on non-2xx — branch on `ok`). Do not scatter raw `fetch` (the shared-header inline scripts are the one exception).
- **Live updates**: mutation responses carry the new `revision`; other tabs converge via `lib/sync.ts` → refetch → re-decrypt. Keep the pattern: apply your own response optimistically, let the signal drive everyone else.
- Forms are plain controlled React with explicit validation — no form library while the forms stay this small.

## Maintenance

Update this file only when a frontend **convention** changes — `web/` structure, a shared client pattern, a styling or tokens rule. Building a page or component that fits the existing patterns needs no doc change. Update [bungo.md](./bungo.md) when framework usage changes, [security.md](./security.md) when the crypto layer changes (and read its change checklist first), and [claude.md](../claude.md) only when the routing table or repo map changes.
