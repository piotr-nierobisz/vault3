# Vault3 Frontend Guide

React views, layouts, styling, the client-side crypto layer, and client patterns served through BunGo. Read this for work under `web/`.

Read [security.md](./security.md) **first** before touching `web/lib/crypto.ts` or `keystore.ts`, and [bungo.md](./bungo.md) **before** adding or changing pages, layouts or view entry files.

---

## How the frontend is delivered

Vault3 does **not** use a separate Node/Vite app. React is compiled by BunGo (embedded esbuild) and served by the Go binary.

- **No** npm, `package.json`, `node_modules`, or Vite dev server.
- **Zero third-party client dependencies, and the CSP names no third-party host.** A CDN allowance in `script-src`/`connect-src` is a standing script source and exfiltration channel for a page that holds unlocked keys. Adding a remote dependency means deliberately re-opening that hole, in the same change.
- BunGo injects view scripts and `window.__BUNGO_DATA__` automatically — see [bungo.md](./bungo.md).

## Type checking

`tsc` is a separate, optional gate: BunGo strips types without checking them, and nothing at runtime depends on it. Run `npx --package typescript tsc -p tsconfig.json` (`noEmit`, so a clean run prints nothing).

- React's declarations are vendored under `web/types/vendor/` so a fresh clone type-checks with no install step. See that directory's README for versions and refresh steps.
- Keep `@types/react` on the 18.x line to match the embedded React 18.2. Never add npm packages to satisfy the type checker; vendor the declarations instead.
- The vendored `.d.ts` files are invisible to esbuild, so `paths` cannot redirect the React that BunGo actually ships. `tsconfig.json` carries no `baseUrl` on purpose — `paths` resolve relative to the config, which keeps the command working on TypeScript versions that removed the option.

## Stack

| Layer | Choice |
|-------|--------|
| Runtime | React 18.2 (embedded via BunGo) |
| Language | TypeScript / TSX |
| Crypto | WebCrypto via `web/lib/crypto.ts`, plus the Argon2id wasm module behind `web/lib/argon2.ts` — no third-party crypto libraries |
| Styling | theme.css design tokens + local Tailwind Play runtime (`web/static/tailwind.js`) |
| Components | shadcn/ui-inspired local primitives (no shadcn CLI or npm) |
| Data fetching | `web/lib/api.ts` (`postJSON`/`getJSON`) |
| Live updates | `web/lib/sync.ts` (EventSource on `/events`) |

## `web/` layout

```text
web/
  layouts/        .gohtml templates; base.gohtml holds head/SEO + shared defines
    app/          authenticated pages (vault, settings, notifications)
    legal/        terms, privacy, cookies, security, whitepaper (server-rendered)
  views/          one .tsx/.ts entry per page
  types/          one file per view, named to match it (see "Type files")
    vendor/       vendored React/csstype declarations for tsc only (see "Type checking")
  components/
    icons.tsx     shared lucide-matched icon set (see "Shared icons")
    ui/           token primitives: password-input, copy-button, dialog, toast,
                  field-error, error-banner, status-panel, loading,
                  fresh-link-callout
    auth/         join ceremony pieces: phrase-grid, strength-meter, emergency-kit
    vault/        the vault surface: lock-screen, item-form, item-detail, generator-popover
  lib/            shared client glue: api.ts, crypto.ts, keystore.ts, sync.ts,
                  use-action.ts, generator.ts, totp.ts, wordlist.ts, motion.ts
  static/         theme.css (all tokens), styles.css (page styles), tailwind.js,
                  favicon.svg, og-image.png, robots.txt, sitemap.xml
```

Conventions the tree encodes:

- `views/` holds one entry per page; anything reusable moves into `components/<feature>/` or `components/ui/`.
- `types/` mirrors the view file name (`views/vault.tsx` ↔ `types/vault.ts`); shared cross-view shapes get their own non-view file and are imported by name, never re-declared.
- `lib/` is the single home for client glue. **All cryptography goes through `lib/crypto.ts`** — no view or component calls WebCrypto directly, ever. All key custody goes through `lib/keystore.ts`.
- `static/` is public and bypasses security layers — never put secrets or user-specific files there.

## The crypto layer (client)

- `lib/crypto.ts` — the 2SKD derivation, envelope seal/open, the registration bundle, item sealing. Constants (info strings, cost defaults, phrase length) are part of the wire contract with the server; see the change checklist in [security.md](./security.md).
- `lib/argon2.ts` — the typed door to the Argon2id wasm module. It spawns a worker per derivation and disposes of it; the module itself, its integrity pin, and the WASI shim live in `web/static/argon2*.js` (served unbundled so `scripts/verify-wasm.mjs` can test the very code the browser runs). Do not inline or bundle those.
- **Long derivations report progress.** `deriveKeys` takes an optional `ProgressCallback` and every unlock path passes it to `<DerivationProgress>`. A KDF that occupies the main thread for a second reads as a broken page; the fix is to say what is happening, not to weaken the KDF.
- `lib/wordlist.ts` — the 2048-word Secret Phrase list. Append-only in spirit: existing phrases must keep validating forever.
- `lib/keystore.ts` — sessionStorage keys per tab, localStorage remembered identity, auto-lock, and the per-tab `clientID()` the api layer sends as `X-Vault3-Client`.
- `lib/sync.ts` — subscribes to `/events`, ignores this tab's own echoes, hands the new revision to the view for refetch.
- `lib/generator.ts` — password/passphrase generation with uniform CSPRNG sampling. `enabledClasses`/`classify` are the single source of truth for the letters/digits/symbols split, so the toggles, the entropy estimate and the colour-coded preview can never disagree.
- `lib/totp.ts` — RFC 6238 codes for seeds stored on items, computed in the browser and **only** there. Read the two-kinds-of-TOTP table in [security.md](./security.md) before touching it; the account 2FA secret is server-side and does not belong here.
- `lib/motion.ts` — the shared brand-motion primitives the server-rendered public pages enhance themselves with (`initScrollReveal`, `scrambleInto`, `randomB64`). Everything there is garnish and no-ops under `prefers-reduced-motion`; a public page must read correctly with JS disabled.

Patterns to preserve:

- **Decrypt late, hold briefly.** Item overviews decrypt for the list; details decrypt on selection; secrets render blurred (`secret-blur`) until revealed and are copied without necessarily revealing.
- **Copying is one code path.** Everything that writes to the clipboard goes through `useCopy()` in `components/ui/copy-button.tsx` — `CopyButton` and the click-to-copy secret values alike. A displayed secret should be clickable to copy: revealing a password on screen in order to select it is the habit not to design for.
- **Rendering a secret is one component.** Any password or key shown as readable text goes through `SecretText` (`components/ui/secret-text.tsx`), which tints each character by `lib/generator`'s `classify` — letters neutral, digits `--accent-2`, symbols `--accent-3`. Never hand-roll a `<code>` or `font-mono` span for one: a password must look identical in the generator that made it, the item that stores it and the share page that received it. `CHARACTER_CLASS_STYLE` is the one tint table and the generator's toggles read from it. Masks (`••••`) stay untinted; editable `<input>`s cannot tint per character, a known limit rather than an oversight.
- **Locking is local.** Sign-out and Lock clear the keystore *before* any network call.
- **Unlock proof is local.** Wrong credentials are detected by GCM authentication failure when unwrapping, never by asking the server.
- Ciphertext payloads (`Keyset`, `ItemRow`) may ride `__BUNGO_DATA__` freely — they are exactly what a database dump already contains. Plaintext secrets must never appear in a handler map.

## Templates and layouts

All `.gohtml` files live in `web/layouts/`. Full rules: [bungo.md](./bungo.md).

- Every `PageRoute` requires a `Template`; `base.gohtml` is the default Layout (head, SEO/OG/robots meta, the site-wide JSON-LD graph, the mark's shared gradient paint servers and its `v3-cut` cutout mask) and holds the shared defines: `wordmark`, `publicHeader` (with its below-`sm` navigation drawer, rendered as a sibling of the `<header>` so a fixed panel is not trapped inside a stacked, sticky one), `siteFooter` (with the colophon), `appHeader` (nav row, bell, lock and sign-out buttons — all inline scripts by design), `legalSidebar`, `cookieNotice`.
- **The public site and `/app` are two surfaces, and their chrome never mixes.** Public pages render `publicHeader` + `siteFooter` for everyone, signed in or not; `/app/*` renders `appHeader`. Each surface offers **exactly one** door to the other: `publicHeader` swaps its sign-up pair for "Open your vault" when `.Viewer` is set, and the app wordmark goes to `/`. Never add a second crossing (a marketing link in the app header, a back-to-vault link in a sidebar). `cookieNotice` is the one exception, and it is a notice rather than navigation.
- `appHeader` has no account menu: every destination and account action sits in the bar itself at all widths, collapsing to icon-only below `sm` (label spans are `hidden sm:inline`). Anything added there must survive that collapse — a phone shows the icons, not a menu — so keep the bar to items that earn a permanent slot. Console is the one conditional item (`{{if .Viewer.IsAdmin}}`), and stays the only one: a bar whose contents vary per visitor stops being a place people know their way around.
- Do **not** manually inject BunGo script tags or `window.__BUNGO_DATA__`.
- SEO is data-driven: handlers override `PageTitle`, `PageDescription`, `CanonicalURL`, and set `NoIndex: true` on every authenticated or token-bearing page. Give each indexable page its own title and description — a shared one has them competing for the same snippet — and keep `<title>` keyword-first while `OGTitle` keeps the brand line.
- Structured data is a graph, not a pile: `base.gohtml` emits `WebSite` + `Organization` + `WebPage` with stable `@id`s on every page, and a page template adds its own entity **referencing those `@id`s** rather than redeclaring them. Where two entities describe the same thing at different depths they name each other, so an answer engine quoting the short one can find the long one. `robots.txt` names the AI/answer-engine crawlers explicitly; `sitemap.xml` lists only indexable URLs, so a `NoIndex` page never appears there.

## React views

- Every mounted view calls `_bungoRender(Component, "<mount-id>")`; do not import `_bungoRender` or `useBungoData` (BunGo injects them; declarations in root `bungo-env.d.ts`).
- Two shapes: **mounted views** (React renders the page body — vault, settings, auth flows) and **enhancement views** (a `.ts` that augments server-rendered DOM and renders no React — `landing.ts`, `features.ts`, `security.ts`, `whitepaper.ts`; shared effects live in `lib/motion.ts`). Marketing/legal pages stay server-rendered for SEO; client-only marketing is a regression. An enhancement view composes its page's own effect from the `lib/motion.ts` primitives rather than reusing another page's finished one — same rule as the tile figures below.
- Break large views into `components/<feature>/`; keep the view a thin orchestrator (`vault.tsx` owns state and mutations; rendering lives in its components).
- Client interactivity lives in `web/views`, never inline `<script>` in templates — the sole exception is `base.gohtml`'s shared, every-page chrome, which is deliberately payload-free: the header behaviours (mobile nav drawer, bell poll, account menu, lock button) and the cookie notice.

## Styling

**The single source of truth for all design tokens is `web/static/theme.css`** — colours (light + dark), typography, spacing, radii, shadows, and the brand motion keyframes. Never hardcode colour values; use tokens or the token utility classes theme.css defines (`bg-card`, `text-accent`, `border-border`, `btn`, `input`, `checkbox`, `slider`, `badge-*`).

- **Never size a `.btn` with a utility class.** Tailwind's stylesheet is appended *after* theme.css, so `text-sm` on a button silently overrides `.btn`'s font-size and it renders at a different size from its neighbours; `px-*`/`py-*` makes a fourth size no other call site can reuse. Size comes from the class alone: `.btn` (default; its *height* matches `.input` so it lines up in a field row), `.btn-sm` for dense chrome, `.btn-lg` for a form's main submit.
- **Buttons are pills; the surfaces around them are not.** `.btn`, `.btn-icon` and `.seg-item` are `--radius-full`; panels stay `--radius-xl` and inputs `--radius-md`. The round shape is reserved for things you press, which is what makes them findable. Anything pressable that is *not* a `.btn` (the app header's lock/sign-out actions, its nav items) takes `rounded-full` too. List rows that happen to be buttons (the vault switcher, the legal sidebar) are navigation rather than controls and keep their rectangle.
- **A row of mutually exclusive choices is `.seg` + `.seg-item`.** Two segmented controls were hand-rolled in Tailwind with different radii and selected treatments before this existed; both now use the primitive, which reads selection from `aria-selected` where the control is a real `tablist` and from `.is-on` where it is not.
- **Recurring class strings live in theme.css, not in JSX.** `.field-label` (small uppercase label above a field or group), `.btn-icon` / `.btn-icon-danger` (bare glyph button), `.scrim` (modal backdrop), `.icon-tile` + `-sm`/`-lg`/`-cool`/`-warm`/`-danger`/`-muted` (glyph in a tinted well). Reach for these before writing the classes out: a hand-rolled copy is how a tile ended up rendering a danger glyph on an accent well.

- **Form controls are painted, not native.** `.checkbox` and `.slider` replace browser chrome with token styling (`appearance: none`) while staying real inputs, so labels, keyboard and form semantics survive. Both take a caller-set custom property for the parts CSS cannot know — `--check-tint` to theme a box to what it toggles, `--slider-pct` for the filled portion of a track. Use the `Checkbox`/`CheckboxBox` primitives rather than a bare `<input type="checkbox">`; `accentColor` is not a substitute.

- **One theme, dark.** The tokens in `theme.css` are literal colours under `:root`; there is no light palette, no `.dark` class, no theme switch and no `dark:` variants. A new colour is a token, never a per-theme pair.
- **The spectrum.** `--accent` (violet) is the brand. `--accent-2` (signal cyan) and `--accent-3` (sealed magenta) exist for gradients, ambient light and accent-on-accent detail — never as a second brand colour standing alone. `--gradient-brand` (magenta → violet → cyan) is the one gradient; reach for the primitives that already apply it (`.text-gradient`, `.bg-gradient-brand`, `.rule-gradient`, `.eyebrow`, `.step-chip`, `.stat-value`) rather than writing new `linear-gradient()` calls. Never on body text.
- **Surfaces.** `.card` is the plain app surface; `.panel` is the marketing-weight one (accent-lit wash, gradient top hairline), and `.panel-interactive` adds the hover lift. Public pages sit on `.site-canvas` — one fixed layer holding the grid, grain and `.glow-orb` ambient colour — so no section paints its own background.
- **Marketing tiles argue, they don't decorate.** A feature tile carries a small figure of its own claim (sealed item titles, the twelve words in their slots, an authenticator counting down, the real response headers), never a generic glyph in an `.icon-tile`. Bento grids size each tile to its figure (`lg:grid-cols-6` + spans), and the figure parts in `styles.css` (`.fig`, `.seal-bar`, `.phrase-grid`, `.otp`, `.trail`, `.kv`, `.deck`, `.ticks`, `.echo`, …) are small and combinable so a new tile composes a new figure. Figures are `aria-hidden` garnish, so the copy beside one must carry the claim alone — and a figure must quote what the product actually produces, because a false figure is a false claim.
- **An index page's header is display type plus one ornament of its own.** `/features` and `/security` open on a single word, so the word takes `.hero-title` — a viewport-scaled clamp rather than a Tailwind step, because Tailwind loads after `styles.css` and a `text-5xl` beside it would silently win, exactly as it does on `.btn`. Keep the line-height at or above 1.1: the gradient is clipped to the glyphs and painted over the element's own box, so a tighter line box leaves descenders unpainted. Everything *around* the title is per page and lives in that page's own block (`/features` boards its chips, `/security` stamps a seal), for the same reason the tile figures below are not shared.
- **Each public page owns its figures.** `styles.css` groups the figure parts by the page that introduced them, and no page borrows another's: `/features` has no seal bars or countdown dial, `/whitepaper` draws the key hierarchy as a tree because `/security` already draws it as flow nodes. The pages should feel like one site and read like four different arguments — the divided remit in [product.md](./product.md). Reusing a finished figure is how two pages start looking like one page twice.
- **Plain-language blocks are prose, not figures.** `.faq` (`<details>` disclosures on `/`) and `.gloss` (a `<dl>` of term → sentence opening `/whitepaper`) are real content: never `aria-hidden`, built from native elements so they open and read with JavaScript off. `.toc` follows the same rule, with `whitepaper.ts` adding only the `aria-current` marker. The technical term sits in the mono/accent slot and the everyday sentence beside it — the same division the copy rules in [product.md](./product.md) require.
- Monospace = secret material, or machinery named precisely. `data-secret` inputs and `.font-mono` get the mono stack; algorithm names and parameters ride in mono badges and `.fig-label`s so prose can stay plain. Keep that signal consistent.
- Motion language: sealing/unsealing. Use the provided classes — `animate-unseal`, `animate-seal`, `animate-rise` (+ `--stagger-i`), `animate-pop`, `animate-shake`, `animate-glow`, `.scroll-reveal` — rather than inventing new keyframes per view. Everything respects `prefers-reduced-motion`.
- **An entrance animation fills `backwards`, never `both`.** A transform or filter of anything but `none` makes an element the containing block for its `position: fixed` descendants, and `both` keeps the final keyframe applied for the element's whole life — so an entrance on a page wrapper silently re-anchors every modal inside it to that wrapper's box. Writing `transform: none` into the 100% keyframe does **not** save you: the filled value resolves to `matrix(1,0,0,1,0,0)`, which is not `none`. `backwards` still fills before the animation starts, which is the part the staggered variants need. Only `animate-seal` keeps `both`, because it ends hidden and must stay that way.
- `styles.css` is for page-specific styles (landing visuals, legal prose, app helpers); it must never redeclare a token.

## Data flow

- **Initial page state**: server handler map → template + `useBungoData()`.
- **Mutations and refetches**: through `lib/api.ts` only (`postJSON`/`getJSON`; they never throw on non-2xx — branch on `ok`). Do not scatter raw `fetch` (the shared-header inline scripts are the one exception).
- **Async actions go through `useAction`** (`lib/use-action.ts`) rather than a hand-rolled `setBusy`/`try`/`catch`/`finally` around each button. It takes the surface's `onError` and dropped-connection wording once, and returns `{ busy, run }`; `run` wraps the request and takes only the success path (`onOK`) plus a `fail` fallback message.

  The hook owns the re-entry guard (a ref, not `busy` — a double click lands before React re-renders the button as disabled), prefers the server's `{"message"}` over `fail`, `await`s `onOK` so an async success path stays inside the busy window and the network catch, and always clears busy. Where a failure is shown and how a dropped connection is worded are per-*surface*, stated once when a component takes the hook. `run` resolves to whether the success path ran.

  Handlers that genuinely do not fit are left alone rather than contorted: an optimistic toggle with no busy state, a wizard whose failure branch routes by `field`, a multi-step machine, a fire-and-forget mark-as-read.
- **Recoverable failures render as `<ErrorBanner message=… />`** (`components/ui/error-banner.tsx`), never a hand-copied shake block. Give it a `key` that changes per attempt when the same message can fail twice running: re-setting an identical message changes no state, so nothing remounts, the shake never replays, and a repeat click gets no visible response at all. `children` render inside the message for a failure offering a way out of itself (login's resend-verification link); `tone="warning"` is the standing-advisory variant and does not shake. `field-error` is the single-field variant.
- **Whole-page states are `<StatusPanel />`**, not a hand-rolled centred box — loading, empty, terminal failure and success-before-redirect all take it, so they cannot drift apart in surface, padding, mark size or entrance animation. `<Loading />` is the inline form (its default label, "unsealing…", is the product's voice for waiting). `<FreshLinkCallout />` is the show-once share/invite link block.
- **A failed load must never render as an empty one.** The share-link and member lists say what is *currently* exposed, so showing a fetch failure as "none" is a lie in the dangerous direction: keep a distinct failed state and offer a retry. The same applies to a list blanked mid-refetch, where a silent failure strands the pane on its spinner for good.
- **Live updates**: mutation responses carry the new `revision`; other tabs converge via `lib/sync.ts` → refetch → re-decrypt. Keep the pattern: apply your own response optimistically, let the signal drive everyone else.
- Forms are plain controlled React with explicit validation — no form library while the forms stay this small.

## Maintenance

Update this file only when a frontend **convention** changes — `web/` structure, a shared client pattern, a styling or tokens rule. Building a page or component that fits the existing patterns needs no doc change. Update [bungo.md](./bungo.md) when framework usage changes, [security.md](./security.md) when the crypto layer changes (and read its change checklist first), and [claude.md](../claude.md) only when the routing table or repo map changes.
