# Vault3 Product Guide

What Vault3 is, who it is for, the rules its copy follows, and where the product is heading. For the cryptography read [security.md](./security.md); this file covers the product decisions built on top of it.

---

## The product in one paragraph

Vault3 (vault3.com) is a zero-knowledge password manager for individuals. A user signs in with three things: their **email**, their **Master Password** (in their head), and their **Secret Phrase** — twelve memorable words generated on their device at sign-up (the mnemonic take on 1Password's Secret Key). Everything they store is encrypted on-device before upload; the server can count items but never read one. The pitch is not "we protect your data" — it is "we could not read your data if we tried, and here is the design that makes that true."

## Vocabulary (use these words, exactly)

| Term | Meaning | Never call it |
|---|---|---|
| Master Password | The secret in the user's head | password, passphrase |
| Secret Phrase | The twelve generated words in the Emergency Kit | secret key, seed phrase, mnemonic |
| Emergency Kit | The downloadable .txt/printable record of email + Secret Phrase | backup, recovery kit |
| Unlock / Lock / Seal | Opening and closing the vault; encrypting an item | log in (for the vault), decrypt (in UI copy) |
| Item | One stored entry (login, secure note, payment card, identity) | record, credential |
| Trash | Soft-deleted items, kept 30 days | archive |

"Unlock" is the sign-in verb; "seal" is the brand's encryption verb (buttons say "Seal item", the wizard step is "Seal"). The lock action is local and instant — copy should never imply the server is involved in locking.

## What v1 does

- Personal vault with four item categories (login, secure note, payment card, identity), favourites, client-side search, trash with 30-day retention, permanent delete.
- Password generator (character and passphrase modes, honest entropy meter).
- Registration ceremony with Secret Phrase minting and mandatory Emergency Kit confirmation; verify-email flow. There is deliberately **no** account recovery or reset flow (see [security.md](./security.md)); account deletion is the only way out.
- TOTP two-factor authentication; per-device session list with revocation; Master Password change with full client-side re-wrap that signs out other devices.
- Live cross-device sync: any change on one device signals every other signed-in client to refresh within a second (SSE + per-user revision).
- Security notifications (new-device sign-in, password change, 2FA changes) in-app and by email; notification preferences; auto-lock preference.
- **Multiple vaults**: create, rename and delete vaults from the sidebar switcher; every vault has its own key.
- **Shared vaults**: a vault owner sends a single-use invite link (`/app/invite#…`, 7-day expiry, revocable); accepting grants **view access** — members can open and read every item but change nothing. Owners manage people and pending invites from the vault settings dialog; members can leave. Changes in a shared vault live-sync to every member.
- **Share links**: expose one item to anyone via `/share#…` (expiry up to 30 days, revocable, view-counted). The decryption key rides in the URL fragment and never reaches the server — see [security.md](./security.md).
- Marketing landing, security explainer (`/security`), contact form, Terms / Privacy / Cookie legal docs, and a first-visit cookie notice.

## What v1 deliberately does not do

- No editable roles beyond owner/viewer: shared-vault members are read-only; there is no "editor" role yet.
- No payments/subscriptions, no admin console (the `vault3_admin` table and `/app/v3-mgmt` path constant are reserved).
- No browser extension or desktop clients yet.
- No third-party integrations beyond Mailgun for email. No analytics, no trackers — this is a product feature and marketing copy relies on it.

## Copy rules

- **Honesty over reassurance.** The zero-knowledge trade-off (lost secrets = lost vault) is stated plainly wherever it is relevant — the landing page, the join wizard, `/security`, the settings danger zone. Never soften it into "contact support to recover", and never imply a reset exists.
- Precise, calm, confident. No hype words ("military-grade", "unhackable", "bank-level"). The numbers speak: AES-256-GCM, Argon2id at 64 MiB, 1,000,000 PBKDF2 rounds, 132 bits.
- **Plain sentence, exact chip.** Prose is written for someone who has never heard of a KDF: locked/unlocked rather than encrypted/decrypted where either works, scrambled text rather than ciphertext, randomness rather than entropy, "made on your device" rather than "derived client-side". The precision is not dropped — it moves into the monospace badges, `.fig-label`s and figures beside the sentence, where the exact primitive and parameters belong. A reader should be able to skip every chip and still understand the product, and read only the chips and still audit it.
- **Every page answers, not just asserts.** `/` carries a plain-answers FAQ (what if I forget my password, what would a hacker get, is it free) and `/security` opens with a glossary of its own jargon. The FAQ copy and the `FAQPage` JSON-LD on the landing page are the same six answers twice — change one and change the other in the same edit.
- **Repeated claims get a fresh angle, not a fresh paste.** The zero-knowledge argument recurs on the landing page, `/security`, the Terms and the Privacy Policy; each states it from its own vantage (what it means for you, how it works, what you are agreeing to, why the policy is short). No two pages should carry the same sentence — the footer, the two CTAs and the meta descriptions included.
- **"Post-quantum" is a claim about structure, not a badge.** Say why it holds — no asymmetric cryptography to break, widths chosen to survive Grover — and never imply a quantum computer exists today that would otherwise read the vault.
- British English. Sentence case for headings and buttons ("Create your vault", not "Create Your Vault").
- Security claims in copy must be literally true of the implementation; when the implementation changes, the copy changes in the same task.
- **We state, we don't ask.** The cookie notice is a notice, not a consent gate: the session cookie is strictly necessary, so there is nothing to accept or reject and the panel carries one acknowledgement button. Never add accept/reject controls unless a non-essential cookie actually ships — and if one ever does, the Cookie Policy and this line change in the same task.
- Monospace styling signals secret material (phrases, generated passwords, ciphertext) — keep that association consistent.
- **One operator, named consistently.** Vault3 is made and operated by **Octa Systems Ltd**, trading as **Octa Digital** ([octa.sh](https://octa.sh)). Legal documents name the legal entity (contracting party in the Terms, data controller in the Privacy Policy); the footer colophon credits the trading name. Both come from the `SITE_COMPANY_*` constants — never type the company name into a template.

## Brand and motion language

- Wordmark: lowercase **vault** + **3** in the brand gradient; mark: a rounded tile carrying the brand gradient with a triangle cut out of it — three sides for the three, and the cut goes all the way through. The cutout is the `v3-cut` mask in `base.gohtml`'s hidden defs, never a background-coloured stroke, so the mark keeps its hole on the page, on a panel or on a tinted surface; in monochrome contexts the tile takes `currentColor`. The favicon is the same drawing with the cut painted `--background` instead of masked, because a standalone image has no surface to show through. One theme, dark. There is no light mode and no theme switch — the palette in [frontend.md](./frontend.md) is the palette.
- Violet is the brand colour. It has two companions — a signal cyan and a sealed magenta — used only for gradients, ambient light and accent-on-accent detail, never alone as a second brand colour. See the spectrum tokens in [frontend.md](./frontend.md).
- The motion metaphor is **sealing/unsealing**: content resolves from scramble/blur into clarity (hero cipher scramble, `animate-unseal`), the accent breathes as a glow, wrong credentials shake. All motion respects `prefers-reduced-motion`. Tokens and keyframes live in `web/static/theme.css`.

## Roadmap runway (design for, don't build)

1. **Editor role for shared vaults** — the access row's role column and server-side write gate are the extension point. Note that `WrapAlgo` is now `'muk'` only: the reserved public-key value was removed with the keypair, and server-mediated (email-addressed) invites would need a post-quantum KEM decided up front — see [security.md](./security.md).
2. **Browser extension / desktop clients** — same APIs, same envelopes; the JSON API is already the full product surface.
3. **Subscriptions** — organisation-less individual billing; keep user hub clean of plan data until then.
4. **Admin console** — gate on `vault3_admin`, mount under `config.AdminConsolePath`.

## Maintenance

Update this file when product behaviour, vocabulary, copy rules, or scope change. Feature inventories above describe v1's shape — when a roadmap item ships, move it into "What v1 does" and update [claude.md](../claude.md) only if the repo map changes.
