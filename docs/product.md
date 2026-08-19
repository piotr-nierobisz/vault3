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
| Unlock / Lock / Seal | Opening and closing the vault; encrypting an item | decrypt (as a button or label) |
| Item | One stored entry (login, secure note, payment card, identity) | record, credential |
| Trash | Soft-deleted items, kept 30 days | archive |

"Unlock" is the sign-in verb, and "seal" is the brand's encryption verb, **in the app's own controls and labels**: buttons say "Seal item", the wizard step is "Seal", the header action is Lock. The lock action is local and instant, and copy should never imply the server is involved in locking.

Explanatory prose on the public pages is the exception and uses **encrypt / decrypt** plainly, because that is the word a password-manager reader already knows and the sentence's job there is to be understood rather than to be branded. "Sealed" survives in the chips and figure labels, where it reads as a state rather than as a euphemism.

**Navigation is the exception and names destinations plainly.** Header, mobile menu, footer columns and legal sidebar say **Features, Security, Whitepaper, Login, Register, Contact** — never "How Vault3 protects you" or "Unlock". A signpost's job is to be recognised, not voiced; the brand's verbs earn their keep in the sentence after the click. Page `<h1>`s, `PageTitle` and `OGTitle` follow the same rule. In-page CTA buttons are copy rather than signposts and keep "Create your vault".

## v1 scope

`/features` is the canonical inventory of what ships — this section carries only the scope rules that constrain future work.

- **Four item categories**: login, secure note, payment card, identity. Adding a fifth is a product decision, not a form change.
- **No account recovery or reset flow**, deliberately ([security.md](./security.md)). Account deletion is the only way out, and the Emergency Kit step in registration is mandatory rather than dismissible.
- **Every vault has its own key.** Sharing one must never expose another.
- **Shared-vault members are read-only.** Invites are single-use, 7-day, revocable; write access is gated server-side on the `owner` role.
- **Share links expose one item**, up to 30 days, revocable, view-counted. The decryption key rides in the URL fragment and never reaches the server ([security.md](./security.md)).
- **Trash retains for 30 days**, then purges. Permanent delete is immediate and irreversible.
- Live cross-device sync is expected behaviour, not a nice-to-have: a change on one device reaches every other signed-in client within a second.
- In-app security alerts **cannot** be switched off; only their emails can.
- Four public pages (`/`, `/features`, `/security`, `/whitepaper`) plus contact and the legal docs. Their divided remit is in the copy rules below.
- **The admin console is an operator's tool, not a super-user's.** It reports what the server can count and changes account state and platform gates; it can never show what is in a vault, and a feature request that would need it to is a request to break the product. `/features` and `/security` describe the product a user buys, so neither mentions it.

## What v1 deliberately does not do

- No editable roles beyond owner/viewer: shared-vault members are read-only; there is no "editor" role yet.
- No payments or subscriptions.
- No browser extension or desktop clients yet.
- No third-party integrations beyond Mailgun for email and Cloudflare Turnstile for the bot check on `/login` and `/join`. No analytics, no trackers — this is a product feature and marketing copy relies on it.

## Copy rules

- **Honesty over reassurance.** The zero-knowledge trade-off (lost secrets = lost vault) is stated plainly wherever it is relevant — the landing page, the join wizard, `/security`, the settings danger zone. Never soften it into "contact support to recover", and never imply a reset exists.
- Precise, calm, confident. No hype words ("military-grade", "unhackable", "bank-level"). The numbers speak: AES-256-GCM, Argon2id at 64 MiB, 1,000,000 PBKDF2 rounds, 132 bits.
- **Declarative, not rhetorical.** Public-page copy states what the product is and does. Three habits are specifically out, because at volume each one reads as defensiveness rather than confidence:
  - **Say it positively where the positive is the claim.** "Both stay on your device", not "neither is ever sent to us". Negations are for the places where the absence genuinely *is* the news — no reset route, no trackers, no readable copy on the server — and they lose force if every other sentence is one too. Roughly one negation per 40+ words of prose; `/security` runs denser because impossibility is its subject.
  - **No aphoristic endings.** A paragraph ends on its substance, not on a short counterweight clause after an em dash or colon ("…, which is the point", "…, ours included", "…, by construction"). One per section at most; em dashes are rare rather than structural.
  - **No two-part headline template.** A heading is one declarative statement. Clause + `<br/>` + counterweight ("Serious protection. / Ordinary, everyday use.") is banned outright: it reads as a formula the moment a second heading on the page uses it. A `<br/>` for typographic balance inside a single sentence is fine.
- **Plain sentence, exact chip.** Prose is written for someone who has never heard of a KDF: "encrypted" rather than "sealed" or "ciphertext", randomness rather than entropy, "made on your device" rather than "derived client-side". **No parameter appears in prose** — not "132 bits of randomness", not "64 MB of memory". Precision moves into the monospace badges, `.fig-label`s and figures beside the sentence. A reader should be able to skip every chip and still understand the product, and read only the chips and still audit it. Chips use binary units (`64 MiB`) and prose never restates them in decimal.
- **The server is the subject, not "us".** Prefer "the server stores a hash" over "we keep only a fingerprint". The argument is structural, so let the structure talk: casting the operator as the antagonist in sentence after sentence invites the reader to think about being betrayed rather than about why betrayal is impossible. First person is right where the commitment genuinely is ours (security reports, the beta, what we will not build) and in `/whitepaper`'s threat model, where "us acting in bad faith" is a named adversary.
- **Every page answers, not just asserts.** `/` carries a plain-answers FAQ (what if I forget my password, what would a hacker get, is it free) and `/whitepaper` opens with a glossary of every term it is about to use. The FAQ copy and the `FAQPage` JSON-LD on the landing page are the same six answers twice — change one and change the other in the same edit.
- **Four public pages, four jobs, and they do not overlap.** This is the rule that keeps the site from becoming four versions of the same argument:

  | Page | Answers | Never carries |
  |---|---|---|
  | `/` | why you would want this at all | the inventory, or any mechanism |
  | `/features` | what you can do, and what it costs you in effort | how any of it works |
  | `/security` | what happens to your data, and what that makes impossible | feature detail (lifetimes, limits, controls) |
  | `/whitepaper` | the construction, exhaustively | anything the product does that is not a security property |

  Two sanctioned exceptions, and only two: `/` may touch anything briefly, because a highlight reel is its job; `/whitepaper` may restate anything on `/security`, because being exhaustive is its job. Everywhere else, a claim lives on exactly one page and the others link to it. When a `/features` sentence starts explaining a key or a fragment, it belongs on `/security`; when a `/security` section grows a second paragraph of mechanism, it belongs in the whitepaper.
- **Repeated claims get a fresh angle, not a fresh paste.** The zero-knowledge argument recurs across the public pages, the Terms and the Privacy Policy, each from its own vantage (what it means for you, how it works, what you are agreeing to, why the policy is short). Even where overlap is sanctioned above the sentences differ: `/security` draws the key hierarchy as plain-language nodes, the whitepaper as a tree. Footer, CTAs and meta descriptions are included in this.
- **"Post-quantum" is a claim about structure, not a badge.** Say why it holds — no asymmetric cryptography to break, widths chosen to survive Grover — and never imply a quantum computer exists today that would otherwise read the vault.
- British English. Sentence case for headings and buttons ("Create your vault", not "Create Your Vault").
- Security claims in copy must be literally true of the implementation; when the implementation changes, the copy changes in the same task.
- **We state, we don't ask.** The cookie notice is a notice, not a consent gate: the session cookie is strictly necessary, so there is nothing to accept or reject and the panel carries one acknowledgement button. Never add accept/reject controls unless a non-essential cookie actually ships — and if one ever does, the Cookie Policy and this line change in the same task.
- Monospace styling signals secret material (phrases, generated passwords, ciphertext) — keep that association consistent.
- **One operator, named consistently.** Vault3 is made and operated by **Octa Systems Ltd**, trading as **Octa Digital** ([octa.sh](https://octa.sh)). Legal documents name the legal entity (contracting party in the Terms, data controller in the Privacy Policy); the footer colophon credits the trading name. Both come from the `SITE_COMPANY_*` constants — never type the company name into a template.

## Brand and motion language

- Wordmark: lowercase **vault** + **3** in the brand gradient. Mark: a rounded gradient tile with a triangle cut through it — three sides for the three. The cutout is the `v3-cut` mask in `base.gohtml`'s hidden defs, **never** a background-coloured stroke, so the hole survives on a panel or tinted surface; monochrome contexts take `currentColor`. The favicon paints the cut `--background` instead, because a standalone image has no surface to show through.
- **One theme, dark.** No light mode, no theme switch; the palette in [frontend.md](./frontend.md) is the palette.
- Violet is the brand colour. It has two companions — a signal cyan and a sealed magenta — used only for gradients, ambient light and accent-on-accent detail, never alone as a second brand colour. See the spectrum tokens in [frontend.md](./frontend.md).
- The motion metaphor is **sealing/unsealing**: content resolves from scramble/blur into clarity (hero cipher scramble, `animate-unseal`), the accent breathes as a glow, wrong credentials shake. All motion respects `prefers-reduced-motion`. Tokens and keyframes live in `web/static/theme.css`.

## Roadmap runway (design for, don't build)

- **Editor role for shared vaults** — extension point is the access row's role column plus the server-side write gate. `WrapAlgo` is `'muk'` only; server-mediated (email-addressed) invites would need a post-quantum KEM decided up front ([security.md](./security.md)).
- **Browser extension / desktop clients** — same APIs, same envelopes; the JSON API is already the full product surface.
- **Subscriptions** — individual billing, no organisations; keep the user hub free of plan data until then.

## Maintenance

Update this file when product behaviour, vocabulary, copy rules, or scope change. Feature inventories above describe v1's shape — when a roadmap item ships, move it into "What v1 does" and update [claude.md](../claude.md) only if the repo map changes.
