# Vault3 — AI agent context

Vault3 is a zero-knowledge password manager at vault3.com. Everything a user stores — logins, notes, cards, identities, item titles included — is encrypted in their browser with keys derived from a Master Password and a nine-word Secret Phrase. The server holds only ciphertext and can never decrypt it; that property is the product.

---

## Where to read next

This file is for **routing**, not content. Open the specialised doc that matches the task; add a second doc only when the work crosses layers.

| You are working on… | Read |
|---------------------|------|
| Product behaviour, copy rules, what's in/out of scope, roadmap runway | [docs/product.md](docs/product.md) |
| The cryptography: key hierarchy, envelopes, auth flow, threat model, what must never change | [docs/security.md](docs/security.md) |
| Go, `internal/*`, SQL, migrations, sessions, Mailgun, jobs, config, the change signal | [docs/backend.md](docs/backend.md) |
| `web/` views, layouts, React, client crypto, keystore, styling tokens | [docs/frontend.md](docs/frontend.md) |
| BunGo routes, engines, security layers, `_bungoRender`, API path rules | [docs/bungo.md](docs/bungo.md) |

**Typical combinations**

- Anything touching keys, blobs, or auth: [security.md](docs/security.md) first, always — then the layer doc.
- New authenticated page: [bungo.md](docs/bungo.md) + [frontend.md](docs/frontend.md) + [backend.md](docs/backend.md).
- API-only change: [backend.md](docs/backend.md); [bungo.md](docs/bungo.md) if routes change.
- Styling or component only: [frontend.md](docs/frontend.md).
- Schema or query change: [backend.md](docs/backend.md) unless the UI must change too.

---

## Repository map (high level)

```text
cmd/vault3/           Web server entry (custom listener: BunGo handler + middleware + /events SSE)
cmd/scheduler/        Background job scheduler entry (housekeeping container; see backend.md)
internal/             Go domain: runtime, config, crypto, database, models, view, jobs
web/                  BunGo frontend: layouts, views, components, lib (client crypto!), static
scripts/sql/          Numbered schema scripts (see backend.md)
docs/                 product.md, security.md, backend.md, frontend.md, bungo.md
```

Stack in one line: **Go + BunGo + PostgreSQL + custom session auth + client-side WebCrypto (the vault) + Mailgun (email, keys empty in dev)**. React/Tailwind ship inside BunGo with no npm toolchain. No other third parties — by design.

---

## Running locally

`./start.sh` is the supported way to run the app: it brings up Docker containers for Postgres, the `bungo dev` server, and the background job scheduler (`cmd/scheduler`, detached; `VAULT3_RUN_SCHEDULER=0` to skip), reading ports and credentials from `.env`. `./stop.sh` tears the dev stack down (`--wipe` to drop the data volume).

**Secrets preflight:** start.sh refuses to boot unless every `REQUIRED_ENV_VARS` entry (parsed live from `internal/config/constants.go`, so the check never drifts) is present in `.env` or the environment. The Mailgun keys are deliberately **not** required: email degrades to a logged skip while they are empty, and the `email_sending_enabled` platform setting (seeded off) keeps dev quiet regardless.

Because the repo is bind-mounted and `bungo` watches it, every save hot-rebuilds and reloads (Go, React, templates, CSS), and the dev server tees all logs to `.vault3.log` (gitignored, truncated on each restart). To verify a change, curl the app (`http://localhost:$PORT_INT`, default 3403) and read `.vault3.log`.

---

## Programming philosophy

### 1. Think before coding

State assumptions. Ask when uncertain. Present tradeoffs. Prefer simpler approaches. Push back when warranted. Name what is unclear instead of guessing.

### 2. Simplicity first

Minimum code for the request. No speculative features, abstractions, or configurability. No handling impossible edge cases. If 200 lines could be 50, simplify.

### 3. Surgical changes

Touch only what the task requires. Match existing style. Remove dead imports from your own edits. Mention unrelated dead code; do not delete it unless asked.

### 4. Goal-driven execution

Define success criteria. For multi-step work: change → verify. Examples: validation + tests; bug → reproduce then fix; refactor → tests before and after.

### 5. Priority order

1. Correctness — and in this codebase, **cryptographic correctness outranks everything**: a change that weakens the zero-knowledge property is wrong no matter what it fixes
2. Security and privacy
3. Simplicity
4. Performance
5. Readability

---

## Maintaining these docs

These docs capture **durable conventions**, not a log of what was built. Update one only when a convention changes — a pattern, interface, layout rule, operational constraint, or architectural decision that future work should follow. A task that simply ships a feature fitting the existing conventions needs **no doc change**. Never add per-handler, per-file, or per-feature inventories: they go stale fast and the code is the source of truth for what currently exists.

When a convention does change, update the doc whose remit it falls under, in the same task:

- Product behaviour, copy rules, scope → [docs/product.md](docs/product.md)
- Key hierarchy, envelope format, auth flow, threat model → [docs/security.md](docs/security.md) (and treat any change here as a breaking migration question first)
- Backend/schema/domains → [docs/backend.md](docs/backend.md)
- `web/` or client patterns → [docs/frontend.md](docs/frontend.md)
- BunGo usage → [docs/bungo.md](docs/bungo.md)
- Routing table, repo map, or programming philosophy → this file
