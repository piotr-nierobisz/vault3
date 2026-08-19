# Vault3 — AI agent context

Vault3 is a zero-knowledge password manager at vault3.com. Everything a user stores — logins, notes, cards, identities, item titles included — is encrypted in their browser with keys derived from a Master Password and a twelve-word Secret Phrase. The server holds only ciphertext and can never decrypt it; that property is the product.

---

## Where to read next

This file is for **routing**, not content. Open the doc that matches the task; add a second only when the work crosses layers. Each doc is also where you *write* a change to its own remit, in the same task that makes it.

| Topic | Doc |
|---|---|
| Product behaviour, copy rules, scope, roadmap runway | [docs/product.md](docs/product.md) |
| Key hierarchy, envelopes, auth flow, threat model, what must never change | [docs/security.md](docs/security.md) |
| Go, `internal/*`, SQL, migrations, sessions, Mailgun, jobs, config | [docs/backend.md](docs/backend.md) |
| `web/` views, layouts, React, client crypto, keystore, styling tokens | [docs/frontend.md](docs/frontend.md) |
| BunGo routes, engines, security layers, `_bungoRender`, API path rules | [docs/bungo.md](docs/bungo.md) |
| Routing table, repo map, programming philosophy | this file |

Anything touching keys, blobs or auth reads [security.md](docs/security.md) **first**, and treats the change as a breaking-migration question before an implementation one.

---

## Repository map

```text
cmd/vault3/           Web server entry (BunGo handler + thin request-fixup wrapper)
cmd/scheduler/        Background job scheduler entry (see backend.md)
internal/             Go domain: runtime, config, crypto, database, models, view, jobs
internal/wasm/argon2/ Argon2id KDF kernel, compiled to WebAssembly (security.md)
web/                  BunGo frontend: layouts, views, components, lib (client crypto!), static
scripts/sql/          Numbered schema scripts (see backend.md)
scripts/              build-wasm.sh (reproducible build), verify-wasm.mjs (known-answer check)
docs/                 product.md, security.md, backend.md, frontend.md, bungo.md
```

Stack: **Go + BunGo + PostgreSQL + custom session auth + client-side WebCrypto and an Argon2id wasm module + Mailgun (email, keys empty in dev) + Cloudflare Turnstile (bot check on `/login` and `/join` only)**. React/Tailwind ship inside BunGo with no npm toolchain. No other third parties, by design; adding one is a [security.md](docs/security.md) decision.

Every primitive is symmetric or hash-based; there is deliberately **no asymmetric cryptography anywhere**, which is what makes it post-quantum with no migration path to maintain. Adding some is a security-model decision — read [docs/security.md](docs/security.md) first.

---

## Running locally

`./start.sh` brings up Docker containers for Postgres, the `bungo dev` server, and the job scheduler (`VAULT3_RUN_SCHEDULER=0` to skip), reading ports and credentials from `.env`. `./stop.sh` tears it down (`--wipe` drops the data volume).

It refuses to boot unless every `REQUIRED_ENV_VARS` entry (parsed live from `internal/config/constants.go`) is present. The Mailgun keys are deliberately **not** required: email degrades to a logged skip while they are empty. Nor is the Turnstile pair, which is read in production only — dev uses Cloudflare's always-pass test keys.

The repo is bind-mounted and watched, so every save hot-rebuilds and reloads (Go, React, templates, CSS). To verify a change: curl `http://localhost:$PORT_INT` (default 3403) and read `.vault3.log` (gitignored, truncated per restart).

Run `./scripts/build-wasm.sh` only when `internal/wasm/argon2/main.go` or the pinned Go version changes; commit its output with the regenerated `web/lib/argon2-manifest.ts`.

---

## Programming philosophy

1. **Think before coding.** State assumptions. Ask when uncertain. Present tradeoffs. Push back when warranted. Name what is unclear instead of guessing.
2. **Simplicity first.** Minimum code for the request. No speculative features, abstractions or configurability. If 200 lines could be 50, simplify.
3. **Surgical changes.** Touch only what the task requires. Match existing style. Remove dead imports from your own edits; mention unrelated dead code rather than deleting it.
4. **Goal-driven execution.** Define success criteria, then change → verify. Bug → reproduce, then fix.
5. **Priority order.** Correctness first — and here, **cryptographic correctness outranks everything**: a change that weakens the zero-knowledge property is wrong no matter what it fixes. Then security and privacy, simplicity, performance, readability.

---

## Maintaining these docs

These docs capture **durable conventions**, not a log of what was built. Update one only when a convention changes — a pattern, interface, layout rule, operational constraint or architectural decision that future work should follow. A task that ships a feature fitting the existing conventions needs **no doc change**.

Never add per-handler, per-file or per-feature inventories: they go stale fast, and the code is the source of truth for what currently exists.
