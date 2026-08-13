# Vault3 Backend Guide

Go server, database, sessions, email, jobs and API conventions. Read this for work under `cmd/`, `internal/` and `scripts/sql/`.

Read [security.md](./security.md) **first** before touching auth, keys or blobs. [bungo.md](./bungo.md) covers route registration and framework rules.

---

## Tech stack

| Area | Choice |
|------|--------|
| Language | Go |
| Web framework | [BunGo](./bungo.md) |
| Logging | Zap (`go.uber.org/zap`) |
| Database | PostgreSQL |
| SQL builder | `github.com/Masterminds/squirrel` |
| Auth | Custom session auth over a client-derived auth key (Argon2id), TOTP 2FA (`github.com/pquerna/otp`) |
| Server field crypto | `internal/crypto` (AES-256-GCM under `SERVER_ENCRYPTION_KEY_STRING`) |
| Email | Mailgun REST API (keys empty in dev; delivery degrades to logged skips) |
| Change signal | In-process SSE hub (`/events`) + per-user revision counter |

No other third parties — deliberately.

---

## Runtime and dependency injection

All application dependencies live in a single `Runtime` struct in `internal/runtime`.

`Runtime` exposes:

- `DB` — database handle
- `TX` — active transaction (when inside `WithTransaction`)
- `Log` — Zap logger
- `Builder` — Squirrel statement builder
- `Config` — parsed environment config
- `Cipher` — the server-side `*crypto.FieldCipher` (operational fields only; vault data never touches it)
- `Lookups` — `*view.Lookups`: in-memory snapshot of reference tables (item categories) loaded once at startup
- `Signals` — the `*SignalHub` behind `/events` (nil in the worker process)

**Rules**

- Do not use globals for app dependencies. Always pass `*runtime.Runtime`.
- Inject through `*runtime.Runtime`. Do not open DB clients or service clients inside handlers, models, or database functions.
- Do not add defensive nil checks for `*Runtime` in every function; assume it is valid after startup.
- Page handlers, API handlers, and security-layer handlers that need app dependencies are methods on `*Runtime`.

Handler shapes, all taking `*bungo.Request`: page handlers return `(map[string]any, error)`, API handlers `(bungo.APIResponse, error)`, security layers a bare `bool`.

### The custom listener (cmd/vault3/main.go)

`srv.Serve` is **not** used. main.go builds the handler through the engine's public `CreateHandler`, mounts the native `/events` SSE endpoint beside it, and wraps everything in `rt.WrapHandler` — security headers (CSP, HSTS, frame denial), rejection of cross-origin state-changing requests, and socket-IP injection so `ClientIP` works without a proxy. All of it uses only BunGo's public API; the framework is unmodified.

Rate limiting is **not** in the app. Per-IP throttling of the auth endpoints belongs to the production reverse proxy, which sees the real client address; an in-process counter keyed on the socket address collapses to one platform-wide bucket the moment traffic arrives through a proxy. Do not reintroduce it in Go.

#### Route registration is secure by default

Routes are registered through seven closures defined at the top of main.go, never by writing a `bungo.ApiRoute`/`PageRoute` literal inline:

| Helper | Layers | Use for |
|--------|--------|---------|
| `api(method, path, handler)` | `require_auth` + `load_viewer` | every authenticated endpoint |
| `page(path, template, view, handler)` | `require_auth` + `load_viewer` | every authenticated page |
| `adminAPI(method, path, handler)` | + `require_admin` | the management console's endpoints |
| `adminPage(...)` | + `require_admin` | the management console page |
| `openAPI(method, path, handler)` | none | the deliberately public API surface |
| `viewerPage(...)` | `optional_auth` + `load_viewer` | public pages that adapt when signed in |
| `anonPage(...)` | none | pre-sign-in pages and the share viewer |

The inversion is the point: authentication is the default, and going public costs a visible word in the name. In a flat list of ~50 routes a missing `SecurityLayer:` field is invisible in review and silently ships an unauthenticated endpoint over the vault. It also keeps the public surface auditable by grepping `main.go` for the three public helper names — and the privileged surface auditable by grepping for the two admin ones.

If a route needs a layer combination none of these covers, add another named helper rather than a struct literal.

### Shared handler helpers

- `rt.Viewer(req)` — the request's `*view.UserSummary` (nil if anonymous), built once by the `load_viewer` layer.
- `CurrentUser(req)` / `CurrentSession(req)` — the hydrated `*models.UserFull` / `*models.Session` stashed by `require_auth`.
- `require_admin` — the console gate. Reads the `vault3_admin` spoke `require_auth` already loaded, so it costs no query and cannot disagree with `view.UserSummary.IsAdmin`; chain it **after** `require_auth`. A signed-in non-admin gets 401 like everyone else, which is also the right answer: the status code should not confirm that the console exists.
- `optional_auth` — carried by **every** public page (landing, features, contact, security, whitepaper, the legal docs) so the marketing header can offer a signed-in visitor the way back into `/app`. Loads the session/user when a valid cookie is present but always passes; pair with `load_viewer`, and have the handler put `rt.Viewer(req)` in its map. Shares `resolveSession` with `require_auth` but does not touch last-seen. It adapts the header only — a public page never renders app chrome (see [frontend.md](./frontend.md)).
- `apiError(status, message)` / `apiFieldError(status, message, field)` — the standard error responses; never inline `bungo.APIResponse` error literals.
- `rt.audit(req, userID, action, entityType, entityID, detail)` — append to the security trail; log-and-continue by design.
- `decodeBody[T](req)` — parse the request body or hand back a ready-to-return 400. Every API handler opens with it and none calls `json.Unmarshal(req.Body, …)` directly. It returns `(payload, deny)`; return `*deny` when non-nil. `payload` is a `*T`, so pass it on as-is rather than taking its address. Give the body a **named type** and reuse the shared single-field ones (`idPayload`, `tokenPayload`, `emailPayload`, `codePayload`); the rest live next to the handler that owns them. One shared malformed-body response also means every endpoint refuses unparseable input identically, so probing one teaches nothing about another.

### Authorisation helpers (vault_view.go)

**Every** vault or item handler authorises through one of these four, and none re-implements the check inline. Each returns `(rows, deny)` — the loaded rows, or a ready-to-return denial to hand back as `*deny` when non-nil. The `ownerOnly` argument is the 403 message a member sees.

| Helper | Requires |
|--------|----------|
| `requireVaultAccess(req, userID, vaultID)` | any access — reads every member is entitled to |
| `requireVaultOwner(req, userID, vaultID, ownerOnly)` | owner; 403 with `ownerOnly` for a member |
| `requireItemAccess(req, userID, itemID)` | any access to the item's vault |
| `requireItemOwner(req, userID, itemID, ownerOnly)` | owner of the item's vault |

Two properties are built in rather than left to callers. "Does not exist" and "is not yours" collapse into one 404, because a distinguishable response turns any id into an existence oracle. And the role requirement is **in the function name**: since members hold read access to a shared vault, the owner check is the only thing between a member and someone else's data, so a handler that wants it must say so — and one that omits it reads as `requireVaultAccess` rather than as a missing line.

`RemoveVaultMemberAPI` is the one legitimate exception (a member may remove themselves): it takes `requireVaultAccess` and branches on the target, and says so in a comment. Any other manual role comparison in a handler is a bug.

---

## Go conventions

### Pointers

Pass pointers to structs unless there is a strong reason not to (models, services, config, handlers, payloads). Struct inputs: pointer. Struct outputs: pointer where practical. Collections as normal. Small primitives by value.

### Logging

- Logger is created once at startup by `newLogger` (`internal/runtime/logger.go`); use `rt.Log`. Development tees console output to `.vault3.log` (gitignored); production uses the JSON logger and writes no file.
- Log lifecycle, security, notification, and job outcomes at boundaries.
- **Never log secrets**: no auth keys, no session tokens, no envelope contents, no email verification/reset tokens, no TOTP secrets. Item data cannot be logged (the server never has it) — keep it that way.
- Avoid noisy happy-path logs. Prefer logging errors at the handling boundary, not where they are created.

### Error handling

- Every fallible function returns `error`; handle at page handlers, API handlers, jobs, or CLI entry points.
- Operation-specific error names when multiple exist in one function (`insertUserErr`, not a reused `err`).
- Wrap with context; do not leak sensitive values into messages.

### Naming and structure

- camelCase variables/functions; PascalCase exported identifiers. Append `Optional` when nil/empty is meaningful.
- Constants live in `internal/config/constants.go`.
- Domain types are defined once in `internal/models`; pure data, no queries, no `internal/database` import.

---

## Configuration and environment

All config parsing lives in `internal/config`. `config.Start()` runs at startup; missing or invalid required values fail fast. Read via `rt.Config`; do not call `os.Getenv` elsewhere.

Environment variables use typed suffixes: `NAME_STRING | NAME_INT | NAME_FLOAT | NAME_BOOL | NAME_DURATION`.

```text
PRODUCTION_BOOL=false
PORT_INT=3403
POSTGRES_DSN_STRING=postgres://...
SERVER_ENCRYPTION_KEY_STRING=<base64 32 bytes>
SUPPORT_EMAIL_STRING=hello@vault3.com
MAILGUN_API_KEY_STRING= / MAILGUN_DOMAIN_STRING= / MAILGUN_FROM_EMAIL_STRING=   # optional; see Email
ADMIN_BOOTSTRAP_EMAIL_STRING=                                                   # optional; see The admin console
```

`PRODUCTION_BOOL` affects cookie Secure, HSTS, log format, and whether `SyncDatabaseSchema` runs. Secrets are read with `MustString` and listed in `REQUIRED_ENV_VARS`, with **two deliberate exceptions** read through `LookupString`: the Mailgun trio, so a dev stack boots with the keys blank, and `ADMIN_BOOTSTRAP_EMAIL_STRING`, which a stack needs exactly once.

---

## Database

### Engine and queries

- PostgreSQL from day one; use native features where they help.
- Use Squirrel for dynamic SQL; dollar placeholders via `rt.Builder`. Never concatenate user input into SQL. Raw SQL is fine for migrations and reviewed static queries.

### Package layout

All SQL lives in `internal/database` as standalone functions, not methods on models. They take `(ctx, db DbTx, builder, …)` and return domain types from `internal/models`.

Functions take `db database.DbTx` (satisfied by both `*sql.DB` and `*sql.Tx` — callers pass `rt.GetDb()`) plus `builder`, keeping the package free of the runtime import. Functions that read or write encrypted-at-rest columns additionally take `cipher *crypto.FieldCipher` and do the FieldCipher work internally, so handlers never touch ciphertext plumbing.

**Writes whose `WHERE` is pure identity must go through `execExpectingRow`**, which returns `ErrNoRowsAffected` when nothing matched. Handlers authorise and these functions mutate by id, so without the guard a forgotten authorisation check produces a write that changes nothing and still returns 200 — indistinguishable from success at every layer above. It matters most on the credential path, where a silent no-op would report a changed Master Password while the old hash still stood.

Writes that legitimately affect zero rows must **not** use it: the revoke helpers (`IS NULL` guarded so a second revoke is a no-op), `DeleteOtherUserSessions`, the session delete/touch helpers, `MarkNotificationRead(All)` and the scheduler's bulk purges. The full list with reasons is on `ErrNoRowsAffected` in `db.go`; adding the guard to one of those turns an ordinary outcome into a 500.

### Connections and transactions

Never query `rt.DB` directly in database code. Use `rt.GetDb()`.

- `runtime.WithTransaction(rt, ctx, fn)` hands `fn` a transaction-scoped `*Runtime`; everything inside uses that one's `GetDb()` and `Builder`, and returning an error rolls back.
- Use `WithTransaction` every time more than one table changes in sequence.
- Do not pass `*sql.Tx` through signatures; do not set/clear `Runtime.TX` outside the helper.
- Keep transactions short; no external APIs inside them.

### The change signal (cross-device sync)

Every mutation follows one shape — mutate, bump the affected users' revisions **inside** the same transaction, then publish and audit **after** it commits. Handlers do not assemble that sequence by hand; they call one of the three commit helpers in `signal.go`, passing the audit fields plus a `mutate` closure that receives a transaction-scoped `*Runtime`, and get back the new revisions.

| Helper | Audience |
|--------|----------|
| `commitUserChange(req, userID, action, entityType, entityID, mutate)` | the acting user alone (profile, credentials) |
| `commitVaultChange(req, actorID, vaultID, action, entityType, entityID, mutate)` | everyone with access, resolved **after** the mutation so a member it adds is included |
| `commitAudienceChange(req, actorID, audience, action, entityType, entityID, mutate)` | a list captured **before** the mutation, for changes that delete the access rows identifying it (vault delete, member removal) |

The ordering is not stylistic. Bumping inside the transaction is what makes a rolled-back change unable to signal anyone; publishing only after commit is what stops a client being told to refetch data that was never written. Both are invariants a handler could get wrong silently, so the helpers own them. API responses return the acting user's own revision from the returned map.

Registration is the sole handler using a bare `WithTransaction`: it creates the user, so there is no prior revision to bump.

Clients send a per-tab id in `X-Vault3-Client`; the event echoes it as `origin` so the originating tab skips its own refetch. `GET /api/v1/sync/revision` is the reconnect/poll fallback. The hub is in-process — if the web tier ever scales horizontally, put Postgres LISTEN/NOTIFY behind the same Publish/Subscribe surface.

### Hub composite getters

`SelectUserFullByKeyValue(ctx, db, builder, cipher, key, value)` is the canonical user loader: hub row plus auth, keys, admin spokes and the vault-access rows each paired with its vault. Lookup keys are an allowlist (`"id"`, `"email"`); `sql.ErrNoRows` means no hub row; missing spokes are nil. Vault and item hubs are small enough that their focused selectors (`SelectUserVaults`, `SelectVaultItems`) serve the same role.

### Schema design

- Hub-and-spoke: `vault3_user` / `vault3_vault` / `vault3_item` are hubs; auth, keys, access, sessions, notifications, audit are spokes.
- Mostly denormalised; no wide god tables. Table names: `vault3_` prefix, lowercase snake_case.
- **Column naming**: every column is `Vault3` + `<TablePascalName>` + `<ColumnPascalName>` (PascalCase, no separators), quoted in DDL and queries so PostgreSQL preserves case. Model `db` tags and Squirrel column strings must match exactly.
- Columns ending in `Enc` hold FieldCipher ciphertext; JSONB columns holding client-side `CipherEnvelope`s carry no suffix (the envelope is the format).
- **Primary keys**: UUIDs only (`github.com/google/uuid`), version 7, generated in Go (`newUUID()` helper). Never `SERIAL`. UUIDs are safe to expose to the frontend.

### Schema scripts and installation

Numbered SQL files in `scripts/sql/` are the source of truth. The installer lives in `internal/config` (`SQLScriptsDir`, `LATEST_SQL_SCRIPT_VERSION`, `SyncDatabaseSchema`); development replays 1..N on each boot, so scripts must be idempotent (`IF NOT EXISTS`, upsert seeds).

Adding a script: create `scripts/sql/00N.sql`, bump `LATEST_SQL_SCRIPT_VERSION = N` in the same change, restart locally and confirm the `executing SQL script (dev)` log lines, apply to production through the manual process when deploying.

---

## Auth and security

The full model is in [security.md](./security.md). Backend-relevant rules:

| Concern | Rule |
|---------|------|
| Sign-in | Client-derived auth key only; Argon2id (PHC-encoded) in `vault3_user_auth` via `crypto.HashAuthKey`/`CompareAuthKey`; the same `GenericLoginError` for every failure |
| KDF params | `/auth/params` serves the per-account salt plus the full `models.KdfCosts` (PBKDF2 iterations + Argon2id memory/time/lanes); unknown emails get deterministic decoys at current defaults. Floors enforced by `validateKdfCosts` |
| Sessions | Opaque 512-bit token client-side; SHA-512 hash in DB; HttpOnly/SameSite/Secure-in-prod; 30-day TTL; revocable; password change revokes all others in-transaction |
| Tokens | Email-verification tokens stored hashed, single-use, time-limited, claimed atomically (`UPDATE … WHERE … RETURNING`) |
| Recovery | **None.** There is no account recovery or reset flow and must never be one — see [security.md](./security.md) |
| 2FA | TOTP secrets FieldCipher-encrypted; pending secret promoted on verify; a valid code required to disable |
| Email verification | Enforced at login only when the `email_verification_required` platform setting is on (off in dev where email cannot send) |
| CSRF | Cross-origin state-changing requests rejected in middleware via `Sec-Fetch-Site`/`Origin`, behind the cookie's `SameSite=Lax` |
| Throttling | Not in the app — the production reverse proxy owns per-IP limits |
| Role strings | `models.RoleOwner` / `RoleMember` / `VaultKind*` / `WrapAlgoMUK`, never bare literals |
| Platform admin | A `vault3_admin` row, checked by `require_admin`. Grants operator powers over accounts and platform gates — never over vault contents, which no key on the server can open |
| Asymmetric crypto | **None, deliberately.** Adding any is a security-model change, not an implementation detail — see [security.md](./security.md) |
| Audit | Security events and item lifecycle (ids only) via `rt.audit`; encrypted at rest |

### Platform settings

Key/value platform config lives in `vault3_platform_setting` (`internal/database/platform_setting.go`), read through dedicated `(*Runtime)` accessors that **fail safe**: `PublicRegistrationEnabled` and `EmailSendingEnabled` default false, `EmailVerificationRequired` defaults false (the one gate where safe means not locking users out). Seeded by `scripts/sql/005.sql`.

Never read or write the table ad hoc. The accessors are the only readers, and the **admin console is the only writer** — through an allowlist (`adminSettingKinds`) rather than an open key/value form, because every reader fails safe on a missing row, so a mistyped key reads as "off" rather than as an error anyone would notice.

### The admin console

The management console (`config.AdminConsolePath`, handlers in `internal/runtime/admin_view.go`, queries in `internal/database/admin.go`) is gated on a `vault3_admin` row and nothing else. Three rules hold across it and are the reason it is safe to have at all:

- **An admin is an operator, not a super-user over vaults.** No endpoint there reads an item, a wrapped key or an envelope, and none usefully could — the server holds no key. What the console exposes is exactly what the server itself can know: row counts, account state, the audit trail, the contact inbox.
- **Admin mutations run through the ordinary commit pipeline** via `commitAudienceChange` with the admin as *actor* and the target as *audience*, so the trail attributes the action to whoever took it while the target's own devices still refresh. Account deletion is the exception, for the same reason self-service deletion is: there is no surviving row to bump.
- **The console cannot lock itself out.** An admin may not suspend, delete or de-admin themselves, and `CountAdmins` refuses the revocation of the last grant.

Every listing is paged at `config.AdminPageSize`; there is no unpaged variant to reach for.

**Bootstrap.** `vault3_admin` ships empty, so `Start()` (web process only) applies the optional `ADMIN_BOOTSTRAP_EMAIL_STRING`: it grants the role to that already-registered account, idempotently, and warns if no such account exists. Without it a fresh deployment has no way into the console short of SQL against production, and revoking the last grant would be irreversible. Unset is the steady state.

---

## Notifications

All notifications run through `(*Runtime).Notify(ctx, event)` (`internal/runtime/notify.go`): handlers never decide who is told, over which channel, or against whose preferences. A handler builds a typed event (`Welcome`, `NewDeviceLogin`, `PasswordChanged`, `TwoFactorChanged`, `EmailVerification`, `AccountReset`) and calls `Notify` **after the triggering write commits**.

Channel gate: **in-app is always allowed** (the bell cannot be disabled); email is gated by the master toggle plus the kind's category toggle (`securityAlerts`, `productUpdates`), except `alwaysEmailKinds` (welcome, verification, reset, password-changed) which bypass preferences. Preferences decode through `models.NotificationPrefs`, the shape the settings page writes. In-app rows are FieldCipher-encrypted at rest.

### Email delivery (Mailgun)

`(*Runtime).SendTemplateEmail` (`internal/runtime/email.go`) renders a named template from `email_templates.go` (subject + branded HTML shell, server-side) and posts it to the Mailgun messages API. Two gates in order: the `email_sending_enabled` platform setting (off → info-log skip naming template/trigger/recipient), then the Mailgun credentials (empty → warn-log skip). Callers never branch on configuration. `frontendUrl`, `supportEmail`, `firstName`, `email` are injected into every render.

---

## Background job scheduler

Housekeeping runs in a **separate process**: `cmd/scheduler`, a second entry point that reuses the web server's Runtime via `runtime.StartWorker()` — identical to `Start()` except it never runs the dev schema sync (the web process owns schema application). Deploy as its own container; `start.sh` wires `vault3-scheduler` locally.

Job orchestration lives in `internal/jobs`: each job is a `func(ctx, rt) error` registered in `jobs.Run` with a name and interval, runs once on startup then on its interval, and drains on SIGINT/SIGTERM. **Jobs must be idempotent** — the WHERE clause is the claim. Job SQL lives in `internal/database/scheduler.go`. To add one: query helper, job function, register in `jobs.Run`.

---

## Maintenance

Update this file only when a **convention** changes — a pattern, interface, layout rule, or architectural decision future code should follow. Shipping a feature that fits existing conventions needs no doc change; no per-handler inventories. Crypto-adjacent changes update [security.md](./security.md) first.
