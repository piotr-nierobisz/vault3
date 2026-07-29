# Vault3 Backend Guide

Go server, database, sessions, email, jobs, and API conventions. Read this for work under `cmd/`, `internal/`, `scripts/sql/`, and anything that touches the database, sessions, Mailgun, notifications, the change signal, or background jobs.

For agent routing, see [claude.md](../claude.md). For the cryptography — key hierarchy, envelope format, threat model — see [security.md](./security.md) (**required** before touching auth, keys, or blobs). For React views and `web/`, see [frontend.md](./frontend.md). For BunGo route registration and framework rules, see [bungo.md](./bungo.md).

---

## Tech stack

| Area | Choice |
|------|--------|
| Language | Go |
| Web framework | [BunGo](./bungo.md) |
| Logging | Zap (`go.uber.org/zap`) |
| Database | PostgreSQL |
| SQL builder | `github.com/Masterminds/squirrel` |
| Auth | Custom session auth over a client-derived auth key (bcrypt), TOTP 2FA (`github.com/pquerna/otp`) |
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

### BunGo handler shapes

```go
func (rt *Runtime) AppVaultPage(breq *bungo.Request) (map[string]any, error)

func (rt *Runtime) CreateItemAPI(breq *bungo.Request) (bungo.APIResponse, error)

func (rt *Runtime) RequireAuth(breq *bungo.Request) bool
```

### The custom listener (cmd/vault3/main.go)

`srv.Serve` is **not** used. main.go builds the handler through the engine's public `CreateHandler`, mounts the native `/events` SSE endpoint beside it, and wraps everything in `rt.WrapHandler` — security headers (CSP, HSTS, frame denial), the per-IP auth throttle (proper 429s, which a bungo security layer cannot produce), and socket-IP injection so `ClientIP` works without a proxy. All of it uses only BunGo's public API; the framework is unmodified.

### Shared handler helpers

- `rt.Viewer(req)` — the request's `*view.UserSummary` (nil if anonymous), built once by the `load_viewer` layer.
- `CurrentUser(req)` / `CurrentSession(req)` — the hydrated `*models.UserFull` / `*models.Session` stashed by `require_auth`.
- `optional_auth` — carried by **every** public page (landing, contact, security, the legal docs) so the marketing header can offer a signed-in visitor the way back into `/app`. Loads the session/user when a valid cookie is present but always passes; pair with `load_viewer`, and have the handler put `rt.Viewer(req)` in its map. Shares `resolveSession` with `require_auth` but does not touch last-seen. It adapts the header only — a public page never renders app chrome (see [frontend.md](./frontend.md)).
- `apiError(status, message)` / `apiFieldError(status, message, field)` — the standard error responses; never inline `bungo.APIResponse` error literals.
- `rt.audit(req, userID, action, entityType, entityID, detail)` — append to the security trail; log-and-continue by design.

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
```

`PRODUCTION_BOOL` affects cookie Secure, HSTS, log format, and whether `SyncDatabaseSchema` runs. Secrets are read with `MustString` and listed in `REQUIRED_ENV_VARS` — the **one deliberate exception** is the Mailgun trio, which is optional (`LookupString`) so a dev stack boots with the keys blank.

---

## Database

### Engine and queries

- PostgreSQL from day one; use native features where they help.
- Use Squirrel for dynamic SQL; dollar placeholders via `rt.Builder`. Never concatenate user input into SQL. Raw SQL is fine for migrations and reviewed static queries.

### Package layout

All SQL lives in `internal/database` as standalone functions (not methods on models):

```go
func SelectVaultItems(ctx context.Context, db DbTx, builder *sq.StatementBuilderType, vaultID string) ([]models.Item, error)
```

Functions take `db database.DbTx` (satisfied by both `*sql.DB` and `*sql.Tx` — callers pass `rt.GetDb()`) plus `builder`, keeping the package free of the runtime import. Functions that read or write encrypted-at-rest columns additionally take `cipher *crypto.FieldCipher` and do the FieldCipher work internally, so handlers never touch ciphertext plumbing.

### Connections and transactions

Never query `rt.DB` directly in database code. Use `rt.GetDb()`.

```go
transactionErr := runtime.WithTransaction(rt, ctx, func(txRt *runtime.Runtime) error {
    if insertErr := database.InsertItem(ctx, txRt.GetDb(), &txRt.Builder, item); insertErr != nil {
        return insertErr
    }
    revision, bumpErr := runtime.SignalUserChanged(ctx, txRt, userID)
    return bumpErr
})
```

- Use `WithTransaction` every time more than one table changes in sequence.
- Do not pass `*sql.Tx` through signatures; do not set/clear `Runtime.TX` outside the helper.
- Keep transactions short; no external APIs inside them.

### The change signal (cross-device sync)

Every mutation of a user's data follows one shape:

1. Inside the transaction: the mutation + `SignalUserChanged` (bumps `vault3_user.Revision`, returning the new value).
2. After commit: `rt.PublishChange(req, userID, revision)` fans the revision out over `/events`; `rt.audit(...)` records the action.

Mutations scoped to a **vault** (items, renames, membership) must reach every member, not just the actor: use `SignalVaultChanged` (bumps every access-holder's revision in-transaction, returning a per-user map) and `rt.PublishChanges` after commit. When the mutation removes access rows (member removal, vault delete), capture the audience with `SelectVaultUserIDs` first and bump via `signalUsersChanged`. API responses return the acting user's own revision from the map.

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
| Sign-in | Client-derived auth key only; bcrypt in `vault3_user_auth`; the same `GenericLoginError` for every failure |
| KDF params | `/auth/params` serves per-account salt/iterations; unknown emails get deterministic decoys |
| Sessions | Opaque token client-side; SHA-256 hash in DB; HttpOnly/SameSite/Secure-in-prod; 30-day TTL; revocable; password change revokes all others in-transaction |
| Tokens | Verification and account-reset tokens stored hashed, single-use, time-limited |
| 2FA | TOTP secrets FieldCipher-encrypted; pending secret promoted on verify; a valid code required to disable |
| Email verification | Enforced at login only when the `email_verification_required` platform setting is on (off in dev where email cannot send) |
| Throttling | Auth endpoints behind the middleware's per-IP limiter (429 + Retry-After) |
| Audit | Security events and item lifecycle (ids only) via `rt.audit`; encrypted at rest |

### Platform settings

Key/value platform config lives in `vault3_platform_setting` (`internal/database/platform_setting.go`), read through dedicated `(*Runtime)` accessors that **fail safe**: `PublicRegistrationEnabled` and `EmailSendingEnabled` default false, `EmailVerificationRequired` defaults false (the one gate where safe means not locking users out). Seeded by `scripts/sql/005.sql`. Never read or write the table ad hoc; the future admin console is the only intended writer.

---

## Notifications

All notifications run through one abstraction, `(*Runtime).Notify(ctx, event)` (`internal/runtime/notify.go`): handlers never decide who is told, over which channel, or against whose preferences. A handler builds a typed event (`Welcome`, `NewDeviceLogin`, `PasswordChanged`, `TwoFactorChanged`, `EmailVerification`, `AccountReset`) and calls `Notify` **after the triggering write commits**; the event expands into per-recipient planned notifications, and `Notify` consults `vault3_user.NotificationPrefs` per channel.

Channel gate: **in-app is always allowed** (the bell cannot be disabled); email is gated by the master toggle plus the kind's category toggle (`securityAlerts`, `productUpdates`), except the always-sent kinds (`alwaysEmailKinds`: welcome, verification, reset, password-changed) which bypass preferences. Preferences decode through `models.NotificationPrefs`, the same shape the settings page writes. In-app rows are FieldCipher-encrypted at rest.

### Email delivery (Mailgun)

`(*Runtime).SendTemplateEmail` (`internal/runtime/email.go`) renders a named template from `email_templates.go` (subject + branded HTML shell, server-side) and posts it to the Mailgun messages API. Two gates in order: the `email_sending_enabled` platform setting (off → info-log skip naming template/trigger/recipient), then the Mailgun credentials (empty → warn-log skip). Callers never branch on configuration. `frontendUrl`, `supportEmail`, `firstName`, `email` are injected into every render.

---

## Background job scheduler

Housekeeping runs in a **separate process**: `cmd/scheduler`, a second entry point that reuses the web server's Runtime via `runtime.StartWorker()` — identical to `Start()` except it never runs the dev schema sync (the web process owns schema application). Deploy as its own container; `start.sh` wires `vault3-scheduler` locally.

Job orchestration lives in `internal/jobs`: each job is a `func(ctx, rt) error` registered in `jobs.Run` with a name and interval; every job runs once on startup then on its interval, and drains on SIGINT/SIGTERM. **Jobs must be idempotent** — the WHERE clause is the claim. Current jobs: `purge_expired_sessions` (hourly), `purge_trashed_items` (daily, 30-day retention), `clear_expired_auth_tokens` (daily), `purge_lapsed_sharing` (daily; drops share links and invites a grace week after they expire, are revoked or are used). Job SQL lives in `internal/database/scheduler.go`. To add a job: query helper, job function, register in `jobs.Run`.

---

## Maintenance

Update this file only when a **convention** changes — a pattern, interface, layout rule, or architectural decision future code should follow. Shipping a feature that fits existing conventions needs no doc change; no per-handler inventories. Crypto-adjacent changes update [security.md](./security.md) first.
