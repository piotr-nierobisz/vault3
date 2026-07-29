# Vault3 Security Architecture

The cryptography is the product. This document is the canonical description of the key hierarchy, the wire formats, and the invariants that must survive every future change. If a task would alter anything in here, treat it as a breaking migration question **before** writing code.

For agent routing see [claude.md](../claude.md). Implementation lives in `web/lib/crypto.ts` (client), `internal/crypto` (server-side field encryption), and the auth handlers in `internal/runtime`.

---

## The invariant

**The server must never be able to decrypt vault data.** Not via a code path, not via logging, not via a debug endpoint. The Master Password, the Secret Phrase, the MUK, the encryption key, vault keys, item keys, and any plaintext of a vault item exist only in the browser. Anything that would move one of them server-side — "for search", "for support", "temporarily" — is a product change of the highest order, not an implementation detail.

## Key hierarchy (2SKD)

```text
Master Password (head)        Secret Phrase (Emergency Kit, 9 words ≈ 99 bits)
        │                             │
        │  PBKDF2-SHA256              │  HKDF-SHA256
        │  650,000 rounds             │  salt = email
        │  salt = HKDF(account salt,  │  info = "v3/2skd/secret-phrase"
        │         salt=email,         │
        │         info="v3/2skd/salt")│
        ▼                             ▼
     passKey (32B)  ──────XOR──────  phraseKey (32B)
                        │
                        ▼
              MUK — master unlock key (32B, never leaves the derivation scope)
                │
                ├── HKDF(info="v3/auth-key") ─▶ authKey  → sent to server, bcrypt-stored
                └── HKDF(info="v3/enc-key")  ─▶ encKey   → never transmitted
                                                  │ wraps
                                                  ▼
                                          vault key (32B random)
                                                  │ wraps
                                                  ▼
                                          item key (32B random, per item)
                                                  │ seals (AES-256-GCM)
                                                  ▼
                                   overview blob  +  details blob
```

Properties this buys:

- **authKey and encKey are independent HKDF expansions**: the server-held authKey (or its bcrypt hash, or a full DB dump) yields nothing about encKey.
- **Two-secret derivation**: a phished Master Password without the Secret Phrase — or a photographed Emergency Kit without the password — decrypts nothing.
- **Per-item keys** are what make share links possible: sharing one item re-wraps one item key, never the vault key.
- **The RSA-OAEP-2048 keypair** (public key plaintext, private key sealed under encKey) remains unused runway: sharing shipped on the link-fragment construction below instead, which kept every stored wrap symmetric.

## Sharing (share links and vault invites)

Both sharing flows use one construction: a random 32-byte **link key** minted in the sender's browser seals the key being shared, and the link key travels only in the URL fragment (`/share#<token>.<key>`, `/app/invite#<token>.<key>`). Browsers never transmit fragments, so the server stores the wrap plus a SHA-256 hash of the opaque token — enough to authorise, expire and revoke redemption, never enough to decrypt.

- **Share links** (`vault3_share_link`): the item's per-item key sealed under the link key. Redemption (`POST /api/v1/share/open`, public, throttled) returns that wrap plus the item's live ciphertext blobs; the fragment key opens everything client-side. Owner-only to create (capped per item, expiry clamped to 30 days), revocable, dead on trashed items; missing/expired/revoked collapse into one 404.
- **Vault invites** (`vault3_vault_invite`): the vault key sealed under the link key. Single-use and 7-day-limited; the signed-in acceptor opens the vault key with the fragment secret, re-wraps it under **their own encKey**, and the server inserts the `vault3_vault_access` row (`role='member'`, `WrapAlgo='muk'`) in the same transaction that atomically claims the invite. Members are read-only: item and vault mutations require the `owner` role server-side.

Because every stored vault wrap stays `muk`, a Master Password change re-wraps a member's access rows exactly like the owner's — no asymmetric special case. A zero-knowledge account reset deletes the user's memberships along with their owned vaults: those wraps were sealed under the old encKey and are permanently opaque afterwards.

The invariant holds throughout: anyone holding the full link can decrypt what it shares; the server, holding everything else, cannot.

Normalisation (must stay bit-identical forever): email lowercased+trimmed; password trimmed + NFKD; phrase lowercased, split on whitespace/hyphens, single-space joined.

## The envelope format

Every encrypted JSONB column stores one `CipherEnvelope`:

```json
{"v":1, "alg":"A256GCM", "n":"<base64url 12-byte nonce>", "c":"<base64url ciphertext+tag>"}
```

`alg` is `A256GCM` (symmetric seals/wraps) or `RSA-OAEP-256` (future public-key wraps, no nonce). The server validates shape and size only (`models.ValidateCipherEnvelope`); it cannot validate content. Version bumps (`v:2`) are how the format evolves — never mutate the meaning of `v:1`.

## Authentication flow

1. `POST /api/v1/auth/params {email}` → `{kdfSalt, kdfIterations}`. Unknown emails receive **deterministic decoy parameters** (HMAC of the address under the server key) so existence never leaks.
2. Browser derives authKey + encKey (the slow part, by design).
3. `POST /api/v1/auth/login {email, authKey, code?}` → bcrypt compare, optional TOTP challenge, session cookie. Every failure returns the same generic 401.
4. Unlock correctness is proven **locally**: unwrapping a vault key either succeeds or fails GCM authentication. The server never learns whether a decryption worked.

Sessions: 256-bit opaque tokens, stored only as SHA-256 hashes, HttpOnly/SameSite=Lax/Secure-in-prod cookies, 30-day expiry, revocable per device. A Master Password change revokes every other session in the same transaction that swaps the wrapped keys.

## Client key custody (deliberate trade-offs)

- **sessionStorage** holds the unlocked keys per tab (survives BunGo full-page navigations, dies with the tab). An inactivity auto-lock (default 15 min) and the Lock button wipe it; locking never waits on the network.
- **localStorage** remembers email + Secret Phrase on a trusted device (the 1Password pattern), so routine unlocks need only the Master Password. Clearing it detaches the device.
- XSS is the residual risk this accepts, mitigated by the strict CSP, no third-party scripts, and React's escaping. An attacker who can run script in the page can use the keys while it is unlocked — true of every web-based vault; the design goal is that *the server* is never such an attacker.

## Recovery = reset

There is no password reset that preserves data. `/recover` emails a single-use, one-hour token; redeeming it **deletes every owned vault**, installs fresh credentials/keypair/vault from a new client-side ceremony, and revokes all sessions. The UI states the consequence in unmissable terms and requires typed confirmation. This is not a UX failure to soften — it is the proof the encryption is real.

## Two kinds of TOTP secret — never conflate them

Vault3 handles one-time-code seeds in two places under opposite rules. Any change here must keep them apart:

| | **Account 2FA** (Settings) | **Item one-time codes** (a login item's `totp` field) |
|---|---|---|
| Who mints it | The server (`pquerna/otp`) | The site the user is enrolling with; pasted into the browser |
| Where it lives | `vault3_user_auth`, encrypted under `FieldCipher` | Inside the item's sealed `details` blob, like the password |
| Who computes codes | The server, to validate a sign-in | The browser only (`web/lib/totp.ts`, WebCrypto HMAC) |
| What the server can read | The seed — necessarily | Ciphertext, and nothing more |

The account secret is operational data: the server *must* read it to check a login code, and the setup QR merely renders the `otpauth://` URL it already returns. The item seed is vault data and falls under the invariant in full. **There must never be an endpoint that computes an item's code**, however convenient — that would hand the server the seed and defeat the point of storing it here.

Two consequences the product owns rather than hides: a vault holding both an account's password and its seed collapses two factors into one, and a share link — which exposes the live `details` blob — carries the seed with it. The item form and the share dialog both say so.

## Server-side encryption at rest (`internal/crypto.FieldCipher`)

The few operational fields the server must read back are AES-256-GCM encrypted under `SERVER_ENCRYPTION_KEY_STRING` (stored form `v1:base64url(nonce||ct)`): display names, session IP/UA, TOTP secrets, notification title/body, audit detail. `FieldCipher.Blind` (keyed HMAC) provides deterministic equality for the one query that needs it (new-device IP matching) without readable storage. This layer is defence in depth for *operational* data — it is unrelated to vault data and must never be presented as the zero-knowledge story.

## Transport and abuse

- Middleware (in `internal/runtime/middleware.go`, wrapped around the BunGo handler by `cmd/vault3/main.go`) sets CSP, frame denial, nosniff, referrer policy, HSTS in production.
- Auth endpoints share a strict per-IP throttle returning proper 429s.
- All auth responses are enumeration-safe: neutral resend/recover messages, decoy KDF parameters, one generic login error.

## Threat model summary

| Adversary | Outcome |
|---|---|
| Full database theft | Ciphertext, bcrypt(authKey), token hashes, FieldCipher blobs. No vault content. |
| Malicious/compelled server operator | Can serve poisoned JS (the web-app residual risk, mitigated by CSP and future extension/desktop clients with pinned code); cannot decrypt stored data. |
| Network attacker | TLS + HSTS; cookies never over plain HTTP in production. |
| Stolen device, vault locked | Needs Master Password (and phrase, if not remembered on device). |
| Compromised endpoint while unlocked | Out of scope — no web vault survives malware on the user's machine. Said honestly on /security. |

## Change checklist

Any PR touching this file's subject matter must answer:

1. Do existing accounts still unlock (KDF inputs, normalisation, info strings, envelope parsing unchanged)?
2. Does any plaintext or key material newly cross the network or reach a log?
3. Is the change expressible as a new envelope/algo version rather than a mutation of the current one?
4. Do the /security page and this document still tell the truth?
