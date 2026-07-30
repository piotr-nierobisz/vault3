# Vault3 Security Architecture

The cryptography is the product. This document is the canonical description of the key hierarchy, the wire formats, and the invariants that must survive every future change. If a task would alter anything in here, treat it as a breaking migration question **before** writing code.

For agent routing see [claude.md](../claude.md). Implementation lives in `web/lib/crypto.ts` (client), `internal/crypto` (server-side field encryption), and the auth handlers in `internal/runtime`.

---

## The invariant

**The server must never be able to decrypt vault data.** Not via a code path, not via logging, not via a debug endpoint. The Master Password, the Secret Phrase, the MUK, the encryption key, vault keys, item keys, and any plaintext of a vault item exist only in the browser. Anything that would move one of them server-side — "for search", "for support", "temporarily" — is a product change of the highest order, not an implementation detail.

## Key hierarchy (2SKD)

```text
Master Password (head)              Secret Phrase (Emergency Kit, 12 words = 132 bits)
        │                                   │
        │  PBKDF2-HMAC-SHA-512              │  HKDF-SHA-512
        │  1,000,000 rounds                 │  salt = email
        │  salt = HKDF(account salt,        │  info = "v4/2skd/secret-phrase"
        │         info="v4/2skd/pbkdf2-salt")│
        ▼                                   │
   stretched (64B)                          │
        │  Argon2id                         │
        │  64 MiB · 4 passes · 4 lanes      │
        │  salt = HKDF(account salt,        │
        │         info="v4/2skd/argon2-salt")│
        ▼                                   ▼
     passKey (64B)  ──────────XOR────────  phraseKey (64B)
                        │
                        ▼
              MUK — master unlock key (64B, never leaves the derivation scope)
                │
                ├── HKDF(info="v4/auth-key") ─▶ authKey (64B) → server, Argon2id-stored
                └── HKDF(info="v4/enc-key")  ─▶ encKey (32B)  → never transmitted
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

- **authKey and encKey are independent HKDF expansions**: the server-held authKey (or its Argon2id hash, or a full DB dump) yields nothing about encKey.
- **Two-secret derivation**: a phished Master Password without the Secret Phrase — or a photographed Emergency Kit without the password — decrypts nothing.
- **Per-item keys** are what make share links possible: sharing one item re-wraps one item key, never the vault key.
- **Two KDFs in series on the password.** PBKDF2-HMAC-SHA-512 is the FIPS-approved floor and is implemented natively by WebCrypto; Argon2id over its output adds the memory-hardness PBKDF2 structurally cannot, which is what prices GPU and ASIC cracking rigs out of a stolen database. Composing them cannot weaken either — both are PRFs over the full 512-bit intermediate — and if the Argon2 module were ever unavailable or wrong, the password has still been through a million rounds of an approved KDF.
- **The Secret Phrase takes the fast path deliberately.** It is 132 bits of uniform random with no guessing to slow down, so stretching it would buy nothing but latency.

**Cost parameters are stored per account** (`vault3_user_auth`) and served by `/api/v1/auth/params`, so every cost above can be raised platform-wide without stranding existing accounts; an account adopts the new profile the next time its Master Password changes.

## Post-quantum posture

Vault3 is quantum-resistant by construction rather than by migration, and the reasoning is short enough to state completely:

- **Nothing here is vulnerable to Shor's algorithm.** There is no RSA, no elliptic curve, no Diffie-Hellman anywhere in the product — no keypair on an account, and no ciphertext ever wrapped to a public key. Harvest-now-decrypt-later has nothing to harvest.
- **Everything is sized for Grover's algorithm**, which costs a square root and nothing better. AES-256 retains 128 bits (NIST PQ Category 5), SHA-512 retains 256, and the 12-word Secret Phrase retains 66 — above the 2⁶⁴ that defines Category 1.

A per-account **RSA-OAEP-2048 keypair used to exist** as runway for wrapping vault keys to another user's public key. It was never used — sharing shipped on the symmetric link-fragment construction below — so it was deleted rather than replaced (`scripts/sql/008.sql`). Reintroducing any asymmetric primitive means introducing the first thing in Vault3 with an expiry date on it; if server-mediated sharing is ever wanted, it must be ML-KEM (FIPS 203) from the start, decided **before** a single wrap is written, because retrofitting means re-keying every user.

The one thing the widths above do *not* cover is a Master Password weak enough to be guessed outright; that is what the two KDFs are for, and it is why the phrase exists as a second factor.

## Sharing (share links and vault invites)

Both sharing flows use one construction: a random 32-byte **link key** minted in the sender's browser seals the key being shared, and the link key travels only in the URL fragment (`/share#<token>.<key>`, `/app/invite#<token>.<key>`). Browsers never transmit fragments, so the server stores the wrap plus a SHA-256 hash of the opaque token — enough to authorise, expire and revoke redemption, never enough to decrypt.

The recipient's client reads that fragment through `consumeLinkFragment`, which **strips it from the URL** once read. Keeping it out of the server's reach is only half the job: a fragment left in the address bar persists in browser history, where profile sync uploads the full URL to the browser vendor and replicates it to every other device on that profile, and the link stays redeemable until it expires or is revoked. Parse it once, carry it in memory, remove it from the URL.

- **Share links** (`vault3_share_link`): the item's per-item key sealed under the link key. Redemption (`POST /api/v1/share/open`, public) returns that wrap plus the item's live ciphertext blobs; the fragment key opens everything client-side. Owner-only to create (capped per item, expiry clamped to 30 days), revocable, dead on trashed items; missing/expired/revoked collapse into one 404.
- **Vault invites** (`vault3_vault_invite`): the vault key sealed under the link key. Single-use and 7-day-limited; the signed-in acceptor opens the vault key with the fragment secret, re-wraps it under **their own encKey**, and the server inserts the `vault3_vault_access` row (`role='member'`, `WrapAlgo='muk'`) in the same transaction that atomically claims the invite. Members are read-only: item and vault mutations require the `owner` role server-side.

Because every stored vault wrap stays `muk`, a Master Password change re-wraps a member's access rows exactly like the owner's — no asymmetric special case. That re-wrap must cover the account's vaults **exactly once each**, verified as a set rather than a count: a vault omitted from the submitted set keeps a key sealed under the superseded MUK, and since the server holds no key material it could never re-wrap it, so the contents would be lost for good.

The invariant holds throughout: anyone holding the full link can decrypt what it shares; the server, holding everything else, cannot.

Normalisation (must stay bit-identical forever): email lowercased+trimmed; password trimmed + NFKD; phrase lowercased, split on whitespace/hyphens, single-space joined.

## The envelope format

Every encrypted JSONB column stores one `CipherEnvelope`:

```json
{"v":2, "alg":"A256GCM", "n":"<base64url 12-byte nonce>", "c":"<base64url ciphertext+tag>"}
```

`alg` is `A256GCM` and there is no other value: with the keypair gone, every wrap and every seal in the product is symmetric. The server validates shape and size only (`models.ValidateCipherEnvelope`); it cannot validate content.

Version 1 was the pre-quantum format, identical but for also permitting `RSA-OAEP-256`. Bumping to `v:2` rather than quietly narrowing v1's meaning is the rule: a version number means what it always meant. Further version bumps are how the format evolves — never mutate the meaning of an existing one.

## Authentication flow

1. `POST /api/v1/auth/params {email}` → `{kdfSalt, kdfIterations, argon2MemoryKiB, argon2Time, argon2Lanes}`. Unknown emails receive **deterministic decoy parameters** (HMAC of the address under the server key, costs set to the current platform defaults) so existence never leaks.
2. Browser derives authKey + encKey (the slow part, by design — around a second, surfaced by the progress UI rather than hidden).
3. `POST /api/v1/auth/login {email, authKey, code?}` → Argon2id compare, optional TOTP challenge, session cookie. Every failure returns the same generic 401.
4. Unlock correctness is proven **locally**: unwrapping a vault key either succeeds or fails GCM authentication. The server never learns whether a decryption worked.

Sessions: 512-bit opaque tokens, stored only as SHA-512 hashes, HttpOnly/SameSite=Lax/Secure-in-prod cookies, 30-day expiry, revocable per device. A Master Password change revokes every other session in the same transaction that swaps the wrapped keys.

## Client key custody (deliberate trade-offs)

- **sessionStorage** holds the unlocked keys per tab (survives BunGo full-page navigations, dies with the tab). An inactivity auto-lock (default 15 min) and the Lock button wipe it; locking never waits on the network.
- **localStorage** remembers email + Secret Phrase on a trusted device (the 1Password pattern), so routine unlocks need only the Master Password. Clearing it detaches the device.
- XSS is the residual risk this accepts, mitigated by the strict CSP, no third-party scripts, and React's escaping. An attacker who can run script in the page can use the keys while it is unlocked — true of every web-based vault; the design goal is that *the server* is never such an attacker.

## There is no recovery

**Vault3 has no account recovery, password reset, or "erase and start over" flow, and must never grow one.** The server holds only ciphertext, so a lost Master Password or Secret Phrase is unrecoverable by construction — not by policy. `/security` and the terms of service state this plainly, and the Emergency Kit (saved during a mandatory onboarding step) is the user's only way back in.

An account-reset flow used to exist: an emailed single-use token that deleted every owned vault and re-ran the onboarding ceremony. It was removed. Nothing about it was cryptographically unsound, but it contradicted the promise the product makes on its own marketing and legal pages ("we cannot reset them, recover them, or decrypt your vault"), and a credential-replacing endpoint reachable from an inbox is a standing takeover surface for a product whose whole claim is that possessing the server buys you nothing. A user who has lost their secrets deletes the account and starts fresh; that path already exists in the settings danger zone and is re-authenticated by the current auth key.

If a future task proposes reinstating any of this, treat it as a product change of the highest order, not an implementation detail.

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

The few operational fields the server must read back are AES-256-GCM encrypted under `SERVER_ENCRYPTION_KEY_STRING` (stored form `v1:base64url(nonce||ct)`): display names, session IP/UA, TOTP secrets, notification title/body, audit detail. `FieldCipher.Blind` (keyed HMAC-SHA-512) provides deterministic equality for the one query that needs it (new-device IP matching) without readable storage. This layer is defence in depth for *operational* data — it is unrelated to vault data and must never be presented as the zero-knowledge story.

## The Argon2id module (`web/static/argon2*.js`, `internal/wasm/argon2`)

Argon2id runs as WebAssembly because memory-hardness is exactly what JavaScript engines are worst at: a pure-JS implementation costs roughly an order of magnitude over native, and the only way to buy that back is to lower the parameters on the honest user's device while the attacker's rig pays nothing.

The module is compiled **from Go, in this repository**, wrapping the same `golang.org/x/crypto/argon2` the server uses to hash auth keys. That is a deliberate choice over vendoring a C or Rust build: it needs no toolchain beyond the one this project already requires, and one implementation serving both targets means a divergence between what the browser derives and what the server verifies is not expressible.

Three things make the binary trustworthy rather than merely present, and all three matter:

- **Reproducible.** `scripts/build-wasm.sh` pins the Go version and passes `-trimpath -buildvcs=false`, so the artifact is byte-identical on any machine. The digest is something a reader of this open-source repo can regenerate, not a number to take on faith.
- **Pinned.** `web/lib/argon2-manifest.ts` carries a SHA-512 of the artifact, generated by that script. The loader hashes the fetched bytes and **refuses to instantiate on any mismatch** — it fails closed rather than falling back to a weaker derivation, because silently deriving a key some other way is how a vault ends up encrypted under something its owner cannot reproduce.
- **Verified against known answers.** `scripts/verify-wasm.mjs` runs the compiled module against vectors generated by Go's own Argon2 (`internal/crypto/testdata/argon2_vectors.json`), including one at the exact production costs; `TestArgon2IDKnownAnswers` asserts the Go side still produces the same vectors. A digest only proves the bytes are the intended bytes — the KAT is what rules out a module that loads cleanly and derives the wrong key.

Be precise about what the pin defends against: **transport and storage, not the server.** A poisoned cache, a compromised CDN or object store, a corrupted download, a stale artifact from a bad deploy — all caught. A malicious server is *not*, because the same server ships the pin. That is the residual risk this document already names for all of the app's JavaScript, and it is precisely why the digest is reproducible from source.

The CSP gains `'wasm-unsafe-eval'` for this, and the name invites misreading: it permits **only** WebAssembly compilation, not `eval()` or `new Function()`. It exists as a separate keyword so a page can compile wasm without the far broader `'unsafe-eval'`. No new host appears in any directive.

Derivation runs in a **Web Worker, one per derivation**, for two reasons: the main thread stays responsive so the progress UI can animate rather than the tab appearing frozen, and a wasm instance's linear memory only ever grows — so a terminated worker returns the 64 MiB arena, and every password-derived Argon2 block in it, to the OS instead of holding it for the life of the tab.

## Transport and abuse

- Middleware (in `internal/runtime/middleware.go`, wrapped around the BunGo handler by `cmd/vault3/main.go`) sets CSP, frame denial, nosniff, referrer policy, HSTS in production.
- The CSP names no third-party host in any directive, and must not grow one: every dependency is compiled in or self-hosted, so a CDN allowance would only ever serve as a script source and exfiltration channel for an injected payload.
- State-changing requests are rejected when `Sec-Fetch-Site`/`Origin` show another site — defence in depth behind the cookie's `SameSite=Lax`. Requests with neither header are not browser-driven and cannot carry ambient cookies, so they pass.
- The production session cookie is `__Host-` prefixed (browser-enforced Secure + `Path=/` + no `Domain`), so no sibling subdomain or plain-http origin can plant or overwrite it. Dev keeps the bare name because `Secure` is impossible over plain HTTP.
- Per-IP throttling of the auth endpoints is the **reverse proxy's** job, not the app's: an in-process counter keyed on the socket address collapses to a single platform-wide bucket once traffic arrives via a proxy. Do not reintroduce it in Go.
- All auth responses are enumeration-safe: neutral resend messages, decoy KDF parameters, one generic login error.
- **TLS key exchange is the reverse proxy's job, and it is the one remaining place a quantum adversary has any purchase.** Nothing stored is at risk, but a recorded TLS session whose key exchange was classical (X25519, P-256) could be opened later, exposing the traffic — which for this app is ciphertext and an auth key, not vault contents. Terminate TLS with hybrid `X25519MLKEM768` where the proxy supports it.

## Threat model summary

| Adversary | Outcome |
|---|---|
| Full database theft | Ciphertext, Argon2id(authKey), token hashes, FieldCipher blobs. No vault content. |
| Adversary with a quantum computer | Nothing to break with Shor (no asymmetric primitives exist); Grover leaves ≥128 bits everywhere. Ciphertext harvested today stays unreadable. |
| Malicious/compelled server operator | Can serve poisoned JS (the web-app residual risk, mitigated by CSP and future extension/desktop clients with pinned code); cannot decrypt stored data. |
| Network attacker | TLS + HSTS; cookies never over plain HTTP in production. |
| Stolen device, vault locked | Needs Master Password (and phrase, if not remembered on device). |
| Compromised endpoint while unlocked | Out of scope — no web vault survives malware on the user's machine. Said honestly on /security. |

## Change checklist

Any PR touching this file's subject matter must answer:

1. Do existing accounts still unlock (KDF inputs, normalisation, info strings, envelope parsing unchanged)?
2. Does any plaintext or key material newly cross the network or reach a log?
3. Is the change expressible as a new envelope/algo version rather than a mutation of the current one?
4. **Does it introduce an asymmetric primitive?** If so, stop: that is the one thing in Vault3 with an expiry date under a quantum adversary, and it needs a deliberate decision (ML-KEM from the start, before any wrap is written) rather than an implementation choice.
5. If it changes Argon2 costs, does `internal/crypto/testdata/argon2_vectors.json` gain a vector at the new parameters, and does `scripts/verify-wasm.mjs` still pass?
6. Do the /security page and this document still tell the truth?
