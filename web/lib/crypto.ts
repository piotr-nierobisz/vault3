// Vault3 client-side cryptography. Everything here runs in the browser; none
// of the derived keys, the Master Password, or the Secret Phrase ever leave
// the device. The server-side contract (envelope shape, auth-key length, KDF
// floors) lives in internal/models/cipher_envelope.go and
// internal/config/constants.go — keep the two in step.
//
// Key hierarchy (docs/security.md draws the full picture):
//
//   Master Password ─┐
//                    ├─ 2SKD ─▶ MUK ─▶ encKey (wraps vault keys)
//   Secret Phrase  ──┘              └─▶ authKey (sent to server, hashed)
//
//   vault key ─ wraps ─▶ item key ─ seals ─▶ overview / details blobs
//
// authKey and encKey are independent HKDF expansions of the MUK: possession
// of one reveals nothing about the other, so the server (which sees authKey)
// can never decrypt.
//
// ── On quantum resistance ───────────────────────────────────────────────────
//
// Every primitive below is symmetric or hash-based. That is the entire
// post-quantum story, and it is worth stating plainly because it is easy to
// assume something exotic is required:
//
//   * Shor's algorithm breaks factoring and discrete logs. Vault3 uses
//     neither — there is no RSA, no elliptic curve, no Diffie-Hellman
//     anywhere in the product. Nothing here is Shor-vulnerable, so nothing
//     recorded today becomes readable when a quantum computer arrives.
//   * Grover's algorithm costs a square root against everything else. So the
//     widths are chosen to survive it: AES-256 keeps 128 bits, SHA-512 keeps
//     256, and the 12-word Secret Phrase keeps 66 — each at or above NIST's
//     Category 1 bar, with the symmetric material far above it.
//
// The consequence is that no primitive here needs replacing later. That is
// why the account has no keypair: an asymmetric key would have been the one
// thing in the system with an expiry date on it.

import { argon2id } from "./argon2";
import { WORDLIST, isWord } from "./wordlist";

export type CipherEnvelope = {
  v: 2;
  alg: "A256GCM";
  n: string;
  c: string;
};

/**
 * A Secret Phrase is twelve words drawn from a 2048-word list: 132 bits.
 *
 * Nine words (99 bits) was the previous size and is the reason this constant
 * carries a comment. Against a classical attacker 99 bits is ample. Against a
 * quantum one, Grover halves the exponent — and 2^49.5 is not a number to
 * rest a vault on, particularly since the phrase is what has to hold when the
 * Master Password has already been phished. Twelve words puts the floor at
 * 2^66, past the AES-128 equivalent that NIST treats as the minimum
 * post-quantum security level.
 */
export const SECRET_PHRASE_WORDS = 12;

/**
 * KdfParams are the per-account cost settings. The server stores them, serves
 * them from /api/v1/auth/params before login, and the browser obeys whatever
 * it is handed — which is what allows the costs to be raised for everyone
 * later without stranding accounts registered under the old ones.
 */
export type KdfParams = {
  kdfSalt: string;
  kdfIterations: number;
  argon2MemoryKiB: number;
  argon2Time: number;
  argon2Lanes: number;
};

/** Mirrors the config.* defaults new registrations are issued with. */
export const KDF_DEFAULTS = {
  kdfIterations: 1000000,
  argon2MemoryKiB: 65536,
  argon2Time: 4,
  argon2Lanes: 4,
} as const;

/**
 * Stages a derivation passes through, in order. Emitted so the unlock screen
 * can say what is happening during the second or so this takes; see
 * web/components/ui/derivation-progress.tsx.
 */
export const DERIVATION_STAGES = ["preparing", "stretching", "hardening", "finishing"] as const;
export type DerivationStage = (typeof DERIVATION_STAGES)[number];
export type ProgressCallback = (stage: DerivationStage) => void;

// ── Encoding helpers ────────────────────────────────────────────────────────

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function b64uEncode(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(text: string): Uint8Array {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=");
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

// ── Secret Phrase ───────────────────────────────────────────────────────────

// generateSecretPhrase draws SECRET_PHRASE_WORDS words uniformly from the
// 2048-word list with rejection-free sampling (2048 is a power of two, so a
// masked 11-bit draw is exactly uniform). 11 bits per word.
export function generateSecretPhrase(): string {
  const words: string[] = [];
  const draws = new Uint16Array(SECRET_PHRASE_WORDS);
  crypto.getRandomValues(draws);
  for (let i = 0; i < SECRET_PHRASE_WORDS; i++) {
    words.push(WORDLIST[draws[i] & 2047]);
  }
  return words.join(" ");
}

export function normalizeSecretPhrase(phrase: string): string {
  return phrase.trim().toLowerCase().split(/[\s-]+/).filter(Boolean).join(" ");
}

// validateSecretPhrase flags structural problems early (wrong word count,
// words outside the list) so a typo fails at the form, not as a generic
// "wrong credentials" after a full derivation.
export function validateSecretPhrase(phrase: string): { ok: boolean; problem?: string } {
  const words = normalizeSecretPhrase(phrase).split(" ").filter(Boolean);
  if (words.length !== SECRET_PHRASE_WORDS) {
    return { ok: false, problem: `Your Secret Phrase has ${SECRET_PHRASE_WORDS} words (you entered ${words.length}).` };
  }
  const unknown = words.filter((w) => !isWord(w));
  if (unknown.length > 0) {
    return { ok: false, problem: `"${unknown[0]}" isn't a Secret Phrase word — check for a typo.` };
  }
  return { ok: true };
}

// ── Key derivation (2SKD) ───────────────────────────────────────────────────

async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: string, bytes = 32): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", ikm as BufferSource, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-512", salt: salt as BufferSource, info: encoder.encode(info) },
    key,
    bytes * 8,
  );
  return new Uint8Array(bits);
}

async function pbkdf2(password: Uint8Array, salt: Uint8Array, iterations: number, bytes = 64): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", password as BufferSource, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-512", salt: salt as BufferSource, iterations },
    key,
    bytes * 8,
  );
  return new Uint8Array(bits);
}

export type DerivedKeys = {
  // authKey is the only secret the server ever sees; it proves identity and
  // can derive nothing else.
  authKey: string;
  // encKeyRaw is the key-encryption key: it wraps vault keys. Held in the
  // tab's keystore while unlocked, never sent anywhere.
  encKeyRaw: Uint8Array;
};

/**
 * deriveKeys runs the two-secret derivation.
 *
 * The Master Password passes through two KDFs in series, which is a
 * deliberate belt-and-braces arrangement rather than indecision:
 *
 *   PBKDF2-HMAC-SHA-512 is FIPS-approved and implemented natively by
 *   WebCrypto. It is the floor — if the Argon2 wasm module were ever wrong,
 *   blocked, or unavailable, the password has still been through a million
 *   rounds of an approved KDF.
 *
 *   Argon2id then supplies the memory-hardness PBKDF2 structurally cannot.
 *   PBKDF2 is a chain of hashes and costs an attacker almost nothing in
 *   silicon area, so a GPU or ASIC runs it thousands of ways at once;
 *   Argon2id forces 64 MiB of random access per guess and prices that rig out
 *   of the attack.
 *
 * Composing them cannot weaken either: both are PRFs consuming the full
 * 512-bit intermediate, so the result is at least as strong as the stronger.
 *
 * The Secret Phrase takes the fast path on purpose. It is 132 bits of
 * uniform random with no guessing to slow down, so stretching it would only
 * add latency; the two halves are then XORed, which means an attacker needs
 * both regardless of how either was derived.
 *
 * Deliberately slow — call it on explicit unlock, never in a loop.
 */
export async function deriveKeys(
  email: string,
  masterPassword: string,
  secretPhrase: string,
  params: KdfParams,
  onProgress?: ProgressCallback,
): Promise<DerivedKeys> {
  onProgress?.("preparing");
  const emailBytes = encoder.encode(email.trim().toLowerCase());
  const accountSalt = b64uDecode(params.kdfSalt);
  // Two independent salts from the same account salt: reusing one value as
  // both the PBKDF2 and the Argon2id salt would tie the two layers together
  // for no benefit.
  const pbkdf2Salt = await hkdf(accountSalt, emailBytes, "v4/2skd/pbkdf2-salt");
  const argon2Salt = await hkdf(accountSalt, emailBytes, "v4/2skd/argon2-salt");

  onProgress?.("stretching");
  const stretched = await pbkdf2(
    encoder.encode(masterPassword.trim().normalize("NFKD")),
    pbkdf2Salt,
    params.kdfIterations,
  );

  onProgress?.("hardening");
  const passKey = await argon2id(stretched, argon2Salt, {
    time: params.argon2Time,
    memoryKiB: params.argon2MemoryKiB,
    lanes: params.argon2Lanes,
    outLen: 64,
  });
  stretched.fill(0);

  onProgress?.("finishing");
  const phraseKey = await hkdf(
    encoder.encode(normalizeSecretPhrase(secretPhrase)),
    emailBytes,
    "v4/2skd/secret-phrase",
    64,
  );

  const muk = new Uint8Array(64);
  for (let i = 0; i < 64; i++) muk[i] = passKey[i] ^ phraseKey[i];

  const empty = new Uint8Array(0);
  const authKeyBytes = await hkdf(muk, empty, "v4/auth-key", 64);
  const encKeyRaw = await hkdf(muk, empty, "v4/enc-key", 32);
  muk.fill(0);
  passKey.fill(0);
  phraseKey.fill(0);

  return { authKey: b64uEncode(authKeyBytes), encKeyRaw };
}

// ── Symmetric envelopes (AES-256-GCM) ───────────────────────────────────────
//
// AES-256 is the only cipher in the product and needs no successor: Grover
// reduces a 256-bit key search to 2^128 work that cannot be parallelised for
// speedup, which is precisely NIST's top post-quantum security category.

async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function seal(keyRaw: Uint8Array, plaintext: Uint8Array): Promise<CipherEnvelope> {
  const key = await importAesKey(keyRaw);
  const nonce = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce as BufferSource }, key, plaintext as BufferSource);
  return { v: 2, alg: "A256GCM", n: b64uEncode(nonce), c: b64uEncode(new Uint8Array(ciphertext)) };
}

// open reverses seal. A wrong key or tampered envelope rejects (GCM
// authentication failure) — callers treat that as "locked/invalid", never as
// empty data.
export async function open(keyRaw: Uint8Array, envelope: CipherEnvelope): Promise<Uint8Array> {
  const key = await importAesKey(keyRaw);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64uDecode(envelope.n) as BufferSource },
    key,
    b64uDecode(envelope.c) as BufferSource,
  );
  return new Uint8Array(plaintext);
}

export async function sealJSON(keyRaw: Uint8Array, value: unknown): Promise<CipherEnvelope> {
  return seal(keyRaw, encoder.encode(JSON.stringify(value)));
}

export async function openJSON<T>(keyRaw: Uint8Array, envelope: CipherEnvelope): Promise<T> {
  return JSON.parse(decoder.decode(await open(keyRaw, envelope))) as T;
}

// ── Registration bundle ─────────────────────────────────────────────────────

export type CryptoBundle = {
  // What the register API receives.
  request: {
    authKey: string;
    kdfSalt: string;
    kdfIterations: number;
    argon2MemoryKiB: number;
    argon2Time: number;
    argon2Lanes: number;
    vault: { encName: CipherEnvelope; wrappedKey: CipherEnvelope };
  };
  // What the keystore holds for the fresh session.
  encKeyRaw: Uint8Array;
  vaultKeyRaw: Uint8Array;
};

// createCryptoBundle runs the full onboarding ceremony: derive, mint the
// personal vault key, wrap everything.
export async function createCryptoBundle(
  email: string,
  masterPassword: string,
  secretPhrase: string,
  costs: Omit<KdfParams, "kdfSalt"> = KDF_DEFAULTS,
  onProgress?: ProgressCallback,
): Promise<CryptoBundle> {
  const kdfSalt = b64uEncode(randomBytes(16));
  const { authKey, encKeyRaw } = await deriveKeys(
    email,
    masterPassword,
    secretPhrase,
    { kdfSalt, ...costs },
    onProgress,
  );
  const vaultKeyRaw = randomBytes(32);
  const wrappedKey = await seal(encKeyRaw, vaultKeyRaw);
  const encName = await sealJSON(vaultKeyRaw, { name: "Personal" });

  return {
    request: {
      authKey,
      kdfSalt,
      kdfIterations: costs.kdfIterations,
      argon2MemoryKiB: costs.argon2MemoryKiB,
      argon2Time: costs.argon2Time,
      argon2Lanes: costs.argon2Lanes,
      vault: { encName, wrappedKey },
    },
    encKeyRaw,
    vaultKeyRaw,
  };
}

// ── Sharing (share links & vault invites) ───────────────────────────────────
//
// Both flows ride the same construction: a random 32-byte link key seals the
// thing being shared (an item key, a vault key), the server stores only that
// wrap plus a token hash, and the link key itself travels exclusively in the
// URL fragment — which browsers never send over the network. Anyone with the
// full link can decrypt; the server, holding everything else, cannot.
//
// That the construction is entirely symmetric is also why sharing needs no
// post-quantum migration: there is no wrapped-to-a-public-key ciphertext for
// a future quantum adversary to have harvested.

export function mintLinkKey(): Uint8Array {
  return randomBytes(32);
}

// composeLinkFragment builds the "#<token>.<key>" payload appended to a
// share or invite URL. Both halves stay out of server logs: the token is
// POSTed by the client, the key never leaves the browser at all.
export function composeLinkFragment(token: string, linkKeyRaw: Uint8Array): string {
  return `${token}.${b64uEncode(linkKeyRaw)}`;
}

// consumeLinkFragment reads the share/invite fragment from the current URL and
// then strips it, returning null when there is nothing usable there.
//
// Stripping matters as much as parsing. The fragment IS the decryption key —
// anyone holding the whole link can open what it shares — and a URL left
// intact lives on in the recipient's history, where browser sync uploads it to
// the vendor's servers and pushes it to every other device on that profile.
// The link stays redeemable until it expires (up to 30 days) or is revoked, so
// a key that was never supposed to leave the recipient's machine ends up
// somewhere neither party can reach to delete it. Removing it from the address
// bar the moment it has been read costs nothing: both callers keep everything
// they need in component state afterwards.
//
// The result is cached, so a second call (React invokes effects twice in
// development) returns the same fragment rather than finding the URL already
// clean and reporting a broken link.
let consumedFragment: { token: string; linkKeyRaw: Uint8Array } | null | undefined;

export function consumeLinkFragment(): { token: string; linkKeyRaw: Uint8Array } | null {
  if (consumedFragment === undefined) {
    consumedFragment = parseLinkFragment(window.location.hash);
    if (consumedFragment) {
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
    }
  }
  return consumedFragment;
}

// parseLinkFragment reverses composeLinkFragment from location.hash. Returns
// null for anything malformed rather than throwing.
export function parseLinkFragment(hash: string): { token: string; linkKeyRaw: Uint8Array } | null {
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  const dot = raw.indexOf(".");
  if (dot <= 0 || dot === raw.length - 1) return null;
  const token = raw.slice(0, dot);
  try {
    const linkKeyRaw = b64uDecode(raw.slice(dot + 1));
    if (linkKeyRaw.length !== 32) return null;
    return { token, linkKeyRaw };
  } catch {
    return null;
  }
}

// ── Vaults ──────────────────────────────────────────────────────────────────

export type VaultName = { name: string };

export type NewVaultBundle = {
  vaultKeyRaw: Uint8Array;
  wrappedKey: CipherEnvelope;
  encName: CipherEnvelope;
};

// createVaultBundle mints a fresh vault: random vault key wrapped under the
// account's key-encryption key, name sealed under the vault key (so future
// members can read it with the vault key alone).
export async function createVaultBundle(encKeyRaw: Uint8Array, name: string): Promise<NewVaultBundle> {
  const vaultKeyRaw = randomBytes(32);
  return {
    vaultKeyRaw,
    wrappedKey: await seal(encKeyRaw, vaultKeyRaw),
    encName: await sealJSON(vaultKeyRaw, { name } satisfies VaultName),
  };
}

export async function sealVaultName(vaultKeyRaw: Uint8Array, name: string): Promise<CipherEnvelope> {
  return sealJSON(vaultKeyRaw, { name } satisfies VaultName);
}

// ── Items ───────────────────────────────────────────────────────────────────

export type ItemOverview = {
  title: string;
  category: string;
  subtitle?: string;
  urls?: string[];
  favorite?: boolean;
  tags?: string[];
};

export type ItemDetails = {
  fields: Record<string, string>;
  notes?: string;
};

export type SealedItem = {
  wrappedItemKey: CipherEnvelope;
  overview: CipherEnvelope;
  details: CipherEnvelope;
};

// sealItem seals both blobs under a per-item key (fresh unless reusing an
// existing one), itself wrapped by the vault key. Per-item keys are what let a
// share link expose one item without the vault key.
export async function sealItem(
  vaultKeyRaw: Uint8Array,
  overview: ItemOverview,
  details: ItemDetails,
  existingItemKeyRaw?: Uint8Array,
): Promise<SealedItem> {
  const itemKeyRaw = existingItemKeyRaw ?? randomBytes(32);
  return {
    wrappedItemKey: await seal(vaultKeyRaw, itemKeyRaw),
    overview: await sealJSON(itemKeyRaw, overview),
    details: await sealJSON(itemKeyRaw, details),
  };
}

export async function unwrapItemKey(vaultKeyRaw: Uint8Array, wrappedItemKey: CipherEnvelope): Promise<Uint8Array> {
  return open(vaultKeyRaw, wrappedItemKey);
}
