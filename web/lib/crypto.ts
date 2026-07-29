// Vault3 client-side cryptography. Everything here runs in the browser via
// WebCrypto; none of the derived keys, the Master Password, or the Secret
// Phrase ever leave the device. The server-side contract (envelope shape,
// auth-key length, KDF floor) lives in internal/models/cipher_envelope.go
// and internal/config/constants.go — keep the two in step.
//
// Key hierarchy (docs/security.md draws the full picture):
//
//   Master Password ─┐
//                    ├─ 2SKD ─▶ MUK ─▶ encKey (wraps vault keys, private key)
//   Secret Phrase  ──┘              └─▶ authKey (sent to server, bcrypted)
//
//   vault key ─ wraps ─▶ item key ─ seals ─▶ overview / details blobs
//
// authKey and encKey are independent HKDF expansions of the MUK: possession
// of one reveals nothing about the other, so the server (which sees authKey)
// can never decrypt.

import { WORDLIST, isWord } from "./wordlist";

export type CipherEnvelope = {
  v: 1;
  alg: "A256GCM" | "RSA-OAEP-256";
  n: string;
  c: string;
};

export const KDF_DEFAULT_ITERATIONS = 650000;
export const SECRET_PHRASE_WORDS = 9;

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

// generateSecretPhrase draws 9 words uniformly from the 2048-word list with
// rejection-free sampling (2048 is a power of two, so a masked 11-bit draw
// is exactly uniform). ≈99 bits of entropy.
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
    { name: "HKDF", hash: "SHA-256", salt: salt as BufferSource, info: encoder.encode(info) },
    key,
    bytes * 8,
  );
  return new Uint8Array(bits);
}

async function pbkdf2(password: Uint8Array, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", password as BufferSource, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
    key,
    256,
  );
  return new Uint8Array(bits);
}

export type DerivedKeys = {
  // authKey is the only secret the server ever sees; it proves identity and
  // can derive nothing else.
  authKey: string;
  // encKeyRaw is the key-encryption key: it wraps vault keys and the private
  // key. Held in the tab's keystore while unlocked, never sent anywhere.
  encKeyRaw: Uint8Array;
};

// deriveKeys runs the two-secret derivation. Deliberately slow (PBKDF2 at
// the account's iteration count) — call it on explicit unlock, never in a
// loop.
export async function deriveKeys(
  email: string,
  masterPassword: string,
  secretPhrase: string,
  kdfSaltB64u: string,
  iterations: number,
): Promise<DerivedKeys> {
  const emailBytes = encoder.encode(email.trim().toLowerCase());
  const saltH = await hkdf(b64uDecode(kdfSaltB64u), emailBytes, "v3/2skd/salt");
  const passKey = await pbkdf2(encoder.encode(masterPassword.trim().normalize("NFKD")), saltH, iterations);
  const phraseKey = await hkdf(encoder.encode(normalizeSecretPhrase(secretPhrase)), emailBytes, "v3/2skd/secret-phrase");

  const muk = new Uint8Array(32);
  for (let i = 0; i < 32; i++) muk[i] = passKey[i] ^ phraseKey[i];

  const empty = new Uint8Array(0);
  const authKeyBytes = await hkdf(muk, empty, "v3/auth-key");
  const encKeyRaw = await hkdf(muk, empty, "v3/enc-key");
  muk.fill(0);
  passKey.fill(0);
  phraseKey.fill(0);

  return { authKey: b64uEncode(authKeyBytes), encKeyRaw };
}

// ── Symmetric envelopes (AES-256-GCM) ───────────────────────────────────────

async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function seal(keyRaw: Uint8Array, plaintext: Uint8Array): Promise<CipherEnvelope> {
  const key = await importAesKey(keyRaw);
  const nonce = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce as BufferSource }, key, plaintext as BufferSource);
  return { v: 1, alg: "A256GCM", n: b64uEncode(nonce), c: b64uEncode(new Uint8Array(ciphertext)) };
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

// ── Keypair (sharing runway) ────────────────────────────────────────────────

export type GeneratedKeypair = {
  algo: "rsa-oaep-2048";
  publicKeyJwk: JsonWebKey;
  encPrivateKey: CipherEnvelope;
};

// generateKeypair creates the account's RSA-OAEP keypair: public half stored
// in the clear (anyone may wrap TO it — the basis for shared vaults and
// share links later), private half sealed under the encKey.
export async function generateKeypair(encKeyRaw: Uint8Array): Promise<GeneratedKeypair> {
  const pair = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"],
  );
  const publicKeyJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const encPrivateKey = await seal(encKeyRaw, pkcs8);
  pkcs8.fill(0);
  return { algo: "rsa-oaep-2048", publicKeyJwk, encPrivateKey };
}

// ── Registration / recovery bundle ──────────────────────────────────────────

export type CryptoBundle = {
  // What the register / recover-confirm API receives.
  request: {
    authKey: string;
    kdfSalt: string;
    kdfIterations: number;
    keysAlgo: "rsa-oaep-2048";
    publicKey: JsonWebKey;
    encPrivateKey: CipherEnvelope;
    vault: { encName: CipherEnvelope; wrappedKey: CipherEnvelope };
  };
  // What the keystore holds for the fresh session.
  encKeyRaw: Uint8Array;
  vaultKeyRaw: Uint8Array;
};

// createCryptoBundle runs the full onboarding ceremony: derive, generate the
// keypair, mint the personal vault key, wrap everything.
export async function createCryptoBundle(
  email: string,
  masterPassword: string,
  secretPhrase: string,
  iterations = KDF_DEFAULT_ITERATIONS,
): Promise<CryptoBundle> {
  const kdfSalt = b64uEncode(randomBytes(16));
  const { authKey, encKeyRaw } = await deriveKeys(email, masterPassword, secretPhrase, kdfSalt, iterations);
  const keypair = await generateKeypair(encKeyRaw);
  const vaultKeyRaw = randomBytes(32);
  const wrappedKey = await seal(encKeyRaw, vaultKeyRaw);
  const encName = await sealJSON(vaultKeyRaw, { name: "Personal" });

  return {
    request: {
      authKey,
      kdfSalt,
      kdfIterations: iterations,
      keysAlgo: keypair.algo,
      publicKey: keypair.publicKeyJwk,
      encPrivateKey: keypair.encPrivateKey,
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

export function mintLinkKey(): Uint8Array {
  return randomBytes(32);
}

// composeLinkFragment builds the "#<token>.<key>" payload appended to a
// share or invite URL. Both halves stay out of server logs: the token is
// POSTed by the client, the key never leaves the browser at all.
export function composeLinkFragment(token: string, linkKeyRaw: Uint8Array): string {
  return `${token}.${b64uEncode(linkKeyRaw)}`;
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
// existing one), itself wrapped by the vault key. Per-item keys are what
// will let a future share link expose one item without the vault key.
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
