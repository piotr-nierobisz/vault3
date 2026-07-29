// RFC 6238 one-time codes, computed in the browser and nowhere else.
//
// A TOTP seed stored on a vault item is vault data: it rides in the item's
// sealed details blob exactly like a password, so the server holds ciphertext
// and could not derive a code if it wanted to. That is the whole point — a
// "compute this code for me" endpoint would hand the server the seed and
// break the invariant in docs/security.md. Everything here is offline maths
// over WebCrypto's HMAC.
//
// (The account 2FA secret in Settings is a different thing entirely: the
// server mints and validates that one, so it lives server-side under
// FieldCipher. Do not route it through here.)

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Every A–Z2–7 string decodes, so a mistyped word is a "valid" seed on
// characters alone. Real seeds are at least 16 base32 characters (the 80-bit
// Google Authenticator shape; RFC 4226 asks for 128 bits and most issuers
// give 160), so anything shorter is a paste error, not a secret.
const MIN_SECRET_BYTES = 10;

export type TotpAlgorithm = "SHA-1" | "SHA-256" | "SHA-512";

export type TotpConfig = {
  secret: Uint8Array;
  digits: number;
  period: number;
  algorithm: TotpAlgorithm;
  issuer?: string;
  account?: string;
};

// base32Decode accepts what authenticator sites actually print: mixed case,
// space- or hyphen-grouped, padded or not. Returns null on any character
// outside the alphabet rather than silently decoding garbage.
function base32Decode(input: string): Uint8Array | null {
  const clean = input.toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "");
  if (!clean) return null;

  const out: number[] = [];
  let value = 0;
  let bits = 0;
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index < 0) return null;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return out.length >= MIN_SECRET_BYTES ? new Uint8Array(out) : null;
}

function normalizeAlgorithm(raw: string | null): TotpAlgorithm | null {
  switch ((raw ?? "SHA1").toUpperCase().replace("-", "")) {
    case "SHA1":
      return "SHA-1";
    case "SHA256":
      return "SHA-256";
    case "SHA512":
      return "SHA-512";
    default:
      return null;
  }
}

function parseOtpauthUri(text: string): TotpConfig | null {
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return null;
  }
  // HOTP is counter-based: there is no "current" code to show, so a seed we
  // cannot render live is rejected at the door rather than stored broken.
  if (url.protocol !== "otpauth:" || url.host.toLowerCase() !== "totp") return null;

  const secret = base32Decode(url.searchParams.get("secret") ?? "");
  if (!secret) return null;

  const algorithm = normalizeAlgorithm(url.searchParams.get("algorithm"));
  if (!algorithm) return null;

  const digits = Number(url.searchParams.get("digits") ?? 6);
  if (!Number.isInteger(digits) || digits < 6 || digits > 10) return null;

  const period = Number(url.searchParams.get("period") ?? 30);
  if (!Number.isInteger(period) || period < 1 || period > 300) return null;

  // Label is "Issuer:account" or just "account"; the issuer query parameter
  // wins when both are present, per the Key URI format.
  const label = decodeURIComponent(url.pathname.replace(/^\//, ""));
  const separator = label.indexOf(":");
  const issuer = url.searchParams.get("issuer") ?? (separator > 0 ? label.slice(0, separator) : "");
  const account = separator > 0 ? label.slice(separator + 1) : label;

  return {
    secret,
    digits,
    period,
    algorithm,
    issuer: issuer.trim() || undefined,
    account: account.trim() || undefined,
  };
}

// parseTotp reads either a full otpauth:// URI or a bare base32 seed. Bare
// seeds take the RFC defaults (6 digits, 30s, SHA-1) — which is what a site
// printing a naked setup key means by it.
export function parseTotp(raw: string): TotpConfig | null {
  const text = raw.trim();
  if (!text) return null;
  if (/^otpauth:/i.test(text)) return parseOtpauthUri(text);

  const secret = base32Decode(text);
  return secret ? { secret, digits: 6, period: 30, algorithm: "SHA-1" } : null;
}

// normalizeTotpInput returns the string to seal into the item, or null if the
// input is not a usable seed. A pasted URI is kept whole so non-default
// digits/period/algorithm survive the round trip; a bare seed is stored
// stripped and upper-cased.
export function normalizeTotpInput(raw: string): string | null {
  const text = raw.trim();
  if (!parseTotp(text)) return null;
  if (/^otpauth:/i.test(text)) return text;
  return text.toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "");
}

// totpCode computes the code for the window containing atMs. The counter is
// written big-endian across 8 bytes via division rather than bit shifts,
// which would wrap at 32 bits.
export async function totpCode(config: TotpConfig, atMs: number): Promise<string> {
  const counter = new Uint8Array(8);
  let remaining = Math.floor(atMs / 1000 / config.period);
  for (let i = 7; i >= 0; i--) {
    counter[i] = remaining & 0xff;
    remaining = Math.floor(remaining / 256);
  }

  const key = await crypto.subtle.importKey(
    "raw",
    config.secret as BufferSource,
    { name: "HMAC", hash: config.algorithm },
    false,
    ["sign"],
  );
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter as BufferSource));

  // Dynamic truncation (RFC 4226 §5.4).
  const offset = mac[mac.length - 1] & 0x0f;
  const truncated =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);

  return String(truncated % 10 ** config.digits).padStart(config.digits, "0");
}

// totpRemaining is the seconds left in the current window — the countdown the
// detail pane renders. Both this and totpCode read the device clock: a badly
// skewed clock yields codes the far side rejects, and there is no server time
// to fall back on that would not leak the window we are in.
export function totpRemaining(config: TotpConfig, atMs: number): number {
  return config.period - (Math.floor(atMs / 1000) % config.period);
}

// formatTotpCode groups a code for reading ("123 456"); copy always uses the
// ungrouped value.
export function formatTotpCode(code: string): string {
  const half = Math.ceil(code.length / 2);
  return `${code.slice(0, half)} ${code.slice(half)}`;
}
