// The tab's key store: where derived keys live while the vault is unlocked.
//
// Storage model (a deliberate, documented trade-off — see docs/security.md):
//   - sessionStorage holds the unlocked keys (encKey + vault keys, base64).
//     Scoped per tab, gone when the tab closes, survives reloads so every
//     BunGo full-page navigation doesn't demand the Master Password again.
//   - localStorage remembers the sign-in identity (email + Secret Phrase) on
//     this device — the 1Password "trusted device" pattern — so routine
//     unlocks need only the Master Password. Clearing it detaches the device.
//   - An inactivity auto-lock wipes the keys after AUTO_LOCK_MS without user
//     input; "Lock now" does the same immediately. Locking is local-only and
//     never waits on the network.

import { b64uEncode, b64uDecode } from "./crypto";

const KEYS_KEY = "v3.keys";
const CLIENT_KEY = "v3.client";
const IDENTITY_KEY = "v3.identity";
const ACTIVITY_KEY = "v3.lastActivity";
const AUTO_LOCK_KEY = "v3.autoLockMinutes";

const DEFAULT_AUTO_LOCK_MINUTES = 15;

export type UnlockedKeys = {
  encKey: Uint8Array;
  vaultKeys: Record<string, Uint8Array>;
};

type StoredKeys = {
  encKey: string;
  vaultKeys: Record<string, string>;
};

export type RememberedIdentity = {
  email: string;
  secretPhrase: string;
};

// ── Unlocked keys (sessionStorage) ──────────────────────────────────────────

export function saveKeys(keys: UnlockedKeys): void {
  const stored: StoredKeys = {
    encKey: b64uEncode(keys.encKey),
    vaultKeys: Object.fromEntries(Object.entries(keys.vaultKeys).map(([id, k]) => [id, b64uEncode(k)])),
  };
  sessionStorage.setItem(KEYS_KEY, JSON.stringify(stored));
  touchActivity();
}

export function loadKeys(): UnlockedKeys | null {
  const raw = sessionStorage.getItem(KEYS_KEY);
  if (!raw) return null;
  if (autoLockExpired()) {
    lock();
    return null;
  }
  try {
    const stored = JSON.parse(raw) as StoredKeys;
    return {
      encKey: b64uDecode(stored.encKey),
      vaultKeys: Object.fromEntries(Object.entries(stored.vaultKeys).map(([id, k]) => [id, b64uDecode(k)])),
    };
  } catch {
    lock();
    return null;
  }
}

// addVaultKey merges one unwrapped vault key into the unlocked set (a vault
// just created or joined this session). No-op while locked.
export function addVaultKey(vaultId: string, keyRaw: Uint8Array): void {
  const keys = loadKeys();
  if (!keys) return;
  keys.vaultKeys[vaultId] = keyRaw;
  saveKeys(keys);
}

// removeVaultKey drops one vault key (vault deleted or left).
export function removeVaultKey(vaultId: string): void {
  const keys = loadKeys();
  if (!keys) return;
  delete keys.vaultKeys[vaultId];
  saveKeys(keys);
}

export function lock(): void {
  sessionStorage.removeItem(KEYS_KEY);
  sessionStorage.removeItem(ACTIVITY_KEY);
}

// ── Auto-lock ───────────────────────────────────────────────────────────────

export function autoLockMinutes(): number {
  const raw = localStorage.getItem(AUTO_LOCK_KEY);
  const parsed = raw ? parseInt(raw, 10) : NaN;
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_AUTO_LOCK_MINUTES;
}

export function setAutoLockMinutes(minutes: number): void {
  localStorage.setItem(AUTO_LOCK_KEY, String(minutes));
}

export function touchActivity(): void {
  sessionStorage.setItem(ACTIVITY_KEY, String(Date.now()));
}

function autoLockExpired(): boolean {
  const raw = sessionStorage.getItem(ACTIVITY_KEY);
  if (!raw) return false;
  const last = parseInt(raw, 10);
  if (!Number.isFinite(last)) return false;
  return Date.now() - last > autoLockMinutes() * 60_000;
}

// startAutoLockWatch wires activity listeners plus a periodic check; when
// the idle window lapses it locks and invokes onLock so the view can swap to
// the lock screen. Returns a cleanup function.
export function startAutoLockWatch(onLock: () => void): () => void {
  const bump = () => {
    if (sessionStorage.getItem(KEYS_KEY)) touchActivity();
  };
  const events: (keyof WindowEventMap)[] = ["mousemove", "keydown", "pointerdown", "scroll"];
  events.forEach((e) => window.addEventListener(e, bump, { passive: true }));
  const timer = window.setInterval(() => {
    if (sessionStorage.getItem(KEYS_KEY) && autoLockExpired()) {
      lock();
      onLock();
    }
  }, 10_000);
  return () => {
    events.forEach((e) => window.removeEventListener(e, bump));
    window.clearInterval(timer);
  };
}

// ── Remembered identity (localStorage, this device) ─────────────────────────

export function rememberIdentity(identity: RememberedIdentity): void {
  localStorage.setItem(IDENTITY_KEY, JSON.stringify(identity));
}

export function loadIdentity(): RememberedIdentity | null {
  const raw = localStorage.getItem(IDENTITY_KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as RememberedIdentity;
    return parsed.email ? parsed : null;
  } catch {
    return null;
  }
}

export function forgetIdentity(): void {
  localStorage.removeItem(IDENTITY_KEY);
}

// ── Per-tab client id (change-signal origin) ────────────────────────────────

// clientID identifies THIS tab on mutating requests (X-Vault3-Client) so the
// change-signal socket can tell it apart from every other tab and device.
export function clientID(): string {
  let id = sessionStorage.getItem(CLIENT_KEY);
  if (!id) {
    const bytes = new Uint8Array(9);
    crypto.getRandomValues(bytes);
    id = b64uEncode(bytes);
    sessionStorage.setItem(CLIENT_KEY, id);
  }
  return id;
}
