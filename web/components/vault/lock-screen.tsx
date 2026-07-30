import React, { useState } from "react";
import { AlertIcon, VaultMark } from "../icons";
import { PasswordInput } from "../ui/password-input";
import { postJSON } from "../../lib/api";
import { deriveKeys, open, validateSecretPhrase } from "../../lib/crypto";
import { loadIdentity, forgetIdentity, saveKeys } from "../../lib/keystore";
import type { KeysetDto } from "../../types/vault";

// The lock screen: shown whenever the tab holds a session but no unlocked
// keys (fresh tab, auto-lock, explicit Lock). Unlock is verified LOCALLY —
// deriving the key and unwrapping the first vault key either succeeds or
// fails GCM authentication; no server round-trip decides it. The /auth/params
// call only fetches the public KDF parameters.

export function LockScreen({
  keyset,
  email,
  onUnlocked,
}: {
  keyset: KeysetDto;
  email: string;
  onUnlocked: (encKey: Uint8Array, vaultKeys: Record<string, Uint8Array>) => void;
}) {
  const remembered = loadIdentity();
  const [password, setPassword] = useState("");
  const [phrase, setPhrase] = useState(remembered?.secretPhrase ?? "");
  const [usingRemembered, setUsingRemembered] = useState(Boolean(remembered?.secretPhrase));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);

  const unlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    const phraseCheck = validateSecretPhrase(phrase);
    if (!phraseCheck.ok) {
      setError(phraseCheck.problem ?? "Check your Secret Phrase.");
      setAttempt((a) => a + 1);
      return;
    }
    setBusy(true);
    try {
      const { encKeyRaw } = await deriveKeys(email, password, phrase, keyset.kdfSalt, keyset.kdfIterations);
      const vaultKeys: Record<string, Uint8Array> = {};
      let openedAny = false;
      for (const vault of keyset.vaults) {
        // GCM authentication is the correctness proof: wrong secrets throw.
        // One damaged wrap must not lock the whole account out, so vaults
        // are opened individually — but zero successes means bad secrets.
        try {
          vaultKeys[vault.id] = await open(encKeyRaw, vault.wrappedKey);
          openedAny = true;
        } catch {
          // Skipped; the vault stays sealed for this session.
        }
      }
      if (!openedAny && keyset.vaults.length > 0) throw new Error("wrong secrets");
      saveKeys({ encKey: encKeyRaw, vaultKeys });
      onUnlocked(encKeyRaw, vaultKeys);
    } catch {
      setError("Those secrets don't open this vault. Check your Master Password and Secret Phrase.");
      setAttempt((a) => a + 1);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-40 lock-veil flex items-center justify-center p-6 overflow-hidden">
      <div
        className="glow-orb"
        style={{ "--orb": "var(--accent-glow)", width: "620px", height: "620px", top: "50%", left: "50%", transform: "translate(-50%,-50%)" } as React.CSSProperties}
        aria-hidden="true"
      />
      <div className="relative panel p-9 w-full max-w-md shadow-accent animate-pop">
        <div className="text-center mb-7">
          <VaultMark className="h-12 w-12 text-accent mx-auto mb-4 mark-pulse" />
          <h1 className="text-2xl font-bold tracking-tight mb-1">
            Vault <span className="text-gradient">locked.</span>
          </h1>
          <p className="text-sm text-muted-foreground font-mono">{email}</p>
        </div>

        <form onSubmit={unlock} className="space-y-4" noValidate aria-busy={busy}>
          <div className="space-y-1.5">
            <label htmlFor="lock-password" className="text-xs font-semibold tracking-widest uppercase text-muted-foreground">
              Master Password
            </label>
            <PasswordInput
              id="lock-password"
              name="password"
              autoComplete="current-password"
              value={password}
              onChange={setPassword}
              disabled={busy}
              autoFocus
            />
          </div>

          {!usingRemembered && (
            <div className="space-y-1.5">
              <label htmlFor="lock-phrase" className="text-xs font-semibold tracking-widest uppercase text-muted-foreground">
                Secret Phrase
              </label>
              <textarea
                id="lock-phrase"
                data-secret
                rows={2}
                autoComplete="off"
                spellCheck={false}
                className="input font-mono resize-none"
                placeholder="nine words from your Emergency Kit"
                value={phrase}
                onChange={(e) => setPhrase(e.target.value)}
                disabled={busy}
              />
            </div>
          )}

          {error && (
            <div key={attempt} className="animate-shake flex items-start gap-2 text-sm rounded-md border border-danger px-3 py-2.5 text-danger" role="alert" style={{ background: "var(--danger-subtle)" }}>
              <AlertIcon className="h-4 w-4 mt-0.5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <button type="submit" disabled={busy || !password} className="btn btn-primary w-full h-11 text-base">
            {busy ? "Deriving keys…" : "Unlock"}
          </button>
        </form>

        {usingRemembered && (
          <button
            type="button"
            onClick={() => {
              forgetIdentity();
              setPhrase("");
              setUsingRemembered(false);
            }}
            className="mt-4 w-full text-center text-xs text-muted-foreground hover:text-foreground underline transition-colors"
          >
            Enter Secret Phrase manually
          </button>
        )}
      </div>
    </div>
  );
}
