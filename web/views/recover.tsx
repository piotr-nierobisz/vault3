import React, { useState } from "react";
import { AlertIcon, CheckIcon, DownloadIcon, VaultMark } from "../components/icons";
import { PasswordInput } from "../components/ui/password-input";
import { CheckboxBox } from "../components/ui/checkbox";
import { PhraseGrid } from "../components/auth/phrase-grid";
import { StrengthMeter, estimateStrength } from "../components/auth/strength-meter";
import { downloadKitHTML, downloadKitText } from "../components/auth/emergency-kit";
import { postJSON } from "../lib/api";
import { createCryptoBundle, generateSecretPhrase } from "../lib/crypto";
import { saveKeys, rememberIdentity } from "../lib/keystore";
import type { RecoverPageData, RecoverResponse } from "../types/recover";

// Zero-knowledge recovery. Without a token: explain the deal, take an email,
// answer neutrally. With a token: an unambiguous, typed-confirmation reset
// that erases the vault and reruns the crypto onboarding.

function RequestBranch() {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const { data } = await postJSON<{ message?: string }>("/api/v1/auth/recover/request", { email: email.trim() });
      setSent(data?.message ?? "If an account exists for that address, a reset link is on its way.");
    } catch {
      setSent("Network error. Please try again shortly.");
    } finally {
      setBusy(false);
    }
  };

  if (sent) {
    return (
      <div className="card p-10 text-center animate-unseal max-w-md mx-auto">
        <div className="w-12 h-12 rounded-full bg-accent-subtle text-accent inline-flex items-center justify-center mx-auto mb-5">
          <CheckIcon className="h-6 w-6" />
        </div>
        <h1 className="text-2xl font-bold tracking-tight mb-2">Check your inbox.</h1>
        <p className="text-sm text-muted-foreground">{sent}</p>
      </div>
    );
  }

  return (
    <div className="max-w-md mx-auto animate-unseal">
      <div className="text-center mb-7">
        <VaultMark className="h-10 w-10 text-accent mx-auto mb-5" />
        <h1 className="text-3xl font-extrabold tracking-tighter mb-3">Lost access?</h1>
        <p className="text-sm text-muted-foreground leading-relaxed">
          First: check your Emergency Kit — with your Secret Phrase and Master Password you can sign in on any device, no reset needed.
        </p>
      </div>

      <div className="rounded-lg border border-danger px-4 py-3.5 mb-6 text-sm leading-relaxed" style={{ background: "var(--danger-subtle)" }}>
        <p className="font-semibold text-danger mb-1">Resetting erases your vault.</p>
        <p className="text-muted-foreground">
          Vault3 is zero-knowledge: we hold only ciphertext and cannot decrypt it without your secrets. A reset gives you a fresh, empty vault with new credentials — the old contents are unrecoverable, by anyone.
        </p>
      </div>

      <form onSubmit={submit} className="space-y-4" noValidate>
        <input className="input" type="email" required placeholder="you@example.com" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} disabled={busy} />
        <button type="submit" disabled={busy || !email.trim()} className="btn btn-danger w-full h-11">
          {busy ? "Sending…" : "Email me a reset link"}
        </button>
      </form>
      <p className="text-sm text-center mt-5 text-muted-foreground">
        Remembered after all? <a href="/login" className="text-accent hover:text-accent-active font-medium">Unlock instead</a>
      </p>
    </div>
  );
}

function ConfirmBranch({ token, iterations }: { token: string; iterations: number }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [typed, setTyped] = useState("");
  const [phrase] = useState(() => generateSecretPhrase());
  const [savedKit, setSavedKit] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const ready =
    typed === "RESET" &&
    savedKit &&
    /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim().toLowerCase()) &&
    estimateStrength(password).bits >= 40 &&
    password === confirm;

  const submit = async () => {
    setError("");
    setBusy(true);
    try {
      const cleanEmail = email.trim().toLowerCase();
      const bundle = await createCryptoBundle(cleanEmail, password, phrase, iterations);
      const res = await postJSON<RecoverResponse>("/api/v1/auth/recover/confirm", {
        token,
        email: cleanEmail,
        ...bundle.request,
      });
      if (!res.ok) {
        setError(res.data?.message ?? "The reset couldn't be completed. Request a fresh link.");
        setBusy(false);
        return;
      }
      rememberIdentity({ email: cleanEmail, secretPhrase: phrase });
      saveKeys({ encKey: bundle.encKeyRaw, vaultKeys: {} });
      window.location.assign(res.data?.redirectTo ?? "/app");
    } catch {
      setError("Network error. Please try again shortly.");
      setBusy(false);
    }
  };

  return (
    <div className="animate-unseal">
      <div className="mb-7">
        <h1 className="text-3xl font-extrabold tracking-tighter mb-3">Reset your account.</h1>
        <p className="text-sm text-muted-foreground leading-relaxed max-w-lg">
          This wipes everything stored in your vault and rebuilds your account's cryptography from scratch: new Master Password, new Secret Phrase, empty vault. There is no undo.
        </p>
      </div>

      {error && (
        <div className="animate-shake flex items-start gap-2 text-sm rounded-md border border-danger px-3 py-2.5 text-danger mb-5" role="alert" style={{ background: "var(--danger-subtle)" }}>
          <AlertIcon className="h-4 w-4 mt-0.5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="card p-8 space-y-5">
        <div className="space-y-1.5">
          <label className="text-xs font-semibold tracking-widest uppercase text-muted-foreground" htmlFor="rec-email">Account email</label>
          <input id="rec-email" className="input" type="email" required autoComplete="email" placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} disabled={busy} />
        </div>
        <div className="space-y-1.5">
          <label className="text-xs font-semibold tracking-widest uppercase text-muted-foreground" htmlFor="rec-password">New Master Password</label>
          <PasswordInput id="rec-password" name="password" autoComplete="new-password" value={password} onChange={setPassword} disabled={busy} />
          <StrengthMeter password={password} />
        </div>
        <div className="space-y-1.5">
          <label className="text-xs font-semibold tracking-widest uppercase text-muted-foreground" htmlFor="rec-confirm">Confirm new Master Password</label>
          <PasswordInput id="rec-confirm" name="confirm" autoComplete="new-password" value={confirm} onChange={setConfirm} disabled={busy} />
        </div>

        <div>
          <p className="text-xs font-semibold tracking-widest uppercase text-muted-foreground mb-2">Your new Secret Phrase</p>
          <PhraseGrid phrase={phrase} withCopy />
          <div className="flex gap-3 mt-3">
            <button type="button" onClick={() => downloadKitText(email.trim().toLowerCase(), phrase)} className="btn btn-secondary text-sm">
              <DownloadIcon className="h-4 w-4" /> Kit (.txt)
            </button>
            <button type="button" onClick={() => downloadKitHTML(email.trim().toLowerCase(), phrase)} className="btn btn-secondary text-sm">
              <DownloadIcon className="h-4 w-4" /> Kit (printable)
            </button>
          </div>
        </div>

        <label className="flex items-start gap-3 rounded-lg border border-border px-4 py-3.5 cursor-pointer hover:border-border-strong transition-colors">
          <CheckboxBox checked={savedKit} onChange={setSavedKit} className="mt-0.5" />
          <span className="text-sm text-foreground leading-relaxed">I've saved my new Emergency Kit somewhere safe and offline.</span>
        </label>

        <div className="space-y-1.5">
          <label className="text-xs font-semibold tracking-widest uppercase text-muted-foreground" htmlFor="rec-typed">
            Type <span className="font-mono normal-case">RESET</span> to confirm the wipe
          </label>
          <input id="rec-typed" className="input font-mono" autoComplete="off" spellCheck={false} placeholder="RESET" value={typed} onChange={(e) => setTyped(e.target.value.toUpperCase())} disabled={busy} />
        </div>

        <button type="button" onClick={submit} disabled={!ready || busy} className="btn btn-danger w-full h-11 text-base">
          {busy ? "Resetting…" : "Erase my vault and reset"}
        </button>
      </div>
    </div>
  );
}

function Recover() {
  const data = useBungoData() as RecoverPageData;
  return data.Token ? <ConfirmBranch token={data.Token} iterations={data.KdfIterations} /> : <RequestBranch />;
}

_bungoRender(Recover, "recover-root");
