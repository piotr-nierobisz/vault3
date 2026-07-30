import React, { useState } from "react";
import { AlertIcon, CheckIcon, DownloadIcon, RefreshIcon, VaultMark } from "../components/icons";
import { PasswordInput } from "../components/ui/password-input";
import { CheckboxBox } from "../components/ui/checkbox";
import { PhraseGrid } from "../components/auth/phrase-grid";
import { StrengthMeter, estimateStrength } from "../components/auth/strength-meter";
import { downloadKitHTML, downloadKitText } from "../components/auth/emergency-kit";
import { postJSON } from "../lib/api";
import { createCryptoBundle, generateSecretPhrase } from "../lib/crypto";
import { saveKeys, rememberIdentity } from "../lib/keystore";
import type { JoinPageData, JoinStep, RegisterResponse } from "../types/join";

// Registration: a three-beat ceremony.
//   1. account  — email, optional name, Master Password
//   2. phrase   — mint the Secret Phrase, download the Emergency Kit, confirm
//   3. sealing  — derive keys, generate keypair + vault key, register
// Everything cryptographic happens on-device; the server receives the
// finished ciphertext bundle.

function stepBadge(active: boolean, done: boolean, n: number, label: string) {
  return (
    <div className="flex items-center gap-2">
      <span
        className={`w-6 h-6 rounded-full inline-flex items-center justify-center text-xs font-bold transition-colors ${
          done ? "bg-accent text-accent-foreground" : active ? "bg-accent-subtle text-accent" : "bg-muted text-muted-foreground"
        }`}
      >
        {done ? <CheckIcon className="h-3.5 w-3.5" /> : n}
      </span>
      <span className={`text-sm ${active || done ? "text-foreground font-medium" : "text-muted-foreground"}`}>{label}</span>
    </div>
  );
}

function JoinWizard() {
  const data = useBungoData() as JoinPageData;
  const [step, setStep] = useState<JoinStep>("account");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [phrase, setPhrase] = useState(() => generateSecretPhrase());
  const [savedKit, setSavedKit] = useState(false);
  const [error, setError] = useState("");

  if (!data.RegistrationOpen) {
    return (
      <div className="card p-10 text-center animate-unseal">
        <VaultMark className="h-10 w-10 text-accent mx-auto mb-5" />
        <h1 className="text-2xl font-bold tracking-tight mb-3">Registration is closed for now.</h1>
        <p className="text-sm text-muted-foreground">
          We're letting people in gradually. Check back soon, or{" "}
          <a href="/contact" className="text-accent hover:text-accent-active">get in touch</a>.
        </p>
      </div>
    );
  }

  const submitAccount = (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    const cleanEmail = email.trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(cleanEmail)) {
      setError("Enter a valid email address.");
      return;
    }
    if (estimateStrength(password).bits < 40) {
      setError("Your Master Password is the half of your key you carry in your head — make it stronger.");
      return;
    }
    if (password !== confirm) {
      setError("The passwords don't match.");
      return;
    }
    setStep("phrase");
  };

  const register = async () => {
    setError("");
    setStep("sealing");
    try {
      const cleanEmail = email.trim().toLowerCase();
      const bundle = await createCryptoBundle(cleanEmail, password, phrase, data.KdfIterations);
      const res = await postJSON<RegisterResponse>("/api/v1/auth/register", {
        email: cleanEmail,
        displayName: name.trim(),
        ...bundle.request,
      });
      if (!res.ok) {
        setError(res.data?.message ?? "We couldn't create your vault. Please try again.");
        setStep(res.data?.field === "email" ? "account" : "phrase");
        return;
      }
      rememberIdentity({ email: cleanEmail, secretPhrase: phrase });
      // The register response includes the personal vault in its keyset on
      // /app; stash the derived keys now so the vault opens straight away.
      saveKeys({ encKey: bundle.encKeyRaw, vaultKeys: {} });
      setStep("done");
      window.setTimeout(() => window.location.assign(res.data?.redirectTo ?? "/app"), 1400);
    } catch {
      setError("Network error. Please try again shortly.");
      setStep("phrase");
    }
  };

  return (
    <div className="animate-unseal">
      <div className="flex items-center gap-6 mb-8">
        {stepBadge(step === "account", step !== "account", 1, "Account")}
        <span className="h-px flex-1 bg-border" />
        {stepBadge(step === "phrase", step === "sealing" || step === "done", 2, "Secret Phrase")}
        <span className="h-px flex-1 bg-border" />
        {stepBadge(step === "sealing" || step === "done", step === "done", 3, "Seal")}
      </div>

      {error && (
        <div className="animate-shake flex items-start gap-2 text-sm rounded-md border border-danger px-3 py-2.5 text-danger mb-5" role="alert" style={{ background: "var(--danger-subtle)" }}>
          <AlertIcon className="h-4 w-4 mt-0.5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {step === "account" && (
        <form onSubmit={submitAccount} className="card p-8 space-y-5" noValidate>
          <div>
            <h1 className="text-2xl font-bold tracking-tight mb-1.5">Create your vault.</h1>
            <p className="text-sm text-muted-foreground">
              Your Master Password never leaves this device. Choose one you can remember and no one could guess.
            </p>
          </div>
          <div className="space-y-1.5">
            <label htmlFor="join-name" className="text-xs font-semibold tracking-widest uppercase text-muted-foreground">
              Name <span className="normal-case font-normal">(optional)</span>
            </label>
            <input id="join-name" className="input" autoComplete="name" placeholder="Nora Sandoval" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <label htmlFor="join-email" className="text-xs font-semibold tracking-widest uppercase text-muted-foreground">Email</label>
            <input id="join-email" className="input" type="email" required autoComplete="email" placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <label htmlFor="join-password" className="text-xs font-semibold tracking-widest uppercase text-muted-foreground">Master Password</label>
            <PasswordInput id="join-password" name="password" autoComplete="new-password" value={password} onChange={setPassword} />
            <StrengthMeter password={password} />
          </div>
          <div className="space-y-1.5">
            <label htmlFor="join-confirm" className="text-xs font-semibold tracking-widest uppercase text-muted-foreground">Confirm Master Password</label>
            <PasswordInput id="join-confirm" name="confirm" autoComplete="new-password" value={confirm} onChange={setConfirm} />
          </div>
          <div className="rounded-lg border border-border bg-muted px-4 py-3 text-xs text-muted-foreground leading-relaxed">
            Vault3 cannot reset this password. If you lose it (and your Secret Phrase), your vault is unrecoverable — that's the zero-knowledge deal.
          </div>
          <button type="submit" className="btn btn-primary w-full h-11 text-base">Continue</button>
        </form>
      )}

      {step === "phrase" && (
        <div className="card p-8 space-y-5">
          <div>
            <h1 className="text-2xl font-bold tracking-tight mb-1.5">Your Secret Phrase.</h1>
            <p className="text-sm text-muted-foreground">
              Nine words, minted on this device just now. Together with your Master Password they form your vault key. We never see them.
            </p>
          </div>

          <PhraseGrid phrase={phrase} withCopy />

          <div className="flex flex-wrap gap-3">
            <button type="button" onClick={() => setPhrase(generateSecretPhrase())} className="btn btn-ghost text-sm">
              <RefreshIcon className="h-4 w-4" /> New phrase
            </button>
            <span className="flex-1" />
            <button type="button" onClick={() => downloadKitText(email.trim().toLowerCase(), phrase)} className="btn btn-secondary text-sm">
              <DownloadIcon className="h-4 w-4" /> Kit (.txt)
            </button>
            <button type="button" onClick={() => downloadKitHTML(email.trim().toLowerCase(), phrase)} className="btn btn-secondary text-sm">
              <DownloadIcon className="h-4 w-4" /> Kit (printable)
            </button>
          </div>

          <label className="flex items-start gap-3 rounded-lg border border-border px-4 py-3.5 cursor-pointer hover:border-border-strong transition-colors">
            <CheckboxBox checked={savedKit} onChange={setSavedKit} className="mt-0.5" />
            <span className="text-sm text-foreground leading-relaxed">
              I've saved my Emergency Kit somewhere safe and offline. I understand that losing both secrets means losing my vault — permanently.
            </span>
          </label>

          <div className="flex items-center gap-3">
            <button type="button" onClick={() => setStep("account")} className="btn btn-ghost">Back</button>
            <button type="button" onClick={register} disabled={!savedKit} className="btn btn-primary flex-1 h-11 text-base">
              Seal my vault
            </button>
          </div>
        </div>
      )}

      {step === "sealing" && (
        <div className="card p-12 text-center">
          <VaultMark className="h-12 w-12 text-accent mx-auto mb-6 mark-pulse" />
          <h1 className="text-2xl font-bold tracking-tight mb-2">Sealing your vault…</h1>
          <p className="text-sm text-muted-foreground font-mono">
            deriving keys · 650,000 rounds · generating keypair · wrapping vault key
          </p>
        </div>
      )}

      {step === "done" && (
        <div className="card p-12 text-center animate-unseal">
          <div className="w-14 h-14 rounded-full bg-accent-subtle text-accent inline-flex items-center justify-center mx-auto mb-6 animate-glow">
            <CheckIcon className="h-7 w-7" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight mb-2">Sealed.</h1>
          <p className="text-sm text-muted-foreground">Opening your vault…</p>
        </div>
      )}

      <p className="text-xs text-muted-foreground text-center mt-6">
        By creating a vault you agree to the{" "}
        <a href="/legal/terms" className="underline hover:text-foreground">Terms of Service</a> and{" "}
        <a href="/legal/privacy" className="underline hover:text-foreground">Privacy Policy</a>.
      </p>
    </div>
  );
}

_bungoRender(JoinWizard, "join-root");
