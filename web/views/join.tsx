import React, { useState } from "react";
import { CheckIcon, DownloadIcon, RefreshIcon } from "../components/icons";
import { PasswordInput } from "../components/ui/password-input";
import { CheckboxBox } from "../components/ui/checkbox";
import { ErrorBanner } from "../components/ui/error-banner";
import { Loading } from "../components/ui/loading";
import { StatusPanel } from "../components/ui/status-panel";
import { PhraseGrid } from "../components/auth/phrase-grid";
import { StrengthMeter, estimateStrength } from "../components/auth/strength-meter";
import { downloadKitHTML, downloadKitText } from "../components/auth/emergency-kit";
import { postJSON } from "../lib/api";
import { createCryptoBundle, generateSecretPhrase, type DerivationStage } from "../lib/crypto";
import { DerivationProgress } from "../components/ui/derivation-progress";
import { saveKeys, rememberIdentity } from "../lib/keystore";
import type { JoinPageData, JoinStep, RegisterResponse } from "../types/join";

// Registration: a three-beat ceremony.
//   1. account  — email, optional name, Master Password
//   2. phrase   — mint the Secret Phrase, download the Emergency Kit, confirm
//   3. sealing  — derive keys, generate the vault key, register
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
  // Keys the banner so a repeated validation failure remounts it and replays
  // the shake; re-setting an identical message alone re-renders nothing.
  const [attempt, setAttempt] = useState(0);
  const [stage, setStage] = useState<DerivationStage | null>(null);

  if (!data.RegistrationOpen) {
    return (
      <StatusPanel
        mark
        title="Registration is closed for now."
        body={
          <>
            We're letting people in gradually. Check back soon, or{" "}
            <a href="/contact" className="text-accent hover:text-accent-active">get in touch</a>.
          </>
        }
      />
    );
  }

  const submitAccount = (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setAttempt((n) => n + 1);
    const cleanEmail = email.trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(cleanEmail)) {
      setError("Enter a valid email address.");
      return;
    }
    if (estimateStrength(password).bits < 40) {
      setError("This is the half of your key you keep in your head — please make it harder to guess.");
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
      const bundle = await createCryptoBundle(cleanEmail, password, phrase, data.KdfCosts, setStage);
      setStage(null);
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

      {error && <ErrorBanner key={attempt} message={error} className="mb-5" />}

      {step === "account" && (
        <form onSubmit={submitAccount} className="panel p-8 space-y-5" noValidate>
          <div>
            <h1 className="text-2xl font-bold tracking-tight mb-1.5">Create your vault.</h1>
            <p className="text-sm text-muted-foreground">
              Your Master Password never leaves this device. Choose one you can remember and no one could guess.
            </p>
          </div>
          <div className="space-y-1.5">
            <label htmlFor="join-name" className="field-label">
              Name <span className="normal-case font-normal">(optional)</span>
            </label>
            <input id="join-name" className="input" autoComplete="name" placeholder="Nora Sandoval" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <label htmlFor="join-email" className="field-label">Email</label>
            <input id="join-email" className="input" type="email" required autoComplete="email" placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <label htmlFor="join-password" className="field-label">Master Password</label>
            <PasswordInput id="join-password" name="password" autoComplete="new-password" value={password} onChange={setPassword} />
            <StrengthMeter password={password} />
          </div>
          <div className="space-y-1.5">
            <label htmlFor="join-confirm" className="field-label">Confirm Master Password</label>
            <PasswordInput id="join-confirm" name="confirm" autoComplete="new-password" value={confirm} onChange={setConfirm} />
          </div>
          <div className="rounded-lg border border-border bg-muted px-4 py-3 text-xs text-muted-foreground leading-relaxed">
            There is no reset for this password. If you lose it along with your Secret Phrase, nobody can open your vault again — us included. That is the trade for keeping it genuinely private.
          </div>
          <button type="submit" className="btn btn-primary btn-lg w-full">Continue</button>
        </form>
      )}

      {step === "phrase" && (
        <div className="panel p-8 space-y-5">
          <div>
            <h1 className="text-2xl font-bold tracking-tight mb-1.5">Your Secret Phrase.</h1>
            <p className="text-sm text-muted-foreground">
              Twelve words, made on this device a moment ago. Together with your Master Password they open your vault, and we never see either of them. Save them now — the app will not show them to you again.
            </p>
          </div>

          <PhraseGrid phrase={phrase} withCopy />

          <div className="flex flex-wrap gap-3">
            <button type="button" onClick={() => setPhrase(generateSecretPhrase())} className="btn btn-ghost btn-sm">
              <RefreshIcon className="h-4 w-4" /> New phrase
            </button>
            <span className="flex-1" />
            <button type="button" onClick={() => downloadKitText(email.trim().toLowerCase(), phrase)} className="btn btn-secondary btn-sm">
              <DownloadIcon className="h-4 w-4" /> Kit (.txt)
            </button>
            <button type="button" onClick={() => downloadKitHTML(email.trim().toLowerCase(), phrase)} className="btn btn-secondary btn-sm">
              <DownloadIcon className="h-4 w-4" /> Kit (printable)
            </button>
          </div>

          <label className="flex items-start gap-3 rounded-lg border border-border px-4 py-3.5 cursor-pointer hover:border-border-strong transition-colors">
            <CheckboxBox checked={savedKit} onChange={setSavedKit} className="mt-0.5" />
            <span className="text-sm text-foreground leading-relaxed">
              I have saved my Emergency Kit somewhere safe and offline. I understand that if I lose both secrets, everything in my vault is gone for good.
            </span>
          </label>

          <div className="flex items-center gap-3">
            <button type="button" onClick={() => setStep("account")} className="btn btn-ghost">Back</button>
            <button type="button" onClick={register} disabled={!savedKit} className="btn btn-primary btn-lg flex-1">
              Seal my vault
            </button>
          </div>
        </div>
      )}

      {step === "sealing" && (
        <StatusPanel
          mark
          pulse
          title="Sealing your vault…"
          body={stage ? <DerivationProgress stage={stage} /> : <Loading label="locking your vault key" />}
        />
      )}

      {step === "done" && (
        <StatusPanel icon={<CheckIcon className="h-6 w-6" />} title="Sealed." body="Opening your vault…" />
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
