import React, { useState } from "react";
import { ErrorBanner } from "../components/ui/error-banner";
import { PasswordInput } from "../components/ui/password-input";
import { postJSON } from "../lib/api";
import { deriveKeys, validateSecretPhrase, type DerivationStage } from "../lib/crypto";
import { DerivationProgress } from "../components/ui/derivation-progress";
import { saveKeys, rememberIdentity, loadIdentity, forgetIdentity } from "../lib/keystore";
import type { AuthParamsResponse, LoginResponse, LoginState, LoginStep } from "../types/login";

// The unlock form. Flow:
//   1. POST /auth/params → this account's KDF salt + iterations
//   2. derive the auth key + encryption key locally (the slow, honest part)
//   3. POST /auth/login with ONLY the auth key (+ TOTP code if challenged)
//   4. stash the encryption key in the tab keystore; /app unwraps the vault
//
// A remembered identity (this device) prefigures email + Secret Phrase, so
// routine unlocks are just the Master Password.

function LoginForm() {
  const remembered = loadIdentity();
  const [email, setEmail] = useState(remembered?.email ?? "");
  const [password, setPassword] = useState("");
  const [phrase, setPhrase] = useState(remembered?.secretPhrase ?? "");
  const [usingRemembered, setUsingRemembered] = useState(Boolean(remembered));
  const [step, setStep] = useState<LoginStep>("credentials");
  const [code, setCode] = useState("");
  const [state, setState] = useState<LoginState>({ kind: "idle" });
  const [shake, setShake] = useState(0);
  const [stage, setStage] = useState<DerivationStage | null>(null);

  const busy = state.kind === "deriving" || state.kind === "submitting";

  const fail = (message: string, unverified?: boolean) => {
    setState({ kind: "error", message, unverified });
    setStage(null);
    setShake((s) => s + 1);
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanEmail = email.trim().toLowerCase();
    if (!cleanEmail || !password) {
      fail("Enter your email and Master Password.");
      return;
    }
    const phraseCheck = validateSecretPhrase(phrase);
    if (!phraseCheck.ok) {
      fail(phraseCheck.problem ?? "Check your Secret Phrase.");
      return;
    }

    try {
      setState({ kind: "deriving" });
      const params = await postJSON<AuthParamsResponse>("/api/v1/auth/params", { email: cleanEmail });
      if (!params.ok || !params.data) {
        fail("Something went wrong. Please try again.");
        return;
      }
      const { authKey, encKeyRaw } = await deriveKeys(cleanEmail, password, phrase, params.data, setStage);
      setStage(null);

      setState({ kind: "submitting" });
      const login = await postJSON<LoginResponse>("/api/v1/auth/login", {
        email: cleanEmail,
        authKey,
        code: code.trim(),
      });

      if (login.data?.twoFactorRequired) {
        setStep("twofactor");
        if (login.data.message) {
          fail(login.data.message);
        } else {
          setState({ kind: "idle" });
        }
        return;
      }
      if (!login.ok) {
        fail(
          login.data?.message ?? "Those details don't match an account. Check them and try again.",
          login.data?.emailNotVerified,
        );
        return;
      }

      // Unlocked: remember the identity on this device and stash the
      // encryption key for the tab. Vault keys are unwrapped by /app from
      // its keyset payload.
      rememberIdentity({ email: cleanEmail, secretPhrase: phrase });
      saveKeys({ encKey: encKeyRaw, vaultKeys: {} });
      setState({ kind: "success" });
      window.location.assign(login.data?.redirectTo ?? "/app");
    } catch {
      fail("Network error. Please try again shortly.");
    }
  };

  return (
    <form onSubmit={submit} className="space-y-4" noValidate aria-busy={busy}>
      {step === "credentials" && (
        <div className="space-y-4">
          <div className="space-y-1.5">
            <label htmlFor="login-email" className="field-label">
              Email
            </label>
            <input
              id="login-email"
              name="email"
              type="email"
              autoComplete="email"
              required
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={busy}
              className="input"
            />
          </div>

          <div className="space-y-1.5">
            <label htmlFor="login-password" className="field-label">
              Master Password
            </label>
            <PasswordInput
              id="login-password"
              name="password"
              autoComplete="current-password"
              value={password}
              onChange={setPassword}
              disabled={busy}
            />
          </div>

          {usingRemembered ? (
            <div className="flex items-center justify-between rounded-lg border border-accent-border bg-accent-subtle px-3.5 py-2.5">
              <p className="text-xs text-foreground">
                <span className="font-semibold text-accent">Secret Phrase saved</span> on this device
              </p>
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  forgetIdentity();
                  setPhrase("");
                  setUsingRemembered(false);
                }}
                className="text-xs text-muted-foreground hover:text-foreground underline transition-colors"
              >
                Use a different one
              </button>
            </div>
          ) : (
            <div className="space-y-1.5">
              <label htmlFor="login-phrase" className="field-label">
                Secret Phrase <span className="normal-case font-normal">(12 words)</span>
              </label>
              <textarea
                id="login-phrase"
                name="phrase"
                data-secret
                rows={2}
                autoComplete="off"
                spellCheck={false}
                placeholder="ember canyon lyric velvet orbit basalt meadow cipher noble harbor thicket lantern"
                value={phrase}
                onChange={(e) => setPhrase(e.target.value)}
                disabled={busy}
                className="input font-mono resize-none"
              />
              <p className="text-xs text-muted-foreground">From your Emergency Kit. It stays on this device.</p>
            </div>
          )}
        </div>
      )}

      {step === "twofactor" && (
        <div className="space-y-1.5">
          <label htmlFor="login-code" className="field-label">
            Authenticator code
          </label>
          <input
            id="login-code"
            name="code"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            required
            autoFocus
            placeholder="123456"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            disabled={busy}
            className="input font-mono tracking-[0.4em]"
          />
          <p className="text-xs text-muted-foreground pt-1">Enter the 6-digit code from your authenticator app.</p>
        </div>
      )}

      {state.kind === "error" && (
        <ErrorBanner key={shake} message={state.message}>
          {state.unverified && (
            <>
              {" "}
              <a href="/verify-email" className="font-semibold underline">
                Resend verification email
              </a>
            </>
          )}
        </ErrorBanner>
      )}

      <DerivationProgress stage={stage} />

      <div className="flex items-center gap-4 pt-1">
        <button
          type="submit"
          disabled={busy || (step === "twofactor" && code.trim().length !== 6)}
          className="btn btn-primary btn-lg flex-1"
        >
          {state.kind === "deriving"
            ? "Making your key…"
            : state.kind === "submitting"
              ? step === "twofactor"
                ? "Verifying…"
                : "Unlocking…"
              : step === "twofactor"
                ? "Verify"
                : "Unlock"}
        </button>
        {step === "twofactor" ? (
          <button
            type="button"
            onClick={() => {
              setStep("credentials");
              setCode("");
              setState({ kind: "idle" });
            }}
            disabled={busy}
            className="text-sm text-accent hover:text-accent-active transition-colors whitespace-nowrap"
          >
            Back
          </button>
        ) : (
          <a href="/security" className="text-sm text-muted-foreground hover:text-foreground transition-colors whitespace-nowrap">
            Lost access?
          </a>
        )}
      </div>
    </form>
  );
}

_bungoRender(LoginForm, "login-root");
