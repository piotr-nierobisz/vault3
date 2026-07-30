import React, { useEffect, useState } from "react";
import { AlertIcon, CheckIcon, VaultMark } from "../components/icons";
import { ErrorBanner } from "../components/ui/error-banner";
import { StatusPanel } from "../components/ui/status-panel";
import { postJSON } from "../lib/api";
import type { VerifyEmailPageData, VerifyResponse } from "../types/verify-email";

// With a token in the URL the page redeems it immediately; without one it
// offers the resend form. Either way the response is calm and single-purpose.

type State =
  | { kind: "verifying" }
  | { kind: "verified" }
  | { kind: "failed"; message: string }
  | { kind: "resend" }
  | { kind: "resent"; message: string };

function VerifyEmail() {
  const data = useBungoData() as VerifyEmailPageData;
  const [state, setState] = useState<State>(data.Token ? { kind: "verifying" } : { kind: "resend" });
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  // Kept apart from the "failed" state, whose heading speaks about a link
  // that did not work — there is no link yet when sending one fails.
  const [resendError, setResendError] = useState("");
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!data.Token) return;
    postJSON<VerifyResponse>("/api/v1/auth/verify-email", { token: data.Token })
      .then(({ ok, data: res }) => {
        if (ok && res?.verified) {
          setState({ kind: "verified" });
        } else {
          setState({ kind: "failed", message: res?.message ?? "This link is invalid or has expired." });
        }
      })
      .catch(() => setState({ kind: "failed", message: "Network error. Refresh to try again." }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const resend = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setResendError("");
    setAttempt((n) => n + 1);
    try {
      // The happy path is always 200 (the answer is neutral either way, so it
      // cannot leak whether the address is registered) — but a refused
      // cross-origin write, a 5xx, or a proxy error page are all still
      // reachable. Announcing "check your inbox" for any of those would tell
      // the user a link is coming when none was sent, on the only route back
      // to a verified account.
      const { ok, data: res } = await postJSON<{ message?: string }>("/api/v1/auth/resend-verification", { email: email.trim() });
      if (!ok) {
        setResendError(res?.message ?? "We couldn't send that link. Please try again shortly.");
        return;
      }
      setState({ kind: "resent", message: res?.message ?? "If an unverified account exists for that address, a new link is on its way." });
    } catch {
      setResendError("Network error. Please try again shortly.");
    } finally {
      setBusy(false);
    }
  };

  if (state.kind === "verifying") {
    return <StatusPanel mark pulse title="Confirming…" body="One moment." />;
  }

  if (state.kind === "verified") {
    return (
      <StatusPanel icon={<CheckIcon className="h-6 w-6" />} title="Email confirmed." body="Account alerts can now reach you.">
        <a href="/app" className="btn btn-primary">Open your vault</a>
      </StatusPanel>
    );
  }

  if (state.kind === "failed") {
    return (
      <StatusPanel icon={<AlertIcon className="h-6 w-6" />} tone="danger" title="That link didn't work." body={state.message}>
        <button type="button" onClick={() => setState({ kind: "resend" })} className="btn btn-secondary">
          Request a new link
        </button>
      </StatusPanel>
    );
  }

  if (state.kind === "resent") {
    return <StatusPanel icon={<CheckIcon className="h-6 w-6" />} title="Check your inbox." body={state.message} />;
  }

  return (
    <form onSubmit={resend} className="panel p-8 space-y-4 animate-unseal" noValidate>
      <div className="text-center mb-2">
        <VaultMark className="h-11 w-11 text-accent mx-auto mb-4" />
        <h1 className="text-2xl font-bold tracking-tight mb-1.5">Verify your email.</h1>
        <p className="text-sm text-muted-foreground">We'll email you a new link. It works once, and lasts 24 hours.</p>
      </div>
      <input className="input" type="email" required placeholder="you@example.com" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} disabled={busy} />
      {resendError && <ErrorBanner key={attempt} message={resendError} />}
      <button type="submit" disabled={busy || !email.trim()} className="btn btn-primary btn-lg w-full">
        {busy ? "Sending…" : "Send verification link"}
      </button>
    </form>
  );
}

_bungoRender(VerifyEmail, "verify-root");
