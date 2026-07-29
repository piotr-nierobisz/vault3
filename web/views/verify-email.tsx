import React, { useEffect, useState } from "react";
import { AlertIcon, CheckIcon, VaultMark } from "../components/icons";
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
    try {
      const { data: res } = await postJSON<{ message?: string }>("/api/v1/auth/resend-verification", { email: email.trim() });
      setState({ kind: "resent", message: res?.message ?? "If an unverified account exists for that address, a new link is on its way." });
    } catch {
      setState({ kind: "failed", message: "Network error. Please try again shortly." });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card p-9 text-center animate-unseal">
      {state.kind === "verifying" && (
        <>
          <VaultMark className="h-10 w-10 text-accent mx-auto mb-5 keyhole-ring" />
          <h1 className="text-2xl font-bold tracking-tight mb-2">Confirming…</h1>
          <p className="text-sm text-muted-foreground">One moment.</p>
        </>
      )}

      {state.kind === "verified" && (
        <>
          <div className="w-12 h-12 rounded-full bg-accent-subtle text-accent inline-flex items-center justify-center mx-auto mb-5 animate-glow">
            <CheckIcon className="h-6 w-6" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight mb-2">Email confirmed.</h1>
          <p className="text-sm text-muted-foreground mb-6">Account alerts can now reach you.</p>
          <a href="/app" className="btn btn-primary">Open your vault</a>
        </>
      )}

      {state.kind === "failed" && (
        <>
          <AlertIcon className="h-9 w-9 text-danger mx-auto mb-5" />
          <h1 className="text-2xl font-bold tracking-tight mb-2">That link didn't work.</h1>
          <p className="text-sm text-muted-foreground mb-6">{state.message}</p>
          <button type="button" onClick={() => setState({ kind: "resend" })} className="btn btn-secondary">
            Request a new link
          </button>
        </>
      )}

      {state.kind === "resend" && (
        <form onSubmit={resend} className="text-left space-y-4" noValidate>
          <div className="text-center mb-2">
            <VaultMark className="h-9 w-9 text-accent mx-auto mb-4" />
            <h1 className="text-2xl font-bold tracking-tight mb-1.5">Verify your email.</h1>
            <p className="text-sm text-muted-foreground">We'll send a fresh single-use link, valid for 24 hours.</p>
          </div>
          <input className="input" type="email" required placeholder="you@example.com" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} disabled={busy} />
          <button type="submit" disabled={busy || !email.trim()} className="btn btn-primary w-full h-11">
            {busy ? "Sending…" : "Send verification link"}
          </button>
        </form>
      )}

      {state.kind === "resent" && (
        <>
          <div className="w-12 h-12 rounded-full bg-accent-subtle text-accent inline-flex items-center justify-center mx-auto mb-5">
            <CheckIcon className="h-6 w-6" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight mb-2">Check your inbox.</h1>
          <p className="text-sm text-muted-foreground">{state.message}</p>
        </>
      )}
    </div>
  );
}

_bungoRender(VerifyEmail, "verify-root");
