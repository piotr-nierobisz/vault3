import React, { useState } from "react";
import { AlertIcon, CheckIcon } from "../components/icons";
import { postJSON } from "../lib/api";

// Contact form: one POST, no drama. Server-side length caps mirror the
// maxLength attributes here.

function ContactForm() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const { ok, data } = await postJSON<{ message?: string }>("/api/v1/contact", { name, email, message });
      if (!ok) {
        setError(data?.message ?? "We couldn't send that. Please try again.");
        return;
      }
      setDone(true);
    } catch {
      setError("Network error. Please try again shortly.");
    } finally {
      setBusy(false);
    }
  };

  if (done) {
    return (
      <div className="card p-10 text-center animate-unseal">
        <div className="w-12 h-12 rounded-full bg-accent-subtle text-accent inline-flex items-center justify-center mx-auto mb-5">
          <CheckIcon className="h-6 w-6" />
        </div>
        <h2 className="text-xl font-bold tracking-tight mb-1.5">Message received.</h2>
        <p className="text-sm text-muted-foreground">We'll get back to you at {email.trim()}.</p>
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="card p-8 space-y-5 animate-unseal" noValidate>
      {error && (
        <div className="animate-shake flex items-start gap-2 text-sm rounded-md border border-danger px-3 py-2.5 text-danger" role="alert" style={{ background: "var(--danger-subtle)" }}>
          <AlertIcon className="h-4 w-4 mt-0.5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}
      <div className="grid sm:grid-cols-2 gap-5">
        <div className="space-y-1.5">
          <label htmlFor="contact-name" className="text-xs font-semibold tracking-widest uppercase text-muted-foreground">Name</label>
          <input id="contact-name" className="input" required maxLength={100} placeholder="Your name" value={name} onChange={(e) => setName(e.target.value)} disabled={busy} />
        </div>
        <div className="space-y-1.5">
          <label htmlFor="contact-email" className="text-xs font-semibold tracking-widest uppercase text-muted-foreground">Email</label>
          <input id="contact-email" className="input" type="email" required placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} disabled={busy} />
        </div>
      </div>
      <div className="space-y-1.5">
        <label htmlFor="contact-message" className="text-xs font-semibold tracking-widest uppercase text-muted-foreground">Message</label>
        <textarea id="contact-message" className="input resize-none" rows={6} required maxLength={2000} placeholder="What's on your mind?" value={message} onChange={(e) => setMessage(e.target.value)} disabled={busy} />
        <p className="text-xs text-muted-foreground text-right">{message.length}/2000</p>
      </div>
      <button type="submit" disabled={busy || !name.trim() || !email.trim() || !message.trim()} className="btn btn-primary h-11 w-full sm:w-auto sm:px-10">
        {busy ? "Sending…" : "Send message"}
      </button>
    </form>
  );
}

_bungoRender(ContactForm, "contact-root");
