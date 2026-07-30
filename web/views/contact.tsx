import React, { useState } from "react";
import { CheckIcon } from "../components/icons";
import { ErrorBanner } from "../components/ui/error-banner";
import { StatusPanel } from "../components/ui/status-panel";
import { postJSON } from "../lib/api";
import { useAction } from "../lib/use-action";

// Contact form: one POST, no drama. Server-side length caps mirror the
// maxLength attributes here.

function ContactForm() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");
  const [done, setDone] = useState(false);
  const [error, setError] = useState("");
  const { busy, run } = useAction({ onError: setError, network: "Network error. Please try again shortly." });

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    await run(() => postJSON("/api/v1/contact", { name, email, message }), {
      onOK: () => setDone(true),
      fail: "We couldn't send that. Please try again.",
    });
  };

  if (done) {
    return (
      <StatusPanel
        icon={<CheckIcon className="h-6 w-6" />}
        title="Message received."
        as="h2"
        body={`We'll get back to you at ${email.trim()}.`}
      />
    );
  }

  return (
    <form onSubmit={submit} className="panel p-8 space-y-5 animate-unseal" noValidate>
      {error && <ErrorBanner message={error} />}
      <div className="grid sm:grid-cols-2 gap-5">
        <div className="space-y-1.5">
          <label htmlFor="contact-name" className="field-label">Name</label>
          <input id="contact-name" className="input" required maxLength={100} placeholder="Your name" value={name} onChange={(e) => setName(e.target.value)} disabled={busy} />
        </div>
        <div className="space-y-1.5">
          <label htmlFor="contact-email" className="field-label">Email</label>
          <input id="contact-email" className="input" type="email" required placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} disabled={busy} />
        </div>
      </div>
      <div className="space-y-1.5">
        <label htmlFor="contact-message" className="field-label">Message</label>
        <textarea id="contact-message" className="input resize-none" rows={6} required maxLength={2000} placeholder="What's on your mind?" value={message} onChange={(e) => setMessage(e.target.value)} disabled={busy} />
        <p className="text-xs text-muted-foreground text-right">{message.length}/2000</p>
      </div>
      <button type="submit" disabled={busy || !name.trim() || !email.trim() || !message.trim()} className="btn btn-primary btn-lg w-full sm:w-auto sm:px-10">
        {busy ? "Sending…" : "Send message"}
      </button>
    </form>
  );
}

_bungoRender(ContactForm, "contact-root");
