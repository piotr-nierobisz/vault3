import React, { useState } from "react";
import { KeyIcon } from "../icons";
import { Dialog } from "../ui/dialog";
import { FieldError } from "../ui/field-error";
import { PasswordInput } from "../ui/password-input";
import { GeneratorPanel } from "./generator-popover";
import { normalizeTotpInput } from "../../lib/totp";
import { CATEGORY_FIELDS, type CategoryDto, type ItemDetails, type ItemOverview } from "../../types/vault";

// The create/edit item dialog. One form, parameterised by category: the
// field template drives which inputs render, and everything funnels into the
// {overview, details} pair the crypto layer seals.

export type ItemFormValue = {
  overview: ItemOverview;
  details: ItemDetails;
};

export function ItemForm({
  open,
  onClose,
  onSubmit,
  categories,
  initial,
  busy,
}: {
  open: boolean;
  onClose: () => void;
  onSubmit: (value: ItemFormValue) => void;
  categories: CategoryDto[];
  initial?: ItemFormValue;
  busy?: boolean;
}) {
  const editing = Boolean(initial);
  const [category, setCategory] = useState(initial?.overview.category ?? "login");
  const [title, setTitle] = useState(initial?.overview.title ?? "");
  const [url, setUrl] = useState(initial?.overview.urls?.[0] ?? "");
  const [fields, setFields] = useState<Record<string, string>>(initial?.details.fields ?? {});
  const [notes, setNotes] = useState(initial?.details.notes ?? "");
  const [showGenerator, setShowGenerator] = useState(false);
  const [fieldError, setFieldError] = useState("");

  const specs = CATEGORY_FIELDS[category] ?? [];

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return;
    const cleanFields: Record<string, string> = {};
    for (const spec of specs) {
      const value = (fields[spec.key] ?? "").trim();
      if (!value) continue;
      if (spec.totp) {
        // Reject an unusable seed here rather than sealing something the
        // detail pane can only apologise for later.
        const normalized = normalizeTotpInput(value);
        if (!normalized) {
          setFieldError("That doesn't look like a one-time-code key. Paste the setup key or the full otpauth:// link.");
          return;
        }
        cleanFields[spec.key] = normalized;
        continue;
      }
      cleanFields[spec.key] = value;
    }
    setFieldError("");
    onSubmit({
      overview: {
        title: title.trim(),
        category,
        subtitle: category === "login" ? (fields.username ?? "").trim() : category === "card" ? (fields.cardholder ?? "").trim() : "",
        urls: url.trim() ? [url.trim()] : [],
        favorite: initial?.overview.favorite ?? false,
        tags: initial?.overview.tags ?? [],
      },
      details: { fields: cleanFields, notes: notes.trim() || undefined },
    });
  };

  return (
    <Dialog open={open} onClose={onClose} title={editing ? "Edit item" : "New item"} wide>
      <form onSubmit={submit} className="space-y-5" noValidate>
        {!editing && (
          <div className="flex flex-wrap gap-2">
            {categories.map((c) => (
              <button
                key={c.code}
                type="button"
                onClick={() => setCategory(c.code)}
                className={`px-3.5 py-2 rounded-lg border text-sm transition-colors ${
                  category === c.code
                    ? "border-accent-border bg-accent-subtle text-accent font-semibold"
                    : "border-border text-muted-foreground hover:text-foreground hover:border-border-strong"
                }`}
              >
                {c.label}
              </button>
            ))}
          </div>
        )}

        <div className="space-y-1.5">
          <label htmlFor="item-title" className="field-label">Title</label>
          <input
            id="item-title"
            className="input"
            required
            autoFocus
            placeholder={category === "login" ? "Acme Bank" : category === "card" ? "Personal Visa" : "Give it a name"}
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            disabled={busy}
          />
        </div>

        {category === "login" && (
          <div className="space-y-1.5">
            <label htmlFor="item-url" className="field-label">Website</label>
            <input id="item-url" className="input" type="url" placeholder="https://acme-bank.com" value={url} onChange={(e) => setUrl(e.target.value)} disabled={busy} />
          </div>
        )}

        {specs.map((spec) => (
          <div key={spec.key} className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label htmlFor={`item-${spec.key}`} className="field-label">
                {spec.label}
              </label>
              {spec.generator && (
                <button
                  type="button"
                  onClick={() => setShowGenerator((v) => !v)}
                  className="text-xs text-accent hover:text-accent-active inline-flex items-center gap-1 transition-colors"
                >
                  <KeyIcon className="h-3.5 w-3.5" /> {showGenerator ? "Hide generator" : "Generate"}
                </button>
              )}
            </div>
            {spec.secret ? (
              <PasswordInput
                id={`item-${spec.key}`}
                name={spec.key}
                value={fields[spec.key] ?? ""}
                onChange={(v) => setFields((f) => ({ ...f, [spec.key]: v }))}
                placeholder={spec.placeholder}
                disabled={busy}
              />
            ) : (
              <input
                id={`item-${spec.key}`}
                className={`input${spec.totp ? " font-mono" : ""}`}
                placeholder={spec.placeholder}
                autoComplete={spec.totp ? "off" : undefined}
                spellCheck={spec.totp ? false : undefined}
                value={fields[spec.key] ?? ""}
                onChange={(e) => {
                  if (spec.totp) setFieldError("");
                  setFields((f) => ({ ...f, [spec.key]: e.target.value }));
                }}
                disabled={busy}
              />
            )}
            {spec.hint && <p className="text-xs text-muted-foreground leading-relaxed">{spec.hint}</p>}
            {spec.totp && <FieldError touched error={fieldError} />}
            {spec.generator && showGenerator && (
              <GeneratorPanel
                onUse={(password) => {
                  setFields((f) => ({ ...f, [spec.key]: password }));
                  setShowGenerator(false);
                }}
              />
            )}
          </div>
        ))}

        <div className="space-y-1.5">
          <label htmlFor="item-notes" className="field-label">
            Notes {category !== "secure_note" && <span className="normal-case font-normal">(optional)</span>}
          </label>
          <textarea
            id="item-notes"
            className="input resize-none"
            rows={category === "secure_note" ? 8 : 3}
            placeholder={category === "secure_note" ? "Anything you'd rather keep sealed…" : "Extra context"}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            disabled={busy}
          />
        </div>

        <div className="flex items-center justify-end gap-3 pt-1">
          <button type="button" onClick={onClose} disabled={busy} className="btn btn-ghost">Cancel</button>
          <button type="submit" disabled={busy || !title.trim()} className="btn btn-primary px-7">
            {busy ? "Sealing…" : editing ? "Save changes" : "Seal item"}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
