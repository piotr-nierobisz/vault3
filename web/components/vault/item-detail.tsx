import React, { useEffect, useMemo, useState } from "react";
import { CardIcon, GlobeIcon, IdentityIcon, KeyIcon, NoteIcon, RestoreIcon, ShareIcon, StarIcon, TrashIcon } from "../icons";
import { CopyButton, useCopy } from "../ui/copy-button";
import { Loading } from "../ui/loading";
import { SecretText } from "../ui/secret-text";
import { EyeIcon, EyeOffIcon } from "../icons";
import { openJSON, type ItemDetails, type ItemOverview } from "../../lib/crypto";
import { formatTotpCode, parseTotp, totpCode, totpRemaining } from "../../lib/totp";
import { CATEGORY_FIELDS, type DecryptedItem } from "../../types/vault";

// The detail pane: opens the details blob on demand with the item's key,
// renders per-category fields with blur-until-reveal and copy. Secrets stay
// out of the DOM until revealed or copied.

export function categoryIcon(code: string, className: string) {
  switch (code) {
    case "secure_note":
      return <NoteIcon className={className} />;
    case "card":
      return <CardIcon className={className} />;
    case "identity":
      return <IdentityIcon className={className} />;
    default:
      return <KeyIcon className={className} />;
  }
}

// RowLabel doubles as the copy confirmation: the field name flips to
// "Copied" for a moment instead of a toast, so the feedback lands where the
// eye already is.
function RowLabel({ label, copied }: { label: string; copied: boolean }) {
  return (
    <p
      className="field-label mb-1 transition-colors"
      style={{ color: copied ? "var(--success)" : "var(--muted-foreground)" }}
    >
      {copied ? "Copied" : label}
    </p>
  );
}

export function SecretRow({ label, value }: { label: string; value: string }) {
  const [revealed, setRevealed] = useState(false);
  const { copied, copy } = useCopy();
  return (
    <div className="py-3 border-b border-border-subtle last:border-0">
      <RowLabel label={label} copied={copied} />
      <div className="flex items-center gap-2">
        {/* The value itself copies. Masked or revealed makes no difference —
            copying has never required putting the secret on screen. The mask
            stays plain: bullets are not the secret's characters, so tinting
            them would invent a pattern that isn't there. */}
        <button
          type="button"
          onClick={() => copy(value)}
          title={`Copy ${label.toLowerCase()}`}
          className={`text-sm flex-1 text-left cursor-pointer rounded-sm min-w-0 secret-blur ${revealed ? "is-revealed" : ""}`}
        >
          {revealed ? (
            <SecretText value={value} className="text-sm break-all" />
          ) : (
            <span className="font-mono text-foreground">••••••••••••••••</span>
          )}
        </button>
        <button
          type="button"
          aria-label={revealed ? "Conceal" : "Reveal"}
          onClick={() => setRevealed((v) => !v)}
          className="btn-icon"
        >
          {revealed ? <EyeOffIcon className="h-4 w-4" /> : <EyeIcon className="h-4 w-4" />}
        </button>
        <CopyButton value={value} label={`Copy ${label.toLowerCase()}`} />
      </div>
    </div>
  );
}

// TotpRow: the live one-time code for a stored seed. Everything here is
// local — the seed came out of the item's sealed details blob and the code is
// HMAC'd in this tab. The code is deliberately shown in the clear rather than
// blurred: it is useless in 30 seconds, and the point is to read it at a
// glance. Copy always yields the ungrouped digits.
export function TotpRow({ label, value }: { label: string; value: string }) {
  const config = useMemo(() => parseTotp(value), [value]);
  const [code, setCode] = useState("");
  const [remaining, setRemaining] = useState(0);
  const { copied, copy } = useCopy();

  useEffect(() => {
    if (!config) return;
    let cancelled = false;
    let timer = 0;

    // Recomputing every second rather than only on window boundaries costs a
    // sub-millisecond HMAC and means a tab that slept through a rollover
    // still wakes showing the right code.
    const tick = () => {
      const now = Date.now();
      totpCode(config, now)
        .then((next) => {
          if (cancelled) return;
          setCode(next);
          setRemaining(totpRemaining(config, now));
          timer = window.setTimeout(tick, 1000);
        })
        .catch(() => {
          if (!cancelled) setCode("");
        });
    };
    tick();

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [config]);

  if (!config) {
    return (
      <div className="py-3 border-b border-border-subtle last:border-0">
        <p className="field-label mb-1">{label}</p>
        <p className="text-sm text-muted-foreground">This one-time-code seed couldn't be read. Edit the item to re-enter it.</p>
      </div>
    );
  }

  const fraction = remaining / config.period;
  const urgent = remaining <= 5;
  const tone = urgent ? "var(--warning)" : "var(--accent)";
  const CIRCUMFERENCE = 2 * Math.PI * 9;

  return (
    <div className="py-3 border-b border-border-subtle last:border-0">
      <RowLabel label={label} copied={copied} />
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => copy(code)}
          title="Copy one-time code"
          className="font-mono text-lg tracking-[0.18em] flex-1 tabular-nums text-left cursor-pointer rounded-sm transition-colors"
          style={{ color: tone }}
          aria-label={code ? `Copy one-time code ${code.split("").join(" ")}` : "Computing one-time code"}
        >
          {code ? formatTotpCode(code) : "······"}
        </button>
        <span
          className="relative flex items-center justify-center flex-shrink-0"
          title={`Refreshes in ${remaining}s`}
          aria-hidden="true"
        >
          <svg viewBox="0 0 24 24" className="h-6 w-6 -rotate-90">
            <circle cx="12" cy="12" r="9" fill="none" stroke="var(--border)" strokeWidth="2.5" />
            <circle
              cx="12"
              cy="12"
              r="9"
              fill="none"
              stroke={tone}
              strokeWidth="2.5"
              strokeLinecap="round"
              strokeDasharray={CIRCUMFERENCE}
              strokeDashoffset={CIRCUMFERENCE * (1 - fraction)}
              style={{ transition: "stroke-dashoffset 1s linear, stroke 200ms" }}
            />
          </svg>
        </span>
        <CopyButton value={code} label="Copy one-time code" />
      </div>
    </div>
  );
}

export function PlainRow({ label, value, copyable }: { label: string; value: string; copyable?: boolean }) {
  return (
    <div className="py-3 border-b border-border-subtle last:border-0">
      <p className="field-label mb-1">{label}</p>
      <div className="flex items-center gap-2">
        <span className="text-sm text-foreground flex-1 break-all">{value}</span>
        {copyable && <CopyButton value={value} label={`Copy ${label.toLowerCase()}`} />}
      </div>
    </div>
  );
}

// The three blocks below are the item as the share page also renders it — a
// share link shows the same item to someone else, so they read from one
// definition rather than two copies drifting apart.

export function ItemHeading({ overview, as: Heading = "h2" }: { overview: ItemOverview; as?: "h1" | "h2" }) {
  return (
    <div className="flex items-center gap-3.5 min-w-0">
      <div className="icon-tile icon-tile-lg flex-shrink-0">{categoryIcon(overview.category, "h-5 w-5")}</div>
      <div className="min-w-0">
        <Heading className="text-xl font-bold tracking-tight text-foreground truncate">{overview.title}</Heading>
        {overview.subtitle && <p className="text-sm text-muted-foreground truncate">{overview.subtitle}</p>}
      </div>
    </div>
  );
}

export function ItemUrlLink({ url }: { url: string }) {
  return (
    <a
      href={url.startsWith("http") ? url : `https://${url}`}
      target="_blank"
      rel="noreferrer noopener"
      className="inline-flex items-center gap-2 text-sm text-accent hover:text-accent-active transition-colors mb-4"
    >
      <GlobeIcon className="h-4 w-4" /> {url}
    </a>
  );
}

export function ItemFieldsCard({
  category,
  details,
  failed,
  className,
}: {
  category: string;
  details: ItemDetails | null;
  failed?: boolean;
  className?: string;
}) {
  const specs = CATEGORY_FIELDS[category] ?? [];
  return (
    <div className={`card px-5 py-1${className ? ` ${className}` : ""}`}>
      {failed && <p className="py-4 text-sm text-danger">This item couldn't be decrypted with the current keys.</p>}
      {!details && !failed && <Loading />}
      {details && (
        <>
          {specs.map((spec) => {
            const value = details.fields[spec.key];
            if (!value) return null;
            // A shared item's blob is the live item's blob, so a seed stored
            // on it is already in the recipient's hands; rendering the code
            // is honest about that rather than hiding a field they hold.
            if (spec.totp) return <TotpRow key={spec.key} label={spec.label} value={value} />;
            return spec.secret ? (
              <SecretRow key={spec.key} label={spec.label} value={value} />
            ) : (
              <PlainRow key={spec.key} label={spec.label} value={value} copyable />
            );
          })}
          {details.notes && (
            <div className="py-3">
              <p className="field-label mb-1.5">Notes</p>
              <p className="text-sm text-foreground whitespace-pre-wrap leading-relaxed">{details.notes}</p>
            </div>
          )}
          {!details.notes && specs.every((s) => !details.fields[s.key]) && (
            <p className="py-4 text-sm text-muted-foreground">Nothing stored in this item.</p>
          )}
        </>
      )}
    </div>
  );
}

export function ItemDetail({
  item,
  onEdit,
  onToggleFavorite,
  onTrash,
  onRestore,
  onDeleteForever,
  onShare,
  readOnly,
  busy,
}: {
  item: DecryptedItem;
  onEdit: (details: ItemDetails) => void;
  onToggleFavorite: () => void;
  onTrash: () => void;
  onRestore: () => void;
  onDeleteForever: () => void;
  onShare?: () => void;
  readOnly?: boolean;
  busy?: boolean;
}) {
  const [details, setDetails] = useState<ItemDetails | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setDetails(null);
    setFailed(false);
    openJSON<ItemDetails>(item.itemKey, item.row.details)
      .then((opened) => {
        if (!cancelled) setDetails(opened);
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, [item]);

  const url = item.overview.urls?.[0];

  return (
    <div className="animate-unseal" key={item.row.id}>
      <div className="flex items-start justify-between gap-4 mb-5">
        <ItemHeading overview={item.overview} />
        {!item.row.trashed && !readOnly && (
          <button
            type="button"
            onClick={onToggleFavorite}
            disabled={busy}
            aria-label={item.overview.favorite ? "Remove from favourites" : "Add to favourites"}
            className={`p-2 rounded-md transition-colors ${item.overview.favorite ? "text-warning" : "text-muted-foreground hover:text-foreground hover:bg-muted"}`}
          >
            <StarIcon className="h-5 w-5" filled={item.overview.favorite} />
          </button>
        )}
      </div>

      {url && <ItemUrlLink url={url} />}

      <ItemFieldsCard category={item.overview.category} details={details} failed={failed} className="mb-5" />

      <div className="flex flex-wrap items-center gap-3">
        {readOnly ? (
          <span className="badge badge-accent-2" title="You have view access to this vault">
            <EyeIcon className="h-3.5 w-3.5" /> view only
          </span>
        ) : item.row.trashed ? (
          <>
            <button type="button" onClick={onRestore} disabled={busy} className="btn btn-secondary btn-sm">
              <RestoreIcon className="h-4 w-4" /> Restore
            </button>
            <button type="button" onClick={onDeleteForever} disabled={busy} className="btn btn-danger btn-sm">
              <TrashIcon className="h-4 w-4" /> Delete forever
            </button>
          </>
        ) : (
          <>
            <button type="button" onClick={() => details && onEdit(details)} disabled={busy || !details} className="btn btn-secondary btn-sm px-6">
              Edit
            </button>
            {onShare && (
              <button type="button" onClick={onShare} disabled={busy} className="btn btn-secondary btn-sm">
                <ShareIcon className="h-4 w-4" /> Share
              </button>
            )}
            <button type="button" onClick={onTrash} disabled={busy} className="btn btn-ghost btn-sm text-danger">
              <TrashIcon className="h-4 w-4" /> Move to trash
            </button>
          </>
        )}
        <span className="flex-1" />
        <p className="text-xs text-muted-foreground font-mono">
          edited {new Date(item.row.updatedAt).toLocaleDateString()}
        </p>
      </div>
    </div>
  );
}
