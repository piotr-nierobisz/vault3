import React, { useEffect, useState } from "react";
import { AlertIcon, LinkIcon, TrashIcon } from "../icons";
import { CopyButton } from "../ui/copy-button";
import { Dialog } from "../ui/dialog";
import { getJSON, postJSON } from "../../lib/api";
import { composeLinkFragment, mintLinkKey, openJSON, seal, type ItemDetails } from "../../lib/crypto";
import { CATEGORY_FIELDS, type DecryptedItem, type ShareCreateResponse, type ShareLinkDto } from "../../types/vault";

// The per-item share dialog. Creating a link mints a random share key HERE,
// re-wraps the item's key under it, and sends only that wrap — the full URL
// (with the key in its fragment) exists once, on this screen, and can never
// be reconstructed later. Revoking kills the server's half.

const EXPIRY_OPTIONS = [
  { hours: 1, label: "1 hour" },
  { hours: 24, label: "24 hours" },
  { hours: 168, label: "7 days" },
  { hours: 720, label: "30 days" },
];

function linkStatus(link: ShareLinkDto): { label: string; dead: boolean } {
  if (link.revoked) return { label: "revoked", dead: true };
  const expiry = new Date(link.expiresAt);
  if (expiry.getTime() <= Date.now()) return { label: "expired", dead: true };
  return { label: `expires ${expiry.toLocaleDateString()}`, dead: false };
}

export function ShareDialog({
  item,
  open,
  onClose,
  notify,
}: {
  item: DecryptedItem;
  open: boolean;
  onClose: () => void;
  notify: (kind: "success" | "error" | "info", message: string) => void;
}) {
  const [links, setLinks] = useState<ShareLinkDto[] | null>(null);
  const [hours, setHours] = useState(24);
  const [busy, setBusy] = useState(false);
  const [freshLink, setFreshLink] = useState("");
  const [sharesSeed, setSharesSeed] = useState(false);

  useEffect(() => {
    if (!open) return;
    setFreshLink("");
    setLinks(null);
    getJSON<{ links: ShareLinkDto[] }>(`/api/v1/shares?itemId=${encodeURIComponent(item.row.id)}`).then((res) => {
      setLinks(res.ok && res.data ? res.data.links : []);
    });
  }, [open, item.row.id]);

  // A share link points at the live details blob, so every field in it goes —
  // including a one-time-code seed. That cannot be redacted without breaking
  // the link's whole design, so it gets said out loud before the link exists.
  useEffect(() => {
    if (!open) {
      setSharesSeed(false);
      return;
    }
    let cancelled = false;
    const totpKeys = (CATEGORY_FIELDS[item.overview.category] ?? []).filter((s) => s.totp).map((s) => s.key);
    if (!totpKeys.length) return;
    openJSON<ItemDetails>(item.itemKey, item.row.details)
      .then((details) => {
        if (!cancelled) setSharesSeed(totpKeys.some((key) => Boolean(details.fields[key])));
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [open, item]);

  const createLink = async () => {
    setBusy(true);
    try {
      const shareKey = mintLinkKey();
      const wrappedItemKey = await seal(shareKey, item.itemKey);
      const res = await postJSON<ShareCreateResponse>("/api/v1/shares/create", {
        itemId: item.row.id,
        wrappedItemKey,
        expiresInHours: hours,
      });
      if (!res.ok || !res.data) {
        const message = (res.data as { message?: string } | null)?.message;
        notify("error", message ?? "Couldn't create the share link.");
        return;
      }
      const url = `${window.location.origin}/share#${composeLinkFragment(res.data.token, shareKey)}`;
      setFreshLink(url);
      setLinks((prev) => (prev ? [res.data!.link, ...prev] : [res.data!.link]));
      try {
        await navigator.clipboard.writeText(url);
        notify("success", "Share link copied to your clipboard");
      } catch {
        notify("info", "Share link created — copy it below");
      }
    } catch {
      notify("error", "Network error. Try again.");
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (link: ShareLinkDto) => {
    const res = await postJSON<{ ok: boolean }>("/api/v1/shares/revoke", { id: link.id });
    if (!res.ok) {
      notify("error", "Couldn't revoke that link.");
      return;
    }
    setLinks((prev) => prev?.map((l) => (l.id === link.id ? { ...l, revoked: true } : l)) ?? null);
    notify("success", "Link revoked — it stops working immediately");
  };

  return (
    <Dialog open={open} onClose={onClose} title={`Share "${item.overview.title}"`}>
      <p className="text-sm text-muted-foreground leading-relaxed mb-5">
        Anyone with the link can view this item until it expires or you revoke it. The decryption key travels{" "}
        <strong className="text-foreground">inside the link</strong> and never touches Vault3's servers.
      </p>

      {sharesSeed && (
        <div
          className="flex items-start gap-2 text-sm rounded-md border px-3 py-2.5 mb-5 leading-relaxed"
          style={{ background: "var(--warning-subtle)", borderColor: "var(--warning)", color: "var(--warning-fg)" }}
          role="note"
        >
          <AlertIcon className="h-4 w-4 mt-0.5 flex-shrink-0" />
          <span>
            This item stores a one-time-code key. A share link hands over{" "}
            <strong>both factors</strong> for that account — the password and the ability to generate its codes.
          </span>
        </div>
      )}

      <div className="flex items-end gap-3 mb-2">
        <div className="flex-1 space-y-1.5">
          <label htmlFor="share-expiry" className="text-xs font-semibold tracking-widest uppercase text-muted-foreground">
            Link lifetime
          </label>
          <select id="share-expiry" className="input" value={hours} onChange={(e) => setHours(Number(e.target.value))} disabled={busy}>
            {EXPIRY_OPTIONS.map((o) => (
              <option key={o.hours} value={o.hours}>
                {o.label}
              </option>
            ))}
          </select>
        </div>
        <button type="button" onClick={createLink} disabled={busy} className="btn btn-primary text-sm whitespace-nowrap">
          <LinkIcon className="h-4 w-4" /> {busy ? "Sealing…" : "Create link"}
        </button>
      </div>

      {freshLink && (
        <div className="animate-pop mt-4 rounded-lg border border-accent-border p-3" style={{ background: "var(--accent-subtle)" }}>
          <p className="text-xs font-semibold tracking-widest uppercase text-accent mb-2">Your new link — visible only now</p>
          <div className="flex items-center gap-2">
            <code className="font-mono text-xs text-foreground break-all flex-1 select-all">{freshLink}</code>
            <CopyButton value={freshLink} label="Copy share link" />
          </div>
        </div>
      )}

      <div className="mt-6">
        <p className="text-xs font-semibold tracking-widest uppercase text-muted-foreground mb-2">Links for this item</p>
        {links === null && <p className="text-sm text-muted-foreground font-mono py-2">loading…</p>}
        {links !== null && links.length === 0 && <p className="text-sm text-muted-foreground py-2">No share links yet.</p>}
        {links !== null && links.length > 0 && (
          <ul className="divide-y divide-border-subtle">
            {links.map((link) => {
              const status = linkStatus(link);
              return (
                <li key={link.id} className="py-2.5 flex items-center gap-3">
                  <LinkIcon className={`h-4 w-4 flex-shrink-0 ${status.dead ? "text-muted-foreground" : "text-accent"}`} />
                  <div className="flex-1 min-w-0">
                    <p className={`text-sm ${status.dead ? "text-muted-foreground line-through" : "text-foreground"}`}>
                      created {new Date(link.createdAt).toLocaleDateString()}
                    </p>
                    <p className="text-xs text-muted-foreground font-mono">
                      {status.label} · {link.viewCount} {link.viewCount === 1 ? "view" : "views"}
                    </p>
                  </div>
                  {!status.dead && (
                    <button
                      type="button"
                      onClick={() => revoke(link)}
                      className="p-1.5 rounded-md text-muted-foreground hover:text-danger hover:bg-muted transition-colors"
                      aria-label="Revoke link"
                      title="Revoke link"
                    >
                      <TrashIcon className="h-4 w-4" />
                    </button>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </Dialog>
  );
}
