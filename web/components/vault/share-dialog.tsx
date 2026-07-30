import React, { useEffect, useState } from "react";
import { LinkIcon, TrashIcon } from "../icons";
import { Dialog } from "../ui/dialog";
import { ErrorBanner } from "../ui/error-banner";
import { FreshLinkCallout } from "../ui/fresh-link-callout";
import { Loading } from "../ui/loading";
import { getJSON, postJSON } from "../../lib/api";
import { composeLinkFragment, mintLinkKey, openJSON, seal, type ItemDetails } from "../../lib/crypto";
import { useAction } from "../../lib/use-action";
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
  const [freshLink, setFreshLink] = useState("");
  const [sharesSeed, setSharesSeed] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);
  const { busy, run } = useAction({ onError: (message) => notify("error", message), network: "Network error. Try again." });
  // Row actions take their own instance so revoking one link does not disable
  // the create controls; they still need the hook's catch and re-entry guard.
  const { run: runRow } = useAction({ onError: (message) => notify("error", message), network: "Network error. Try again." });

  useEffect(() => {
    if (!open) return;
    setFreshLink("");
    setLinks(null);
    setLoadFailed(false);
    getJSON<{ links: ShareLinkDto[] }>(`/api/v1/shares?itemId=${encodeURIComponent(item.row.id)}`)
      .then((res) => {
        // A failed load must not render as "no share links yet". This list's
        // whole job is to tell the user what is currently exposed so they can
        // revoke it — showing an empty one on a 500 is a lie in the dangerous
        // direction.
        if (res.ok && res.data) {
          setLinks(res.data.links);
          return;
        }
        setLinks([]);
        setLoadFailed(true);
      })
      .catch(() => {
        setLinks([]);
        setLoadFailed(true);
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
    // The share key stays here: the server is handed the wrap, the fragment
    // gets the key, and only this screen ever holds both.
    const shareKey = mintLinkKey();
    await run(
      async () => {
        const wrappedItemKey = await seal(shareKey, item.itemKey);
        return postJSON<ShareCreateResponse>("/api/v1/shares/create", {
          itemId: item.row.id,
          wrappedItemKey,
          expiresInHours: hours,
        });
      },
      {
        onOK: async (created) => {
          const url = `${window.location.origin}/share#${composeLinkFragment(created.token, shareKey)}`;
          setFreshLink(url);
          setLinks((prev) => (prev ? [created.link, ...prev] : [created.link]));
          try {
            await navigator.clipboard.writeText(url);
            notify("success", "Share link copied to your clipboard");
          } catch {
            notify("info", "Share link created — copy it below");
          }
        },
        fail: "Couldn't create the share link.",
      },
    );
  };

  const revoke = (link: ShareLinkDto) =>
    runRow(() => postJSON<{ ok: boolean }>("/api/v1/shares/revoke", { id: link.id }), {
      onOK: () => {
        setLinks((prev) => prev?.map((l) => (l.id === link.id ? { ...l, revoked: true } : l)) ?? null);
        notify("success", "Link revoked — it stops working immediately");
      },
      fail: "Couldn't revoke that link.",
    });

  return (
    <Dialog open={open} onClose={onClose} title={`Share "${item.overview.title}"`}>
      <p className="text-sm text-muted-foreground leading-relaxed mb-5">
        Anyone with the link can view this item until it expires or you revoke it. The decryption key travels{" "}
        <strong className="text-foreground">inside the link</strong> and never touches Vault3's servers.
      </p>

      {sharesSeed && (
        <ErrorBanner
          tone="warning"
          className="mb-5"
          message="This item stores a one-time-code key. A share link hands over"
        >
          {" "}
          <strong>both factors</strong> for that account — the password and the ability to generate its codes.
        </ErrorBanner>
      )}

      <div className="flex items-end gap-3 mb-2">
        <div className="flex-1 space-y-1.5">
          <label htmlFor="share-expiry" className="field-label">
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
        <button type="button" onClick={createLink} disabled={busy} className="btn btn-primary whitespace-nowrap">
          <LinkIcon className="h-4 w-4" /> {busy ? "Sealing…" : "Create link"}
        </button>
      </div>

      {freshLink && (
        <FreshLinkCallout label="Your new link — visible only now" value={freshLink} copyLabel="Copy share link" />
      )}

      <div className="mt-6">
        <p className="field-label mb-2">Links for this item</p>
        {links === null && <Loading />}
        {loadFailed && (
          <p className="text-sm text-danger py-2">
            Couldn't load this item's share links — so this list may not show everything that is currently shared. Close and reopen to retry.
          </p>
        )}
        {links !== null && !loadFailed && links.length === 0 && (
          <p className="text-sm text-muted-foreground py-2">No share links yet.</p>
        )}
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
                      className="btn-icon btn-icon-danger"
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
