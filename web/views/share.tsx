import React, { useEffect, useState } from "react";
import { AlertIcon, GlobeIcon, VaultMark } from "../components/icons";
import { PlainRow, SecretRow, TotpRow, categoryIcon } from "../components/vault/item-detail";
import { postJSON } from "../lib/api";
import { open as openEnvelope, openJSON, parseLinkFragment, type ItemDetails, type ItemOverview } from "../lib/crypto";
import { CATEGORY_FIELDS } from "../types/vault";
import type { ShareOpenResponse } from "../types/share";

// The public share viewer. The URL fragment carries "<token>.<share key>":
// the token is POSTed to fetch ciphertext, the share key never leaves this
// browser. Decryption failing (tampered link, wrong key) and the server
// refusing (expired, revoked) both land on the same friendly error.

type ShareState =
  | { phase: "loading" }
  | { phase: "error"; message: string }
  | { phase: "open"; overview: ItemOverview; details: ItemDetails; expiresAt: string };

const LINK_PROBLEM =
  "This share link is invalid, expired or revoked. Ask the person who sent it for a fresh one.";

function ShareApp() {
  const [state, setState] = useState<ShareState>({ phase: "loading" });

  useEffect(() => {
    (async () => {
      const parsed = parseLinkFragment(window.location.hash);
      if (!parsed) {
        setState({ phase: "error", message: "This link is incomplete — the part after # is missing or damaged. Check that the whole link was copied." });
        return;
      }
      try {
        const res = await postJSON<ShareOpenResponse>("/api/v1/share/open", { token: parsed.token });
        if (!res.ok || !res.data) {
          setState({ phase: "error", message: LINK_PROBLEM });
          return;
        }
        const itemKey = await openEnvelope(parsed.linkKeyRaw, res.data.wrappedItemKey);
        const overview = await openJSON<ItemOverview>(itemKey, res.data.overview);
        const details = await openJSON<ItemDetails>(itemKey, res.data.details);
        setState({ phase: "open", overview, details, expiresAt: res.data.expiresAt });
      } catch {
        setState({ phase: "error", message: LINK_PROBLEM });
      }
    })();
  }, []);

  if (state.phase === "loading") {
    return (
      <div className="panel p-12 text-center animate-unseal">
        <VaultMark className="h-11 w-11 text-accent mx-auto mb-4 keyhole-ring" />
        <p className="text-sm text-muted-foreground font-mono">unsealing the shared item…</p>
      </div>
    );
  }

  if (state.phase === "error") {
    return (
      <div className="panel p-10 text-center animate-pop">
        <div className="w-12 h-12 rounded-xl bg-accent-subtle text-danger flex items-center justify-center mx-auto mb-5">
          <AlertIcon className="h-6 w-6" />
        </div>
        <h1 className="text-xl font-bold tracking-tight mb-2">Nothing to unseal</h1>
        <p className="text-sm text-muted-foreground leading-relaxed max-w-sm mx-auto">{state.message}</p>
      </div>
    );
  }

  const { overview, details, expiresAt } = state;
  const specs = CATEGORY_FIELDS[overview.category] ?? [];
  const url = overview.urls?.[0];
  const expiry = new Date(expiresAt);

  return (
    <div className="animate-unseal">
      <p className="eyebrow mb-4">Shared securely with you</p>

      <div className="panel p-6 sm:p-8">
        <div className="flex items-center gap-3.5 mb-5">
          <div className="w-11 h-11 rounded-xl bg-accent-subtle text-accent flex items-center justify-center flex-shrink-0">
            {categoryIcon(overview.category, "h-5 w-5")}
          </div>
          <div className="min-w-0">
            <h1 className="text-xl font-bold tracking-tight text-foreground truncate">{overview.title}</h1>
            {overview.subtitle && <p className="text-sm text-muted-foreground truncate">{overview.subtitle}</p>}
          </div>
        </div>

        {url && (
          <a
            href={url.startsWith("http") ? url : `https://${url}`}
            target="_blank"
            rel="noreferrer noopener"
            className="inline-flex items-center gap-2 text-sm text-accent hover:text-accent-active transition-colors mb-4"
          >
            <GlobeIcon className="h-4 w-4" /> {url}
          </a>
        )}

        <div className="card px-5 py-1">
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
              <p className="text-xs font-semibold tracking-widest uppercase text-muted-foreground mb-1.5">Notes</p>
              <p className="text-sm text-foreground whitespace-pre-wrap leading-relaxed">{details.notes}</p>
            </div>
          )}
          {!details.notes && specs.every((s) => !details.fields[s.key]) && (
            <p className="py-4 text-sm text-muted-foreground">Nothing stored in this item.</p>
          )}
        </div>

        <p className="mt-5 text-xs text-muted-foreground font-mono">
          link expires {expiry.toLocaleDateString()} {expiry.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
        </p>
      </div>

      <div className="mt-8 card p-5 flex flex-col sm:flex-row items-start sm:items-center gap-4">
        <VaultMark className="h-8 w-8 text-accent flex-shrink-0" />
        <p className="text-sm text-muted-foreground leading-relaxed flex-1">
          This item was decrypted in your browser — the key travelled in the link itself and never reached Vault3's servers.
        </p>
        <a href="/join" className="btn btn-primary text-sm whitespace-nowrap">Create your vault</a>
      </div>
    </div>
  );
}

_bungoRender(ShareApp, "share-root");
