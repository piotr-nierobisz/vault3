import React, { useEffect, useState } from "react";
import { AlertIcon, VaultMark } from "../components/icons";
import { Loading } from "../components/ui/loading";
import { StatusPanel } from "../components/ui/status-panel";
import { ItemFieldsCard, ItemHeading, ItemUrlLink } from "../components/vault/item-detail";
import { postJSON } from "../lib/api";
import { consumeLinkFragment, open as openEnvelope, openJSON, type ItemDetails, type ItemOverview } from "../lib/crypto";
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
  "This link no longer works — it may have expired, or been switched off by whoever sent it. Ask them for a fresh one.";

function ShareApp() {
  const [state, setState] = useState<ShareState>({ phase: "loading" });

  useEffect(() => {
    (async () => {
      const parsed = consumeLinkFragment();
      if (!parsed) {
        setState({ phase: "error", message: "Part of this link is missing — the piece after the # is what unlocks it. Ask for the whole link again, and copy it in one go." });
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
    return <StatusPanel mark pulse body={<Loading label="unsealing the shared item…" />} />;
  }

  if (state.phase === "error") {
    return (
      <StatusPanel
        icon={<AlertIcon className="h-6 w-6" />}
        tone="danger"
        title="Nothing to unseal"
        body={state.message}
      />
    );
  }

  const { overview, details, expiresAt } = state;
  const url = overview.urls?.[0];
  const expiry = new Date(expiresAt);

  return (
    <div className="animate-unseal">
      <p className="eyebrow mb-4">Shared securely with you</p>

      <div className="panel p-6 sm:p-8">
        <div className="mb-5">
          <ItemHeading overview={overview} as="h1" />
        </div>

        {url && <ItemUrlLink url={url} />}

        <ItemFieldsCard category={overview.category} details={details} />

        <p className="mt-5 text-xs text-muted-foreground font-mono">
          link expires {expiry.toLocaleDateString()} {expiry.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
        </p>
      </div>

      <div className="mt-8 card p-5 flex flex-col sm:flex-row items-start sm:items-center gap-4">
        <VaultMark className="h-8 w-8 text-accent flex-shrink-0" />
        <p className="text-sm text-muted-foreground leading-relaxed flex-1">
          This was unlocked here in your browser. The key came inside the link you followed, and never reached Vault3 at all — so we cannot see what you are looking at.
        </p>
        <a href="/join" className="btn btn-primary btn-sm whitespace-nowrap">Create your vault</a>
      </div>
    </div>
  );
}

_bungoRender(ShareApp, "share-root");
