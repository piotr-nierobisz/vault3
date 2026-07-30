import React, { useEffect, useState } from "react";
import { AlertIcon, UsersIcon } from "../components/icons";
import { ErrorBanner } from "../components/ui/error-banner";
import { Loading } from "../components/ui/loading";
import { StatusPanel } from "../components/ui/status-panel";
import { LockScreen } from "../components/vault/lock-screen";
import { postJSON } from "../lib/api";
import {
  open as openEnvelope,
  openJSON,
  consumeLinkFragment,
  seal,
  type VaultName,
} from "../lib/crypto";
import { addVaultKey, loadKeys, type UnlockedKeys } from "../lib/keystore";
import { useAction } from "../lib/use-action";
import type { InviteAcceptResponse, InvitePageData, InvitePreviewResponse } from "../types/invite";

// The vault invite accept flow. The URL fragment carries "<token>.<invite
// key>"; the invite key opens the vault key, which lets the visitor read the
// vault's name BEFORE accepting, then re-wrap that key under their own
// key-encryption key. The server never sees any of those keys — accepting
// hands it one opaque envelope.

const INVITE_PROBLEM =
  "This invite no longer works — it may have expired, been used already, or been withdrawn. Ask the vault's owner for a new one.";

type InviteState =
  | { phase: "loading" }
  | { phase: "error"; message: string }
  | {
      phase: "ready";
      token: string;
      vaultId: string;
      vaultKeyRaw: Uint8Array;
      vaultName: string;
      inviterEmail: string;
      memberCount: number;
      alreadyMember: boolean;
      expiresAt: string;
    }
  | { phase: "accepted"; vaultName: string };

function Shell({ children }: { children: React.ReactNode }) {
  return <div className="animate-unseal">{children}</div>;
}

function ErrorCard({ message }: { message: string }) {
  return (
    <StatusPanel icon={<AlertIcon className="h-6 w-6" />} tone="danger" title="Can't open this invite" body={message}>
      <a href="/app" className="btn btn-secondary btn-sm">Go to your vault</a>
    </StatusPanel>
  );
}

function InviteApp() {
  const data = useBungoData() as InvitePageData;
  const email = data.Viewer?.User.email ?? "";

  const [keys, setKeys] = useState<UnlockedKeys | null>(() => loadKeys());
  const [state, setState] = useState<InviteState>({ phase: "loading" });
  const [acceptError, setAcceptError] = useState("");
  const { busy, run } = useAction({ onError: setAcceptError, network: "Network error. Try again." });

  const signedIn = Boolean(data.Viewer);
  const unlocked = Boolean(keys);

  // Preview once signed in and unlocked: fetch the wrapped vault key and
  // decrypt the vault's name locally with the fragment's invite key.
  useEffect(() => {
    if (!signedIn || !unlocked) return;
    (async () => {
      const parsed = consumeLinkFragment();
      if (!parsed) {
        setState({ phase: "error", message: "Part of this link is missing — the piece after the # is what unlocks it. Ask for the whole link again, and copy it in one go." });
        return;
      }
      try {
        const res = await postJSON<InvitePreviewResponse>("/api/v1/vaults/invites/preview", { token: parsed.token });
        if (!res.ok || !res.data) {
          setState({ phase: "error", message: INVITE_PROBLEM });
          return;
        }
        const vaultKeyRaw = await openEnvelope(parsed.linkKeyRaw, res.data.wrappedVaultKey);
        const vaultName = (await openJSON<VaultName>(vaultKeyRaw, res.data.encName)).name || "Sealed vault";
        setState({
          phase: "ready",
          token: parsed.token,
          vaultId: res.data.vaultId,
          vaultKeyRaw,
          vaultName,
          inviterEmail: res.data.inviterEmail,
          memberCount: res.data.memberCount,
          alreadyMember: res.data.alreadyMember,
          expiresAt: res.data.expiresAt,
        });
      } catch {
        setState({ phase: "error", message: INVITE_PROBLEM });
      }
    })();
  }, [signedIn, unlocked]);

  const accept = async () => {
    if (state.phase !== "ready" || !keys) return;
    setAcceptError("");
    const invite = state;
    const { encKey } = keys;
    await run(
      async () => {
        const wrappedKey = await seal(encKey, invite.vaultKeyRaw);
        return postJSON<InviteAcceptResponse>("/api/v1/vaults/invites/accept", {
          token: invite.token,
          wrappedKey,
        });
      },
      {
        onOK: () => {
          addVaultKey(invite.vaultId, invite.vaultKeyRaw);
          setState({ phase: "accepted", vaultName: invite.vaultName });
          window.setTimeout(() => {
            window.location.href = "/app";
          }, 1200);
        },
        fail: "Accepting didn't work. Try again.",
      },
    );
  };

  // ── Gates ─────────────────────────────────────────────────────────────────

  if (!signedIn) {
    return (
      <Shell>
        <StatusPanel
          mark
          pulse
          title="You've been invited to a shared vault"
          body="Sign in to see the invitation. If you don't have a Vault3 account yet, create one first, then open this link again."
        >
          <div className="flex items-center justify-center gap-3">
            <a href="/login" className="btn btn-primary btn-sm px-6">Sign in</a>
            <a href="/join" className="btn btn-secondary btn-sm px-6">Create account</a>
          </div>
          <p className="mt-5 text-xs text-muted-foreground">Keep this tab open, or reopen the invite link afterwards.</p>
        </StatusPanel>
      </Shell>
    );
  }

  if (!unlocked) {
    if (!data.Keyset) {
      return <ErrorCard message="Your own vault isn't set up yet, so there is nothing to add this one to. Open your vault once, then come back to this link." />;
    }
    return (
      <LockScreen
        keyset={data.Keyset}
        email={email}
        onUnlocked={(encKey, vaultKeys) => setKeys({ encKey, vaultKeys })}
      />
    );
  }

  if (state.phase === "loading") {
    return (
      <Shell>
        <StatusPanel mark pulse body={<Loading label="unsealing the invitation…" />} />
      </Shell>
    );
  }

  if (state.phase === "error") {
    return (
      <Shell>
        <ErrorCard message={state.message} />
      </Shell>
    );
  }

  if (state.phase === "accepted") {
    return (
      <Shell>
        <StatusPanel
          mark
          title={<>Welcome to <span className="text-gradient">{state.vaultName}</span></>}
          body="Taking you to your vault…"
        />
      </Shell>
    );
  }

  const expiry = new Date(state.expiresAt);
  return (
    <Shell>
      <p className="eyebrow mb-4">Vault invitation</p>
      <div className="panel p-8 animate-pop">
        <div className="flex items-center gap-4 mb-6">
          <div className="icon-tile icon-tile-lg flex-shrink-0">
            <UsersIcon className="h-6 w-6" />
          </div>
          <div className="min-w-0">
            <h1 className="text-xl font-bold tracking-tight truncate">{state.vaultName}</h1>
            <p className="text-sm text-muted-foreground truncate">
              {state.inviterEmail ? `${state.inviterEmail} invited you` : "You've been invited"} ·{" "}
              {state.memberCount} {state.memberCount === 1 ? "person" : "people"} so far
            </p>
          </div>
        </div>

        {state.alreadyMember ? (
          <>
            <p className="text-sm text-muted-foreground leading-relaxed mb-6">
              You already have access to this vault, so there's nothing to accept.
            </p>
            <a href="/app" className="btn btn-primary btn-sm px-6">Open your vault</a>
          </>
        ) : (
          <>
            <p className="text-sm text-muted-foreground leading-relaxed mb-6">
              Accepting gives you <strong className="text-foreground">read-only access</strong>: you can open and read
              every item in this vault, but not change anything. The key to it was unlocked here in your browser and is
              locked again with your own — it never passes through Vault3 in a readable form.
            </p>
            {acceptError && <ErrorBanner message={acceptError} className="mb-4" />}
            <div className="flex items-center gap-3">
              <button type="button" onClick={accept} disabled={busy} className="btn btn-primary btn-sm px-6">
                {busy ? "Sealing your access…" : "Accept invitation"}
              </button>
              <a href="/app" className="btn btn-ghost btn-sm">Not now</a>
            </div>
            <p className="mt-5 text-xs text-muted-foreground font-mono">
              invite expires {expiry.toLocaleDateString()}
            </p>
          </>
        )}
      </div>
    </Shell>
  );
}

_bungoRender(InviteApp, "invite-root");
