import React, { useEffect, useState } from "react";
import { AlertIcon, UsersIcon, VaultMark } from "../components/icons";
import { LockScreen } from "../components/vault/lock-screen";
import { postJSON } from "../lib/api";
import {
  open as openEnvelope,
  openJSON,
  parseLinkFragment,
  seal,
  type VaultName,
} from "../lib/crypto";
import { addVaultKey, loadKeys, type UnlockedKeys } from "../lib/keystore";
import type { InviteAcceptResponse, InvitePageData, InvitePreviewResponse } from "../types/invite";

// The vault invite accept flow. The URL fragment carries "<token>.<invite
// key>"; the invite key opens the vault key, which lets the visitor read the
// vault's name BEFORE accepting, then re-wrap that key under their own
// key-encryption key. The server never sees any of those keys — accepting
// hands it one opaque envelope.

const INVITE_PROBLEM =
  "This invite is invalid, expired, revoked or already used. Ask the vault owner for a fresh one.";

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
    <div className="panel p-10 text-center animate-pop">
      <div className="w-12 h-12 rounded-xl bg-accent-subtle text-danger flex items-center justify-center mx-auto mb-5">
        <AlertIcon className="h-6 w-6" />
      </div>
      <h1 className="text-xl font-bold tracking-tight mb-2">Can't open this invite</h1>
      <p className="text-sm text-muted-foreground leading-relaxed max-w-sm mx-auto">{message}</p>
      <a href="/app" className="btn btn-secondary text-sm mt-6">Go to your vault</a>
    </div>
  );
}

function InviteApp() {
  const data = useBungoData() as InvitePageData;
  const email = data.Viewer?.User.email ?? "";

  const [keys, setKeys] = useState<UnlockedKeys | null>(() => loadKeys());
  const [state, setState] = useState<InviteState>({ phase: "loading" });
  const [busy, setBusy] = useState(false);
  const [acceptError, setAcceptError] = useState("");

  const signedIn = Boolean(data.Viewer);
  const unlocked = Boolean(keys);

  // Preview once signed in and unlocked: fetch the wrapped vault key and
  // decrypt the vault's name locally with the fragment's invite key.
  useEffect(() => {
    if (!signedIn || !unlocked) return;
    (async () => {
      const parsed = parseLinkFragment(window.location.hash);
      if (!parsed) {
        setState({ phase: "error", message: "This link is incomplete — the part after # is missing or damaged. Check that the whole link was copied." });
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
    setBusy(true);
    setAcceptError("");
    try {
      const wrappedKey = await seal(keys.encKey, state.vaultKeyRaw);
      const res = await postJSON<InviteAcceptResponse>("/api/v1/vaults/invites/accept", {
        token: state.token,
        wrappedKey,
      });
      if (!res.ok || !res.data) {
        const message = (res.data as { message?: string } | null)?.message;
        setAcceptError(message ?? "Accepting didn't work. Try again.");
        return;
      }
      addVaultKey(state.vaultId, state.vaultKeyRaw);
      setState({ phase: "accepted", vaultName: state.vaultName });
      window.setTimeout(() => {
        window.location.href = "/app";
      }, 1200);
    } catch {
      setAcceptError("Network error. Try again.");
    } finally {
      setBusy(false);
    }
  };

  // ── Gates ─────────────────────────────────────────────────────────────────

  if (!signedIn) {
    return (
      <Shell>
        <div className="panel p-10 text-center animate-pop">
          <VaultMark className="h-11 w-11 text-accent mx-auto mb-5 mark-pulse" />
          <h1 className="text-xl font-bold tracking-tight mb-2">You've been invited to a shared vault</h1>
          <p className="text-sm text-muted-foreground leading-relaxed max-w-sm mx-auto mb-6">
            Sign in to see the invitation. If you don't have a Vault3 account yet, create one first — then open this
            link again.
          </p>
          <div className="flex items-center justify-center gap-3">
            <a href="/login" className="btn btn-primary text-sm px-6">Sign in</a>
            <a href="/join" className="btn btn-secondary text-sm px-6">Create account</a>
          </div>
          <p className="mt-5 text-xs text-muted-foreground">Keep this tab open, or reopen the invite link afterwards.</p>
        </div>
      </Shell>
    );
  }

  if (!unlocked) {
    if (!data.Keyset) {
      return <ErrorCard message="This account has no vault keys yet, so it can't accept invites." />;
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
        <div className="panel p-12 text-center">
          <VaultMark className="h-11 w-11 text-accent mx-auto mb-4 mark-pulse" />
          <p className="text-sm text-muted-foreground font-mono">unsealing the invitation…</p>
        </div>
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
        <div className="panel p-10 text-center animate-pop">
          <VaultMark className="h-11 w-11 text-accent mx-auto mb-5" />
          <h1 className="text-xl font-bold tracking-tight mb-2">
            Welcome to <span className="text-gradient">{state.vaultName}</span>
          </h1>
          <p className="text-sm text-muted-foreground">Taking you to your vault…</p>
        </div>
      </Shell>
    );
  }

  const expiry = new Date(state.expiresAt);
  return (
    <Shell>
      <p className="eyebrow mb-4">Vault invitation</p>
      <div className="panel p-8 animate-pop">
        <div className="flex items-center gap-4 mb-6">
          <div className="w-12 h-12 rounded-xl bg-accent-subtle text-accent flex items-center justify-center flex-shrink-0">
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
            <a href="/app" className="btn btn-primary text-sm px-6">Open your vault</a>
          </>
        ) : (
          <>
            <p className="text-sm text-muted-foreground leading-relaxed mb-6">
              Accepting gives you <strong className="text-foreground">view access</strong>: you'll be able to open and
              read every item in this vault, but not change anything. The vault key was decrypted here in your browser
              and will be resealed under your own keys — Vault3's servers never see it.
            </p>
            {acceptError && (
              <div className="animate-shake flex items-start gap-2 text-sm rounded-md border border-danger px-3 py-2.5 text-danger mb-4" role="alert" style={{ background: "var(--danger-subtle)" }}>
                <AlertIcon className="h-4 w-4 mt-0.5 flex-shrink-0" />
                <span>{acceptError}</span>
              </div>
            )}
            <div className="flex items-center gap-3">
              <button type="button" onClick={accept} disabled={busy} className="btn btn-primary text-sm px-6">
                {busy ? "Sealing your access…" : "Accept invitation"}
              </button>
              <a href="/app" className="btn btn-ghost text-sm">Not now</a>
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
