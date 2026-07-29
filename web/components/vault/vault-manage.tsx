import React, { useEffect, useState } from "react";
import { LeaveIcon, LinkIcon, TrashIcon, UsersIcon, XIcon } from "../icons";
import { CopyButton } from "../ui/copy-button";
import { Dialog } from "../ui/dialog";
import { getJSON, postJSON } from "../../lib/api";
import { composeLinkFragment, mintLinkKey, seal, sealVaultName } from "../../lib/crypto";
import type {
  InviteCreateResponse,
  KeysetVaultDto,
  VaultInviteDto,
  VaultMemberDto,
  VaultMembersResponse,
} from "../../types/vault";

// The vault settings dialog: rename, people (members + invite links), and
// the danger zone. Owners see everything; members see the people list and a
// leave button. Invite links follow the share-link construction: the vault
// key sealed under a random invite key that lives only in the URL fragment.

export function VaultManageDialog({
  vault,
  vaultName,
  vaultKey,
  meEmail,
  open,
  onClose,
  onRenamed,
  onDeleted,
  onLeft,
  notify,
}: {
  vault: KeysetVaultDto;
  vaultName: string;
  vaultKey: Uint8Array | undefined;
  meEmail: string;
  open: boolean;
  onClose: () => void;
  onRenamed: (name: string) => void;
  onDeleted: () => void;
  onLeft: () => void;
  notify: (kind: "success" | "error" | "info", message: string) => void;
}) {
  const isOwner = vault.role === "owner";
  const [members, setMembers] = useState<VaultMemberDto[] | null>(null);
  const [invites, setInvites] = useState<VaultInviteDto[]>([]);
  const [name, setName] = useState(vaultName);
  const [busy, setBusy] = useState(false);
  const [freshInvite, setFreshInvite] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);

  useEffect(() => {
    if (!open) return;
    setName(vaultName);
    setFreshInvite("");
    setConfirmDelete(false);
    setMembers(null);
    getJSON<VaultMembersResponse>(`/api/v1/vaults/members?vaultId=${encodeURIComponent(vault.id)}`).then((res) => {
      if (res.ok && res.data) {
        setMembers(res.data.members);
        setInvites(res.data.invites);
      } else {
        setMembers([]);
      }
    });
  }, [open, vault.id, vaultName]);

  const rename = async () => {
    const trimmed = name.trim();
    if (!trimmed || !vaultKey || trimmed === vaultName) return;
    setBusy(true);
    try {
      const encName = await sealVaultName(vaultKey, trimmed);
      const res = await postJSON<{ ok: boolean }>("/api/v1/vaults/rename", { vaultId: vault.id, encName });
      if (!res.ok) {
        notify("error", "Couldn't rename the vault.");
        return;
      }
      onRenamed(trimmed);
      notify("success", "Vault renamed");
    } catch {
      notify("error", "Network error. Try again.");
    } finally {
      setBusy(false);
    }
  };

  const createInvite = async () => {
    if (!vaultKey) return;
    setBusy(true);
    try {
      const inviteKey = mintLinkKey();
      const wrappedVaultKey = await seal(inviteKey, vaultKey);
      const res = await postJSON<InviteCreateResponse>("/api/v1/vaults/invites/create", {
        vaultId: vault.id,
        wrappedVaultKey,
      });
      if (!res.ok || !res.data) {
        const message = (res.data as { message?: string } | null)?.message;
        notify("error", message ?? "Couldn't create the invite.");
        return;
      }
      const url = `${window.location.origin}/app/invite#${composeLinkFragment(res.data.token, inviteKey)}`;
      setFreshInvite(url);
      setInvites((prev) => [res.data!.invite, ...prev]);
      try {
        await navigator.clipboard.writeText(url);
        notify("success", "Invite link copied to your clipboard");
      } catch {
        notify("info", "Invite link created — copy it below");
      }
    } catch {
      notify("error", "Network error. Try again.");
    } finally {
      setBusy(false);
    }
  };

  const revokeInvite = async (invite: VaultInviteDto) => {
    const res = await postJSON<{ ok: boolean }>("/api/v1/vaults/invites/revoke", { id: invite.id });
    if (!res.ok) {
      notify("error", "Couldn't revoke that invite.");
      return;
    }
    setInvites((prev) => prev.filter((i) => i.id !== invite.id));
    notify("success", "Invite revoked");
  };

  const removeMember = async (member: VaultMemberDto) => {
    const res = await postJSON<{ ok: boolean }>("/api/v1/vaults/members/remove", {
      vaultId: vault.id,
      userId: member.userId,
    });
    if (!res.ok) {
      notify("error", "Couldn't remove that member.");
      return;
    }
    setMembers((prev) => prev?.filter((m) => m.userId !== member.userId) ?? null);
    notify("success", `${member.email} no longer has access`);
  };

  const leave = async () => {
    const me = members?.find((m) => m.email === meEmail);
    if (!me) return;
    setBusy(true);
    const res = await postJSON<{ ok: boolean }>("/api/v1/vaults/members/remove", {
      vaultId: vault.id,
      userId: me.userId,
    });
    setBusy(false);
    if (!res.ok) {
      notify("error", "Couldn't leave the vault.");
      return;
    }
    onLeft();
  };

  const deleteVault = async () => {
    if (!confirmDelete) {
      setConfirmDelete(true);
      return;
    }
    setBusy(true);
    const res = await postJSON<{ ok?: boolean }>("/api/v1/vaults/delete", { vaultId: vault.id });
    setBusy(false);
    if (!res.ok) {
      const message = (res.data as { message?: string } | null)?.message;
      notify("error", message ?? "Couldn't delete the vault.");
      setConfirmDelete(false);
      return;
    }
    onDeleted();
  };

  return (
    <Dialog open={open} onClose={onClose} title={`${vaultName} — vault settings`}>
      {isOwner && (
        <div className="mb-6">
          <label htmlFor="vault-name" className="text-xs font-semibold tracking-widest uppercase text-muted-foreground block mb-1.5">
            Vault name
          </label>
          <div className="flex items-center gap-2">
            <input
              id="vault-name"
              className="input flex-1"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={60}
              disabled={busy}
            />
            <button
              type="button"
              onClick={rename}
              disabled={busy || !name.trim() || name.trim() === vaultName}
              className="btn btn-secondary text-sm"
            >
              Rename
            </button>
          </div>
          <p className="mt-1.5 text-xs text-muted-foreground">The name is sealed with the vault key — we can't read it either.</p>
        </div>
      )}

      <div className="mb-6">
        <p className="text-xs font-semibold tracking-widest uppercase text-muted-foreground mb-2 flex items-center gap-1.5">
          <UsersIcon className="h-3.5 w-3.5" /> People
        </p>
        {members === null && <p className="text-sm text-muted-foreground font-mono py-2">loading…</p>}
        {members !== null && (
          <ul className="divide-y divide-border-subtle">
            {members.map((member) => (
              <li key={member.userId} className="py-2.5 flex items-center gap-3">
                <div className="w-8 h-8 rounded-full bg-accent-subtle text-accent flex items-center justify-center text-xs font-bold uppercase flex-shrink-0">
                  {(member.displayName || member.email).slice(0, 1)}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-foreground truncate">
                    {member.displayName || member.email}
                    {member.email === meEmail && <span className="text-muted-foreground"> (you)</span>}
                  </p>
                  {member.displayName && <p className="text-xs text-muted-foreground truncate">{member.email}</p>}
                </div>
                <span className={`badge ${member.role === "owner" ? "badge-accent" : "badge-accent-2"}`}>
                  {member.role === "owner" ? "owner" : "can view"}
                </span>
                {isOwner && member.role !== "owner" && (
                  <button
                    type="button"
                    onClick={() => removeMember(member)}
                    className="p-1.5 rounded-md text-muted-foreground hover:text-danger hover:bg-muted transition-colors"
                    aria-label={`Remove ${member.email}`}
                    title="Remove access"
                  >
                    <XIcon className="h-4 w-4" />
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      {isOwner && (
        <div className="mb-6">
          <p className="text-xs font-semibold tracking-widest uppercase text-muted-foreground mb-2">Invite someone</p>
          <p className="text-sm text-muted-foreground leading-relaxed mb-3">
            An invite link grants <strong className="text-foreground">view access</strong> to whoever accepts it first.
            It's single-use, expires in 7 days, and carries its own key — send it somewhere private.
          </p>
          <button type="button" onClick={createInvite} disabled={busy || !vaultKey} className="btn btn-primary text-sm">
            <LinkIcon className="h-4 w-4" /> {busy ? "Sealing…" : "Create invite link"}
          </button>

          {freshInvite && (
            <div className="animate-pop mt-3 rounded-lg border border-accent-border p-3" style={{ background: "var(--accent-subtle)" }}>
              <p className="text-xs font-semibold tracking-widest uppercase text-accent mb-2">Invite link — visible only now</p>
              <div className="flex items-center gap-2">
                <code className="font-mono text-xs text-foreground break-all flex-1 select-all">{freshInvite}</code>
                <CopyButton value={freshInvite} label="Copy invite link" />
              </div>
            </div>
          )}

          {invites.length > 0 && (
            <ul className="mt-3 divide-y divide-border-subtle">
              {invites.map((invite) => (
                <li key={invite.id} className="py-2 flex items-center gap-3">
                  <LinkIcon className="h-4 w-4 text-accent flex-shrink-0" />
                  <p className="flex-1 text-sm text-muted-foreground">
                    Pending invite · expires {new Date(invite.expiresAt).toLocaleDateString()}
                  </p>
                  <button
                    type="button"
                    onClick={() => revokeInvite(invite)}
                    className="p-1.5 rounded-md text-muted-foreground hover:text-danger hover:bg-muted transition-colors"
                    aria-label="Revoke invite"
                    title="Revoke invite"
                  >
                    <TrashIcon className="h-4 w-4" />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {isOwner ? (
        <div className="pt-4 border-t border-border">
          <p className="text-xs font-semibold tracking-widest uppercase text-danger mb-2">Danger zone</p>
          <p className="text-sm text-muted-foreground leading-relaxed mb-3">
            Deleting this vault permanently destroys every item in it, for you and every member. There is no undo.
          </p>
          <button type="button" onClick={deleteVault} disabled={busy} className="btn btn-danger text-sm">
            <TrashIcon className="h-4 w-4" /> {confirmDelete ? "Click again to delete forever" : "Delete vault"}
          </button>
        </div>
      ) : (
        <div className="pt-4 border-t border-border">
          <p className="text-sm text-muted-foreground leading-relaxed mb-3">
            Leaving removes this vault from your account. The owner can invite you again later.
          </p>
          <button type="button" onClick={leave} disabled={busy} className="btn btn-secondary text-sm text-danger">
            <LeaveIcon className="h-4 w-4" /> Leave vault
          </button>
        </div>
      )}
    </Dialog>
  );
}
