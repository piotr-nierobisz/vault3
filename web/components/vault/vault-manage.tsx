import React, { useEffect, useState } from "react";
import { LeaveIcon, LinkIcon, TrashIcon, UsersIcon, XIcon } from "../icons";
import { Dialog } from "../ui/dialog";
import { FreshLinkCallout } from "../ui/fresh-link-callout";
import { Loading } from "../ui/loading";
import { getJSON, postJSON } from "../../lib/api";
import { composeLinkFragment, mintLinkKey, seal, sealVaultName } from "../../lib/crypto";
import { useAction } from "../../lib/use-action";
import { ROLE_OWNER } from "../../types/vault";
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
  const isOwner = vault.role === ROLE_OWNER;
  const [members, setMembers] = useState<VaultMemberDto[] | null>(null);
  const [invites, setInvites] = useState<VaultInviteDto[]>([]);
  const [name, setName] = useState(vaultName);
  const [freshInvite, setFreshInvite] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);
  const { busy, run } = useAction({ onError: (message) => notify("error", message), network: "Network error. Try again." });
  // Row actions take their own instance so revoking an invite or removing a
  // member does not disable the rename field and Create-link button; they
  // still need the hook's catch and re-entry guard.
  const { run: runRow } = useAction({ onError: (message) => notify("error", message), network: "Network error. Try again." });

  useEffect(() => {
    if (!open) return;
    setName(vaultName);
    setFreshInvite("");
    setConfirmDelete(false);
    setMembers(null);
    setLoadFailed(false);
    const fail = () => {
      // Never present a failed load as an empty vault: this list is how an
      // owner sees who currently has access.
      setMembers([]);
      setInvites([]);
      setLoadFailed(true);
    };
    getJSON<VaultMembersResponse>(`/api/v1/vaults/members?vaultId=${encodeURIComponent(vault.id)}`)
      .then((res) => {
        if (res.ok && res.data) {
          setMembers(res.data.members);
          setInvites(res.data.invites);
          return;
        }
        fail();
      })
      .catch(fail);
  }, [open, vault.id, vaultName]);

  const rename = async () => {
    const trimmed = name.trim();
    if (!trimmed || !vaultKey || trimmed === vaultName) return;
    await run(
      async () => {
        const encName = await sealVaultName(vaultKey, trimmed);
        return postJSON<{ ok: boolean }>("/api/v1/vaults/rename", { vaultId: vault.id, encName });
      },
      {
        onOK: () => {
          onRenamed(trimmed);
          notify("success", "Vault renamed");
        },
        fail: "Couldn't rename the vault.",
      },
    );
  };

  const createInvite = async () => {
    if (!vaultKey) return;
    // The invite key stays here: the server is handed the wrap, the fragment
    // gets the key, and only this screen ever holds both.
    const inviteKey = mintLinkKey();
    await run(
      async () => {
        const wrappedVaultKey = await seal(inviteKey, vaultKey);
        return postJSON<InviteCreateResponse>("/api/v1/vaults/invites/create", {
          vaultId: vault.id,
          wrappedVaultKey,
        });
      },
      {
        onOK: async (created) => {
          const url = `${window.location.origin}/app/invite#${composeLinkFragment(created.token, inviteKey)}`;
          setFreshInvite(url);
          setInvites((prev) => [created.invite, ...prev]);
          try {
            await navigator.clipboard.writeText(url);
            notify("success", "Invite link copied to your clipboard");
          } catch {
            notify("info", "Invite link created — copy it below");
          }
        },
        fail: "Couldn't create the invite.",
      },
    );
  };

  const revokeInvite = (invite: VaultInviteDto) =>
    runRow(() => postJSON<{ ok: boolean }>("/api/v1/vaults/invites/revoke", { id: invite.id }), {
      onOK: () => {
        setInvites((prev) => prev.filter((i) => i.id !== invite.id));
        notify("success", "Invite revoked");
      },
      fail: "Couldn't revoke that invite.",
    });

  const removeMember = (member: VaultMemberDto) =>
    runRow(
      () => postJSON<{ ok: boolean }>("/api/v1/vaults/members/remove", { vaultId: vault.id, userId: member.userId }),
      {
        onOK: () => {
          setMembers((prev) => prev?.filter((m) => m.userId !== member.userId) ?? null);
          notify("success", `${member.email} no longer has access`);
        },
        fail: "Couldn't remove that member.",
      },
    );

  const leave = async () => {
    const me = members?.find((m) => m.email === meEmail);
    if (!me) return;
    await run(
      () => postJSON<{ ok: boolean }>("/api/v1/vaults/members/remove", { vaultId: vault.id, userId: me.userId }),
      { onOK: () => onLeft(), fail: "Couldn't leave the vault." },
    );
  };

  const deleteVault = async () => {
    if (!confirmDelete) {
      setConfirmDelete(true);
      return;
    }
    const deleted = await run(() => postJSON<{ ok?: boolean }>("/api/v1/vaults/delete", { vaultId: vault.id }), {
      onOK: () => onDeleted(),
      fail: "Couldn't delete the vault.",
    });
    // A refused delete drops back to one click, so a stale confirmation
    // can't turn the next click into a destruction.
    if (!deleted) setConfirmDelete(false);
  };

  return (
    <Dialog open={open} onClose={onClose} title={`${vaultName} — vault settings`}>
      {isOwner && (
        <div className="mb-6">
          <label htmlFor="vault-name" className="field-label block mb-1.5">
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
              className="btn btn-secondary"
            >
              Rename
            </button>
          </div>
          <p className="mt-1.5 text-xs text-muted-foreground">The name is sealed with the vault key — we can't read it either.</p>
        </div>
      )}

      <div className="mb-6">
        <p className="field-label mb-2 flex items-center gap-1.5">
          <UsersIcon className="h-3.5 w-3.5" /> People
        </p>
        {members === null && <Loading />}
        {loadFailed && (
          <p className="text-sm text-danger py-2">
            Couldn't load this vault's people — so this list may be incomplete. Close and reopen to retry.
          </p>
        )}
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
                <span className={`badge ${member.role === ROLE_OWNER ? "badge-accent" : "badge-accent-2"}`}>
                  {member.role === ROLE_OWNER ? "owner" : "can view"}
                </span>
                {isOwner && member.role !== ROLE_OWNER && (
                  <button
                    type="button"
                    onClick={() => removeMember(member)}
                    className="btn-icon btn-icon-danger"
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
          <p className="field-label mb-2">Invite someone</p>
          <p className="text-sm text-muted-foreground leading-relaxed mb-3">
            An invite link grants <strong className="text-foreground">view access</strong> to whoever accepts it first.
            It's single-use, expires in 7 days, and carries its own key — send it somewhere private.
          </p>
          <button type="button" onClick={createInvite} disabled={busy || !vaultKey} className="btn btn-primary btn-sm">
            <LinkIcon className="h-4 w-4" /> {busy ? "Sealing…" : "Create invite link"}
          </button>

          {freshInvite && (
            <FreshLinkCallout label="Invite link — visible only now" value={freshInvite} copyLabel="Copy invite link" />
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
                    className="btn-icon btn-icon-danger"
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
          <p className="field-label field-label-danger mb-2">Danger zone</p>
          <p className="text-sm text-muted-foreground leading-relaxed mb-3">
            Deleting this vault permanently destroys every item in it, for you and every member. There is no undo.
          </p>
          <button type="button" onClick={deleteVault} disabled={busy} className="btn btn-danger btn-sm">
            <TrashIcon className="h-4 w-4" /> {confirmDelete ? "Click again to delete forever" : "Delete vault"}
          </button>
        </div>
      ) : (
        <div className="pt-4 border-t border-border">
          <p className="text-sm text-muted-foreground leading-relaxed mb-3">
            Leaving removes this vault from your account. The owner can invite you again later.
          </p>
          <button type="button" onClick={leave} disabled={busy} className="btn btn-secondary btn-sm text-danger">
            <LeaveIcon className="h-4 w-4" /> Leave vault
          </button>
        </div>
      )}
    </Dialog>
  );
}
