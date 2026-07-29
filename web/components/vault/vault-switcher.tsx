import React, { useState } from "react";
import { PlusIcon, SettingsIcon, UsersIcon, VaultMark } from "../icons";
import { Dialog } from "../ui/dialog";
import type { KeysetVaultDto } from "../../types/vault";

// The sidebar vault switcher: every vault the account can open, with its
// client-side decrypted name, a shared badge, and the settings entry point
// on the active row. Creating a vault is a name away — the crypto (fresh
// vault key, wrapping, sealing) happens in the parent.

export function VaultSwitcher({
  vaults,
  names,
  activeId,
  busy,
  onSelect,
  onManage,
  onCreate,
}: {
  vaults: KeysetVaultDto[];
  names: Record<string, string>;
  activeId: string;
  busy: boolean;
  onSelect: (id: string) => void;
  onManage: () => void;
  onCreate: (name: string) => Promise<boolean>;
}) {
  const [createOpen, setCreateOpen] = useState(false);
  const [newName, setNewName] = useState("");

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = newName.trim();
    if (!trimmed) return;
    if (await onCreate(trimmed)) {
      setCreateOpen(false);
      setNewName("");
    }
  };

  return (
    <div className="mb-5">
      <div className="pb-1 px-3 text-xs font-semibold uppercase tracking-widest text-muted-foreground select-none">Vaults</div>
      <nav className="space-y-0.5">
        {vaults.map((vault) => {
          const active = vault.id === activeId;
          const shared = vault.memberCount > 1;
          return (
            <div
              key={vault.id}
              className={`group flex items-center rounded-lg border transition-colors ${
                active ? "bg-accent-subtle border-accent-border" : "border-transparent hover:bg-muted"
              }`}
            >
              <button
                type="button"
                onClick={() => onSelect(vault.id)}
                className={`flex-1 min-w-0 flex items-center gap-2.5 px-3 py-2 text-sm text-left ${
                  active ? "text-accent font-semibold" : "text-muted-foreground hover:text-foreground"
                }`}
              >
                <VaultMark className="h-4 w-4 flex-shrink-0" />
                <span className="truncate">{names[vault.id] ?? "…"}</span>
                {shared && (
                  <span className="badge badge-accent-2 flex-shrink-0" title={`${vault.memberCount} people`}>
                    <UsersIcon className="h-3 w-3" /> {vault.memberCount}
                  </span>
                )}
              </button>
              {active && (
                <button
                  type="button"
                  onClick={onManage}
                  aria-label="Vault settings"
                  title="Vault settings"
                  className="p-2 mr-1 rounded-md text-muted-foreground hover:text-accent transition-colors flex-shrink-0"
                >
                  <SettingsIcon className="h-4 w-4" />
                </button>
              )}
            </div>
          );
        })}
        <button
          type="button"
          onClick={() => setCreateOpen(true)}
          className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm border border-transparent text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
        >
          <PlusIcon className="h-4 w-4" />
          <span className="flex-1 text-left">New vault</span>
        </button>
      </nav>

      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} title="Create a new vault">
        <form onSubmit={create} className="space-y-4">
          <p className="text-sm text-muted-foreground leading-relaxed">
            A fresh vault gets its own key, minted right here. Use separate vaults to keep areas of your life apart —
            or to share a set of items with someone later.
          </p>
          <div className="space-y-1.5">
            <label htmlFor="new-vault-name" className="text-xs font-semibold tracking-widest uppercase text-muted-foreground">
              Vault name
            </label>
            <input
              id="new-vault-name"
              className="input"
              placeholder="e.g. Family, Work, Side project"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              maxLength={60}
              autoFocus
              disabled={busy}
            />
          </div>
          <div className="flex justify-end gap-3">
            <button type="button" onClick={() => setCreateOpen(false)} className="btn btn-ghost text-sm" disabled={busy}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary text-sm px-6" disabled={busy || !newName.trim()}>
              {busy ? "Sealing…" : "Create vault"}
            </button>
          </div>
        </form>
      </Dialog>
    </div>
  );
}
