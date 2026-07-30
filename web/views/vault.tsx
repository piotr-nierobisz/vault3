import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { PlusIcon, SearchIcon, StarIcon, TrashIcon, VaultMark } from "../components/icons";
import { ToastProvider, useToasts } from "../components/ui/toast";
import { LockScreen } from "../components/vault/lock-screen";
import { ItemForm, type ItemFormValue } from "../components/vault/item-form";
import { ItemDetail, categoryIcon } from "../components/vault/item-detail";
import { ShareDialog } from "../components/vault/share-dialog";
import { VaultManageDialog } from "../components/vault/vault-manage";
import { VaultSwitcher } from "../components/vault/vault-switcher";
import { getJSON, postJSON } from "../lib/api";
import {
  createVaultBundle,
  open as openEnvelope,
  openJSON,
  sealItem,
  unwrapItemKey,
  type ItemOverview,
  type VaultName,
} from "../lib/crypto";
import { addVaultKey, loadKeys, lock, removeVaultKey, saveKeys, startAutoLockWatch } from "../lib/keystore";
import { startSync } from "../lib/sync";
import type {
  DecryptedItem,
  ItemRowDto,
  ItemsResponse,
  ItemWriteResponse,
  KeysetVaultDto,
  VaultFilter,
  VaultPageData,
  VaultsResponse,
  VaultWriteResponse,
} from "../types/vault";

// The vault orchestrator. Owns: unlock state, the vault list (switching,
// creating, managing, sharing), the decrypted item cache for the active
// vault, the filter/search/selection UI state, mutations (seal → POST →
// update cache), and the live-sync subscription that refetches when another
// device — or another MEMBER of a shared vault — writes.

const ACTIVE_VAULT_KEY = "v3.activeVault";

async function decryptRows(vaultKey: Uint8Array, rows: ItemRowDto[]): Promise<DecryptedItem[]> {
  const out: DecryptedItem[] = [];
  for (const row of rows) {
    try {
      const itemKey = await unwrapItemKey(vaultKey, row.wrappedItemKey);
      const overview = await openJSON<ItemOverview>(itemKey, row.overview);
      out.push({ row, overview, itemKey });
    } catch {
      // A row that fails to open is skipped rather than blanking the vault;
      // it will reappear if keys/data heal on the next sync.
    }
  }
  return out;
}

function VaultApp() {
  const data = useBungoData() as VaultPageData;
  const toast = useToasts();
  const email = data.Viewer?.User.email ?? "";
  const firstVaultId = data.Keyset?.vaults[0]?.id ?? "";

  const [keys, setKeys] = useState(() => loadKeys());
  const [vaults, setVaults] = useState<KeysetVaultDto[]>(data.Keyset?.vaults ?? []);
  const [vaultNames, setVaultNames] = useState<Record<string, string>>({});
  const [activeVaultId, setActiveVaultId] = useState<string>(() => {
    const remembered = sessionStorage.getItem(ACTIVE_VAULT_KEY);
    const known = (data.Keyset?.vaults ?? []).some((v) => v.id === remembered);
    return known && remembered ? remembered : firstVaultId;
  });
  const [items, setItems] = useState<DecryptedItem[] | null>(null);
  const [filter, setFilter] = useState<VaultFilter>({ kind: "all" });
  const [query, setQuery] = useState("");
  const [selectedID, setSelectedID] = useState<string>("");
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<{ item: DecryptedItem; value: ItemFormValue } | null>(null);
  const [manageOpen, setManageOpen] = useState(false);
  const [shareOpen, setShareOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const revisionRef = useRef(data.Revision);
  const initialItemsConsumed = useRef(false);

  const vaultKey = keys?.vaultKeys[activeVaultId];
  const activeVault = vaults.find((v) => v.id === activeVaultId);
  const readOnly = (activeVault?.role ?? "owner") !== "owner";

  // Complete the keystore whenever a vault lacks its key (fresh login
  // stashed only the encKey; a new vault arrived via sync or invite). Every
  // wrap is 'muk' — sealed under this account's own key-encryption key.
  useEffect(() => {
    if (!keys || vaults.length === 0) return;
    const missing = vaults.filter((v) => !keys.vaultKeys[v.id]);
    if (missing.length === 0) return;
    (async () => {
      const nextVaultKeys = { ...keys.vaultKeys };
      let opened = 0;
      for (const vault of missing) {
        try {
          nextVaultKeys[vault.id] = await openEnvelope(keys.encKey, vault.wrappedKey);
          opened++;
        } catch {
          // This wrap doesn't fit the encKey. Skip; zero total keys below
          // means the whole session is stale.
        }
      }
      if (opened === 0 && Object.keys(keys.vaultKeys).length === 0) {
        lock();
        setKeys(null);
        return;
      }
      const next = { encKey: keys.encKey, vaultKeys: nextVaultKeys };
      saveKeys(next);
      setKeys(next);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [keys, vaults]);

  // Decrypt every reachable vault's name for the switcher.
  useEffect(() => {
    if (!keys) return;
    (async () => {
      const names: Record<string, string> = {};
      for (const vault of vaults) {
        const key = keys.vaultKeys[vault.id];
        if (!key) {
          names[vault.id] = "Sealed vault";
          continue;
        }
        try {
          names[vault.id] = (await openJSON<VaultName>(key, vault.encName)).name || "Vault";
        } catch {
          names[vault.id] = "Sealed vault";
        }
      }
      setVaultNames(names);
    })();
  }, [keys, vaults]);

  const refetch = useCallback(async () => {
    const key = loadKeys()?.vaultKeys[activeVaultId];
    if (!key) return;
    const res = await getJSON<ItemsResponse>(`/api/v1/items?vaultId=${encodeURIComponent(activeVaultId)}`);
    if (res.ok && res.data) {
      revisionRef.current = res.data.revision;
      setItems(await decryptRows(key, res.data.items));
    }
  }, [activeVaultId]);

  const refetchVaults = useCallback(async () => {
    const res = await getJSON<VaultsResponse>("/api/v1/vaults");
    if (res.ok && res.data) {
      revisionRef.current = res.data.revision;
      setVaults(res.data.vaults);
    }
  }, []);

  // Load the active vault's items: the server-rendered payload covers the
  // first vault once; everything else (and every switch) refetches.
  useEffect(() => {
    if (!vaultKey) return;
    if (!initialItemsConsumed.current && activeVaultId === firstVaultId) {
      initialItemsConsumed.current = true;
      decryptRows(vaultKey, data.Items).then(setItems);
      return;
    }
    setItems(null);
    refetch();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vaultKey, activeVaultId]);

  // If the active vault vanishes (deleted, or access removed), fall back.
  useEffect(() => {
    if (vaults.length === 0 || vaults.some((v) => v.id === activeVaultId)) return;
    toast("info", "That vault is no longer available");
    setActiveVaultId(vaults[0].id);
    sessionStorage.setItem(ACTIVE_VAULT_KEY, vaults[0].id);
    setSelectedID("");
    setManageOpen(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vaults]);

  // Live sync: another device or vault member writes → refetch both lists.
  useEffect(() => {
    if (!keys) return;
    const handle = startSync(revisionRef.current, () => {
      refetch();
      refetchVaults();
      toast("info", "Vault updated elsewhere");
    });
    return () => handle.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [keys, refetch, refetchVaults]);

  // Auto-lock on inactivity.
  useEffect(() => {
    const stop = startAutoLockWatch(() => {
      setKeys(null);
      setItems(null);
    });
    return () => stop();
  }, []);

  const visible = useMemo(() => {
    if (!items) return [];
    const q = query.trim().toLowerCase();
    return items
      .filter((item) => {
        if (filter.kind === "trash") return item.row.trashed;
        if (item.row.trashed) return false;
        if (filter.kind === "favorites") return Boolean(item.overview.favorite);
        if (filter.kind === "category") return item.overview.category === filter.code;
        return true;
      })
      .filter((item) => {
        if (!q) return true;
        return (
          item.overview.title.toLowerCase().includes(q) ||
          (item.overview.subtitle ?? "").toLowerCase().includes(q) ||
          (item.overview.urls ?? []).some((u) => u.toLowerCase().includes(q))
        );
      })
      .sort((a, b) => a.overview.title.localeCompare(b.overview.title));
  }, [items, filter, query]);

  const selected = useMemo(() => visible.find((i) => i.row.id === selectedID) ?? null, [visible, selectedID]);

  const applyWrite = (updated: ItemRowDto, itemKey: Uint8Array, overview: ItemOverview) => {
    setItems((prev) => {
      if (!prev) return prev;
      const next = prev.filter((i) => i.row.id !== updated.id);
      next.push({ row: updated, overview, itemKey });
      return next;
    });
  };

  const createItem = async (value: ItemFormValue) => {
    if (!vaultKey) return;
    setBusy(true);
    try {
      const sealed = await sealItem(vaultKey, value.overview, value.details);
      const res = await postJSON<ItemWriteResponse>("/api/v1/items/create", { vaultId: activeVaultId, ...sealed });
      if (!res.ok || !res.data) {
        toast("error", "Couldn't seal that item. Try again.");
        return;
      }
      revisionRef.current = res.data.revision;
      const itemKey = await unwrapItemKey(vaultKey, res.data.item.wrappedItemKey);
      applyWrite(res.data.item, itemKey, value.overview);
      setFormOpen(false);
      setSelectedID(res.data.item.id);
      toast("success", "Item sealed");
    } catch {
      toast("error", "Network error. Try again.");
    } finally {
      setBusy(false);
    }
  };

  const updateItem = async (item: DecryptedItem, value: ItemFormValue) => {
    setBusy(true);
    try {
      const sealed = await sealItem(vaultKey!, value.overview, value.details, item.itemKey);
      const res = await postJSON<ItemWriteResponse>("/api/v1/items/update", {
        id: item.row.id,
        overview: sealed.overview,
        details: sealed.details,
      });
      if (!res.ok || !res.data) {
        toast("error", "Couldn't save the changes. Try again.");
        return;
      }
      revisionRef.current = res.data.revision;
      applyWrite(res.data.item, item.itemKey, value.overview);
      setEditing(null);
      setFormOpen(false);
      toast("success", "Changes sealed");
    } catch {
      toast("error", "Network error. Try again.");
    } finally {
      setBusy(false);
    }
  };

  const lifecycle = async (item: DecryptedItem, action: "trash" | "restore" | "delete") => {
    setBusy(true);
    try {
      const res = await postJSON<{ ok?: boolean; revision?: number }>(`/api/v1/items/${action}`, { id: item.row.id });
      if (!res.ok) {
        toast("error", "That didn't work. Try again.");
        return;
      }
      if (res.data?.revision) revisionRef.current = res.data.revision;
      setItems((prev) => {
        if (!prev) return prev;
        if (action === "delete") return prev.filter((i) => i.row.id !== item.row.id);
        return prev.map((i) =>
          i.row.id === item.row.id ? { ...i, row: { ...i.row, trashed: action === "trash" } } : i,
        );
      });
      if (action !== "restore") setSelectedID("");
      toast("success", action === "trash" ? "Moved to trash" : action === "restore" ? "Restored" : "Deleted forever");
    } catch {
      toast("error", "Network error. Try again.");
    } finally {
      setBusy(false);
    }
  };

  const toggleFavorite = async (item: DecryptedItem) => {
    try {
      const details = await openJSON<{ fields: Record<string, string>; notes?: string }>(item.itemKey, item.row.details);
      await updateItem(item, {
        overview: { ...item.overview, favorite: !item.overview.favorite },
        details,
      });
    } catch {
      toast("error", "Couldn't update the item.");
    }
  };

  // ── Vault lifecycle ───────────────────────────────────────────────────────

  const selectVault = (id: string) => {
    if (id === activeVaultId) return;
    setActiveVaultId(id);
    sessionStorage.setItem(ACTIVE_VAULT_KEY, id);
    setSelectedID("");
    setQuery("");
    setFilter({ kind: "all" });
  };

  const createVault = async (name: string): Promise<boolean> => {
    if (!keys) return false;
    setBusy(true);
    try {
      const bundle = await createVaultBundle(keys.encKey, name);
      const res = await postJSON<VaultWriteResponse>("/api/v1/vaults/create", {
        encName: bundle.encName,
        wrappedKey: bundle.wrappedKey,
      });
      if (!res.ok || !res.data) {
        const message = (res.data as { message?: string } | null)?.message;
        toast("error", message ?? "Couldn't create the vault.");
        return false;
      }
      revisionRef.current = res.data.revision;
      addVaultKey(res.data.vault.id, bundle.vaultKeyRaw);
      setKeys(loadKeys());
      setVaults((prev) => [...prev, res.data!.vault]);
      selectVault(res.data.vault.id);
      toast("success", `"${name}" sealed and ready`);
      return true;
    } catch {
      toast("error", "Network error. Try again.");
      return false;
    } finally {
      setBusy(false);
    }
  };

  const dropVault = (id: string, message: string) => {
    setManageOpen(false);
    removeVaultKey(id);
    setKeys(loadKeys());
    setVaults((prev) => prev.filter((v) => v.id !== id));
    toast("success", message);
  };

  // ── Render ────────────────────────────────────────────────────────────────

  if (!data.Keyset) {
    return (
      <div className="max-w-md mx-auto mt-24 panel p-10 text-center">
        <VaultMark className="h-10 w-10 text-accent mx-auto mb-5" />
        <p className="text-sm text-muted-foreground">This account has no vault yet. Contact support.</p>
      </div>
    );
  }

  if (!keys || !vaultKey) {
    return (
      <LockScreen
        keyset={data.Keyset}
        email={email}
        onUnlocked={(encKey, vaultKeys) => setKeys({ encKey, vaultKeys })}
      />
    );
  }

  const counts = {
    all: items?.filter((i) => !i.row.trashed).length ?? 0,
    favorites: items?.filter((i) => !i.row.trashed && i.overview.favorite).length ?? 0,
    trash: items?.filter((i) => i.row.trashed).length ?? 0,
    byCategory: (code: string) => items?.filter((i) => !i.row.trashed && i.overview.category === code).length ?? 0,
  };

  const sidebarButton = (active: boolean, onClick: () => void, icon: React.ReactNode, label: string, count: number) => (
    <button
      type="button"
      onClick={onClick}
      className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm border transition-colors ${
        active
          ? "bg-accent-subtle text-accent font-semibold border-accent-border"
          : "text-muted-foreground border-transparent hover:bg-muted hover:text-foreground"
      }`}
    >
      {icon}
      <span className="flex-1 text-left">{label}</span>
      <span className="text-xs font-mono opacity-70">{count}</span>
    </button>
  );

  return (
    <div className="max-w-6xl mx-auto w-full px-3 sm:px-4 lg:px-8 py-6 animate-unseal">
      <div className="grid gap-6" style={{ gridTemplateColumns: "minmax(0,1fr)" }}>
        <div className="lg:grid lg:gap-6" style={{ gridTemplateColumns: "220px minmax(0,1.1fr) minmax(0,1.6fr)" }}>
          {/* ── Sidebar ── */}
          <aside className="mb-5 lg:mb-0">
            <VaultSwitcher
              vaults={vaults}
              names={vaultNames}
              activeId={activeVaultId}
              busy={busy}
              onSelect={selectVault}
              onManage={() => setManageOpen(true)}
              onCreate={createVault}
            />

            {!readOnly && (
              <button type="button" onClick={() => { setEditing(null); setFormOpen(true); }} className="btn btn-primary w-full mb-5">
                <PlusIcon className="h-4 w-4" /> New item
              </button>
            )}
            {readOnly && (
              <p className="mb-5 px-3 py-2 rounded-lg text-xs text-muted-foreground border border-border-subtle leading-relaxed">
                You can view this shared vault but not change it.
              </p>
            )}
            <nav className="space-y-0.5">
              {sidebarButton(filter.kind === "all", () => setFilter({ kind: "all" }), <VaultMark className="h-4 w-4" />, "All items", counts.all)}
              {sidebarButton(
                filter.kind === "favorites",
                () => setFilter({ kind: "favorites" }),
                <StarIcon className="h-4 w-4" />,
                "Favourites",
                counts.favorites,
              )}
              <div className="pt-3 pb-1 px-3 text-xs font-semibold uppercase tracking-widest text-muted-foreground select-none">Categories</div>
              {data.Categories.map((c) =>
                sidebarButton(
                  filter.kind === "category" && filter.code === c.code,
                  () => setFilter({ kind: "category", code: c.code }),
                  categoryIcon(c.code, "h-4 w-4"),
                  c.label,
                  counts.byCategory(c.code),
                ),
              )}
              <div className="pt-3">
                {sidebarButton(filter.kind === "trash", () => setFilter({ kind: "trash" }), <TrashIcon className="h-4 w-4" />, "Trash", counts.trash)}
              </div>
            </nav>
          </aside>

          {/* ── Item list ── */}
          <section className="mb-5 lg:mb-0">
            <div className="relative mb-3">
              <SearchIcon className="h-4 w-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
              <input
                className="input pl-9"
                placeholder={`Search ${vaultNames[activeVaultId] ?? "your vault"}…`}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                aria-label="Search items"
              />
            </div>

            <div className="panel divide-y divide-border-subtle">
              {items === null && <p className="px-4 py-8 text-sm text-muted-foreground font-mono text-center">unsealing your vault…</p>}
              {items !== null && visible.length === 0 && (
                <div className="px-4 py-12 text-center">
                  <p className="text-sm text-muted-foreground">
                    {filter.kind === "trash"
                      ? "Trash is empty."
                      : query
                        ? "Nothing matches that search."
                        : readOnly
                          ? "This shared vault is empty."
                          : "Nothing here yet. Seal your first item."}
                  </p>
                </div>
              )}
              {visible.map((item, index) => (
                <button
                  key={item.row.id}
                  type="button"
                  onClick={() => setSelectedID(item.row.id)}
                  className={`item-row-enter w-full flex items-center gap-3 px-4 py-3 text-left transition-colors ${
                    selectedID === item.row.id ? "row-accent" : "hover:bg-muted"
                  }`}
                  style={{ "--stagger-i": index } as React.CSSProperties}
                >
                  <div className={`icon-tile flex-shrink-0${selectedID === item.row.id ? "" : " icon-tile-muted"}`} aria-hidden="true">
                    {categoryIcon(item.overview.category, "h-4 w-4")}
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium text-foreground truncate">{item.overview.title}</p>
                    {item.overview.subtitle && <p className="text-xs text-muted-foreground truncate">{item.overview.subtitle}</p>}
                  </div>
                  {item.overview.favorite && !item.row.trashed && <StarIcon className="h-3.5 w-3.5 text-warning flex-shrink-0" filled />}
                </button>
              ))}
            </div>
          </section>

          {/* ── Detail pane ── */}
          <section>
            {selected ? (
              <div className="panel p-6">
                <ItemDetail
                  item={selected}
                  busy={busy}
                  readOnly={readOnly}
                  onEdit={(details) => {
                    setEditing({ item: selected, value: { overview: selected.overview, details } });
                    setFormOpen(true);
                  }}
                  onToggleFavorite={() => toggleFavorite(selected)}
                  onTrash={() => lifecycle(selected, "trash")}
                  onRestore={() => lifecycle(selected, "restore")}
                  onDeleteForever={() => lifecycle(selected, "delete")}
                  onShare={readOnly ? undefined : () => setShareOpen(true)}
                />
              </div>
            ) : (
              <div className="panel p-12 text-center hidden lg:block">
                <VaultMark className="h-11 w-11 text-accent mx-auto mb-4 mark-pulse" />
                <p className="text-sm text-muted-foreground">Select an item to unseal it.</p>
              </div>
            )}
          </section>
        </div>
      </div>

      {formOpen && (
        <ItemForm
          key={editing?.item.row.id ?? "new"}
          open={formOpen}
          busy={busy}
          onClose={() => {
            setFormOpen(false);
            setEditing(null);
          }}
          onSubmit={(value) => (editing ? updateItem(editing.item, value) : createItem(value))}
          categories={data.Categories}
          initial={editing?.value}
        />
      )}

      {selected && (
        <ShareDialog item={selected} open={shareOpen} onClose={() => setShareOpen(false)} notify={toast} />
      )}

      {activeVault && (
        <VaultManageDialog
          vault={activeVault}
          vaultName={vaultNames[activeVaultId] ?? "Vault"}
          vaultKey={vaultKey}
          meEmail={email}
          open={manageOpen}
          onClose={() => setManageOpen(false)}
          notify={toast}
          onRenamed={(name) => {
            setVaultNames((prev) => ({ ...prev, [activeVaultId]: name }));
            refetchVaults();
          }}
          onDeleted={() => dropVault(activeVaultId, "Vault deleted forever")}
          onLeft={() => dropVault(activeVaultId, "You left the vault")}
        />
      )}
    </div>
  );
}

function VaultRoot() {
  return (
    <ToastProvider>
      <VaultApp />
    </ToastProvider>
  );
}

_bungoRender(VaultRoot, "vault-root");
