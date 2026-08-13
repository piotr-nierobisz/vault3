import React, { useCallback, useEffect, useState } from "react";
import { AlertIcon, CheckIcon, DeviceIcon, SearchIcon, SettingsIcon, ShieldIcon, UsersIcon } from "../components/icons";
import { CheckboxBox } from "../components/ui/checkbox";
import { Dialog } from "../components/ui/dialog";
import { ErrorBanner } from "../components/ui/error-banner";
import { Loading } from "../components/ui/loading";
import { StatusPanel } from "../components/ui/status-panel";
import { ToastProvider, useToasts } from "../components/ui/toast";
import { getJSON, postJSON } from "../lib/api";
import { useAction } from "../lib/use-action";
import type {
  AdminAuditResponse,
  AdminAuditRow,
  AdminInquiriesResponse,
  AdminOverview,
  AdminPageData,
  AdminUserRow,
  AdminUsersResponse,
  ContactInquiry,
  PlatformSetting,
  PlatformStats,
} from "../types/admin";

// The management console. Four tabs over one question each: how the platform
// is doing, who is on it, what has happened, and who has written in.
//
// Worth stating once, because the surface invites the assumption: nothing on
// this page can open a vault. Every figure is a row count and every action
// changes account state — the server holds no key to an item, so there is no
// screen here that could show one.

const SETTING_COPY: Record<string, { label: string; hint: string }> = {
  public_registration_enabled: {
    label: "Public registration",
    hint: "Anyone can create an account at /join. Off closes signup platform-wide.",
  },
  email_sending_enabled: {
    label: "Outbound email",
    hint: "Send through Mailgun. Off skips every message and logs it instead.",
  },
  email_verification_required: {
    label: "Require verified email",
    hint: "Refuse sign-in until the address is confirmed.",
  },
};

function fmtDate(value?: string) {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

function fmtNumber(value: number) {
  return value.toLocaleString();
}

// --- Overview ---------------------------------------------------------------

function Stat({ label, value, hint }: { label: string; value: number; hint?: string }) {
  return (
    <div className="card p-4">
      <p className="field-label">{label}</p>
      <p className="text-2xl font-extrabold tracking-tighter mt-1 tabular-nums">{fmtNumber(value)}</p>
      {hint && <p className="text-xs text-muted-foreground mt-0.5">{hint}</p>}
    </div>
  );
}

function StatGroup({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mb-6">
      <p className="field-label mb-2.5">{title}</p>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">{children}</div>
    </div>
  );
}

function SettingsPanel({
  settings,
  onSaved,
}: {
  settings: PlatformSetting[];
  onSaved: (next: PlatformSetting[]) => void;
}) {
  const toast = useToasts();
  const { busy, run } = useAction({ onError: (m) => toast("error", m), network: "Network error" });

  const valueOf = (key: string) => settings.find((s) => s.key === key)?.value === "true";
  // The one combination that locks people out: verification enforced while no
  // email can be delivered leaves an unverified account with no way to become
  // verified. Said here rather than blocked, because it is a legitimate state
  // to pass through while wiring up a domain.
  const lockout = valueOf("email_verification_required") && !valueOf("email_sending_enabled");

  const save = async (setting: PlatformSetting, next: boolean) => {
    const value = next ? "true" : "false";
    await run(() => postJSON("/api/v1/admin/settings", { key: setting.key, value }), {
      onOK: () => {
        onSaved(settings.map((s) => (s.key === setting.key ? { ...s, value } : s)));
        toast("success", `${SETTING_COPY[setting.key]?.label ?? setting.key} ${next ? "on" : "off"}`);
      },
      fail: "Couldn't save that setting",
    });
  };

  return (
    <section className="panel p-6">
      <div className="flex items-start gap-3.5 mb-5">
        <span className="icon-tile flex-shrink-0" aria-hidden="true">
          <SettingsIcon className="h-5 w-5" />
        </span>
        <div>
          <h2 className="text-lg font-bold tracking-tight">Platform settings</h2>
          <p className="text-sm text-muted-foreground mt-0.5">Gates that apply to everyone. They take effect on the next request.</p>
        </div>
      </div>

      {lockout && (
        <div className="mb-4">
          <ErrorBanner
            tone="warning"
            message="Verification is required while outbound email is off, so an unverified account has no way to sign in."
          />
        </div>
      )}

      <div className="divide-y divide-border-subtle">
        {settings.map((setting) => {
          const copy = SETTING_COPY[setting.key];
          const editable = setting.kind === "bool" && copy !== undefined;
          return (
            <label
              key={setting.key}
              className={`flex items-center justify-between gap-4 py-3.5 ${editable && !busy ? "cursor-pointer" : ""}`}
            >
              <span className="min-w-0">
                <span className="block text-sm text-foreground">{copy?.label ?? setting.key}</span>
                <span className="block text-xs text-muted-foreground">
                  {copy?.hint ?? "Stored setting with no control here."}
                </span>
                <span className="block text-xs text-muted-foreground font-mono mt-1">
                  {setting.key} · changed {fmtDate(setting.updatedAt)}
                </span>
              </span>
              <CheckboxBox
                checked={setting.value === "true"}
                disabled={!editable || busy}
                onChange={(next) => save(setting, next)}
              />
            </label>
          );
        })}
      </div>
    </section>
  );
}

function OverviewTab({
  stats,
  settings,
  onSettingsSaved,
}: {
  stats: PlatformStats;
  settings: PlatformSetting[];
  onSettingsSaved: (next: PlatformSetting[]) => void;
}) {
  return (
    <div className="animate-rise">
      <StatGroup title="Accounts">
        <Stat label="Registered" value={stats.users} hint={`${fmtNumber(stats.usersLast7Days)} in the last 7 days`} />
        <Stat label="Active" value={stats.activeUsers} hint={`${fmtNumber(stats.suspendedUsers)} suspended`} />
        <Stat label="Verified" value={stats.verifiedUsers} />
        <Stat label="Two-factor on" value={stats.twoFactorUsers} />
      </StatGroup>

      <StatGroup title="Stored, unreadable">
        <Stat label="Vaults" value={stats.vaults} hint={`${fmtNumber(stats.sharedVaults)} shared`} />
        <Stat label="Items" value={stats.items} />
        <Stat label="In trash" value={stats.trashedItems} hint="Purged after 30 days" />
        <Stat label="New this month" value={stats.usersLast30Days} hint="Accounts" />
      </StatGroup>

      <StatGroup title="Live">
        <Stat label="Sessions" value={stats.activeSessions} />
        <Stat label="Share links" value={stats.activeShareLinks} />
        <Stat label="Pending invites" value={stats.pendingInvites} />
        <Stat label="Open messages" value={stats.openInquiries} />
      </StatGroup>

      <SettingsPanel settings={settings} onSaved={onSettingsSaved} />
    </div>
  );
}

// --- Accounts ---------------------------------------------------------------

function Pager({
  page,
  total,
  pageSize,
  onPage,
}: {
  page: number;
  total: number;
  pageSize: number;
  onPage: (page: number) => void;
}) {
  const last = Math.max(0, Math.ceil(total / pageSize) - 1);
  if (total <= pageSize) return null;
  return (
    <div className="flex items-center justify-between pt-4">
      <button type="button" className="btn btn-secondary btn-sm" disabled={page <= 0} onClick={() => onPage(page - 1)}>
        Previous
      </button>
      <span className="text-xs text-muted-foreground font-mono">
        {page + 1} / {last + 1} · {fmtNumber(total)} total
      </span>
      <button type="button" className="btn btn-secondary btn-sm" disabled={page >= last} onClick={() => onPage(page + 1)}>
        Next
      </button>
    </div>
  );
}

function UserBadges({ user }: { user: AdminUserRow }) {
  return (
    <>
      {user.isAdmin && <span className="badge badge-accent ml-2">admin</span>}
      {!user.isActive && <span className="badge badge-danger ml-2">suspended</span>}
      {!user.emailVerified && <span className="badge badge-warning ml-2">unverified</span>}
      {user.twoFactor && <span className="badge badge-accent-2 ml-2">2FA</span>}
    </>
  );
}

// One account, every action an operator has over it. A dialog rather than a
// row of buttons per line: six controls per row makes the list unscannable,
// and the destructive one deserves to be somewhere you arrived deliberately.
function UserDialog({
  user,
  isSelf,
  onClose,
  onChanged,
}: {
  user: AdminUserRow;
  isSelf: boolean;
  onClose: () => void;
  onChanged: () => void;
}) {
  const toast = useToasts();
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [reason, setReason] = useState("");
  const [typedEmail, setTypedEmail] = useState("");
  const { busy, run } = useAction({
    onError: (message) => {
      setAttempt((n) => n + 1);
      setError(message);
    },
    network: "Network error. Nothing was changed.",
  });

  const act = async <T,>(path: string, body: unknown, success: string, after?: () => void) => {
    setError("");
    await run(() => postJSON<T>(path, body), {
      onOK: () => {
        toast("success", success);
        after?.();
        onChanged();
      },
      fail: "That didn't work.",
    });
  };

  return (
    <Dialog open onClose={onClose} title={user.email} wide>
      <div className="space-y-5">
        {error && <ErrorBanner key={attempt} message={error} />}

        <div className="grid sm:grid-cols-2 gap-x-6 gap-y-2 text-xs text-muted-foreground font-mono">
          <span>id · {user.id}</span>
          <span>joined · {fmtDate(user.createdAt)}</span>
          <span>last sign-in · {fmtDate(user.lastLoginAt)}</span>
          <span>
            {fmtNumber(user.vaultCount)} vaults · {fmtNumber(user.itemCount)} items · {fmtNumber(user.sessionCount)} sessions
          </span>
        </div>
        {user.archivedReason && (
          <p className="text-xs text-warning">Suspension note: {user.archivedReason}</p>
        )}

        {isSelf ? (
          <p className="text-xs text-muted-foreground leading-relaxed">
            This is your own account. Suspending it, revoking your console access and deleting it are all refused here — your
            own devices and your own deletion live in Settings, where they are re-authenticated by your Master Password.
          </p>
        ) : (
        <div className="space-y-2.5">
          <p className="field-label">Access</p>
          {user.isActive ? (
            <div className="flex flex-col sm:flex-row gap-2.5">
              <input
                className="input flex-1"
                placeholder="Reason (kept on the account)"
                maxLength={200}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                disabled={busy}
              />
              <button
                type="button"
                className="btn btn-secondary"
                disabled={busy}
                onClick={() => act("/api/v1/admin/users/suspend", { userId: user.id, suspend: true, reason }, "Account suspended")}
              >
                Suspend
              </button>
            </div>
          ) : (
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy}
              onClick={() => act("/api/v1/admin/users/suspend", { userId: user.id, suspend: false }, "Account reactivated")}
            >
              Reactivate
            </button>
          )}
          <div className="flex flex-wrap gap-2.5">
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              disabled={busy || user.sessionCount === 0}
              onClick={() => act("/api/v1/admin/users/sessions/revoke", { id: user.id }, "Signed out everywhere")}
            >
              <DeviceIcon className="h-4 w-4" /> Sign out everywhere
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              disabled={busy}
              onClick={() =>
                act(
                  "/api/v1/admin/users/admin",
                  { userId: user.id, grant: !user.isAdmin },
                  user.isAdmin ? "Console access revoked" : "Console access granted",
                )
              }
            >
              <ShieldIcon className="h-4 w-4" /> {user.isAdmin ? "Revoke console access" : "Grant console access"}
            </button>
          </div>
        </div>
        )}

        {!user.emailVerified && (
          <div className="space-y-2.5">
            <p className="field-label">Email</p>
            <div className="flex flex-wrap gap-2.5">
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                disabled={busy}
                onClick={() =>
                  act<{ sent: boolean }>("/api/v1/admin/users/resend-verification", { id: user.id }, "Verification link sent")
                }
              >
                Resend verification link
              </button>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                disabled={busy}
                onClick={() => act("/api/v1/admin/users/verify-email", { id: user.id }, "Address marked verified")}
              >
                <CheckIcon className="h-4 w-4" /> Mark verified
              </button>
            </div>
            <p className="text-xs text-muted-foreground">
              Marking verified is the way through when email delivery is off — the link would never arrive.
            </p>
          </div>
        )}

        {!isSelf && (
        <div className="rounded-lg border border-danger p-4 space-y-3">
          <p className="field-label field-label-danger">Erase this account</p>
          <p className="text-xs text-muted-foreground leading-relaxed">
            Removes the account, its vaults, items, sessions and notifications. Nothing can be restored afterwards: every blob
            was encrypted with keys only its owner held, so no backup of this data is readable by anyone here.
          </p>
          <div className="flex flex-col sm:flex-row gap-2.5">
            <input
              className="input flex-1 font-mono"
              placeholder={user.email}
              value={typedEmail}
              onChange={(e) => setTypedEmail(e.target.value)}
              disabled={busy}
              aria-label="Type the account email to confirm"
            />
            <button
              type="button"
              className="btn btn-danger"
              disabled={busy || typedEmail.trim().toLowerCase() !== user.email}
              onClick={() =>
                act("/api/v1/admin/users/delete", { userId: user.id, email: typedEmail.trim() }, "Account erased", onClose)
              }
            >
              Erase
            </button>
          </div>
        </div>
        )}
      </div>
    </Dialog>
  );
}

function AccountsTab({ pageSize, selfId, onChanged }: { pageSize: number; selfId: string; onChanged: () => void }) {
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [data, setData] = useState<AdminUsersResponse | null>(null);
  const [failed, setFailed] = useState(false);
  const [selected, setSelected] = useState<AdminUserRow | null>(null);

  const load = useCallback(async () => {
    setFailed(false);
    const params = new URLSearchParams({ page: String(page) });
    if (search) params.set("q", search);
    try {
      const res = await getJSON<AdminUsersResponse>(`/api/v1/admin/users?${params}`);
      // A failed load must not render as an empty list: "no accounts match"
      // and "the query did not come back" are different answers.
      if (!res.ok || !res.data) setFailed(true);
      else setData(res.data);
    } catch {
      setFailed(true);
    }
  }, [page, search]);

  useEffect(() => {
    void load();
  }, [load]);

  const refresh = () => {
    void load();
    onChanged();
  };

  return (
    <div className="animate-rise">
      <form
        className="flex gap-2.5 mb-5"
        onSubmit={(e) => {
          e.preventDefault();
          setPage(0);
          setSearch(query.trim());
        }}
      >
        <input
          className="input flex-1"
          placeholder="Search by email"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Search accounts by email"
        />
        <button type="submit" className="btn btn-secondary">
          <SearchIcon className="h-4 w-4" /> Search
        </button>
      </form>

      {failed ? (
        <StatusPanel
          icon={<AlertIcon className="h-5 w-5" />}
          tone="danger"
          as="h2"
          title="The account list didn't load"
          body="Nothing has changed. Try again."
        >
          <button type="button" className="btn btn-secondary" onClick={() => void load()}>
            Retry
          </button>
        </StatusPanel>
      ) : !data ? (
        <Loading />
      ) : data.users.length === 0 ? (
        <StatusPanel as="h2" title="No accounts match" body={search ? `Nothing found for “${search}”.` : "Nobody has registered yet."} />
      ) : (
        <section className="panel p-2 sm:p-4">
          <div className="divide-y divide-border-subtle">
            {data.users.map((user) => (
              <button
                key={user.id}
                type="button"
                onClick={() => setSelected(user)}
                className="w-full text-left flex items-center gap-3 py-3 px-2 hover:bg-muted transition-colors rounded-md"
              >
                <div className={`icon-tile icon-tile-sm flex-shrink-0${user.isActive ? "" : " icon-tile-danger"}`}>
                  <UsersIcon className="h-4 w-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-sm text-foreground truncate">
                    {user.email}
                    <UserBadges user={user} />
                  </p>
                  <p className="text-xs text-muted-foreground font-mono truncate">
                    {fmtNumber(user.vaultCount)} vaults · {fmtNumber(user.itemCount)} items · joined{" "}
                    {new Date(user.createdAt).toLocaleDateString()}
                  </p>
                </div>
                <span className="text-xs text-muted-foreground hidden sm:inline">Manage</span>
              </button>
            ))}
          </div>
          <Pager page={data.page} total={data.total} pageSize={pageSize} onPage={setPage} />
        </section>
      )}

      {selected && (
        <UserDialog
          user={selected}
          isSelf={selected.id === selfId}
          onClose={() => setSelected(null)}
          onChanged={() => {
            setSelected(null);
            refresh();
          }}
        />
      )}
    </div>
  );
}

// --- Security trail ---------------------------------------------------------

function TrailTab() {
  const [page, setPage] = useState(0);
  const [entries, setEntries] = useState<AdminAuditRow[] | null>(null);
  const [failed, setFailed] = useState(false);

  const load = useCallback(async () => {
    setFailed(false);
    try {
      const res = await getJSON<AdminAuditResponse>(`/api/v1/admin/audit?page=${page}`);
      if (!res.ok || !res.data) setFailed(true);
      else setEntries(res.data.entries);
    } catch {
      setFailed(true);
    }
  }, [page]);

  useEffect(() => {
    void load();
  }, [load]);

  if (failed) {
    return (
      <StatusPanel icon={<AlertIcon className="h-5 w-5" />} tone="danger" as="h2" title="The trail didn't load" body="Try again.">
        <button type="button" className="btn btn-secondary" onClick={() => void load()}>
          Retry
        </button>
      </StatusPanel>
    );
  }
  if (!entries) return <Loading />;
  if (entries.length === 0) {
    return <StatusPanel as="h2" title="Nothing recorded yet" body="Sign-ins, account changes and item lifecycle events land here." />;
  }

  return (
    <section className="panel p-2 sm:p-4 animate-rise">
      <div className="divide-y divide-border-subtle">
        {entries.map((entry) => (
          <div key={entry.id} className="py-3 px-2">
            <p className="text-sm text-foreground">
              <span className="font-mono text-accent">{entry.action}</span>
              {entry.email && <span className="text-muted-foreground"> · {entry.email}</span>}
            </p>
            <p className="text-xs text-muted-foreground font-mono break-all">
              {fmtDate(entry.createdAt)}
              {entry.entityType && ` · ${entry.entityType} ${entry.entityId ?? ""}`}
              {entry.ipAddress && ` · ${entry.ipAddress}`}
              {entry.detail && ` · ${entry.detail}`}
            </p>
          </div>
        ))}
      </div>
      <div className="flex items-center justify-between pt-4">
        <button type="button" className="btn btn-secondary btn-sm" disabled={page <= 0} onClick={() => setPage(page - 1)}>
          Newer
        </button>
        <span className="text-xs text-muted-foreground font-mono">page {page + 1}</span>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          disabled={entries.length === 0}
          onClick={() => setPage(page + 1)}
        >
          Older
        </button>
      </div>
    </section>
  );
}

// --- Contact inbox ----------------------------------------------------------

function InboxTab({ pageSize, onChanged }: { pageSize: number; onChanged: () => void }) {
  const toast = useToasts();
  const [showAll, setShowAll] = useState(false);
  const [page, setPage] = useState(0);
  const [data, setData] = useState<AdminInquiriesResponse | null>(null);
  const [failed, setFailed] = useState(false);
  const { busy, run } = useAction({ onError: (m) => toast("error", m), network: "Network error" });

  const load = useCallback(async () => {
    setFailed(false);
    try {
      const res = await getJSON<AdminInquiriesResponse>(`/api/v1/admin/inquiries?page=${page}&all=${showAll ? "1" : "0"}`);
      if (!res.ok || !res.data) setFailed(true);
      else setData(res.data);
    } catch {
      setFailed(true);
    }
  }, [page, showAll]);

  useEffect(() => {
    void load();
  }, [load]);

  const setHandled = async (inquiry: ContactInquiry, handled: boolean) => {
    await run(() => postJSON("/api/v1/admin/inquiries/handled", { id: inquiry.id, handled }), {
      onOK: () => {
        toast("success", handled ? "Marked handled" : "Reopened");
        void load();
        onChanged();
      },
      fail: "Couldn't update that message",
    });
  };

  return (
    <div className="animate-rise">
      <div className="seg mb-5" role="tablist" aria-label="Message filter">
        <button
          type="button"
          role="tab"
          aria-selected={!showAll}
          className="seg-item"
          onClick={() => {
            setPage(0);
            setShowAll(false);
          }}
        >
          Open
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={showAll}
          className="seg-item"
          onClick={() => {
            setPage(0);
            setShowAll(true);
          }}
        >
          Everything
        </button>
      </div>

      {failed ? (
        <StatusPanel icon={<AlertIcon className="h-5 w-5" />} tone="danger" as="h2" title="The inbox didn't load" body="Try again.">
          <button type="button" className="btn btn-secondary" onClick={() => void load()}>
            Retry
          </button>
        </StatusPanel>
      ) : !data ? (
        <Loading />
      ) : data.inquiries.length === 0 ? (
        <StatusPanel as="h2" title="Nothing waiting" body={showAll ? "No one has written in yet." : "Every message has been handled."} />
      ) : (
        <section className="panel p-4 sm:p-6">
          <div className="divide-y divide-border-subtle">
            {data.inquiries.map((inquiry) => (
              <article key={inquiry.id} className="py-4 first:pt-0">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <p className="text-sm text-foreground">
                      {inquiry.name}
                      {inquiry.handledAt && <span className="badge badge-success ml-2">handled</span>}
                    </p>
                    <a href={`mailto:${inquiry.email}`} className="text-xs text-accent hover:text-accent-active font-mono break-all">
                      {inquiry.email}
                    </a>
                  </div>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm flex-shrink-0"
                    disabled={busy}
                    onClick={() => setHandled(inquiry, !inquiry.handledAt)}
                  >
                    {inquiry.handledAt ? "Reopen" : "Mark handled"}
                  </button>
                </div>
                <p className="text-sm text-muted-foreground mt-2.5 whitespace-pre-wrap break-words leading-relaxed">
                  {inquiry.message}
                </p>
                <p className="text-xs text-muted-foreground font-mono mt-2">
                  {fmtDate(inquiry.createdAt)}
                  {inquiry.ipAddress && ` · ${inquiry.ipAddress}`}
                </p>
              </article>
            ))}
          </div>
          <Pager page={data.page} total={data.total} pageSize={pageSize} onPage={setPage} />
        </section>
      )}
    </div>
  );
}

// --- Shell ------------------------------------------------------------------

type TabKey = "overview" | "accounts" | "trail" | "inbox";

// .seg-item is a text pill — it lays out no flex, so a glyph beside a label
// stacks on top of it. The labels carry these four on their own.
const TABS: { key: TabKey; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "accounts", label: "Accounts" },
  { key: "trail", label: "Security trail" },
  { key: "inbox", label: "Messages" },
];

function AdminApp() {
  const data = useBungoData() as AdminPageData;
  const [tab, setTab] = useState<TabKey>("overview");
  const [stats, setStats] = useState(data.Stats);
  const [settings, setSettings] = useState(data.Settings);

  // Counts go stale the moment an action changes one, so every mutation asks
  // for the overview again rather than adjusting a number locally: a tile that
  // drifts from the database is worse than one that reloads.
  const refreshOverview = useCallback(async () => {
    const res = await getJSON<AdminOverview>("/api/v1/admin/overview");
    if (res.ok && res.data) {
      setStats(res.data.stats);
      setSettings(res.data.settings);
    }
  }, []);

  return (
    <div className="animate-unseal">
      <header className="mb-7">
        <p className="eyebrow mb-3">Operations</p>
        <h1 className="text-3xl font-extrabold tracking-tighter">Console</h1>
        <p className="text-sm text-muted-foreground mt-2 max-w-2xl leading-relaxed">
          Platform gates, accounts and the security trail. Vault contents are not here and cannot be: every item was encrypted
          on its owner's device, and the server holds no key to any of them.
        </p>
      </header>

      <div className="seg mb-7" role="tablist" aria-label="Console sections">
        {TABS.map((entry) => (
          <button
            key={entry.key}
            type="button"
            role="tab"
            aria-selected={tab === entry.key}
            className="seg-item"
            onClick={() => setTab(entry.key)}
          >
            {entry.label}
          </button>
        ))}
      </div>

      {tab === "overview" && <OverviewTab stats={stats} settings={settings} onSettingsSaved={setSettings} />}
      {tab === "accounts" && (
        <AccountsTab pageSize={data.PageSize} selfId={data.SelfID} onChanged={() => void refreshOverview()} />
      )}
      {tab === "trail" && <TrailTab />}
      {tab === "inbox" && <InboxTab pageSize={data.PageSize} onChanged={() => void refreshOverview()} />}
    </div>
  );
}

function AdminRoot() {
  return (
    <ToastProvider>
      <AdminApp />
    </ToastProvider>
  );
}

_bungoRender(AdminRoot, "admin-root");
