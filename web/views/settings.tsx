import React, { useState } from "react";
import { AlertIcon, BellIcon, CheckIcon, DeviceIcon, IdentityIcon, LockIcon, ShieldIcon } from "../components/icons";
import { PasswordInput } from "../components/ui/password-input";
import { CheckboxBox } from "../components/ui/checkbox";
import { ErrorBanner } from "../components/ui/error-banner";
import { SecretText } from "../components/ui/secret-text";
import { CopyButton } from "../components/ui/copy-button";
import { Dialog } from "../components/ui/dialog";
import { ToastProvider, useToasts } from "../components/ui/toast";
import { postJSON } from "../lib/api";
import { b64uEncode, deriveKeys, open as openEnvelope, seal, type DerivationStage } from "../lib/crypto";
import { DerivationProgress } from "../components/ui/derivation-progress";
import { autoLockMinutes, forgetIdentity, loadIdentity, saveKeys, setAutoLockMinutes } from "../lib/keystore";
import { useAction } from "../lib/use-action";
import type { NotificationPrefs, SessionRow, SettingsPageData, TwoFactorSetupResponse } from "../types/settings";

// Settings. The Master Password change is the flagship flow: everything is
// re-derived and re-wrapped in this browser, then applied server-side in one
// transaction (which also signs out every other device).

// Every settings block is the same object: an icon tile naming the area,
// the title, and an optional one-line explanation of what it controls.
function Section({
  icon,
  title,
  subtitle,
  tone,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  subtitle?: string;
  tone?: "danger";
  children: React.ReactNode;
}) {
  return (
    <section className={`panel p-7 mb-6 animate-rise${tone === "danger" ? " panel-danger" : ""}`}>
      <div className="flex items-start gap-3.5 mb-6">
        <span className={`icon-tile flex-shrink-0${tone === "danger" ? " icon-tile-danger" : ""}`} aria-hidden="true">
          {icon}
        </span>
        <div className="min-w-0">
          <h2 className="text-lg font-bold tracking-tight">{title}</h2>
          {subtitle && <p className="text-sm text-muted-foreground mt-0.5 leading-relaxed">{subtitle}</p>}
        </div>
      </div>
      {children}
    </section>
  );
}

function ProfileSection({ initialName }: { initialName: string }) {
  const toast = useToasts();
  const [name, setName] = useState(initialName);
  const { busy, run } = useAction({ onError: (message) => toast("error", message), network: "Network error" });

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    await run(() => postJSON("/api/v1/account/profile", { displayName: name.trim() }), {
      onOK: () => toast("success", "Profile saved"),
      fail: "Couldn't save the profile",
    });
  };

  return (
    <form onSubmit={save} className="flex items-end gap-3">
      <div className="flex-1 space-y-1.5">
        <label htmlFor="settings-name" className="field-label">Display name</label>
        <input id="settings-name" className="input" maxLength={100} placeholder="Your name" value={name} onChange={(e) => setName(e.target.value)} disabled={busy} />
      </div>
      <button type="submit" disabled={busy} className="btn btn-primary">Save</button>
    </form>
  );
}

function PasswordSection({ data }: { data: SettingsPageData }) {
  const toast = useToasts();
  const email = data.Viewer?.User.email ?? "";
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  // Bumped per submit and used as the banner's key. Re-setting an identical
  // message is a no-op to React, so without this a second failed submit
  // re-renders nothing and the shake never replays — the user sees no
  // response at all to their click.
  const [attempt, setAttempt] = useState(0);
  const [stage, setStage] = useState<DerivationStage | null>(null);

  const change = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setAttempt((n) => n + 1);
    const identity = loadIdentity();
    if (!identity?.secretPhrase) {
      setError("Your Secret Phrase isn't saved on this device — sign out and back in first, entering it manually.");
      return;
    }
    if (!data.Keyset) return;
    if (next !== confirm) {
      setError("The new passwords don't match.");
      return;
    }
    if (next.length < 10) {
      setError("Make the new Master Password at least 10 characters.");
      return;
    }
    setBusy(true);
    try {
      // 1. Re-derive the CURRENT keys and prove them locally by unwrapping.
      const currentKeys = await deriveKeys(email, current, identity.secretPhrase, data.Keyset, setStage);
      const vaultKeyByID: Record<string, Uint8Array> = {};
      try {
        for (const vault of data.Keyset.vaults) {
          vaultKeyByID[vault.id] = await openEnvelope(currentKeys.encKeyRaw, vault.wrappedKey);
        }
      } catch {
        setError("Your current Master Password wasn't right.");
        return;
      }

      // 2. Derive the NEW keys under a fresh salt (same Secret Phrase) and at
      // the platform's CURRENT costs, which may have been raised since this
      // account registered — a password change is where an account catches up.
      const saltBytes = new Uint8Array(16);
      crypto.getRandomValues(saltBytes);
      const newSalt = b64uEncode(saltBytes);
      const newKeys = await deriveKeys(
        email,
        next,
        identity.secretPhrase,
        { kdfSalt: newSalt, ...data.KdfCosts },
        setStage,
      );
      setStage(null);

      // 3. Re-wrap every vault key under the new encryption key.
      const vaults = [] as { vaultId: string; wrappedKey: unknown }[];
      for (const vault of data.Keyset.vaults) {
        vaults.push({ vaultId: vault.id, wrappedKey: await seal(newKeys.encKeyRaw, vaultKeyByID[vault.id]) });
      }

      // 4. Apply atomically server-side.
      const res = await postJSON<{ changed?: boolean; message?: string }>("/api/v1/account/password", {
        currentAuthKey: currentKeys.authKey,
        newAuthKey: newKeys.authKey,
        newKdfSalt: newSalt,
        ...data.KdfCosts,
        vaults,
      });
      if (!res.ok) {
        setError(res.data?.message ?? "The change couldn't be applied.");
        return;
      }

      saveKeys({ encKey: newKeys.encKeyRaw, vaultKeys: vaultKeyByID });
      setCurrent("");
      setNext("");
      setConfirm("");
      toast("success", "Master Password changed. Other sessions were signed out.");
      window.setTimeout(() => window.location.reload(), 900);
    } catch {
      setError("Network error. Nothing was changed.");
    } finally {
      setBusy(false);
      setStage(null);
    }
  };

  return (
    <form onSubmit={change} className="space-y-4" noValidate>
      {error && <ErrorBanner key={attempt} message={error} />}
      <DerivationProgress stage={stage} />
      <div className="space-y-1.5">
        <label htmlFor="pw-current" className="field-label">Current Master Password</label>
        <PasswordInput id="pw-current" name="current" autoComplete="current-password" value={current} onChange={setCurrent} disabled={busy} />
      </div>
      <div className="grid sm:grid-cols-2 gap-4">
        <div className="space-y-1.5">
          <label htmlFor="pw-next" className="field-label">New Master Password</label>
          <PasswordInput id="pw-next" name="next" autoComplete="new-password" value={next} onChange={setNext} disabled={busy} />
        </div>
        <div className="space-y-1.5">
          <label htmlFor="pw-confirm" className="field-label">Confirm</label>
          <PasswordInput id="pw-confirm" name="confirm" autoComplete="new-password" value={confirm} onChange={setConfirm} disabled={busy} />
        </div>
      </div>
      <p className="text-xs text-muted-foreground leading-relaxed">
        Your vault keys are re-wrapped in this browser under the new password; your Secret Phrase stays the same. Every other device is signed out.
      </p>
      <button type="submit" disabled={busy || !current || !next} className="btn btn-primary">
        {busy ? "Re-sealing…" : "Change Master Password"}
      </button>
    </form>
  );
}

function TwoFactorSection({ enabled: initialEnabled }: { enabled: boolean }) {
  const toast = useToasts();
  const [enabled, setEnabled] = useState(initialEnabled);
  const [setup, setSetup] = useState<TwoFactorSetupResponse | null>(null);
  const [code, setCode] = useState("");
  const [disableOpen, setDisableOpen] = useState(false);
  const { busy, run } = useAction({ onError: (message) => toast("error", message), network: "Network error" });

  const begin = async () => {
    await run(() => postJSON<TwoFactorSetupResponse>("/api/v1/account/2fa/setup", {}), {
      onOK: (started) => {
        setSetup(started);
        setCode("");
      },
      fail: "Couldn't start the setup.",
    });
  };

  const verify = async () => {
    await run(() => postJSON<{ enabled?: boolean }>("/api/v1/account/2fa/verify", { code }), {
      onOK: () => {
        setEnabled(true);
        setSetup(null);
        toast("success", "Two-factor authentication is on");
      },
      fail: "That code wasn't right.",
    });
  };

  const disable = async () => {
    await run(() => postJSON<{ disabled?: boolean }>("/api/v1/account/2fa/disable", { code }), {
      onOK: () => {
        setEnabled(false);
        setDisableOpen(false);
        setCode("");
        toast("success", "Two-factor authentication is off");
      },
      fail: "That code wasn't right.",
    });
  };

  return (
    <div>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className={`icon-tile icon-tile-sm flex-shrink-0${enabled ? "" : " icon-tile-muted"}`}>
            <ShieldIcon className="h-5 w-5" />
          </div>
          <div>
            <p className="text-sm font-medium text-foreground">Authenticator app</p>
            <p className="text-xs text-muted-foreground">{enabled ? "Enabled — codes required at sign-in" : "Off — your Secret Phrase remains the second factor"}</p>
          </div>
        </div>
        {enabled ? (
          <button type="button" onClick={() => { setDisableOpen(true); setCode(""); }} className="btn btn-secondary btn-sm" disabled={busy}>Disable</button>
        ) : (
          <button type="button" onClick={begin} className="btn btn-primary btn-sm" disabled={busy}>Enable</button>
        )}
      </div>

      {setup && (
        <div className="mt-5 rounded-lg border border-border bg-muted p-5 space-y-4 animate-pop">
          <p className="text-sm text-foreground">Scan this with your authenticator app, then enter the 6-digit code it shows.</p>
          {/* The QR is a data: URI minted per setup call — nothing to fetch,
              nothing cached. The setup key below is the manual fallback for
              anyone who can't scan (desktop app, no camera). */}
          <div className="flex flex-col sm:flex-row sm:items-center gap-5">
            <img
              src={setup.qrDataUri}
              alt="QR code for your authenticator app"
              width={232}
              height={232}
              className="w-[176px] h-[176px] rounded-lg bg-white p-2 flex-shrink-0 self-center sm:self-start"
            />
            <div className="min-w-0 flex-1 space-y-2">
              <p className="field-label">Or enter this key by hand</p>
              <div className="flex items-center gap-2">
                <SecretText value={setup.secret} className="text-sm break-all flex-1 min-w-0" />
                <CopyButton value={setup.secret} label="Copy setup key" />
              </div>
              <a href={setup.otpauthUrl} className="inline-block text-xs text-accent hover:text-accent-active underline">Open in authenticator app</a>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <input
              className="input font-mono tracking-[0.4em] max-w-[180px]"
              inputMode="numeric"
              maxLength={6}
              placeholder="123456"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
              disabled={busy}
            />
            <button type="button" onClick={verify} disabled={busy || code.length !== 6} className="btn btn-primary">
              <CheckIcon className="h-4 w-4" /> Verify
            </button>
            <button type="button" onClick={() => setSetup(null)} disabled={busy} className="btn btn-ghost">Cancel</button>
          </div>
        </div>
      )}

      <Dialog open={disableOpen} onClose={() => setDisableOpen(false)} title="Disable two-factor authentication">
        <p className="text-sm text-muted-foreground mb-4">Enter a current code from your authenticator app to switch 2FA off.</p>
        <div className="flex items-center gap-3">
          <input
            className="input font-mono tracking-[0.4em] max-w-[180px]"
            inputMode="numeric"
            maxLength={6}
            placeholder="123456"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            disabled={busy}
            autoFocus
          />
          <button type="button" onClick={disable} disabled={busy || code.length !== 6} className="btn btn-danger">Disable</button>
        </div>
      </Dialog>
    </div>
  );
}

function SessionsSection({ sessions: initial }: { sessions: SessionRow[] }) {
  const toast = useToasts();
  const [sessions, setSessions] = useState(initial);
  const { busy, run } = useAction({ onError: (message) => toast("error", message), network: "Network error" });

  const revoke = async (id: string) => {
    await run(() => postJSON("/api/v1/account/sessions/revoke", { sessionId: id }), {
      onOK: () => {
        setSessions((s) => s.filter((x) => x.id !== id));
        toast("success", "Session revoked");
      },
      fail: "Couldn't revoke that session",
    });
  };

  return (
    <div className="divide-y divide-border-subtle">
      {sessions.map((s) => (
        <div key={s.id} className="flex items-center gap-3 py-3">
          <div className="icon-tile icon-tile-sm icon-tile-muted flex-shrink-0">
            <DeviceIcon className="h-4 w-4" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-sm text-foreground truncate">
              {s.userAgent || "Unknown device"}
              {s.current && <span className="badge badge-accent ml-2">this device</span>}
            </p>
            <p className="text-xs text-muted-foreground font-mono">
              {s.ipAddress || "unknown ip"} · last seen {new Date(s.lastSeenAt).toLocaleString()}
            </p>
          </div>
          {!s.current && (
            <button type="button" onClick={() => revoke(s.id)} disabled={busy} className="btn btn-ghost btn-sm text-danger">
              Revoke
            </button>
          )}
        </div>
      ))}
    </div>
  );
}

function PrefsSection({ initial }: { initial: NotificationPrefs }) {
  const toast = useToasts();
  const [prefs, setPrefs] = useState(initial);
  const [autoLock, setAutoLock] = useState(autoLockMinutes());

  // Optimistic: the checkbox moves first so toggling stays instant. Which
  // means a failure has to put it back — leaving it flipped would state,
  // permanently and silently, a preference the server never accepted.
  const save = async (next: NotificationPrefs) => {
    const previous = prefs;
    setPrefs(next);
    try {
      const res = await postJSON("/api/v1/account/notifications", next);
      if (!res.ok) {
        setPrefs(previous);
        toast("error", "Couldn't save preferences");
      }
    } catch {
      setPrefs(previous);
      toast("error", "Network error");
    }
  };

  const toggle = (label: string, hint: string, value: boolean, onChange: (v: boolean) => void, disabled?: boolean) => (
    <label className={`flex items-center justify-between py-3 ${disabled ? "opacity-50" : "cursor-pointer"}`}>
      <span>
        <span className="block text-sm text-foreground">{label}</span>
        <span className="block text-xs text-muted-foreground">{hint}</span>
      </span>
      <CheckboxBox checked={value} disabled={disabled} onChange={onChange} />
    </label>
  );

  return (
    <div className="divide-y divide-border-subtle">
      {toggle("Email notifications", "Master switch. Critical account emails are always sent.", prefs.emailEnabled, (v) => save({ ...prefs, emailEnabled: v }))}
      {toggle("Security alerts", "New device sign-ins, 2FA changes.", prefs.securityAlerts, (v) => save({ ...prefs, securityAlerts: v }), !prefs.emailEnabled)}
      {toggle("Product updates", "Occasional news about Vault3.", prefs.productUpdates, (v) => save({ ...prefs, productUpdates: v }), !prefs.emailEnabled)}
      <div className="flex items-center justify-between py-3">
        <span>
          <span className="block text-sm text-foreground">Auto-lock this device</span>
          <span className="block text-xs text-muted-foreground">Seal the vault after inactivity.</span>
        </span>
        <select
          className="input w-auto"
          value={autoLock}
          onChange={(e) => {
            const minutes = parseInt(e.target.value, 10);
            setAutoLock(minutes);
            setAutoLockMinutes(minutes);
            toast("success", `Auto-lock set to ${minutes} minutes`);
          }}
        >
          <option value={5}>5 minutes</option>
          <option value={15}>15 minutes</option>
          <option value={60}>1 hour</option>
        </select>
      </div>
    </div>
  );
}

function DangerSection({ data }: { data: SettingsPageData }) {
  const toast = useToasts();
  const email = data.Viewer?.User.email ?? "";
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [typed, setTyped] = useState("");
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const { busy, run } = useAction({ onError: setError, network: "Network error. Nothing was deleted." });

  const destroy = async () => {
    setError("");
    setAttempt((n) => n + 1);
    const identity = loadIdentity();
    if (!identity?.secretPhrase || !data.Keyset) {
      setError("Your Secret Phrase isn't on this device. Sign in entering it manually first.");
      return;
    }
    const secretPhrase = identity.secretPhrase;
    const keyset = data.Keyset;
    await run(
      async () => {
        const { authKey } = await deriveKeys(email, password, secretPhrase, keyset);
        return postJSON<{ deleted?: boolean }>("/api/v1/account/delete", { authKey });
      },
      {
        onOK: () => {
          // Through the keystore, not by name: the storage keys are its
          // business, and a hardcoded copy here would silently stop clearing
          // the remembered Secret Phrase the day one of them is renamed.
          sessionStorage.clear();
          forgetIdentity();
          window.location.assign("/");
        },
        fail: "Deletion failed.",
      },
    );
  };

  return (
    <div>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-foreground">Delete this account</p>
          <p className="text-xs text-muted-foreground">Erases your vault, sessions and account. Permanent.</p>
        </div>
        <button type="button" onClick={() => setOpen(true)} className="btn btn-danger btn-sm">Delete account</button>
      </div>
      <Dialog open={open} onClose={() => setOpen(false)} title="Delete your account">
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">
            This permanently erases your vault and everything in it. Because Vault3 is zero-knowledge, there is no backup we could restore.
          </p>
          {error && <ErrorBanner key={attempt} message={error} />}
          <div className="space-y-1.5">
            <label className="field-label" htmlFor="del-password">Master Password</label>
            <PasswordInput id="del-password" name="password" value={password} onChange={setPassword} disabled={busy} />
          </div>
          <div className="space-y-1.5">
            <label className="field-label" htmlFor="del-typed">
              Type <span className="font-mono normal-case">DELETE</span> to confirm
            </label>
            <input id="del-typed" className="input font-mono" value={typed} onChange={(e) => setTyped(e.target.value.toUpperCase())} disabled={busy} placeholder="DELETE" />
          </div>
          <button type="button" onClick={destroy} disabled={busy || typed !== "DELETE" || !password} className="btn btn-danger btn-lg w-full">
            {busy ? "Deleting…" : "Delete everything"}
          </button>
        </div>
      </Dialog>
    </div>
  );
}

function SettingsApp() {
  const data = useBungoData() as SettingsPageData;
  return (
    <div className="animate-unseal">
      <header className="mb-9">
        <p className="eyebrow mb-3">Your account</p>
        <h1 className="text-3xl font-extrabold tracking-tighter">Settings</h1>
      </header>
      <Section icon={<IdentityIcon className="h-5 w-5" />} title="Profile" subtitle="How Vault3 addresses you. Stored encrypted at rest.">
        <ProfileSection initialName={data.Viewer?.User.displayName ?? ""} />
      </Section>
      <Section icon={<LockIcon className="h-5 w-5" />} title="Master Password" subtitle="Rotate the half of your key you carry in your head.">
        <PasswordSection data={data} />
      </Section>
      <Section icon={<ShieldIcon className="h-5 w-5" />} title="Two-factor authentication" subtitle="An authenticator-app code on top of your two secrets.">
        <TwoFactorSection enabled={data.TwoFactorEnabled} />
      </Section>
      <Section icon={<DeviceIcon className="h-5 w-5" />} title="Active sessions" subtitle="Everywhere this account is signed in.">
        <SessionsSection sessions={data.Sessions} />
      </Section>
      <Section icon={<BellIcon className="h-5 w-5" />} title="Notifications &amp; locking" subtitle="What Vault3 tells you about, and when it seals itself.">
        <PrefsSection initial={data.Prefs} />
      </Section>
      <Section icon={<AlertIcon className="h-5 w-5" />} title="Danger zone" subtitle="Irreversible. Read twice." tone="danger">
        <DangerSection data={data} />
      </Section>
    </div>
  );
}

function SettingsRoot() {
  return (
    <ToastProvider>
      <SettingsApp />
    </ToastProvider>
  );
}

_bungoRender(SettingsRoot, "settings-root");
