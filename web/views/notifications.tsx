import React, { useState } from "react";
import { DeviceIcon, ShieldIcon, SparkleIcon, CheckIcon } from "../components/icons";
import { StatusPanel } from "../components/ui/status-panel";
import { postJSON } from "../lib/api";
import type { NotificationItem, NotificationsPageData } from "../types/notifications";

// The notifications centre: the bell's big sibling. Same projection, plus
// mark-read / mark-all.

function iconFor(token: string) {
  switch (token) {
    case "device":
      return <DeviceIcon className="h-4 w-4" />;
    case "shield":
      return <ShieldIcon className="h-4 w-4" />;
    case "seal":
      return <CheckIcon className="h-4 w-4" />;
    case "sparkle":
      return <SparkleIcon className="h-4 w-4" />;
    default:
      return <ShieldIcon className="h-4 w-4" />;
  }
}

function NotificationsCentre() {
  const data = useBungoData() as NotificationsPageData;
  const [items, setItems] = useState<NotificationItem[]>(data.Notifications ?? []);
  const unread = items.filter((n) => !n.isRead).length;

  const markRead = async (id: string) => {
    setItems((list) => list.map((n) => (n.id === id ? { ...n, isRead: true } : n)));
    postJSON("/api/v1/notifications/read", { id }).catch(() => {});
  };

  const markAll = async () => {
    setItems((list) => list.map((n) => ({ ...n, isRead: true })));
    postJSON("/api/v1/notifications/read-all", {}).catch(() => {});
  };

  return (
    <div className="animate-unseal">
      <div className="flex items-end justify-between gap-4 mb-8">
        <div>
          <p className="eyebrow mb-3">Account activity</p>
          <h1 className="text-3xl font-extrabold tracking-tighter">Notifications</h1>
          <p className="text-sm text-muted-foreground mt-1.5">
            {unread > 0 ? `${unread} unread` : "All caught up"}
          </p>
        </div>
        <button type="button" onClick={markAll} disabled={unread === 0} className="btn btn-secondary btn-sm disabled:opacity-40">
          Mark all as read
        </button>
      </div>

      {items.length === 0 ? (
        <StatusPanel body="Nothing yet — quiet is good." />
      ) : (
        <div className="panel divide-y divide-border-subtle">
          {items.map((n, index) => (
            <button
              key={n.id}
              type="button"
              onClick={() => {
                if (!n.isRead) markRead(n.id);
                if (n.href) window.location.assign(n.href);
              }}
              className={`item-row-enter w-full flex items-start gap-3.5 px-5 py-4 text-left transition-colors hover:bg-muted ${
                n.isRead ? "" : "row-accent "
              }${n.href ? "cursor-pointer" : "cursor-default"}`}
              style={{ "--stagger-i": index } as React.CSSProperties}
            >
              <div
                className={`icon-tile flex-shrink-0 mt-0.5${n.isRead ? " icon-tile-muted" : ""}`}
                aria-hidden="true"
              >
                {iconFor(n.icon)}
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-start justify-between gap-3">
                  <p className={`text-sm font-semibold leading-snug ${n.isRead ? "text-muted-foreground" : "text-foreground"}`}>{n.title}</p>
                  <span className="text-xs text-muted-foreground whitespace-nowrap mt-0.5">{n.timeLabel}</span>
                </div>
                <p className="text-sm text-muted-foreground mt-1 leading-relaxed">{n.body}</p>
              </div>
              {!n.isRead && <span className="w-2 h-2 rounded-full bg-accent mt-2 flex-shrink-0" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

_bungoRender(NotificationsCentre, "notifications-root");
