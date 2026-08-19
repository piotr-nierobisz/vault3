// Change-signal client: holds a WebSocket to /ws/changes and invokes onChange
// whenever ANOTHER client mutates this user's data. Signals originating from
// this tab (matched via the per-tab client id the api layer sends) are ignored
// — the tab already has the freshest state from its own response.
//
// Unlike EventSource a WebSocket does not reconnect itself, so that is this
// module's other job: retry with capped, jittered backoff, and retry at once
// when a backgrounded tab comes back. Every (re)connection opens with the
// current revision, so a window missed while disconnected is caught by
// comparing against the last revision this tab applied.

import { clientID } from "./keystore";

export type SyncHandle = { close: () => void };

const RETRY_MIN_MS = 1_000;
const RETRY_MAX_MS = 30_000;

type ChangeSignal = { revision: number; origin?: string };

export function startSync(initialRevision: number, onChange: (revision: number) => void): SyncHandle {
  let lastApplied = initialRevision;
  const self = clientID();

  let socket: WebSocket | null = null;
  let retryDelay = RETRY_MIN_MS;
  let retryTimer = 0;
  let stopped = false;

  const endpoint = () => `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/changes`;

  const scheduleRetry = () => {
    if (stopped || retryTimer) return;
    // Jitter so a server restart does not bring every client back at once.
    const delay = retryDelay * (0.5 + Math.random() / 2);
    retryTimer = window.setTimeout(() => {
      retryTimer = 0;
      connect();
    }, delay);
    retryDelay = Math.min(retryDelay * 2, RETRY_MAX_MS);
  };

  const connect = () => {
    if (stopped || socket) return;

    const ws = new WebSocket(endpoint());
    socket = ws;

    ws.onopen = () => {
      retryDelay = RETRY_MIN_MS;
    };

    ws.onmessage = (event) => {
      try {
        const signal = JSON.parse(event.data as string) as ChangeSignal;
        if (signal.revision <= lastApplied) return;
        lastApplied = signal.revision;
        if (signal.origin === self) return;
        onChange(signal.revision);
      } catch {
        // Malformed frame: ignore; the next signal or reconnect resyncs.
      }
    };

    // onclose fires after onerror too, so retries are scheduled in one place.
    ws.onclose = () => {
      socket = null;
      scheduleRetry();
    };
  };

  // A laptop that slept can sit out the whole backoff otherwise; returning to
  // the tab is exactly when a stale vault is about to be looked at.
  const onVisible = () => {
    if (document.visibilityState !== "visible" || socket) return;
    window.clearTimeout(retryTimer);
    retryTimer = 0;
    retryDelay = RETRY_MIN_MS;
    connect();
  };
  document.addEventListener("visibilitychange", onVisible);

  connect();

  return {
    close: () => {
      stopped = true;
      document.removeEventListener("visibilitychange", onVisible);
      window.clearTimeout(retryTimer);
      socket?.close();
      socket = null;
    },
  };
}