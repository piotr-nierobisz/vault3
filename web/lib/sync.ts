// Change-signal client: subscribes to the /events SSE stream and invokes
// onChange whenever ANOTHER client mutates this user's data. Events
// originating from this tab (matched via the per-tab client id the api layer
// sends) are ignored — the tab already has the freshest state from its own
// response. EventSource reconnects automatically; the opening event carries
// the current revision, so a missed window is detected by comparing against
// the last revision this tab applied.

import { clientID } from "./keystore";

export type SyncHandle = { close: () => void };

export function startSync(initialRevision: number, onChange: (revision: number) => void): SyncHandle {
  let lastApplied = initialRevision;
  const self = clientID();

  const source = new EventSource("/events");
  source.addEventListener("change", (event) => {
    try {
      const payload = JSON.parse((event as MessageEvent).data) as { revision: number; origin?: string };
      if (payload.revision <= lastApplied) return;
      lastApplied = payload.revision;
      if (payload.origin === self) return;
      onChange(payload.revision);
    } catch {
      // Malformed frame: ignore; the next heartbeat/open resyncs.
    }
  });

  return {
    close: () => source.close(),
  };
}
