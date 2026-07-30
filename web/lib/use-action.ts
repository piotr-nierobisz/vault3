// Every async action in the app repeats one shape: refuse to re-enter while
// one is in flight, call the API, branch on `ok`, surface the failure, and
// clear the busy flag whatever happened. useAction owns that shape so a
// handler is left holding only its own success path.
//
// Where a failure is shown (a toast, an inline banner) and how a dropped
// connection is worded belong to the surface rather than to each button on
// it, so a component states them once when it takes the hook.

import { useRef, useState } from "react";
import type { ApiResult } from "./api";

export function useAction(surface: { onError: (message: string) => void; network: string }) {
  const [busy, setBusy] = useState(false);
  // The re-entry guard reads a ref, not `busy`: a double click lands before
  // React has re-rendered the button as disabled, so the state value is
  // still the stale one from the render that handled the first click.
  const inFlight = useRef(false);

  // Resolves to whether the success path ran, so a caller can undo state of
  // its own — a two-step confirm — without re-deriving the outcome.
  const run = async <T>(
    call: () => Promise<ApiResult<T>>,
    opts: { onOK: (data: T) => void | Promise<void>; fail: string },
  ): Promise<boolean> => {
    if (inFlight.current) return false;
    inFlight.current = true;
    setBusy(true);
    try {
      const res = await call();
      const data = res.data;
      if (!res.ok || data === null) {
        // Every API failure answers {"message": …}, while response types are
        // written for what a SUCCESS returns — so the message is read off
        // the side rather than declared on twenty response shapes.
        const body: unknown = data;
        surface.onError((body as { message?: string } | null)?.message ?? opts.fail);
        return false;
      }
      // Awaited: a success path that unwraps a key is still the action, and
      // must finish inside the busy window and the network catch.
      await opts.onOK(data);
      return true;
    } catch {
      surface.onError(surface.network);
      return false;
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  };

  return { busy, run };
}