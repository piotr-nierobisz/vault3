// Central client for the JSON API. Views POST through postJSON rather than
// re-declaring the fetch boilerplate (method, JSON headers, credentials,
// body parse) per form. It never throws on a non-2xx status: the caller
// branches on `ok` and reads the parsed `data`. Only a network failure
// rejects, so callers keep a try/catch for that case.
//
// Every request carries the per-tab client id (X-Vault3-Client) so the
// change-signal stream can distinguish this tab's own mutations from
// everyone else's.

import { clientID } from "./keystore";

export type ApiResult<T> = {
  ok: boolean;
  status: number;
  data: T | null;
};

export async function postJSON<T = unknown>(
  path: string,
  body: unknown,
  opts?: { credentials?: RequestCredentials },
): Promise<ApiResult<T>> {
  const res = await fetch(path, {
    method: "POST",
    credentials: opts?.credentials ?? "same-origin",
    headers: { "Content-Type": "application/json", "X-Vault3-Client": clientID() },
    body: JSON.stringify(body),
  });
  const data = (await res.json().catch(() => null)) as T | null;
  return { ok: res.ok, status: res.status, data };
}

// getJSON is the GET counterpart, for refetches (the change signal, later
// pages). Same contract: never throws on non-2xx; branch on `ok`.
export async function getJSON<T = unknown>(
  path: string,
  opts?: { credentials?: RequestCredentials },
): Promise<ApiResult<T>> {
  const res = await fetch(path, {
    method: "GET",
    credentials: opts?.credentials ?? "same-origin",
    headers: { Accept: "application/json", "X-Vault3-Client": clientID() },
  });
  const data = (await res.json().catch(() => null)) as T | null;
  return { ok: res.ok, status: res.status, data };
}
