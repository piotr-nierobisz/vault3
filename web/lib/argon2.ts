// Argon2id, as the browser sees it.
//
// The implementation is a WebAssembly module compiled from
// internal/wasm/argon2/main.go, which wraps the same golang.org/x/crypto/argon2
// the server uses. This file is only the typed door to it: it spawns the
// worker, hands over the pinned digest, and disposes of the worker afterwards.
//
// Why not pure JavaScript: Argon2id's cost is deliberately memory-bound, and a
// JS engine pays roughly an order of magnitude over native for the random
// access pattern that makes it memory-bound. Paying that tax would mean
// lowering the parameters until the honest user's unlock was tolerable — while
// an attacker's native cracking rig pays nothing either way. The whole point
// of choosing a memory-hard KDF is lost if it has to run slowly.
//
// Why not WASM compiled from C or Rust: it would mean adding a second
// cross-compiler to a repository whose entire build is `go build` and BunGo's
// bundled esbuild. Go reaches wasm natively, so the artifact is reproducible
// with the toolchain already required to work on this project — which is what
// makes the digest below independently checkable rather than a number someone
// has to take on faith. See scripts/build-wasm.sh.

import { ARGON2_WASM_SHA512, ARGON2_WASM_URL } from "./argon2-manifest";

const WORKER_URL = "/static/argon2-worker.js";

export type Argon2Params = {
  /** Passes over memory. */
  time: number;
  /** Memory cost in KiB. */
  memoryKiB: number;
  /** Degree of parallelism. */
  lanes: number;
  /** Length of the derived key in bytes. */
  outLen: number;
};

/**
 * argon2id derives `params.outLen` bytes from a password and salt.
 *
 * Each call runs in its own worker, which is terminated as soon as the key is
 * out — see web/static/argon2-worker.js for why a shared instance is the wrong
 * shape here. The inputs are copied before being transferred, so the caller's
 * arrays survive the call and can be zeroed on their own schedule.
 */
export async function argon2id(password: Uint8Array, salt: Uint8Array, params: Argon2Params): Promise<Uint8Array> {
  if (typeof Worker === "undefined") {
    throw new Error("This browser cannot run the key-derivation module (Web Workers unavailable).");
  }

  const worker = new Worker(WORKER_URL, { type: "module", name: "vault3-argon2" });
  const passwordCopy = password.slice();
  const saltCopy = salt.slice();

  try {
    return await new Promise<Uint8Array>((resolve, reject) => {
      worker.onmessage = (event: MessageEvent) => {
        const result = event.data as { ok: boolean; key?: Uint8Array; error?: string };
        if (result.ok && result.key) resolve(result.key);
        else reject(new Error(result.error ?? "Key derivation failed."));
      };
      // A worker that fails to load at all (module blocked, file missing)
      // fires onerror and never messages back, so the promise would otherwise
      // hang on the unlock screen forever.
      worker.onerror = (event: ErrorEvent) => {
        reject(new Error(event.message || "The key-derivation module could not be started."));
      };
      worker.onmessageerror = () => reject(new Error("The key-derivation module sent an unreadable reply."));

      worker.postMessage(
        {
          wasmUrl: ARGON2_WASM_URL,
          expectedSha512: ARGON2_WASM_SHA512,
          password: passwordCopy,
          salt: saltCopy,
          ...params,
        },
        [passwordCopy.buffer, saltCopy.buffer],
      );
    });
  } finally {
    worker.terminate();
  }
}
