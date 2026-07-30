// Argon2id worker: runs one derivation, off the main thread, then exits.
//
// Two reasons this is a worker rather than a straight call.
//
// The obvious one is that Argon2id at the registered costs occupies a core
// for the better part of a second. On the main thread that is a frozen tab —
// no repaint, no spinner motion, nothing to tell the user the app is working
// rather than broken. The progress UI in web/components/ui/derivation-progress
// only animates because this thread is busy instead of that one.
//
// The less obvious one is memory hygiene. A wasm instance's linear memory can
// only ever grow, so a long-lived instance that has hashed at 64 MiB keeps
// that allocation for the life of the page, and reusing one across several
// derivations eventually fails outright. One worker per derivation, terminated
// by the caller once the key is out, means the whole arena — and every
// intermediate Argon2 block, which is password-derived material — is released
// to the OS rather than lingering in a tab that stays open for hours.
//
// Served from /static/ as-is, not bundled: it must share exactly one copy of
// argon2-kernel.js with scripts/verify-wasm.mjs so the known-answer tests
// speak about the code that actually runs here.

import { instantiateKernel } from "./argon2-kernel.js";

self.onmessage = async (event) => {
  const { wasmUrl, expectedSha512, password, salt, time, memoryKiB, lanes, outLen } = event.data;

  try {
    // Fetch, verify and instantiate all happen here rather than being handed
    // an already-compiled module: the integrity check and the execution then
    // live in the same context, with no interval in between where a verified
    // module could be swapped for another.
    const response = await fetch(wasmUrl, { credentials: "omit", cache: "force-cache" });
    if (!response.ok) {
      throw new Error(`could not load the key-derivation module (HTTP ${response.status})`);
    }
    const wasmBytes = new Uint8Array(await response.arrayBuffer());

    const kernel = await instantiateKernel(wasmBytes, expectedSha512);
    const key = kernel.argon2id(password, salt, { time, memoryKiB, lanes, outLen });
    kernel.zero();

    password.fill(0);
    salt.fill(0);

    self.postMessage({ ok: true, key }, [key.buffer]);
  } catch (err) {
    if (password) password.fill(0);
    if (salt) salt.fill(0);
    self.postMessage({ ok: false, error: err instanceof Error ? err.message : String(err) });
  }
};
