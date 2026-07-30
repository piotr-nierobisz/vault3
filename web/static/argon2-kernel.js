// Argon2id WebAssembly kernel: integrity gate, WASI shim, and call ABI.
//
// This file is served verbatim from /static/ — it is deliberately NOT part of
// the bundled application code, because two very different callers import it
// and both need to be running the same bytes:
//
//   * web/static/argon2-worker.js   — the browser, off the main thread
//   * scripts/verify-wasm.mjs       — the known-answer check, under node
//
// If the verification script exercised its own copy of this logic, it would
// prove nothing about what the browser actually executes. Sharing it means a
// passing KAT is a statement about the real unlock path.
//
// Nothing here is secret. The password material passes through, but the file
// is public, cached, and CSP-restricted to this origin like every other
// script in the app.

// Byte offsets inside the module's fixed arena. These mirror the constants in
// internal/wasm/argon2/main.go and must be changed in step with it.
export const ARENA = Object.freeze({
  PASSWORD: 0,
  PASSWORD_MAX: 1024,
  SALT: 1024,
  SALT_MAX: 1024,
  OUTPUT: 2048,
  OUTPUT_MAX: 1024,
});

const STATUS_MESSAGES = {
  1: "argon2id rejected the input lengths",
  2: "argon2id rejected the cost parameters",
};

// wasiShim supplies the ten imports Go's wasip1 runtime links against. The
// module does no I/O of its own: it never opens a file, never sees the
// network, and returns a single buffer of bytes. Everything below is either a
// constant answer (no arguments, no environment, nothing to poll) or the two
// facilities the Go runtime genuinely needs to start — a monotonic clock and
// an entropy source.
//
// fd_write is the exception worth keeping honest: it is the only way a Go
// panic inside the module can surface as anything other than silence, so it
// captures the runtime's stderr and hands it back with the trap.
function wasiShim(getMemory, onExit, diagnostics) {
  const view = () => new DataView(getMemory().buffer);
  const bytes = () => new Uint8Array(getMemory().buffer);
  const decoder = new TextDecoder();
  const origin = performanceNow();
  let stderr = "";

  const emptyPair = (countPtr, sizePtr) => {
    const dv = view();
    dv.setUint32(countPtr, 0, true);
    dv.setUint32(sizePtr, 0, true);
    return 0;
  };

  return {
    sched_yield: () => 0,
    proc_exit: (code) => onExit(code, stderr),
    args_get: () => 0,
    args_sizes_get: emptyPair,
    environ_get: () => 0,
    environ_sizes_get: emptyPair,
    clock_time_get: (_clockID, _precision, resultPtr) => {
      const elapsedNanos = BigInt(Math.round((performanceNow() - origin) * 1e6));
      view().setBigUint64(resultPtr, elapsedNanos, true);
      return 0;
    },
    fd_write: (_fd, iovsPtr, iovsLen, writtenPtr) => {
      let written = 0;
      const dv = view();
      for (let i = 0; i < iovsLen; i++) {
        const bufPtr = dv.getUint32(iovsPtr + i * 8, true);
        const bufLen = dv.getUint32(iovsPtr + i * 8 + 4, true);
        stderr += decoder.decode(bytes().slice(bufPtr, bufPtr + bufLen));
        written += bufLen;
      }
      diagnostics.stderr = stderr;
      dv.setUint32(writtenPtr, written, true);
      return 0;
    },
    random_get: (ptr, len) => {
      crypto.getRandomValues(bytes().subarray(ptr, ptr + len));
      return 0;
    },
    // poll_oneoff cannot be stubbed out, however much it looks like it should
    // be: the module has no files and no sockets, so the obvious ENOSYS is
    // tempting. But Go's scheduler calls this whenever every goroutine is
    // parked on a timer — which happens for real once a GC background worker
    // sleeps partway through a large hash — and a runtime that gets ENOSYS
    // here throws "errno= 52" and traps the instance mid-derivation.
    //
    // Every subscription the runtime can raise is therefore a clock, and the
    // honest answer is to wait out the shortest one and report it fired. The
    // wait is a spin because a worker cannot block without SharedArrayBuffer
    // (which needs COOP/COEP headers this app does not set), and it is capped
    // because a spin is a poor way to pass real time — overshooting a
    // scheduler tick costs nothing but correctness never depends on it.
    poll_oneoff: (inPtr, outPtr, nsubscriptions, neventsPtr) => {
      if (nsubscriptions === 0) return 28; // EINVAL
      const dv = view();
      let earliestDeadline = Infinity;

      for (let i = 0; i < nsubscriptions; i++) {
        const sub = inPtr + i * 48;
        if (dv.getUint8(sub + 8) !== 0) return 58; // ENOTSUP — not a clock
        const timeoutNanos = Number(dv.getBigUint64(sub + 24, true));
        const isAbsolute = (dv.getUint16(sub + 40, true) & 1) === 1;
        const nowNanos = (performanceNow() - origin) * 1e6;
        const deadline = isAbsolute ? timeoutNanos : nowNanos + timeoutNanos;
        if (deadline < earliestDeadline) earliestDeadline = deadline;
      }

      const spinUntil = performanceNow() + Math.min(earliestDeadline / 1e6 - (performanceNow() - origin), 20);
      while (performanceNow() < spinUntil) {
        /* spin */
      }

      // One event, for the first subscription: the runtime only needs to learn
      // that time has passed, not which of several identical timers won.
      const out = view();
      out.setBigUint64(outPtr, dv.getBigUint64(inPtr, true), true); // userdata
      out.setUint16(outPtr + 8, 0, true); // error
      out.setUint8(outPtr + 10, 0); // type = clock
      out.setUint32(neventsPtr, 1, true);
      return 0;
    },
  };
}

function performanceNow() {
  return typeof performance !== "undefined" ? performance.now() : Number(process.hrtime.bigint()) / 1e6;
}

// base64 of a digest, in the same encoding the manifest pins.
async function sha512Base64(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-512", bytes));
  let binary = "";
  digest.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary);
}

// instantiateKernel checks the module against its pinned digest and only then
// compiles it.
//
// This is the tamper-evidence boundary, and it is worth being precise about
// what it does and does not buy. It defends against anything that can alter
// the bytes in transit or at rest — a poisoned cache, a compromised CDN or
// object store, a corrupted download, a stale artifact left behind by a bad
// deploy. It does NOT defend against a malicious server, because the same
// server serves the pin; that residual risk is the one docs/security.md
// already names for all of the app's JavaScript, and it is why the digest is
// reproducible from source (scripts/build-wasm.sh) rather than merely
// asserted.
//
// It fails closed. A mismatch throws rather than falling back to a slower or
// weaker derivation, because silently deriving a key by some other means is
// how a vault ends up encrypted under something its owner cannot reproduce.
export async function instantiateKernel(wasmBytes, expectedSha512) {
  const actual = await sha512Base64(wasmBytes);
  if (actual !== expectedSha512) {
    throw new Error(
      `Argon2 module integrity check failed: expected sha512-${expectedSha512}, got sha512-${actual}`,
    );
  }

  let instance;
  // A Go runtime failure inside the module (most plausibly "out of memory" on
  // a device that cannot grow linear memory to the requested cost) writes its
  // reason to stderr and then executes `unreachable`. The trap that reaches
  // JavaScript carries none of that text, so the shim keeps the last thing the
  // runtime said and the call wrapper below reattaches it. Without this, every
  // such failure reads as a bare "unreachable".
  const diagnostics = { stderr: "" };
  const imports = {
    wasi_snapshot_preview1: wasiShim(
      () => instance.exports.memory,
      (code, stderr) => {
        throw new Error(`Argon2 module exited (${code})${stderr ? `: ${stderr.trim()}` : ""}`);
      },
      diagnostics,
    ),
  };

  instance = (await WebAssembly.instantiate(wasmBytes, imports)).instance;
  instance.exports._initialize();

  const arena = instance.exports.arena_ptr();

  return {
    // argon2id writes password and salt into the arena, hashes, and copies the
    // result out. Linear memory grows during hashing, which detaches every
    // ArrayBuffer view taken before the call, so the views are re-derived on
    // each side of it rather than cached.
    argon2id(password, salt, { time, memoryKiB, lanes, outLen }) {
      if (password.length > ARENA.PASSWORD_MAX) throw new Error("argon2id: password too long");
      if (salt.length > ARENA.SALT_MAX) throw new Error("argon2id: salt too long");
      if (outLen > ARENA.OUTPUT_MAX) throw new Error("argon2id: output too long");

      new Uint8Array(instance.exports.memory.buffer).set(password, arena + ARENA.PASSWORD);
      new Uint8Array(instance.exports.memory.buffer).set(salt, arena + ARENA.SALT);

      let status;
      try {
        status = instance.exports.argon2id(password.length, salt.length, time, memoryKiB, lanes, outLen);
      } catch (trap) {
        const reason = diagnostics.stderr.trim().split("\n")[0];
        throw new Error(`argon2id trapped (${trap.message})${reason ? `: ${reason}` : ""}`);
      }
      if (status !== 0) {
        throw new Error(STATUS_MESSAGES[status] ?? `argon2id failed with status ${status}`);
      }

      const start = arena + ARENA.OUTPUT;
      return new Uint8Array(instance.exports.memory.buffer).slice(start, start + outLen);
    },
    // zero wipes password-derived material out of linear memory. Call it once
    // the derived key has been copied somewhere it belongs.
    zero() {
      instance.exports.zero_arena();
    },
  };
}