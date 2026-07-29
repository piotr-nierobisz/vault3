// Enhancement view for the server-rendered landing page (no React, no
// _bungoRender): scroll reveals, the hero cipher scramble, and the sealing
// demo. The page reads perfectly with JS disabled — these are garnish.

import { initScrollReveal, randomB64, REDUCED_MOTION, scrambleInto } from "../lib/motion";

initScrollReveal();

// ── Hero cipher scramble ────────────────────────────────────────────────────
// The headline keyword resolves out of cipher noise: the brand's
// "unsealing" move.

const heroTarget = document.querySelector<HTMLElement>("[data-cipher-target]");
if (heroTarget) {
  const finalText = heroTarget.textContent ?? "sealed.";
  if (REDUCED_MOTION) {
    heroTarget.textContent = finalText;
  } else {
    scrambleInto(heroTarget, finalText, 1500);
  }
}

// ── Sealing demo ────────────────────────────────────────────────────────────
// Loops: plaintext visible → fields scramble into cipher → badge flips to
// "sealed", ciphertext block refreshes → pause → restore and repeat.

const demo = document.querySelector<HTMLElement>("[data-seal-demo]");
if (demo && !REDUCED_MOTION) {
  const stateBadge = demo.querySelector<HTMLElement>("[data-seal-state]");
  const cipherBlock = demo.querySelector<HTMLElement>("[data-seal-cipher]");
  const fields = Array.from(demo.querySelectorAll<HTMLElement>("[data-seal-plain]"));
  const originals = fields.map((f) => f.textContent ?? "");

  const cycle = () => {
    if (stateBadge) stateBadge.textContent = "sealing…";
    fields.forEach((field, i) => {
      window.setTimeout(() => scrambleInto(field, randomB64(originals[i].length), 700), i * 220);
    });
    window.setTimeout(() => {
      if (cipherBlock) cipherBlock.textContent = randomB64(46) + "…";
      if (stateBadge) stateBadge.textContent = "sealed ✓";
    }, 1300);
    window.setTimeout(() => {
      fields.forEach((field, i) => scrambleInto(field, originals[i], 600));
      if (stateBadge) stateBadge.textContent = "on your device";
    }, 4200);
    window.setTimeout(cycle, 7600);
  };
  window.setTimeout(cycle, 1800);
}