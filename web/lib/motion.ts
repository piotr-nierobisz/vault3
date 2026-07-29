// Brand motion primitives shared by the server-rendered public pages
// (landing, security). Everything here is garnish: the markup reads
// correctly with JS disabled, and every effect no-ops under
// prefers-reduced-motion.

export const REDUCED_MOTION = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const CIPHER_GLYPHS = "!<>-_\\/[]{}—=+*^?#ABCDEF0123456789";
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function randomGlyph(): string {
  return CIPHER_GLYPHS[Math.floor(Math.random() * CIPHER_GLYPHS.length)];
}

/** Base64url filler: stand-in ciphertext for the marketing visuals. */
export function randomB64(length: number): string {
  return Array.from({ length }, () => B64[Math.floor(Math.random() * B64.length)]).join("");
}

/**
 * Sections marked .scroll-reveal fade up as they enter the viewport.
 *
 * This sweeps on scroll rather than using IntersectionObserver: the
 * observer only reports at sampling points, so a fling or a programmatic
 * jump can carry a section past the viewport without ever firing, leaving
 * it stuck at opacity 0. A sweep reveals anything whose top has crossed
 * the trigger line, including everything already scrolled past, so content
 * can never be left invisible. It unbinds once every section is revealed.
 */
export function initScrollReveal(): void {
  const targets = Array.from(document.querySelectorAll<HTMLElement>(".scroll-reveal"));
  if (!targets.length) return;
  if (REDUCED_MOTION) {
    targets.forEach((el) => el.classList.add("is-visible"));
    return;
  }

  let pending = targets;
  let queued = false;

  const sweep = () => {
    queued = false;
    const trigger = window.innerHeight * 0.88;
    pending = pending.filter((el) => {
      if (el.getBoundingClientRect().top >= trigger) return true;
      el.classList.add("is-visible");
      return false;
    });
    if (!pending.length) {
      window.removeEventListener("scroll", onChange);
      window.removeEventListener("resize", onChange);
    }
  };

  const onChange = () => {
    if (queued) return;
    queued = true;
    requestAnimationFrame(sweep);
  };

  window.addEventListener("scroll", onChange, { passive: true });
  window.addEventListener("resize", onChange, { passive: true });
  sweep();
}

/**
 * The unsealing move: text resolves out of cipher noise, character by
 * character, left to right. Replaces the element's contents with one span
 * per character.
 */
export function scrambleInto(el: HTMLElement, finalText: string, durationMs = 1400): void {
  const chars = finalText.split("");
  const spans = chars.map((ch) => {
    const span = document.createElement("span");
    span.className = "cipher-char is-scrambling";
    span.textContent = ch === " " ? " " : randomGlyph();
    return span;
  });
  el.textContent = "";
  spans.forEach((s) => el.appendChild(s));

  const start = performance.now();
  const tick = (now: number) => {
    const progress = Math.min(1, (now - start) / durationMs);
    const settled = Math.floor(progress * chars.length);
    spans.forEach((span, i) => {
      if (i < settled || progress === 1) {
        if (span.classList.contains("is-scrambling")) {
          span.classList.remove("is-scrambling");
          span.textContent = chars[i] === " " ? " " : chars[i];
        }
      } else if (Math.random() < 0.35) {
        span.textContent = randomGlyph();
      }
    });
    if (progress < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}