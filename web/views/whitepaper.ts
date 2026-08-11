// Enhancement view for the server-rendered whitepaper. Scroll reveals, plus
// a table of contents that marks the section currently being read.
//
// The document is long by design, and a reader who has scrolled into the
// middle of it should be able to see where they are without scrolling back.
// Garnish only: with JS disabled the contents list is still a working set of
// anchor links, and every section still renders.

import { initScrollReveal } from "../lib/motion";

initScrollReveal();

// ── Table-of-contents scrollspy ─────────────────────────────────────────────
// Same sweep-on-scroll approach as initScrollReveal, and for the same reason:
// an observer reports at sampling points, so a fling can carry a section past
// without ever firing. Sweeping the section tops picks the last one above the
// reading line, which is correct no matter how the reader got there.

const links = Array.from(document.querySelectorAll<HTMLAnchorElement>("[data-toc] a[href^='#']"));
const sections = links
  .map((link) => document.getElementById(decodeURIComponent(link.hash.slice(1))))
  .filter((el): el is HTMLElement => el !== null);

if (links.length && links.length === sections.length) {
  let queued = false;
  let current = -1;

  const sweep = () => {
    queued = false;
    // A third of the way down the viewport: a section counts as "being read"
    // once its heading has risen past that line, not when it first appears.
    const line = window.innerHeight / 3;
    let active = 0;
    sections.forEach((section, i) => {
      if (section.getBoundingClientRect().top <= line) active = i;
    });
    // Anchored to the bottom, the last section may never cross the line —
    // reaching the end of the page selects it regardless.
    if (window.innerHeight + window.scrollY >= document.body.scrollHeight - 2) {
      active = sections.length - 1;
    }
    if (active === current) return;
    if (current >= 0) links[current].removeAttribute("aria-current");
    links[active].setAttribute("aria-current", "true");
    current = active;
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
