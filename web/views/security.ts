// Enhancement view for the server-rendered security page. Scroll reveals
// plus a slow reseal of the ciphertext pane in the "what the server sees"
// comparison, so the claim is demonstrated rather than only asserted.
// Garnish only: the page is complete with JS disabled.

import { initScrollReveal, randomB64, REDUCED_MOTION, scrambleInto } from "../lib/motion";

initScrollReveal();

const cipherPane = document.querySelector<HTMLElement>("[data-security-cipher]");
if (cipherPane && !REDUCED_MOTION) {
  const lines = Array.from(cipherPane.querySelectorAll<HTMLElement>("[data-cipher-line]"));
  const reseal = () => {
    lines.forEach((line, i) => {
      const length = (line.textContent ?? "").replace("…", "").length;
      window.setTimeout(() => scrambleInto(line, randomB64(length) + "…", 900), i * 260);
    });
    window.setTimeout(reseal, 6400);
  };
  window.setTimeout(reseal, 1200);
}