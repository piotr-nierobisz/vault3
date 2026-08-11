// Enhancement view for the server-rendered features page. Scroll reveals,
// plus the item-type showcase: the specimen card cycles through the four
// categories, and clicking a tab takes it over.
//
// Deliberately not the landing's or the security page's effects — this page
// has its own figures and its own motion. Garnish only: with JavaScript off
// the first tab stays selected and its fields are already in the markup.

import { initScrollReveal, REDUCED_MOTION } from "../lib/motion";

initScrollReveal();

// ── Item-type showcase ──────────────────────────────────────────────────────
// Field lists mirror CATEGORY_FIELDS in web/types/vault.ts, plus the notes
// every item carries. Keep them in step: a figure that shows fields the app
// does not have is a false claim, same as any other.

type Field = { label: string; value: string; secret?: boolean };
type Category = { title: string; fields: Field[] };

const CATEGORIES: Record<string, Category> = {
  login: {
    title: "Acme Bank",
    fields: [
      { label: "Username / email", value: "nora@fastmail.com" },
      { label: "Password", value: "••••••••••••", secret: true },
      { label: "One-time code", value: "481 207" },
      { label: "Notes", value: "joint account" },
    ],
  },
  secure_note: {
    title: "Safe combination",
    fields: [
      { label: "Notes", value: "third drawer, behind the deeds" },
      { label: "Everything else", value: "up to you" },
    ],
  },
  card: {
    title: "Travel card",
    fields: [
      { label: "Cardholder name", value: "NORA SANDOVAL" },
      { label: "Card number", value: "•••• •••• •••• 4242", secret: true },
      { label: "Expiry", value: "12/28" },
      { label: "CVV", value: "•••", secret: true },
    ],
  },
  identity: {
    title: "Me, for forms",
    fields: [
      { label: "Full name", value: "Nora Sandoval" },
      { label: "Email", value: "nora@fastmail.com" },
      { label: "Phone", value: "+44 7700 900000" },
      { label: "Address", value: "12 Example Street" },
    ],
  },
};

const tabWrap = document.querySelector<HTMLElement>("[data-cat-tabs]");
const body = document.querySelector<HTMLElement>("[data-spec-body]");
const title = document.querySelector<HTMLElement>("[data-spec-title]");

if (tabWrap && body && title) {
  const tabs = Array.from(tabWrap.querySelectorAll<HTMLButtonElement>("[data-cat]"));
  const order = tabs.map((t) => t.dataset.cat ?? "");
  let index = 0;
  let auto = !REDUCED_MOTION;
  let timer = 0;

  const paint = (key: string) => {
    const category = CATEGORIES[key];
    if (!category) return;
    title.textContent = category.title;
    body.replaceChildren(
      ...category.fields.map((field) => {
        const row = document.createElement("p");
        row.className = "spec-field";
        const label = document.createElement("span");
        label.textContent = field.label;
        const value = document.createElement("span");
        if (field.secret) value.className = "is-secret";
        value.textContent = field.value;
        row.append(label, value);
        return row;
      }),
    );
  };

  const select = (next: number) => {
    index = next;
    tabs.forEach((tab, i) => tab.setAttribute("aria-selected", String(i === index)));
    // Fade out, swap, fade back: a slide would drag the eye away from the
    // copy sitting beside the card.
    if (REDUCED_MOTION) {
      paint(order[index]);
      return;
    }
    body.classList.add("is-swapping");
    window.setTimeout(() => {
      paint(order[index]);
      body.classList.remove("is-swapping");
    }, 200);
  };

  const queue = () => {
    if (!auto) return;
    timer = window.setTimeout(() => {
      select((index + 1) % order.length);
      queue();
    }, 3800);
  };

  tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => {
      // A deliberate choice outranks the carousel — once someone has picked
      // a type, moving it under them is the rudest thing this page could do.
      auto = false;
      window.clearTimeout(timer);
      select(i);
    });
  });

  queue();
}
